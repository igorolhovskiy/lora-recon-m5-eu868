#!/usr/bin/env python3
"""
Unit tests for lora_recon.py
Tests do NOT require hardware — all serial I/O is mocked.
"""

import pytest
import time
import threading
from unittest.mock import MagicMock, patch, call
from dataclasses import asdict

from lora_recon import (
    parse_lorawan,
    parse_events,
    PacketRecord,
    DeduplicationCache,
    LoRaUnit,
    SweepScanner,
    LockMonitor,
    OutputManager,
    auto_detect_port,
    EU868_CHANNELS,
    RX2_FREQ,
    RX2_SF,
    SPREADING_FACTORS,
)


# ---------------------------------------------------------------------------
# parse_lorawan
# ---------------------------------------------------------------------------
class TestParseLoraWan:
    def test_unconfirmed_data_up(self):
        # Build a minimal Unconfirmed Data Up frame manually
        # MHDR = 0x40 (010 00000 = Unconfirmed Data Up)
        # DevAddr = 0x260B1234 (little-endian: 34 12 0B 26)
        # FCtrl = 0x00, FCnt = 0x0001
        frame = bytes([0x40, 0x34, 0x12, 0x0B, 0x26, 0x00, 0x01, 0x00, 0xAA, 0xBB])
        result = parse_lorawan(frame.hex())
        assert result["mtype"] == "Unconfirmed Data Up"
        assert result["dev_addr"] == "260B1234"
        assert result["fcnt"] == 1

    def test_confirmed_data_up(self):
        # MHDR = 0x80 (100 00000 = Confirmed Data Up)
        frame = bytes([0x80, 0x34, 0x12, 0x0B, 0x26, 0x80, 0x05, 0x00, 0xCC])
        result = parse_lorawan(frame.hex())
        assert result["mtype"] == "Confirmed Data Up"
        assert result["adr"] is True

    def test_join_request(self):
        # MHDR = 0x00 (000 = Join Request)
        # JoinEUI bytes 1-8, DevEUI bytes 9-16 (both stored little-endian, reversed in parse)
        join_eui_raw = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        dev_eui_raw  = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        mic = bytes([0xAA, 0xBB, 0xCC, 0xDD])
        frame = bytes([0x00]) + join_eui_raw + dev_eui_raw + mic
        result = parse_lorawan(frame.hex())
        assert result["mtype"] == "Join Request"
        assert result["join_eui"] == join_eui_raw[::-1].hex().upper()
        assert result["dev_eui"]  == dev_eui_raw[::-1].hex().upper()

    def test_ttn_nwkid(self):
        # DevAddr with NwkID = 0x13 → TTN
        # NwkID = top 7 bits of DevAddr >> 25
        # 0x13 << 25 = 0x26000000
        dev_addr_val = 0x26000000
        import struct
        da_bytes = struct.pack("<I", dev_addr_val)
        frame = bytes([0x40]) + da_bytes + bytes([0x00, 0x00, 0x00, 0xAA])
        result = parse_lorawan(frame.hex())
        assert result.get("operator_hint", "").startswith("TTN")

    def test_actility_nwkid(self):
        dev_addr_val = 0x48000000  # NwkID = 0x24
        import struct
        da_bytes = struct.pack("<I", dev_addr_val)
        frame = bytes([0x40]) + da_bytes + bytes([0x00, 0x00, 0x00, 0xAA])
        result = parse_lorawan(frame.hex())
        assert result.get("operator_hint", "").startswith("Actility")

    def test_private_nwkid(self):
        dev_addr_val = 0x00000001  # NwkID = 0x00
        import struct
        da_bytes = struct.pack("<I", dev_addr_val)
        frame = bytes([0x40]) + da_bytes + bytes([0x00, 0x00, 0x00, 0xAA])
        result = parse_lorawan(frame.hex())
        assert result.get("operator_hint", "").startswith("Private")

    def test_too_short(self):
        assert parse_lorawan("AABB") == {}

    def test_invalid_hex(self):
        result = parse_lorawan("ZZZZ")
        assert result == {}

    def test_empty(self):
        assert parse_lorawan("") == {}


# ---------------------------------------------------------------------------
# parse_events
# ---------------------------------------------------------------------------
class TestParseEvents:
    def test_adjacent_lines(self):
        lines = [
            "+EVT:RXP2P,RSSI -110,SNR 5",
            "+EVT:00112233AABBCC",
        ]
        results = parse_events(lines)
        assert len(results) == 1
        assert results[0]["rssi"] == -110
        assert results[0]["snr"] == 5
        assert results[0]["raw_hex"] == "00112233AABBCC"

    def test_non_adjacent_lines(self):
        lines = [
            "+EVT:RXP2P,RSSI -90,SNR 8",
            "some garbage line",
            "+EVT:DEADBEEF",
        ]
        results = parse_events(lines)
        assert len(results) == 1
        assert results[0]["rssi"] == -90
        assert results[0]["raw_hex"] == "DEADBEEF"

    def test_multiple_events(self):
        lines = [
            "+EVT:RXP2P,RSSI -100,SNR 3",
            "+EVT:AABBCCDD",
            "+EVT:RXP2P,RSSI -80,SNR 10",
            "+EVT:11223344",
        ]
        results = parse_events(lines)
        assert len(results) == 2
        assert results[0]["rssi"] == -100
        assert results[0]["raw_hex"] == "AABBCCDD"
        assert results[1]["rssi"] == -80
        assert results[1]["raw_hex"] == "11223344"

    def test_signal_without_payload(self):
        lines = ["+EVT:RXP2P,RSSI -100,SNR 3"]
        results = parse_events(lines)
        assert len(results) == 1
        assert results[0]["rssi"] == -100
        assert results[0]["raw_hex"] == ""

    def test_orphan_payload(self):
        lines = ["+EVT:DEADBEEF"]
        results = parse_events(lines)
        assert len(results) == 1
        assert results[0]["rssi"] is None
        assert results[0]["raw_hex"] == "DEADBEEF"

    def test_empty_input(self):
        assert parse_events([]) == []

    def test_noise_only(self):
        lines = ["OK", "AT+PRECV=5000", "some other line"]
        assert parse_events(lines) == []

    def test_case_insensitive_rssi(self):
        lines = ["+EVT:RXP2P,rssi -55,snr 9", "+EVT:CAFEBABE"]
        results = parse_events(lines)
        assert results[0]["rssi"] == -55
        assert results[0]["snr"] == 9

    def test_payload_not_matched_to_wrong_event(self):
        # Two signal lines followed by two payload lines; should pair correctly
        lines = [
            "+EVT:RXP2P,RSSI -100,SNR 3",
            "+EVT:RXP2P,RSSI -80,SNR 7",
            "+EVT:AAAA1111",
            "+EVT:BBBB2222",
        ]
        results = parse_events(lines)
        # First signal gets first available payload, second signal gets second
        assert len(results) == 2
        hexes = {r["raw_hex"] for r in results}
        assert "AAAA1111" in hexes
        assert "BBBB2222" in hexes


# ---------------------------------------------------------------------------
# DeduplicationCache
# ---------------------------------------------------------------------------
class TestDeduplicationCache:
    def test_no_dup_different_fcnt(self):
        dc = DeduplicationCache(window_seconds=30)
        assert not dc.is_duplicate("AABBCCDD", 1)
        assert not dc.is_duplicate("AABBCCDD", 2)

    def test_dup_same_addr_fcnt(self):
        dc = DeduplicationCache(window_seconds=30)
        assert not dc.is_duplicate("AABBCCDD", 10)
        assert dc.is_duplicate("AABBCCDD", 10)

    def test_no_dup_after_window_expires(self):
        dc = DeduplicationCache(window_seconds=0.05)
        assert not dc.is_duplicate("AABBCCDD", 5)
        time.sleep(0.1)
        assert not dc.is_duplicate("AABBCCDD", 5)  # window expired

    def test_none_values_never_dedup(self):
        dc = DeduplicationCache()
        assert not dc.is_duplicate(None, None)
        assert not dc.is_duplicate(None, None)  # still not a dup

    def test_purge_removes_old_entries(self):
        dc = DeduplicationCache(window_seconds=0.05)
        dc.is_duplicate("X", 1)
        time.sleep(0.1)
        dc.purge()
        assert len(dc._seen) == 0

    def test_different_devices_same_fcnt(self):
        dc = DeduplicationCache()
        assert not dc.is_duplicate("AAAA", 1)
        assert not dc.is_duplicate("BBBB", 1)  # different device, same FCnt → not a dup


# ---------------------------------------------------------------------------
# PacketRecord
# ---------------------------------------------------------------------------
class TestPacketRecord:
    def test_summary_uplink(self):
        pkt = PacketRecord(
            timestamp="2024-01-01T00:00:00Z",
            freq=868100000, sf=7, bw=125,
            rssi=-90, snr=5, raw_hex="DEADBEEF",
            mtype="Unconfirmed Data Up",
            dev_addr="AABBCCDD", fcnt=42,
        )
        s = pkt.summary()
        assert "868.100MHz" in s
        assert "SF7" in s
        assert "RSSI=-90dBm" in s
        assert "DevAddr=AABBCCDD" in s
        assert "FCnt=42" in s
        assert "DOWNLINK" not in s

    def test_summary_downlink(self):
        pkt = PacketRecord(
            timestamp="2024-01-01T00:00:00Z",
            freq=869525000, sf=12, bw=125,
            rssi=-100, snr=2, raw_hex="",
            is_downlink=True,
        )
        assert "DOWNLINK" in pkt.summary()
        assert "GATEWAY EVIDENCE" in pkt.summary()

    def test_summary_join_request(self):
        pkt = PacketRecord(
            timestamp="2024-01-01T00:00:00Z",
            freq=868100000, sf=9, bw=125,
            rssi=-95, snr=4, raw_hex="AA",
            mtype="Join Request",
            join_eui="0102030405060708",
        )
        s = pkt.summary()
        assert "JoinEUI" in s


# ---------------------------------------------------------------------------
# LoRaUnit (mocked serial)
# ---------------------------------------------------------------------------
class TestLoRaUnit:
    def _make_unit(self, readline_responses):
        """Return a LoRaUnit with a mocked serial port."""
        mock_ser = MagicMock()
        mock_ser.readline.side_effect = [
            (line + "\r\n").encode() if line else b""
            for line in readline_responses
        ] + [b""] * 100  # trailing empty reads

        with patch("lora_recon.serial.Serial", return_value=mock_ser):
            unit = LoRaUnit("/dev/ttyUSB0")
        unit.ser = mock_ser
        return unit

    def test_ping_ok(self):
        unit = self._make_unit(["OK"])
        assert unit.ping() is True

    def test_ping_fail(self):
        unit = self._make_unit(["AT_ERROR"])
        assert unit.ping() is False

    def test_configure_p2p(self):
        unit = self._make_unit(["OK"])
        assert unit.configure_p2p(868100000, 7) is True
        call_args = unit.ser.write.call_args_list
        written = b"".join(c[0][0] for c in call_args)
        assert b"AT+P2P=868100000:7:125:0:8:14" in written

    def test_start_rx(self):
        unit = self._make_unit(["OK"])
        assert unit.start_rx(5000) is True

    def test_stop_rx(self):
        unit = self._make_unit(["OK"])
        assert unit.stop_rx() is True

    def test_get_version(self):
        unit = self._make_unit(["RUI_4.1.0", "OK"])
        assert unit.get_version() == "RUI_4.1.0"

    def test_read_async_events(self):
        lines_in = [
            "+EVT:RXP2P,RSSI -90,SNR 6",
            "+EVT:DEADBEEF",
            "",
        ]
        unit = self._make_unit(lines_in)
        # Override timeout behaviour: read_async_events uses duration
        # We patch time.time to control loop
        original_time = time.time
        t0 = original_time()
        call_count = [0]

        def fake_time():
            call_count[0] += 1
            # Advance by 0.1s per call to exhaust 0.3s duration
            return t0 + call_count[0] * 0.1

        with patch("lora_recon.time.time", side_effect=fake_time):
            result = unit.read_async_events(0.25)
        assert any("+EVT:RXP2P" in l for l in result)


# ---------------------------------------------------------------------------
# SweepScanner (mocked unit)
# ---------------------------------------------------------------------------
class TestSweepScanner:
    def _make_scanner(self, packets_per_hop=0):
        """
        Returns (scanner, mock_unit).
        packets_per_hop: number of fake packets to inject per channel hop.
        """
        unit = MagicMock(spec=LoRaUnit)
        unit.configure_p2p.return_value = True
        unit.start_rx.return_value = True
        unit.stop_rx.return_value = True

        if packets_per_hop > 0:
            # Build a frame: Unconfirmed Data Up, DevAddr=0x260B1234, FCnt=1
            import struct
            dev_addr = struct.pack("<I", 0x260B1234)
            frame = bytes([0x40]) + dev_addr + bytes([0x00, 0x01, 0x00, 0xAA, 0xBB])
            hex_payload = frame.hex().upper()
            evt_lines = [
                "+EVT:RXP2P,RSSI -90,SNR 6",
                f"+EVT:{hex_payload}",
            ]
            unit.read_async_events.return_value = evt_lines
        else:
            unit.read_async_events.return_value = []

        output = MagicMock(spec=OutputManager)
        dedup = DeduplicationCache()
        stop = threading.Event()
        scanner = SweepScanner(unit, output, dedup, rx2_interval=100, stop_event=stop)
        return scanner, unit, output

    def test_sweep_no_packets(self):
        scanner, unit, output = self._make_scanner(packets_per_hop=0)
        active = scanner.run()
        assert active == []
        # configure_p2p called for each channel × SF
        expected_calls = len(EU868_CHANNELS) * len(SPREADING_FACTORS)
        assert unit.configure_p2p.call_count == expected_calls

    def test_sweep_detects_packet(self):
        scanner, unit, output = self._make_scanner(packets_per_hop=1)
        active = scanner.run()
        # At least one combo should be found
        assert len(active) >= 1
        # output.record should have been called
        assert output.record.called

    def test_sweep_stop_event(self):
        scanner, unit, output = self._make_scanner(packets_per_hop=0)
        scanner.stop_event.set()  # stop immediately
        active = scanner.run()
        assert active == []
        assert unit.configure_p2p.call_count == 0

    def test_rx2_check_triggered(self):
        scanner, unit, output = self._make_scanner(packets_per_hop=0)
        scanner.rx2_interval = 1  # check RX2 on every hop
        scanner.run()
        # RX2 checks should have been made — configure_p2p should have been called
        # with RX2_FREQ at some point
        calls = [c for c in unit.configure_p2p.call_args_list
                 if c[0][0] == RX2_FREQ]
        assert len(calls) > 0

    def test_dedup_prevents_double_record(self):
        scanner, unit, output = self._make_scanner(packets_per_hop=1)
        # Pre-fill dedup cache so the packet is "already seen"
        import struct
        dev_addr = struct.pack("<I", 0x260B1234)
        scanner.dedup.is_duplicate("260B1234", 1)  # mark as seen
        scanner.run()
        # record should not be called again for duplicate
        assert not output.record.called


# ---------------------------------------------------------------------------
# LockMonitor (mocked unit)
# ---------------------------------------------------------------------------
class TestLockMonitor:
    def _make_monitor(self, cycles=2, with_packet=False):
        unit = MagicMock(spec=LoRaUnit)
        unit.configure_p2p.return_value = True
        unit.start_rx.return_value = True
        unit.stop_rx.return_value = True

        if with_packet:
            import struct
            dev_addr = struct.pack("<I", 0x260B1234)
            frame = bytes([0x40]) + dev_addr + bytes([0x00, 0x05, 0x00, 0xAA])
            hex_payload = frame.hex().upper()
            unit.read_async_events.return_value = [
                "+EVT:RXP2P,RSSI -85,SNR 7",
                f"+EVT:{hex_payload}",
            ]
        else:
            unit.read_async_events.return_value = []

        output = MagicMock(spec=OutputManager)
        dedup = DeduplicationCache()
        stop = threading.Event()

        monitor = LockMonitor(
            unit=unit, output=output, dedup=dedup,
            freq=868100000, sf=7,
            duration_minutes=0.001,  # very short
            rx2_interval=100,
            stop_event=stop,
        )
        return monitor, unit, output

    def test_lock_runs_without_crash(self):
        monitor, unit, output = self._make_monitor()
        monitor.run()  # should not raise

    def test_lock_records_packets(self):
        monitor, unit, output = self._make_monitor(with_packet=True)
        monitor.run()
        assert output.record.called

    def test_lock_stop_event(self):
        monitor, unit, output = self._make_monitor()
        monitor.stop_event.set()
        monitor.run()
        assert unit.configure_p2p.call_count == 0


# ---------------------------------------------------------------------------
# auto_detect_port
# ---------------------------------------------------------------------------
class TestAutoDetectPort:
    def test_prefers_ttyUSB(self):
        mock_ports = [
            MagicMock(device="/dev/ttyACM0", description="ACM"),
            MagicMock(device="/dev/ttyUSB0", description="USB Serial"),
        ]
        with patch("lora_recon.serial.tools.list_ports.comports", return_value=mock_ports):
            assert auto_detect_port() == "/dev/ttyUSB0"

    def test_falls_back_to_ttyACM(self):
        mock_ports = [
            MagicMock(device="/dev/ttyACM0", description="ACM Device"),
        ]
        mock_ports[0].description = "ACM Device"
        with patch("lora_recon.serial.tools.list_ports.comports", return_value=mock_ports):
            result = auto_detect_port()
            assert result == "/dev/ttyACM0"

    def test_returns_none_when_no_ports(self):
        with patch("lora_recon.serial.tools.list_ports.comports", return_value=[]):
            assert auto_detect_port() is None


# ---------------------------------------------------------------------------
# Integration: parse_events → parse_lorawan pipeline
# ---------------------------------------------------------------------------
class TestPipeline:
    def test_full_packet_pipeline(self):
        import struct
        # Build Confirmed Data Up frame
        dev_addr = struct.pack("<I", 0x260B5678)
        frame = bytes([0x80]) + dev_addr + bytes([0x80, 0x03, 0x00, 0xCC, 0xDD])
        hex_payload = frame.hex().upper()

        lines = [
            "+EVT:RXP2P,RSSI -95,SNR 4",
            f"+EVT:{hex_payload}",
        ]
        events = parse_events(lines)
        assert len(events) == 1
        lw = parse_lorawan(events[0]["raw_hex"])
        assert lw["mtype"] == "Confirmed Data Up"
        assert lw["dev_addr"] == "260B5678"
        assert lw["fcnt"] == 3
        assert lw["adr"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
