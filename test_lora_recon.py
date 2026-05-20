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
    parse_fopts,
    parse_netid,
    parse_lpp,
    parse_beacon,
    parse_meshtastic,
    lookup_operator,
    lookup_vendor,
    is_multicast_devaddr,
    PacketRecord,
    DeduplicationCache,
    RetransmissionTracker,
    ReplayTracker,
    LoRaUnit,
    SweepScanner,
    LockMonitor,
    MeshtasticScanner,
    OutputManager,
    auto_detect_port,
    EU868_CHANNELS,
    RX2_FREQ,
    RX2_SF,
    SPREADING_FACTORS,
    BEACON_FREQ_EU868,
    BEACON_SF,
    LORAWAN_SYNCWORD,
    MESHTASTIC_SYNCWORD,
    MESHTASTIC_EU_PRESETS,
    OUI_VENDORS,
    NETID_OPERATORS,
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
# parse_fopts
# ---------------------------------------------------------------------------
class TestParseFopts:
    def test_link_check_req_uplink(self):
        result = parse_fopts(bytes([0x02]), is_uplink=True)
        assert result == ["LinkCheckReq"]

    def test_link_check_ans_downlink(self):
        result = parse_fopts(bytes([0x02, 5, 2]), is_uplink=False)
        assert len(result) == 1
        assert "LinkCheckAns" in result[0]
        assert "margin=5dB" in result[0]
        assert "gw=2" in result[0]

    def test_link_adr_req_downlink(self):
        # DR=5 (SF7), TXPow=1 (14dBm), ChMask=0x00FF, NbTrans=1, ctrl=0
        result = parse_fopts(bytes([0x03, 0x51, 0xFF, 0x00, 0x01]), is_uplink=False)
        assert len(result) == 1
        assert "LinkADRReq" in result[0]
        assert "SF7" in result[0]
        assert "14dBm" in result[0]
        assert "0x00FF" in result[0]

    def test_dev_status_ans_uplink(self):
        # battery=128 (~50%), margin=7dB
        result = parse_fopts(bytes([0x06, 128, 7]), is_uplink=True)
        assert len(result) == 1
        assert "DevStatusAns" in result[0]
        assert "snr_margin=7dB" in result[0]

    def test_dev_status_req_downlink(self):
        result = parse_fopts(bytes([0x06]), is_uplink=False)
        assert result == ["DevStatusReq"]

    def test_new_channel_req_downlink(self):
        # ch=3, freq=867.1MHz (8671000 * 10 = 86710000... wait, freq in 100Hz steps
        # 867.1 MHz = 8671000 * 100Hz = 86710000 → but that's 8671000 * 100Hz
        # Actually: 867.1 MHz = 867100000 Hz / 100 = 8671000
        # 8671000 in 3 bytes LE: 8671000 = 0x843E28 → [0x28, 0x3E, 0x84]
        freq_raw = 867100000 // 100  # = 8671000
        b = freq_raw.to_bytes(3, "little")
        payload = bytes([0x07, 3]) + b + bytes([0x50])  # ch=3, DrRange=0x50 (min=DR0/SF12, max=DR5/SF7)
        result = parse_fopts(payload, is_uplink=False)
        assert len(result) == 1
        assert "NewChannelReq" in result[0]
        assert "867.100MHz" in result[0]

    def test_multiple_commands_in_fopts(self):
        # DevStatusReq (0x06, 0 bytes) + RXTimingSetupReq (0x08, 1 byte: delay=3)
        result = parse_fopts(bytes([0x06, 0x08, 0x03]), is_uplink=False)
        assert len(result) == 2
        assert "DevStatusReq" in result[0]
        assert "RXTimingSetupReq" in result[1]
        assert "3s" in result[1]

    def test_truncated_command(self):
        # LinkADRReq needs 4 payload bytes; only give 2
        result = parse_fopts(bytes([0x03, 0x51, 0xFF]), is_uplink=False)
        assert len(result) == 1
        assert "truncated" in result[0]

    def test_fopts_in_parse_lorawan(self):
        import struct
        # Unconfirmed Data Up with FOptsLen=1 and a LinkCheckReq (0x02) in FOpts
        # MHDR=0x40, DevAddr=0x260B1234, FCtrl=0x01 (FOptsLen=1), FCnt=0x0001
        # FOpts=0x02 (LinkCheckReq)
        dev_addr = struct.pack("<I", 0x260B1234)
        frame = bytes([0x40]) + dev_addr + bytes([0x01, 0x01, 0x00, 0x02, 0xAA])
        result = parse_lorawan(frame.hex())
        assert "mac_commands" in result
        assert result["mac_commands"] == ["LinkCheckReq"]


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

    # --- RUI3 v4.x single-line format tests ---

    def test_single_line_format(self):
        lines = ["+EVT:RXP2P:-107:-3:DEADBEEF1234"]
        results = parse_events(lines)
        assert len(results) == 1
        assert results[0]["rssi"] == -107
        assert results[0]["snr"] == -3
        assert results[0]["raw_hex"] == "DEADBEEF1234"

    def test_single_line_positive_snr(self):
        lines = ["+EVT:RXP2P:-85:7:AABBCCDD"]
        results = parse_events(lines)
        assert results[0]["rssi"] == -85
        assert results[0]["snr"] == 7
        assert results[0]["raw_hex"] == "AABBCCDD"

    def test_single_line_multiple_events(self):
        lines = [
            "+EVT:RXP2P:-90:5:AABBCCDD",
            "+EVT:RXP2P:-80:9:11223344",
        ]
        results = parse_events(lines)
        assert len(results) == 2
        assert results[0]["rssi"] == -90
        assert results[0]["raw_hex"] == "AABBCCDD"
        assert results[1]["rssi"] == -80
        assert results[1]["raw_hex"] == "11223344"

    def test_single_line_mixed_with_noise(self):
        lines = ["OK", "+EVT:RXP2P:-95:4:CAFEBABE", "some noise"]
        results = parse_events(lines)
        assert len(results) == 1
        assert results[0]["raw_hex"] == "CAFEBABE"

    def test_single_line_hex_case_normalised(self):
        lines = ["+EVT:RXP2P:-80:6:cafebabe"]
        results = parse_events(lines)
        assert results[0]["raw_hex"] == "CAFEBABE"


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

    def test_set_p2p_mode_already_p2p_sets_syncword_and_iq(self):
        # NWM=0 already; OK for SYNCWORD; OK for IQINVER
        unit = self._make_unit(["AT+NWM=0", "OK", "OK", "OK"])
        result = unit.set_p2p_mode()
        assert result is True
        written = b"".join(c[0][0] for c in unit.ser.write.call_args_list)
        assert b"AT+NWM=?" in written
        assert b"AT+SYNCWORD=3444" in written
        assert b"AT+IQINVER=0" in written
        assert b"AT+NWM=0\r\n" not in written  # no mode switch when already P2P

    def test_set_p2p_mode_switches_and_sets_syncword_and_iq(self):
        # NWM=1 → switch; ping OK; SYNCWORD OK; IQINVER OK
        unit = self._make_unit(["AT+NWM=1", "OK", "AT", "OK", "OK", "OK"])
        result = unit.set_p2p_mode()
        assert result is True
        written = b"".join(c[0][0] for c in unit.ser.write.call_args_list)
        assert b"AT+NWM=0\r\n" in written
        assert b"AT+SYNCWORD=3444" in written
        assert b"AT+IQINVER=0" in written

    def test_set_iq_inversion_normal(self):
        unit = self._make_unit(["OK"])
        assert unit.set_iq_inversion(False) is True
        written = b"".join(c[0][0] for c in unit.ser.write.call_args_list)
        assert b"AT+IQINVER=0" in written

    def test_set_iq_inversion_inverted(self):
        unit = self._make_unit(["OK"])
        assert unit.set_iq_inversion(True) is True
        written = b"".join(c[0][0] for c in unit.ser.write.call_args_list)
        assert b"AT+IQINVER=1" in written

    def test_configure_p2p(self):
        unit = self._make_unit(["OK"])
        assert unit.configure_p2p(868100000, 7) is True
        call_args = unit.ser.write.call_args_list
        written = b"".join(c[0][0] for c in call_args)
        assert b"AT+P2P=868100000:7:0:0:8:14" in written

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
            # RUI3 v4.x single-line format
            evt_lines = [f"+EVT:RXP2P:-90:6:{hex_payload}"]
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

    def test_rx2_check_toggles_iq(self):
        scanner, unit, output = self._make_scanner(packets_per_hop=0)
        scanner.rx2_interval = 1
        scanner.run()
        iq_calls = [c[0][0] for c in unit.set_iq_inversion.call_args_list]
        # Must have at least one True (inverted for RX2) followed by False (restored)
        assert True in iq_calls
        assert False in iq_calls
        # Last IQ call must restore normal polarity
        assert iq_calls[-1] is False

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
    def _make_monitor(self, with_packet=False, freq_hop=False):
        unit = MagicMock(spec=LoRaUnit)
        unit.configure_p2p.return_value = True
        unit.start_rx.return_value = True
        unit.stop_rx.return_value = True

        if with_packet:
            import struct
            dev_addr = struct.pack("<I", 0x260B1234)
            frame = bytes([0x40]) + dev_addr + bytes([0x00, 0x05, 0x00, 0xAA])
            hex_payload = frame.hex().upper()
            # RUI3 v4.x single-line format
            unit.read_async_events.return_value = [
                f"+EVT:RXP2P:-85:7:{hex_payload}",
            ]
        else:
            unit.read_async_events.return_value = []

        output = MagicMock(spec=OutputManager)
        dedup = DeduplicationCache()
        stop = threading.Event()

        monitor = LockMonitor(
            unit=unit, output=output, dedup=dedup,
            freq=None if freq_hop else 868100000, sf=7,
            freq_hop=freq_hop,
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

    def test_freq_hop_visits_all_channels(self):
        monitor, unit, output = self._make_monitor(freq_hop=True)
        monitor.run()
        called_freqs = {c[0][0] for c in unit.configure_p2p.call_args_list}
        for ch in EU868_CHANNELS:
            assert ch in called_freqs

    def test_freq_hop_requires_no_freq(self):
        """freq=None is valid when freq_hop=True."""
        unit = MagicMock(spec=LoRaUnit)
        unit.configure_p2p.return_value = True
        unit.start_rx.return_value = True
        unit.stop_rx.return_value = True
        unit.read_async_events.return_value = []
        output = MagicMock(spec=OutputManager)
        monitor = LockMonitor(
            unit=unit, output=output, dedup=DeduplicationCache(),
            freq=None, sf=9, freq_hop=True, duration_minutes=0.001,
        )
        monitor.run()  # should not raise

    def test_single_lock_requires_freq(self):
        """freq=None with freq_hop=False must raise."""
        with pytest.raises(ValueError):
            LockMonitor(
                unit=MagicMock(), output=MagicMock(), dedup=DeduplicationCache(),
                freq=None, sf=7, freq_hop=False,
            )

    def test_rx2_interleave_toggles_iq(self):
        monitor, unit, output = self._make_monitor()
        monitor.rx2_interval = 1   # trigger RX2 on every cycle
        monitor.run()
        iq_calls = [c[0][0] for c in unit.set_iq_inversion.call_args_list]
        assert True in iq_calls
        assert False in iq_calls
        assert iq_calls[-1] is False  # always restored to normal after RX2


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

        # RUI3 v4.x single-line format
        lines = [f"+EVT:RXP2P:-95:4:{hex_payload}"]
        events = parse_events(lines)
        assert len(events) == 1
        lw = parse_lorawan(events[0]["raw_hex"])
        assert lw["mtype"] == "Confirmed Data Up"
        assert lw["dev_addr"] == "260B5678"
        assert lw["fcnt"] == 3
        assert lw["adr"] is True


# ---------------------------------------------------------------------------
# parse_netid — NetID type discrimination for all 8 LoRaWAN types
# ---------------------------------------------------------------------------
class TestParseNetID:
    def test_type0_top_bit_zero(self):
        # 0b0_010011_<25 bits> → Type 0, NwkID=0x13
        assert parse_netid(0x26000001) == (0, 0x13)

    def test_type0_private_zero(self):
        assert parse_netid(0x00000001) == (0, 0x00)

    def test_type0_actility(self):
        assert parse_netid(0x48000000) == (0, 0x24)

    def test_type1_prefix_10(self):
        # 0b10_000110_<24 bits> → Type 1, NwkID=0x06 (Comcast-style)
        da = (0b10 << 30) | (0x06 << 24)
        t, n = parse_netid(da)
        assert t == 1 and n == 0x06

    def test_type2_prefix_110(self):
        # 0b110_<9-bit ID>_<20 bits>
        da = (0b110 << 29) | (0x1AA << 20)
        t, n = parse_netid(da)
        assert t == 2 and n == 0x1AA

    def test_type3_prefix_1110(self):
        da = (0b1110 << 28) | (0x555 << 17)
        t, n = parse_netid(da)
        assert t == 3 and n == 0x555

    def test_type4_prefix_11110(self):
        da = (0b11110 << 27) | (0x777 << 15)
        t, n = parse_netid(da)
        assert t == 4 and n == 0x777

    def test_type5_prefix_111110(self):
        da = (0b111110 << 26) | (0x1234 << 13)
        t, n = parse_netid(da)
        assert t == 5 and n == 0x1234

    def test_type6_helium_prefix_1111110(self):
        # Helium NetID 0xC00053 → NwkID 0x0053; DevAddr starts with 1111110 (Type 6)
        da = (0b1111110 << 25) | (0x0053 << 10)
        t, n = parse_netid(da)
        assert t == 6 and n == 0x53

    def test_type7_prefix_11111110(self):
        da = (0b11111110 << 24) | (0x1ABCD << 7)
        t, n = parse_netid(da)
        assert t == 7 and n == 0x1ABCD


# ---------------------------------------------------------------------------
# lookup_operator + lookup_vendor
# ---------------------------------------------------------------------------
class TestOperatorLookup:
    def test_known_ttn(self):
        assert lookup_operator(0, 0x13).startswith("TTN")

    def test_known_actility(self):
        assert lookup_operator(0, 0x24).startswith("Actility")

    def test_known_private(self):
        assert lookup_operator(0, 0x00).startswith("Private")

    def test_known_helium(self):
        assert lookup_operator(6, 0x53) == "Helium"

    def test_unknown_returns_none(self):
        assert lookup_operator(0, 0x7E) is None
        assert lookup_operator(2, 0x123) is None

    def test_dict_keys_are_tuples(self):
        # all keys are (type, id) tuples within spec ranges
        for (typ, _) in NETID_OPERATORS:
            assert 0 <= typ <= 7


class TestVendorLookup:
    def test_known_24bit_dragino(self):
        assert lookup_vendor("A84041000102030A") == "Dragino"

    def test_known_24bit_milesight(self):
        assert lookup_vendor("24E1240ABBCCDDEE") == "Milesight IoT"

    def test_long_prefix_takes_precedence_over_short(self):
        # 70:B3:D5:CF is a Dragino MA-S sub-allocation; the 24-bit 70:B3:D5
        # is the generic IEEE-RA block. Longest match wins.
        assert lookup_vendor("70B3D5CF12345678").startswith("Dragino")

    def test_sub_allocation_lookup(self):
        assert lookup_vendor("70B3D567ABCDEF01") == "Tektelic"

    def test_24bit_fallback_when_no_sub_allocation_match(self):
        # 70B3D5 with an unmapped 4th byte falls back to the parent label
        result = lookup_vendor("70B3D5FF11223344")
        assert "IEEE-RA" in result

    def test_case_insensitive(self):
        assert lookup_vendor("a84041aabbccddee") == "Dragino"

    def test_with_colons(self):
        assert lookup_vendor("A8:40:41:00:01:02:03:04") == "Dragino"

    def test_with_dashes(self):
        assert lookup_vendor("A8-40-41-00-01-02-03-04") == "Dragino"

    def test_unknown_returns_none(self):
        assert lookup_vendor("BADCAFEDEADBEEF0") is None

    def test_empty_input(self):
        assert lookup_vendor("") is None

    def test_short_input(self):
        assert lookup_vendor("A8") is None

    def test_oui_dict_keys_are_uppercase_and_aligned(self):
        for key in OUI_VENDORS:
            assert key == key.upper()
            # 6 = MA-L, 7 = MA-M, 8 = community 32-bit shorthand, 9 = MA-S
            assert len(key) in (6, 7, 8, 9)


# ---------------------------------------------------------------------------
# is_multicast_devaddr
# ---------------------------------------------------------------------------
class TestMulticast:
    def test_broadcast_address(self):
        assert is_multicast_devaddr(0xFFFFFFFF) is True

    def test_in_range(self):
        assert is_multicast_devaddr(0xFF000000) is True
        assert is_multicast_devaddr(0xFFABCDEF) is True

    def test_below_range(self):
        assert is_multicast_devaddr(0xFEFFFFFF) is False

    def test_unicast_normal_addresses(self):
        assert is_multicast_devaddr(0x26000013) is False
        assert is_multicast_devaddr(0x00000000) is False


# ---------------------------------------------------------------------------
# parse_lorawan integration with the new helpers
# ---------------------------------------------------------------------------
class TestParseLoraWanExtras:
    def test_dev_nonce_extracted_from_join_request(self):
        import struct
        # MHDR + JoinEUI(8) + DevEUI(8) + DevNonce(2 LE) + MIC(4)
        # DevEUI is transmitted LE, but stored/displayed big-endian after reversal.
        # For displayed DevEUI to start with the Dragino OUI A84041, the LE bytes
        # in the frame must end with [..., 0x41, 0x40, 0xA8].
        join_eui = bytes([0x01]*8)
        dev_eui_le = bytes([0x55, 0x44, 0x33, 0x22, 0x11, 0x41, 0x40, 0xA8])
        nonce = struct.pack("<H", 0xBEEF)
        mic   = b"\xAA\xBB\xCC\xDD"
        frame = bytes([0x00]) + join_eui + dev_eui_le + nonce + mic
        r = parse_lorawan(frame.hex())
        assert r["mtype"] == "Join Request"
        assert r["dev_nonce"] == 0xBEEF
        assert r["dev_eui"] == "A840411122334455"
        assert r["dev_eui_vendor"] == "Dragino"

    def test_join_request_unknown_vendor(self):
        join_eui = bytes([0x01]*8)
        dev_eui_le  = bytes([0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22])
        frame = bytes([0x00]) + join_eui + dev_eui_le + b"\x00\x00" + b"\xAA\xBB\xCC\xDD"
        r = parse_lorawan(frame.hex())
        assert r["dev_eui_vendor"] is None

    def test_netid_type_attached_to_data_frame(self):
        import struct
        da = struct.pack("<I", 0x26000001)
        frame = bytes([0x40]) + da + bytes([0x00, 0x00, 0x00, 0xAA])
        r = parse_lorawan(frame.hex())
        assert r["netid_type"] == 0
        assert r["operator_hint"].startswith("TTN")

    def test_helium_netid_recognised(self):
        import struct
        helium_da = (0b1111110 << 25) | (0x0053 << 10) | 0x1AB
        da = struct.pack("<I", helium_da)
        frame = bytes([0x40]) + da + bytes([0x00, 0x00, 0x00, 0xAA])
        r = parse_lorawan(frame.hex())
        assert r["netid_type"] == 6
        assert r["operator_hint"] == "Helium"

    def test_multicast_flag_set_for_high_devaddrs(self):
        import struct
        da = struct.pack("<I", 0xFF000001)
        frame = bytes([0x60]) + da + bytes([0x00, 0x00, 0x00])  # downlink data
        r = parse_lorawan(frame.hex())
        assert r["is_multicast"] is True

    def test_multicast_flag_unset_for_unicast(self):
        import struct
        da = struct.pack("<I", 0x26000001)
        frame = bytes([0x40]) + da + bytes([0x00, 0x00, 0x00, 0xAA])
        r = parse_lorawan(frame.hex())
        assert r["is_multicast"] is False

    def test_lpp_decoded_on_private_network(self):
        # ChirpStack / private deployments often expose unencrypted payloads.
        # Build an Unconfirmed Data Up with NwkID=0x00 (private), FPort=1, and
        # an LPP "temperature 23.5°C" measurement on channel 1.
        import struct
        da = struct.pack("<I", 0x00000001)        # NetID type 0, NwkID 0x00
        mhdr = bytes([0x40])
        fctrl = bytes([0x00])                     # no FOpts
        fcnt  = bytes([0x01, 0x00])               # 1
        fport = bytes([0x01])
        # ch=1, type=0x67 (temperature, signed 0.1 °C), value=235 → 23.5 °C
        lpp   = bytes([0x01, 0x67, 0x00, 0xEB])
        mic   = b"\xAA\xBB\xCC\xDD"
        frame = mhdr + da + fctrl + fcnt + fport + lpp + mic
        r = parse_lorawan(frame.hex())
        assert r["lpp_sensors"] == ["ch1 temperature=23.5C"]

    def test_lpp_skipped_on_commercial_network(self):
        # TTN NwkID 0x13 → payload is encrypted, LPP decode should be skipped
        import struct
        da = struct.pack("<I", 0x26000001)
        mhdr = bytes([0x40])
        fctrl = bytes([0x00])
        fcnt  = bytes([0x01, 0x00])
        fport = bytes([0x01])
        lpp   = bytes([0x01, 0x67, 0x00, 0xEB])
        mic   = b"\xAA\xBB\xCC\xDD"
        frame = mhdr + da + fctrl + fcnt + fport + lpp + mic
        r = parse_lorawan(frame.hex())
        assert "lpp_sensors" not in r


# ---------------------------------------------------------------------------
# parse_lpp — Cayenne LPP decoder
# ---------------------------------------------------------------------------
class TestParseLPP:
    def test_temperature(self):
        # ch=2, type=0x67, value=235 (23.5°C)
        assert parse_lpp(bytes([0x02, 0x67, 0x00, 0xEB])) == ["ch2 temperature=23.5C"]

    def test_negative_temperature(self):
        # value = -50 (-5.0°C) → 0xFFCE big-endian
        assert parse_lpp(bytes([0x01, 0x67, 0xFF, 0xCE])) == ["ch1 temperature=-5.0C"]

    def test_humidity(self):
        # ch=1, type=0x68, value=93 → 46.5%
        assert parse_lpp(bytes([0x01, 0x68, 0x5D])) == ["ch1 humidity=46.5%"]

    def test_barometer(self):
        # ch=1, type=0x73, value=10133 → 1013.3 hPa
        assert parse_lpp(bytes([0x01, 0x73, 0x27, 0x95])) == ["ch1 barometer=1013.3hPa"]

    def test_digital_in(self):
        assert parse_lpp(bytes([0x03, 0x00, 0x01])) == ["ch3 digital_in=1"]

    def test_multiple_sensors(self):
        payload = bytes([0x01, 0x67, 0x00, 0xEB, 0x02, 0x68, 0x5D])
        out = parse_lpp(payload)
        assert "ch1 temperature=23.5C" in out
        assert "ch2 humidity=46.5%" in out

    def test_unknown_type_stops_decode(self):
        # Type 0xAA is not in the LPP table — must stop, not produce garbage
        payload = bytes([0x01, 0x67, 0x00, 0xEB, 0x02, 0xAA, 0xDE, 0xAD])
        assert parse_lpp(payload) == ["ch1 temperature=23.5C"]

    def test_truncated_payload_safe(self):
        # Temperature expects 2 bytes; only 1 supplied
        assert parse_lpp(bytes([0x01, 0x67, 0x00])) == []

    def test_empty_payload(self):
        assert parse_lpp(b"") == []

    def test_gps(self):
        # ch=1, type=0x88, lat=42.3519 (423519), lon=-87.9094 (-879094), alt=10.00 m (1000)
        import struct
        lat = (423519).to_bytes(3, "big", signed=True)
        lon = (-879094).to_bytes(3, "big", signed=True)
        alt = (1000).to_bytes(3, "big", signed=True)
        out = parse_lpp(bytes([0x01, 0x88]) + lat + lon + alt)
        assert len(out) == 1
        assert "gps" in out[0]
        assert "42.3519" in out[0]
        assert "-87.9094" in out[0]


# ---------------------------------------------------------------------------
# parse_beacon — Class B beacon frame parser
# ---------------------------------------------------------------------------
class TestParseBeacon:
    def test_well_formed_beacon(self):
        import struct
        # 17 bytes: 2 RFU + 4 GPS time + 2 CRC1 + 7 GwSpecific + 2 CRC2
        rfu  = b"\x00\x00"
        gps  = struct.pack("<I", 1_400_000_000)   # arbitrary
        crc1 = b"\x12\x34"
        gws  = b"\x01\xAA\xBB\xCC\xDD\xEE\xFF"
        crc2 = b"\xAB\xCD"
        frame = rfu + gps + crc1 + gws + crc2
        r = parse_beacon(frame.hex())
        assert r["gps_seconds"] == 1_400_000_000
        assert r["crc1"] == 0x3412
        assert r["info_desc"] == 0x01
        assert r["gw_info"] == "01AABBCCDDEEFF"

    def test_wrong_length(self):
        assert parse_beacon("00" * 16) == {}
        assert parse_beacon("00" * 18) == {}

    def test_invalid_hex(self):
        assert parse_beacon("ZZ") == {}


# ---------------------------------------------------------------------------
# parse_meshtastic — header decoder
# ---------------------------------------------------------------------------
class TestParseMeshtastic:
    def test_well_formed_header(self):
        import struct
        # dst, src, packet_id are LE 32-bit; flags=0x0A (hop_limit=2, want_ack=1)
        dst  = struct.pack("<I", 0xFFFFFFFF)
        src  = struct.pack("<I", 0xDEADBEEF)
        pid  = struct.pack("<I", 0x12345678)
        flags = bytes([0x0A])
        chh   = bytes([0x42])
        rest  = b"\x00\x00"                       # next_hop / relay_node padding
        frame = dst + src + pid + flags + chh + rest
        r = parse_meshtastic(frame.hex())
        assert r["src"] == "DEADBEEF"
        assert r["dst"] == "FFFFFFFF"
        assert r["packet_id"] == 0x12345678
        assert r["hop_limit"] == 2
        assert r["want_ack"] is True
        assert r["via_mqtt"] is False
        assert r["channel_hash"] == 0x42

    def test_via_mqtt_flag(self):
        import struct
        frame = (b"\x00"*8) + struct.pack("<I", 1) + bytes([0x10, 0x00]) + b"\x00"*2
        r = parse_meshtastic(frame.hex())
        assert r["via_mqtt"] is True

    def test_too_short(self):
        assert parse_meshtastic("00" * 15) == {}

    def test_invalid_hex(self):
        assert parse_meshtastic("nothex") == {}


# ---------------------------------------------------------------------------
# RetransmissionTracker
# ---------------------------------------------------------------------------
class TestRetransmissionTracker:
    def test_first_sighting_returns_zero(self):
        t = RetransmissionTracker(window_seconds=5)
        assert t.observe("260B1234", 5) == 0

    def test_retransmit_increments(self):
        t = RetransmissionTracker(window_seconds=5)
        assert t.observe("260B1234", 5) == 0
        assert t.observe("260B1234", 5) == 1
        assert t.observe("260B1234", 5) == 2

    def test_different_devices_independent(self):
        t = RetransmissionTracker(window_seconds=5)
        assert t.observe("AAAA", 7) == 0
        assert t.observe("BBBB", 7) == 0
        assert t.observe("AAAA", 7) == 1

    def test_different_fcnt_resets(self):
        t = RetransmissionTracker(window_seconds=5)
        assert t.observe("260B1234", 5) == 0
        assert t.observe("260B1234", 6) == 0   # different FCnt → fresh

    def test_window_expiry(self):
        t = RetransmissionTracker(window_seconds=0.1)
        assert t.observe("260B1234", 5) == 0
        time.sleep(0.15)
        # After window: the next observation should reset to first-sighting
        assert t.observe("260B1234", 5) == 0

    def test_none_inputs_safe(self):
        t = RetransmissionTracker()
        assert t.observe(None, 5) == 0
        assert t.observe("addr", None) == 0


# ---------------------------------------------------------------------------
# ReplayTracker — DevNonce + FCnt anomaly detection
# ---------------------------------------------------------------------------
class TestReplayTracker:
    def test_first_devnonce_is_clean(self):
        t = ReplayTracker()
        assert t.check_join("70B3D5CF12345678", 0x0001) is None

    def test_repeated_devnonce_alerts(self):
        t = ReplayTracker()
        t.check_join("EUI", 0x0001)
        alert = t.check_join("EUI", 0x0001)
        assert alert is not None
        assert "0x0001" in alert
        assert "EUI" in alert

    def test_different_devices_independent(self):
        t = ReplayTracker()
        t.check_join("A", 0x0001)
        assert t.check_join("B", 0x0001) is None

    def test_fcnt_increase_is_clean(self):
        t = ReplayTracker()
        assert t.check_fcnt("260B1234", 1) is None
        assert t.check_fcnt("260B1234", 2) is None
        assert t.check_fcnt("260B1234", 100) is None

    def test_fcnt_regression_alerts(self):
        t = ReplayTracker()
        t.check_fcnt("260B1234", 1000)
        alert = t.check_fcnt("260B1234", 5)
        assert alert is not None
        assert "1000" in alert
        assert "5" in alert

    def test_fcnt_max_tracked(self):
        t = ReplayTracker()
        t.check_fcnt("addr", 100)
        t.check_fcnt("addr", 50)        # regression — doesn't update max
        assert t.fcnt_max["addr"] == 100

    def test_persistence_roundtrip(self, tmp_path):
        path = str(tmp_path / "replay.json")
        t = ReplayTracker(path)
        t.check_join("EUI", 0x0042)
        t.check_fcnt("260B1234", 500)
        t.save()
        # Reload — history must survive
        t2 = ReplayTracker(path)
        assert 0x0042 in t2.nonces["EUI"]
        assert t2.fcnt_max["260B1234"] == 500
        alert = t2.check_join("EUI", 0x0042)
        assert alert is not None

    def test_missing_state_file_is_fine(self, tmp_path):
        path = str(tmp_path / "nope.json")
        t = ReplayTracker(path)
        assert t.nonces == {} or len(t.nonces) == 0
        assert t.fcnt_max == {}

    def test_none_inputs_safe(self):
        t = ReplayTracker()
        assert t.check_join(None, 5) is None
        assert t.check_join("EUI", None) is None
        assert t.check_fcnt(None, 5) is None
        assert t.check_fcnt("addr", None) is None


# ---------------------------------------------------------------------------
# PacketRecord summary string with the new flags
# ---------------------------------------------------------------------------
class TestPacketRecordFlags:
    def _base(self):
        return PacketRecord(
            timestamp="2026-05-20T10:00:00Z",
            freq=868100000, sf=7, bw=125, rssi=-90, snr=5,
            raw_hex="40341234", mtype="Unconfirmed Data Up",
            dev_addr="34125678", fcnt=10,
        )

    def test_summary_includes_retransmit_tag(self):
        p = self._base()
        p.is_retransmit = True
        assert "[RETRANSMIT]" in p.summary()

    def test_summary_includes_multicast_tag(self):
        p = self._base()
        p.is_multicast = True
        assert "[MULTICAST]" in p.summary()

    def test_summary_includes_beacon_tag(self):
        p = self._base()
        p.is_beacon = True
        assert "[BEACON]" in p.summary()

    def test_summary_includes_meshtastic_tag(self):
        p = self._base()
        p.is_meshtastic = True
        assert "[MESHTASTIC]" in p.summary()

    def test_summary_clean_when_no_flags(self):
        p = self._base()
        s = p.summary()
        for tag in ("[BEACON]", "[MULTICAST]", "[RETRANSMIT]", "[MESHTASTIC]"):
            assert tag not in s


# ---------------------------------------------------------------------------
# CLI parser accepts the new flags
# ---------------------------------------------------------------------------
class TestCLI:
    def test_beacon_interval_flag(self):
        from lora_recon import build_parser
        args = build_parser().parse_args(["--beacon-interval", "3"])
        assert args.beacon_interval == 3

    def test_meshtastic_flag(self):
        from lora_recon import build_parser
        args = build_parser().parse_args(["--meshtastic"])
        assert args.meshtastic is True
        assert args.meshtastic_preset == "LongFast"

    def test_meshtastic_preset_choices(self):
        from lora_recon import build_parser
        args = build_parser().parse_args(["--meshtastic", "--meshtastic-preset", "LongSlow"])
        assert args.meshtastic_preset == "LongSlow"

    def test_replay_state_flag(self):
        from lora_recon import build_parser
        args = build_parser().parse_args(["--replay-state", "/tmp/r.json"])
        assert args.replay_state == "/tmp/r.json"


# ---------------------------------------------------------------------------
# MeshtasticScanner sets the correct sync word and RF config
# ---------------------------------------------------------------------------
class TestMeshtasticScanner:
    def test_unknown_preset_raises(self):
        with pytest.raises(ValueError):
            MeshtasticScanner(MagicMock(), MagicMock(), preset="Bogus")

    def test_run_sets_sync_word_and_restores(self):
        unit = MagicMock()
        unit.set_syncword.return_value = True
        unit.configure_p2p.return_value = True
        unit.set_iq_inversion.return_value = True
        unit.start_rx.return_value = True
        unit.stop_rx.return_value = True
        unit.read_async_events.return_value = []

        out = MagicMock()
        stop = threading.Event()
        # Stop the loop immediately on the first read
        unit.read_async_events.side_effect = lambda *a, **kw: (stop.set() or [])

        s = MeshtasticScanner(unit, out, preset="LongFast", stop_event=stop)
        s.run()

        # Meshtastic sync word applied for the run, then restored to LoRaWAN
        sync_calls = [c.args[0] for c in unit.set_syncword.call_args_list]
        assert MESHTASTIC_SYNCWORD in sync_calls
        assert LORAWAN_SYNCWORD == sync_calls[-1]   # restored last

    def test_uses_eu_longfast_preset(self):
        unit = MagicMock()
        unit.set_syncword.return_value = True
        unit.configure_p2p.return_value = True
        unit.set_iq_inversion.return_value = True
        unit.read_async_events.return_value = []

        out = MagicMock()
        stop = threading.Event()
        unit.read_async_events.side_effect = lambda *a, **kw: (stop.set() or [])
        s = MeshtasticScanner(unit, out, preset="LongFast", stop_event=stop)
        s.run()

        # Verify configure_p2p was called with the LongFast preset (869.525 SF11 BW250)
        cp_args = unit.configure_p2p.call_args_list[0]
        assert cp_args.args[0] == 869525000
        assert cp_args.args[1] == 11
        assert cp_args.kwargs.get("bw") == 250


# ---------------------------------------------------------------------------
# SweepScanner beacon + replay integration (mocked LoRaUnit)
# ---------------------------------------------------------------------------
class TestSweepScannerIntegration:
    def _scanner_with_unit(self, beacon_interval=0, replay_tracker=None):
        unit = MagicMock()
        unit.configure_p2p.return_value = True
        unit.set_iq_inversion.return_value = True
        unit.start_rx.return_value = True
        unit.stop_rx.return_value = True
        unit.read_async_events.return_value = []
        output = MagicMock()
        dedup  = DeduplicationCache(window_seconds=30)
        stop   = threading.Event()
        s = SweepScanner(unit, output, dedup,
                         rx2_interval=1000,        # disable RX2 in this test
                         stop_event=stop,
                         beacon_interval=beacon_interval,
                         replay_tracker=replay_tracker)
        return s, unit, output, stop

    def test_beacon_interval_zero_means_no_beacon_check(self):
        s, unit, _, stop = self._scanner_with_unit(beacon_interval=0)
        # Stop after the first hop
        def stop_after_one(*a, **kw):
            if unit.configure_p2p.call_count > 0:
                stop.set()
            return []
        unit.read_async_events.side_effect = stop_after_one
        s.run()
        calls = [c.args[0] for c in unit.configure_p2p.call_args_list]
        assert BEACON_FREQ_EU868 not in calls

    def test_beacon_interval_triggers_beacon_check(self):
        s, unit, _, stop = self._scanner_with_unit(beacon_interval=1)
        # After the first hop the beacon check fires; stop after that
        call_log = []
        def trace(*a, **kw):
            call_log.append(a)
            if len(call_log) >= 4:                   # uplink + beacon (+ extras)
                stop.set()
            return []
        unit.read_async_events.side_effect = trace
        s.run()
        configured_freqs = [c.args[0] for c in unit.configure_p2p.call_args_list]
        assert BEACON_FREQ_EU868 in configured_freqs

    def test_replay_tracker_annotates_join_packet(self):
        tracker = ReplayTracker()
        s, unit, output, stop = self._scanner_with_unit(replay_tracker=tracker)
        # Inject a JOIN packet event with a repeated nonce
        join_eui_le = bytes([0x01]*8)
        dev_eui_le  = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x40, 0xA8])
        nonce       = b"\x01\x00"     # DevNonce 0x0001
        mic         = b"\xAA\xBB\xCC\xDD"
        frame_bytes = bytes([0x00]) + join_eui_le + dev_eui_le + nonce + mic
        frame       = frame_bytes.hex().upper()
        # Pre-seed the tracker so the next sighting is a "repeat".
        # parse_lorawan stores DevEUI as the big-endian reversal of the LE bytes.
        stored_dev_eui = dev_eui_le[::-1].hex().upper()
        tracker.check_join(stored_dev_eui, 0x0001)

        # Inject the event on the very first sweep hop, then stop
        first = [True]
        def inject(*a, **kw):
            stop.set()
            if first[0]:
                first[0] = False
                return [f"+EVT:RXP2P:-50:6:{frame}"]
            return []
        unit.read_async_events.side_effect = inject
        s.run()

        recorded = [c.args[0] for c in output.record.call_args_list]
        assert len(recorded) >= 1
        assert any(r.replay_alert and "DevNonce 0x0001" in r.replay_alert
                   for r in recorded)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
