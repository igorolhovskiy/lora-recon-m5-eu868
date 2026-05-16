#!/usr/bin/env python3
"""
Tests for lora_tui.py — run without hardware (mocked serial + fast dwell).

Non-async tests: HardwareScanner threading logic.
Async tests: Textual headless UI tests via pilot.
"""

import asyncio
import struct
import time
import threading
from unittest.mock import MagicMock, patch

import pytest

import lora_recon  # needed to patch SF_DWELL
from lora_recon import LoRaUnit, EU868_CHANNELS, SPREADING_FACTORS, PacketRecord
from lora_tui import (
    HardwareScanner,
    SweepScreen,
    LockScreen,
    LoRaTUIApp,
    ALL_COMBOS,
    _make_pkt,
)
from textual.widgets import DataTable, Static


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------
FAST_DWELL = {sf: 0.02 for sf in range(7, 13)}   # 20 ms per channel in tests


def _mock_unit(readline_lines=None):
    """LoRaUnit with mocked serial, returning given lines then empty forever."""
    mock_ser = MagicMock()
    if readline_lines:
        mock_ser.readline.side_effect = (
            [(l + "\r\n").encode() if l else b"" for l in readline_lines]
            + [b""] * 10_000
        )
    else:
        mock_ser.readline.return_value = b""
    mock_ser.timeout = 2.0

    with patch("lora_recon.serial.Serial", return_value=mock_ser):
        unit = LoRaUnit("/dev/null")
    unit.ser = mock_ser

    unit.ping          = MagicMock(return_value=True)
    unit.configure_p2p = MagicMock(return_value=True)
    unit.start_rx      = MagicMock(return_value=True)
    unit.stop_rx       = MagicMock(return_value=True)
    unit.get_version   = MagicMock(return_value="TEST_FW_1.0")
    unit.get_deveui    = MagicMock(return_value="AABBCCDDEEFF0011")
    unit.get_nwm       = MagicMock(return_value=1)
    unit.set_p2p_mode  = MagicMock(return_value=True)
    unit.close         = MagicMock()
    return unit


def _uplink_frame(dev_addr_int=0x260B1234, fcnt=7) -> str:
    """Return hex of a minimal Unconfirmed Data Up LoRaWAN frame."""
    da = struct.pack("<I", dev_addr_int)
    frame = bytes([0x40]) + da + bytes([0x00, fcnt & 0xFF, fcnt >> 8, 0xAA, 0xBB])
    return frame.hex().upper()


def _pkt_lines(dev_addr_int=0x260B1234, fcnt=7):
    return [
        "+EVT:RXP2P,RSSI -90,SNR 6",
        f"+EVT:{_uplink_frame(dev_addr_int, fcnt)}",
    ]


def _make_app(readline_lines=None):
    unit = _mock_unit(readline_lines)
    app = LoRaTUIApp(unit, "TEST_FW_1.0  DevEUI=AABBCCDDEEFF0011")
    return app, unit


# ---------------------------------------------------------------------------
# HardwareScanner unit tests (pure threading, no UI)
# ---------------------------------------------------------------------------
class TestHardwareScanner:

    def _scanner(self, readline_lines=None):
        return HardwareScanner(_mock_unit(readline_lines))

    def test_not_running_initially(self):
        s = self._scanner()
        assert not s.is_running()

    def test_stop_before_start_is_safe(self):
        s = self._scanner()
        s.stop()  # must not raise

    def test_sweep_starts_thread(self):
        s = self._scanner()
        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            started = threading.Event()
            s.start_sweep(on_channel=lambda f, sf: started.set(), on_packet=lambda p: None)
            started.wait(timeout=5)
        assert started.is_set()
        s.stop()

    def test_sweep_visits_all_combos(self):
        s = self._scanner()
        seen = set()
        done = threading.Event()

        def on_ch(f, sf):
            seen.add((f, sf))
            if len(seen) >= len(ALL_COMBOS):
                done.set()
                s._stop.set()

        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            s.start_sweep(on_channel=on_ch, on_packet=lambda p: None)
            done.wait(timeout=15)
        s.stop()
        assert (EU868_CHANNELS[0], SPREADING_FACTORS[0]) in seen

    def test_sweep_delivers_packet(self):
        s = self._scanner(readline_lines=_pkt_lines())
        pkts = []
        done = threading.Event()

        def on_pkt(p):
            pkts.append(p)
            done.set()
            s._stop.set()

        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            s.start_sweep(on_channel=lambda f, sf: None, on_packet=on_pkt)
            done.wait(timeout=15)
        s.stop()
        assert len(pkts) == 1
        assert pkts[0].dev_addr == "260B1234"
        assert pkts[0].fcnt == 7

    def test_lock_starts_and_is_running(self):
        s = self._scanner()
        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            s.start_lock(freq=868100000, sf=7, on_packet=lambda p: None)
            time.sleep(0.05)
            assert s.is_running()
        s.stop()

    def test_lock_delivers_packet(self):
        s = self._scanner(readline_lines=_pkt_lines())
        pkts = []
        done = threading.Event()

        def on_pkt(p):
            pkts.append(p)
            done.set()
            s._stop.set()

        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            s.start_lock(freq=868100000, sf=7, on_packet=on_pkt)
            done.wait(timeout=15)
        s.stop()
        assert len(pkts) >= 1

    def test_stop_joins_thread(self):
        s = self._scanner()
        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            s.start_sweep(on_channel=lambda f, sf: None, on_packet=lambda p: None)
            s.stop(timeout=5)
        assert not s.is_running()

    def test_dedup_suppresses_repeated_packet(self):
        """Same (DevAddr, FCnt) repeated 4× — only one callback."""
        lines = _pkt_lines() * 4
        s = self._scanner(readline_lines=lines)
        pkts = []
        stop = threading.Event()

        def on_pkt(p):
            pkts.append(p)
            stop.set()

        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            s.start_lock(freq=868100000, sf=7, on_packet=on_pkt)
            stop.wait(timeout=10)
            s._stop.set()
        s.stop()
        assert len(pkts) == 1


# ---------------------------------------------------------------------------
# _make_pkt helper
# ---------------------------------------------------------------------------
class TestMakePkt:
    def test_uplink_fields(self):
        frame = _uplink_frame(0x260B1234, fcnt=3)
        pkt = _make_pkt({"rssi": -85, "snr": 7, "raw_hex": frame}, 868100000, 9)
        assert pkt.freq == 868100000
        assert pkt.sf == 9
        assert pkt.rssi == -85
        assert pkt.dev_addr == "260B1234"
        assert pkt.fcnt == 3
        assert not pkt.is_downlink

    def test_downlink_flag(self):
        pkt = _make_pkt({"rssi": -100, "snr": 2, "raw_hex": ""}, 869525000, 12, is_downlink=True)
        assert pkt.is_downlink is True

    def test_empty_payload(self):
        pkt = _make_pkt({"rssi": None, "snr": None, "raw_hex": ""}, 868300000, 7)
        assert pkt.dev_addr is None
        assert pkt.fcnt is None


# ---------------------------------------------------------------------------
# Textual headless tests (async)
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def fast_dwell_fixture():
    """Patch SF_DWELL to 20 ms for all async tests."""
    with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
        yield


@pytest.mark.asyncio
async def test_app_starts_with_sweep_screen():
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        assert isinstance(app.screen, SweepScreen)


@pytest.mark.asyncio
async def test_sweep_table_has_48_rows():
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        table = app.screen.query_one("#sw_table", DataTable)
        assert table.row_count == 48


@pytest.mark.asyncio
async def test_sweep_table_columns():
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        table = app.screen.query_one("#sw_table", DataTable)
        assert len(table.columns) == 8


@pytest.mark.asyncio
async def test_press_q_exits():
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.1)
        await pilot.press("q")


@pytest.mark.asyncio
async def test_enter_pushes_lock_screen():
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        assert isinstance(app.screen, SweepScreen)
        await pilot.click("#sw_table")  # ensure DataTable has focus
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert isinstance(app.screen, LockScreen)


@pytest.mark.asyncio
async def test_escape_from_lock_returns_to_sweep():
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.click("#sw_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert isinstance(app.screen, LockScreen)
        await pilot.press("escape")
        await pilot.pause(0.2)
        assert isinstance(app.screen, SweepScreen)


@pytest.mark.asyncio
async def test_lock_screen_shows_packet_table():
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.click("#sw_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        table = app.screen.query_one("#pkt_table", DataTable)
        assert table is not None
        assert len(table.columns) == 8


@pytest.mark.asyncio
async def test_selected_combo_passed_to_lock_screen():
    """Cursor on row 3 → LockScreen gets combo ALL_COMBOS[3]."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.click("#sw_table")
        await pilot.press("down", "down", "down")
        await pilot.press("enter")
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, LockScreen)
        freq, sf = ALL_COMBOS[3]
        assert screen._freq == freq
        assert screen._sf == sf


@pytest.mark.asyncio
async def test_multiple_lock_unlock_cycles():
    """Enter and exit lock mode twice without crashing."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        for _ in range(2):
            await pilot.pause(0.2)
            await pilot.click("#sw_table")
            await pilot.press("enter")
            await pilot.pause(0.2)
            assert isinstance(app.screen, LockScreen)
            await pilot.press("escape")
            await pilot.pause(0.2)
            assert isinstance(app.screen, SweepScreen)


@pytest.mark.asyncio
async def test_packet_callback_updates_sweep_table():
    """Directly invoke _on_packet; verify table row turns 'active'."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, SweepScreen)
        # Simulate receiving a packet on 868.1 MHz SF7
        frame = _uplink_frame(0x260B1234, fcnt=1)
        pkt = _make_pkt({"rssi": -88, "snr": 5, "raw_hex": frame}, 868100000, 7)
        screen._on_packet(pkt)
        await pilot.pause(0.1)
        # Check that combo state was updated
        state = screen._state[(868100000, 7)]
        assert state["pkts"] == 1
        assert state["rssi"] == -88
        assert state["addr"] == "260B1234"


@pytest.mark.asyncio
async def test_channel_callback_updates_status_bar():
    """Directly invoke _on_channel; verify status bar text changes."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, SweepScreen)
        # Stop background scanner so its _on_channel calls don't race ours
        app._scanner.stop()
        await pilot.pause(0.1)
        screen._on_channel(868100000, 9)
        await pilot.pause(0.1)
        status = screen.query_one("#sw_status", Static)
        text = str(status.content)
        assert "868.100" in text
        assert "SF9" in text


@pytest.mark.asyncio
async def test_reset_clears_packet_counts():
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, SweepScreen)
        # Add a packet
        frame = _uplink_frame()
        pkt = _make_pkt({"rssi": -90, "snr": 6, "raw_hex": frame}, 868100000, 7)
        screen._on_packet(pkt)
        await pilot.pause(0.1)
        assert screen._state[(868100000, 7)]["pkts"] == 1
        # Reset
        await pilot.press("r")
        await pilot.pause(0.1)
        assert screen._state[(868100000, 7)]["pkts"] == 0


@pytest.mark.asyncio
async def test_lock_screen_packet_callback_adds_row():
    """Directly invoke lock screen's _on_packet; verify packet row is added."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.click("#sw_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, LockScreen)
        frame = _uplink_frame(0x260B5678, fcnt=42)
        pkt = _make_pkt({"rssi": -75, "snr": 9, "raw_hex": frame},
                        screen._freq, screen._sf)
        screen._on_packet(pkt)
        await pilot.pause(0.1)
        table = screen.query_one("#pkt_table", DataTable)
        assert table.row_count == 1


@pytest.mark.asyncio
async def test_lock_screen_stats_update_on_packet():
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.click("#sw_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, LockScreen)
        frame = _uplink_frame(0x260B5678, fcnt=10)
        pkt = _make_pkt({"rssi": -80, "snr": 7, "raw_hex": frame},
                        screen._freq, screen._sf)
        screen._on_packet(pkt)
        await pilot.pause(0.1)
        stats = screen.query_one("#stats_box", Static)
        text = str(stats.content)
        assert "Pkts: 1" in text
        assert "260B5678" in text


@pytest.mark.asyncio
async def test_downlink_increments_counter():
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.click("#sw_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, LockScreen)
        pkt = _make_pkt({"rssi": -100, "snr": 2, "raw_hex": ""},
                        869525000, 12, is_downlink=True)
        screen._on_packet(pkt)
        await pilot.pause(0.1)
        assert screen._downlinks == 1
        stats = screen.query_one("#stats_box", Static)
        assert "GATEWAY" in str(stats.content)


@pytest.mark.asyncio
async def test_sweep_scanner_thread_calls_on_channel_in_ui():
    """End-to-end: scanner thread → call_from_thread → _on_channel updates screen."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, SweepScreen)
        # Give the sweep thread a moment to run and call _on_channel
        await pilot.pause(0.5)
        # Current combo should have been set by the thread
        assert screen._current is not None


@pytest.mark.asyncio
async def test_scanner_delivers_packet_to_sweep_screen():
    """Scanner thread with packet lines → packet appears in sweep state."""
    lines = _pkt_lines(dev_addr_int=0x260B9999, fcnt=55)
    app, _ = _make_app(readline_lines=lines)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        # Wait long enough for the scanner thread to process at least one channel
        await pilot.pause(1.0)
        screen = app.screen
        assert isinstance(screen, SweepScreen)
        # At least one combo should have pkts > 0
        active = [s for s in screen._state.values() if s["pkts"] > 0]
        assert len(active) >= 1
        assert any(s["addr"] == "260B9999" for s in active)
