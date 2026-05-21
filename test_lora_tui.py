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
from lora_recon import LoRaUnit, EU868_CHANNELS, SPREADING_FACTORS, PacketRecord, RX2_FREQ, RX2_SF
from lora_tui import (
    HardwareScanner,
    SweepScreen,
    LockScreen,
    MeshtasticScreen,
    PacketDetailScreen,
    LoRaTUIApp,
    ALL_COMBOS,
    SF_SENSITIVITY,
    _make_pkt,
    _link_margin,
    _lorawan_airtime_ms,
    _format_packet_detail,
)
from lora_recon import MESHTASTIC_SYNCWORD, LORAWAN_SYNCWORD, MESHTASTIC_EU_PRESETS
from textual.widgets import DataTable, Static


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------
FAST_DWELL = {sf: 0.02 for sf in range(7, 13)}   # 20 ms per channel in tests


def _mock_unit(readline_lines=None):
    """LoRaUnit with mocked serial; returns provided lines then blocks briefly."""
    mock_ser = MagicMock()
    mock_ser.timeout = 0.2

    lines = [(l + "\r\n").encode() if l else b"" for l in (readline_lines or [])]
    idx = 0

    def blocking_readline():
        nonlocal idx
        if idx < len(lines):
            val = lines[idx]
            idx += 1
            return val
        time.sleep(0.01)  # simulate blocking I/O; prevents busy-spinning and StopIteration cascades
        return b""

    mock_ser.readline.side_effect = blocking_readline

    with patch("lora_recon.serial.Serial", return_value=mock_ser):
        unit = LoRaUnit("/dev/null")
    unit.ser = mock_ser

    unit.ping             = MagicMock(return_value=True)
    unit.configure_p2p    = MagicMock(return_value=True)
    unit.start_rx         = MagicMock(return_value=True)
    unit.stop_rx          = MagicMock(return_value=True)
    unit.set_iq_inversion = MagicMock(return_value=True)
    unit.get_version      = MagicMock(return_value="TEST_FW_1.0")
    unit.get_deveui       = MagicMock(return_value="AABBCCDDEEFF0011")
    unit.get_nwm          = MagicMock(return_value=1)
    unit.set_p2p_mode     = MagicMock(return_value=True)
    unit.close            = MagicMock()
    return unit


def _uplink_frame(dev_addr_int=0x260B1234, fcnt=7) -> str:
    """Return hex of a minimal Unconfirmed Data Up LoRaWAN frame."""
    da = struct.pack("<I", dev_addr_int)
    frame = bytes([0x40]) + da + bytes([0x00, fcnt & 0xFF, fcnt >> 8, 0xAA, 0xBB])
    return frame.hex().upper()


def _pkt_lines(dev_addr_int=0x260B1234, fcnt=7):
    # RUI3 v4.x single-line format
    return [f"+EVT:RXP2P:-90:6:{_uplink_frame(dev_addr_int, fcnt)}"]


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

    def test_lock_freq_hop_visits_all_channels(self):
        s = self._scanner()
        seen_freqs = set()
        done = threading.Event()

        original_configure = s.unit.configure_p2p

        def tracking_configure(freq, sf, **kwargs):
            seen_freqs.add(freq)
            if all(ch in seen_freqs for ch in EU868_CHANNELS):
                done.set()
                s._stop.set()
            return True

        s.unit.configure_p2p = tracking_configure

        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            s.start_lock(freq=None, sf=7, on_packet=lambda p: None, freq_hop=True)
            done.wait(timeout=10)
        s.stop()

        for ch in EU868_CHANNELS:
            assert ch in seen_freqs

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

    def test_sweep_checks_rx2_after_n_hops(self):
        """With rx2_interval=1, sweep visits RX2 after the first EU868 hop."""
        s = self._scanner()
        s.rx2_interval = 1
        seen = set()
        done = threading.Event()

        def on_ch(f, sf):
            seen.add((f, sf))
            if (RX2_FREQ, RX2_SF) in seen:
                done.set()
                s._stop.set()

        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            s.start_sweep(on_channel=on_ch, on_packet=lambda p: None)
            done.wait(timeout=5)
        s.stop()
        assert (RX2_FREQ, RX2_SF) in seen

    def test_sweep_rx2_uses_downlink_iq(self):
        """Sweep RX2 check calls set_iq_inversion(True) then restores False."""
        s = self._scanner()
        s.rx2_interval = 1
        iq_calls = []
        done = threading.Event()

        def tracking_iq(inverted):
            iq_calls.append(inverted)
            if True in iq_calls:
                done.set()
                s._stop.set()
            return True

        s.unit.set_iq_inversion = tracking_iq

        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            s.start_sweep(on_channel=lambda f, sf: None, on_packet=lambda p: None)
            done.wait(timeout=5)
        s.stop()
        assert True in iq_calls

    def test_rx2_lock_uses_downlink_iq_throughout(self):
        """start_lock with is_downlink=True uses IQINVER=1 on every cycle."""
        s = self._scanner()
        iq_calls = []
        done = threading.Event()

        def tracking_iq(inverted):
            iq_calls.append(inverted)
            if True in iq_calls:
                done.set()
                s._stop.set()
            return True

        s.unit.set_iq_inversion = tracking_iq

        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            s.start_lock(freq=RX2_FREQ, sf=RX2_SF, on_packet=lambda p: None,
                         is_downlink=True)
            done.wait(timeout=5)
        s.stop()
        assert iq_calls[0] is True          # first call is inverted (downlink)
        assert True in iq_calls

    def test_rx2_lock_skips_rx2_interleave(self):
        """When already locked on RX2, no additional RX2 interleave cycles are run."""
        s = self._scanner()
        s.rx2_interval = 1          # interleave every cycle if it were to run
        seen_freqs = []
        done = threading.Event()

        def tracking_configure(freq, sf, **kwargs):
            seen_freqs.append(freq)
            if len(seen_freqs) >= 3:
                done.set()
                s._stop.set()
            return True

        s.unit.configure_p2p = tracking_configure

        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            s.start_lock(freq=RX2_FREQ, sf=RX2_SF, on_packet=lambda p: None,
                         is_downlink=True)
            done.wait(timeout=5)
        s.stop()
        # Every configure_p2p call must be for RX2_FREQ — no EU868 interleave
        assert all(f == RX2_FREQ for f in seen_freqs)


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
# _link_margin helper
# ---------------------------------------------------------------------------
class TestLinkMargin:
    def test_known_floor(self):
        # SF7 floor is -123; RSSI=-90 → margin = 33
        assert _link_margin(-90, 7) == 33

    def test_sf12_floor(self):
        # SF12 floor is -137; RX2 downlink at -80 dBm
        assert _link_margin(-80, 12) == 57

    def test_none_rssi_returns_none(self):
        assert _link_margin(None, 9) is None

    def test_all_sfs_covered(self):
        for sf in range(7, 13):
            assert sf in SF_SENSITIVITY
            assert _link_margin(-100, sf) == -100 - SF_SENSITIVITY[sf]

    def test_marginal_negative_margin(self):
        # A packet decoded barely below the listed floor (firmware may still decode it)
        assert _link_margin(-140, 12) == -3


# ---------------------------------------------------------------------------
# Textual headless tests (async)
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def fast_dwell_fixture():
    """Patch SF_DWELL to 20 ms and rx overhead to 0 for all tests."""
    with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
        with patch.object(HardwareScanner, '_rx_overhead', 0.0):
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
        assert table.row_count == 49


@pytest.mark.asyncio
async def test_sweep_table_columns():
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        table = app.screen.query_one("#sw_table", DataTable)
        assert len(table.columns) == 9


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
        assert len(table.columns) == 10  # +Margin column


@pytest.mark.asyncio
async def test_enter_sf_hop_uses_correct_sf():
    """Enter (SF-hop): LockScreen gets SF from the selected row, freq_hop=True."""
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
        assert screen._sf == sf
        assert screen._freq_hop is True


@pytest.mark.asyncio
async def test_l_key_single_lock_passes_freq_and_sf():
    """L (single lock): LockScreen gets exact freq+SF from row, freq_hop=False."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.click("#sw_table")
        await pilot.press("down", "down", "down")
        await pilot.press("l")
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, LockScreen)
        freq, sf = ALL_COMBOS[3]
        assert screen._freq == freq
        assert screen._sf == sf
        assert screen._freq_hop is False


@pytest.mark.asyncio
async def test_enter_on_rx2_row_enters_rx2_lock():
    """Enter on the 49th row (RX2) opens LockScreen in downlink mode."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.click("#sw_table")
        # Navigate to the RX2 row (index 48, one past the 48 EU868 combos)
        for _ in range(len(ALL_COMBOS)):
            await pilot.press("down")
        await pilot.press("enter")
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, LockScreen)
        assert screen._freq == RX2_FREQ
        assert screen._sf == RX2_SF
        assert screen._is_downlink is True
        assert screen._freq_hop is False


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
async def test_lock_screen_channel_callback_updates_status():
    """_on_channel updates the #lk_status bar with freq, SF and dwell."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.click("#sw_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, LockScreen)
        app._scanner.stop()
        await pilot.pause(0.1)
        screen._on_channel(868300000, 9)
        await pilot.pause(0.1)
        status = screen.query_one("#lk_status", Static)
        text = str(status.content)
        assert "868.300" in text
        assert "SF9" in text
        assert "dwell=" in text   # exact value varies (patched to 20ms in tests)


@pytest.mark.asyncio
async def test_lock_screen_rx2_check_label():
    """_on_channel with RX2 freq shows 'RX2 check' label."""
    from lora_recon import RX2_FREQ, RX2_SF
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.click("#sw_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, LockScreen)
        app._scanner.stop()
        await pilot.pause(0.1)
        screen._on_channel(RX2_FREQ, RX2_SF)
        await pilot.pause(0.1)
        status = screen.query_one("#lk_status", Static)
        assert "RX2 check" in str(status.content)


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


# ---------------------------------------------------------------------------
# RX2 interval keybinding
# ---------------------------------------------------------------------------

def test_rx2_interval_default():
    scanner = HardwareScanner(_mock_unit())
    assert scanner.rx2_interval == 10


def test_rx2_interval_cycles_through_presets():
    scanner = HardwareScanner(_mock_unit())
    presets = HardwareScanner.RX2_PRESETS
    scanner.rx2_interval = presets[0]
    for expected in presets[1:] + [presets[0]]:
        cur = scanner.rx2_interval
        nxt = presets[(presets.index(cur) + 1) % len(presets)]
        scanner.rx2_interval = nxt
        assert scanner.rx2_interval == expected


async def test_i_key_cycles_rx2_interval_on_sweep_screen():
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, SweepScreen)
        before = app._scanner.rx2_interval
        await pilot.press("i")
        await pilot.pause(0.1)
        after = app._scanner.rx2_interval
        assert after != before
        assert after in HardwareScanner.RX2_PRESETS


async def test_i_key_cycles_rx2_interval_on_lock_screen():
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.click("#sw_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, LockScreen)
        app._scanner.stop()
        before = app._scanner.rx2_interval
        await pilot.press("i")
        await pilot.pause(0.1)
        after = app._scanner.rx2_interval
        assert after != before
        assert after in HardwareScanner.RX2_PRESETS


async def test_rx2_interval_shared_between_screens():
    """Interval set on sweep screen persists when entering lock screen."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        # Set to first preset on sweep screen
        app._scanner.rx2_interval = HardwareScanner.RX2_PRESETS[0]
        await pilot.click("#sw_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert isinstance(app.screen, LockScreen)
        assert app._scanner.rx2_interval == HardwareScanner.RX2_PRESETS[0]


# ---------------------------------------------------------------------------
# Link margin in UI
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_sweep_packet_state_stores_margin():
    """_on_packet on SweepScreen populates the margin field in _state."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, SweepScreen)
        app._scanner.stop()
        pkt = _make_pkt({"rssi": -90, "snr": 6, "raw_hex": ""}, 868100000, 7)
        screen._on_packet(pkt)
        await pilot.pause(0.1)
        state = screen._state[(868100000, 7)]
        assert state["margin"] == 33   # -90 - (-123) = 33


@pytest.mark.asyncio
async def test_lock_packet_row_includes_margin():
    """_on_packet on LockScreen adds a row that contains the margin string."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.click("#sw_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, LockScreen)
        app._scanner.stop()
        # RSSI=-80, SF=12 → margin = -80 - (-137) = +57
        pkt = _make_pkt({"rssi": -80, "snr": 5, "raw_hex": ""}, 869525000, 12, is_downlink=True)
        screen._on_packet(pkt)
        await pilot.pause(0.1)
        t = screen.query_one("#pkt_table", DataTable)
        assert t.row_count == 1


@pytest.mark.asyncio
async def test_rx2_packet_appears_in_sweep_table():
    """RX2 downlink delivered via _on_packet is stored in the 869.525/SF12 state."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, SweepScreen)
        app._scanner.stop()
        pkt = _make_pkt({"rssi": -95, "snr": 4, "raw_hex": ""}, RX2_FREQ, RX2_SF, is_downlink=True)
        screen._on_packet(pkt)
        await pilot.pause(0.1)
        state = screen._state[(RX2_FREQ, RX2_SF)]
        assert state["pkts"] == 1
        assert state["rssi"] == -95
        assert state["margin"] == -95 - (-137)  # +42 dB


# ---------------------------------------------------------------------------
# _lorawan_airtime_ms
# ---------------------------------------------------------------------------
class TestAirtimeMs:
    def test_returns_positive(self):
        assert _lorawan_airtime_ms(20, 7) > 0

    def test_sf12_longer_than_sf7(self):
        assert _lorawan_airtime_ms(20, 12) > _lorawan_airtime_ms(20, 7)

    def test_longer_payload_more_airtime(self):
        assert _lorawan_airtime_ms(30, 9) > _lorawan_airtime_ms(10, 9)

    def test_zero_payload_still_has_preamble(self):
        assert _lorawan_airtime_ms(0, 7) > 0

    def test_sf7_20bytes_in_expected_range(self):
        # SF7 BW=125kHz 20-byte payload: ~56 ms per Semtech LoRa calculator
        airtime = _lorawan_airtime_ms(20, 7)
        assert 40 < airtime < 80

    def test_sf12_low_dr_optimisation_applied(self):
        # SF12 BW=125kHz triggers DE=1; airtime should be longer than without it
        airtime_sf12 = _lorawan_airtime_ms(20, 12)
        airtime_sf11 = _lorawan_airtime_ms(20, 11)
        assert airtime_sf12 > airtime_sf11

    def test_all_sfs_return_finite(self):
        for sf in range(7, 13):
            a = _lorawan_airtime_ms(20, sf)
            assert a > 0
            assert a < 30000  # no SF takes > 30 s for a normal payload


# ---------------------------------------------------------------------------
# _format_packet_detail
# ---------------------------------------------------------------------------
def _join_request_pkt() -> PacketRecord:
    """Minimal Join Request PacketRecord with known fields."""
    join_eui = bytes.fromhex("0102030405060708")[::-1]
    dev_eui  = bytes.fromhex("AABBCCDDEEFF0011")[::-1]
    raw = bytes([0x00]) + join_eui + dev_eui + bytes([0x01, 0x00]) + bytes(4)
    return PacketRecord(
        timestamp="2024-01-15T12:34:56+00:00",
        freq=868100000, sf=7, bw=125,
        rssi=-85, snr=8,
        raw_hex=raw.hex().upper(),
        mtype="Join Request",
        join_eui="0807060504030201",
        dev_eui="1100FFEEDDCCBBAA",
    )


def _uplink_pkt() -> PacketRecord:
    frame = _uplink_frame(0x260B1234, fcnt=42)
    return PacketRecord(
        timestamp="2024-01-15T12:34:56+00:00",
        freq=868100000, sf=9, bw=125,
        rssi=-90, snr=5,
        raw_hex=frame,
        mtype="Unconfirmed Data Up",
        dev_addr="260B1234",
        nwk_id="0x13",
        operator="TTN (The Things Network)",
        fcnt=42,
    )


def _downlink_pkt() -> PacketRecord:
    return PacketRecord(
        timestamp="2024-01-15T12:34:56+00:00",
        freq=869525000, sf=12, bw=125,
        rssi=-95, snr=3,
        raw_hex="",
        mtype="Unconfirmed Data Down",
        is_downlink=True,
    )


class TestFormatPacketDetail:
    def test_rf_section_present(self):
        text = _format_packet_detail(_uplink_pkt())
        assert "RF LAYER" in text
        assert "868.100 MHz" in text
        assert "SF9" in text

    def test_lorawan_section_present(self):
        text = _format_packet_detail(_uplink_pkt())
        assert "LORAWAN FRAME" in text
        assert "260B1234" in text
        assert "42" in text  # FCnt

    def test_link_margin_shown(self):
        # RSSI=-90, SF9, floor=-129 → margin = +39
        text = _format_packet_detail(_uplink_pkt())
        assert "+39 dB" in text

    def test_airtime_shown(self):
        text = _format_packet_detail(_uplink_pkt())
        assert "airtime" in text.lower()
        assert " ms" in text

    def test_join_request_analysis(self):
        text = _format_packet_detail(_join_request_pkt())
        assert "OTAA join attempt" in text
        assert "NOT encrypted" in text
        assert "DevEUI" in text
        assert "JoinEUI" in text

    def test_join_request_oui_shown(self):
        text = _format_packet_detail(_join_request_pkt())
        assert "1100FF" in text  # OUI from DevEUI "1100FFEEDDCCBBAA"

    def test_uplink_analysis(self):
        text = _format_packet_detail(_uplink_pkt())
        assert "Regular uplink" in text
        assert "AES-128 encrypted" in text
        assert "TTN" in text

    def test_downlink_analysis(self):
        text = _format_packet_detail(_downlink_pkt())
        assert "gateway confirmed" in text.lower() or "gateway" in text.lower()
        assert "RX2" in text

    def test_recon_section_present(self):
        for pkt in [_join_request_pkt(), _uplink_pkt(), _downlink_pkt()]:
            assert "RECONNAISSANCE ANALYSIS" in _format_packet_detail(pkt)

    def test_strong_signal_note(self):
        # Link margin >= 20 → "very strong" note
        pkt = _uplink_pkt()
        pkt.rssi = -60  # SF9 floor=-129 → margin=69
        text = _format_packet_detail(pkt)
        assert "very strong" in text.lower()

    def test_iq_polarity_downlink(self):
        text = _format_packet_detail(_downlink_pkt())
        assert "inverted" in text

    def test_iq_polarity_uplink(self):
        text = _format_packet_detail(_uplink_pkt())
        assert "normal" in text

    def test_no_raw_hex_does_not_crash(self):
        pkt = PacketRecord(
            timestamp="2024-01-15T12:00:00+00:00",
            freq=868100000, sf=7, bw=125,
            rssi=None, snr=None, raw_hex="",
        )
        text = _format_packet_detail(pkt)
        assert "RF LAYER" in text  # still renders


# ---------------------------------------------------------------------------
# PacketDetailScreen UI tests
# ---------------------------------------------------------------------------
async def _navigate_to_lock_with_packet(pilot, app, dev_addr_int=0x260B1234, fcnt=7):
    """Helper: start app, enter lock, stop scanner, inject one packet."""
    await pilot.pause(0.2)
    await pilot.click("#sw_table")
    await pilot.press("enter")
    await pilot.pause(0.2)
    screen = app.screen
    assert isinstance(screen, LockScreen)
    app._scanner.stop()
    frame = _uplink_frame(dev_addr_int, fcnt)
    pkt = _make_pkt({"rssi": -85, "snr": 7, "raw_hex": frame},
                    screen._freq, screen._sf)
    screen._on_packet(pkt)
    await pilot.pause(0.1)
    return screen


@pytest.mark.asyncio
async def test_enter_on_packet_row_opens_detail_screen():
    """Enter on pkt_table row pushes PacketDetailScreen."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await _navigate_to_lock_with_packet(pilot, app)
        await pilot.click("#pkt_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert isinstance(app.screen, PacketDetailScreen)


@pytest.mark.asyncio
async def test_detail_screen_escape_returns_to_lock():
    """Esc from PacketDetailScreen returns to LockScreen."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await _navigate_to_lock_with_packet(pilot, app)
        await pilot.click("#pkt_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert isinstance(app.screen, PacketDetailScreen)
        await pilot.press("escape")
        await pilot.pause(0.2)
        assert isinstance(app.screen, LockScreen)


@pytest.mark.asyncio
async def test_detail_screen_shows_dev_addr():
    """PacketDetailScreen body contains the packet's DevAddr."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await _navigate_to_lock_with_packet(pilot, app, dev_addr_int=0x260B9ABC)
        await pilot.click("#pkt_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        detail = app.screen
        assert isinstance(detail, PacketDetailScreen)
        body = detail.query_one("#pd_body", Static)
        assert "260B9ABC" in str(body.content)


@pytest.mark.asyncio
async def test_detail_screen_header_shows_packet_count():
    """PacketDetailScreen header shows '1 of 1' for a single packet."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await _navigate_to_lock_with_packet(pilot, app)
        await pilot.click("#pkt_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        detail = app.screen
        assert isinstance(detail, PacketDetailScreen)
        header = detail.query_one("#pd_header", Static)
        assert "1 of 1" in str(header.content)


@pytest.mark.asyncio
async def test_detail_screen_right_arrow_navigates_next():
    """Right arrow in PacketDetailScreen increments the packet index."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.click("#sw_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, LockScreen)
        app._scanner.stop()
        for i, fcnt in enumerate([1, 2]):
            pkt = _make_pkt(
                {"rssi": -80, "snr": 6,
                 "raw_hex": _uplink_frame(0x260B0001 + i, fcnt=fcnt)},
                screen._freq, screen._sf,
            )
            screen._on_packet(pkt)
        await pilot.pause(0.1)
        await pilot.click("#pkt_table")
        await pilot.press("enter")  # opens detail at row 0
        await pilot.pause(0.2)
        detail = app.screen
        assert isinstance(detail, PacketDetailScreen)
        assert detail._idx == 0
        await pilot.press("right")
        await pilot.pause(0.1)
        assert detail._idx == 1


@pytest.mark.asyncio
async def test_detail_screen_left_at_first_does_not_wrap():
    """Left arrow at index 0 does not decrement below zero."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await _navigate_to_lock_with_packet(pilot, app)
        await pilot.click("#pkt_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        detail = app.screen
        assert isinstance(detail, PacketDetailScreen)
        assert detail._idx == 0
        await pilot.press("left")
        await pilot.pause(0.1)
        assert detail._idx == 0  # unchanged


@pytest.mark.asyncio
async def test_detail_screen_right_at_last_does_not_wrap():
    """Right arrow at the last packet does not exceed bounds."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await _navigate_to_lock_with_packet(pilot, app)
        await pilot.click("#pkt_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        detail = app.screen
        assert isinstance(detail, PacketDetailScreen)
        assert detail._idx == 0
        await pilot.press("right")  # already at the only packet
        await pilot.pause(0.1)
        assert detail._idx == 0  # unchanged


@pytest.mark.asyncio
async def test_detail_screen_q_quits():
    """Q key in PacketDetailScreen exits the app."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await _navigate_to_lock_with_packet(pilot, app)
        await pilot.click("#pkt_table")
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert isinstance(app.screen, PacketDetailScreen)
        await pilot.press("q")


# ---------------------------------------------------------------------------
# New-field rendering in _format_packet_detail
# ---------------------------------------------------------------------------
class TestFormatPacketDetailNewFields:
    def _uplink_base(self):
        # Helper — TTN-style data uplink with no extra fields
        return PacketRecord(
            timestamp="2024-01-15T12:34:56+00:00",
            freq=868100000, sf=7, bw=125,
            rssi=-90, snr=5,
            raw_hex="40341234000000AA",
            mtype="Unconfirmed Data Up",
            dev_addr="260B1234", nwk_id="0x13", fcnt=10,
            operator="TTN (The Things Network)",
        )

    def test_join_request_shows_vendor(self):
        pkt = PacketRecord(
            timestamp="2024-01-15T12:00:00+00:00",
            freq=868100000, sf=7, bw=125, rssi=-80, snr=7,
            raw_hex="00" + "01"*8 + "00"*8 + "0000" + "AABBCCDD",
            mtype="Join Request",
            join_eui="0102030405060708",
            dev_eui="A84041AABBCCDD00",
            dev_eui_vendor="Dragino",
            dev_nonce=0x0042,
        )
        text = _format_packet_detail(pkt)
        assert "DevEUI vendor" in text
        assert "Dragino" in text
        assert "DevNonce" in text
        assert "0x0042" in text

    def test_multicast_flag_rendered(self):
        pkt = self._uplink_base()
        pkt.dev_addr = "FF000001"
        pkt.is_multicast = True
        text = _format_packet_detail(pkt)
        assert "Multicast" in text
        assert "FF000000" in text

    def test_retransmit_note_in_recon(self):
        pkt = self._uplink_base()
        pkt.is_retransmit = True
        text = _format_packet_detail(pkt)
        assert "Retransmission" in text

    def test_replay_alert_renders_security_section(self):
        pkt = self._uplink_base()
        pkt.replay_alert = "FCnt regression for 260B1234: 1000 → 5"
        text = _format_packet_detail(pkt)
        assert "SECURITY ALERT" in text
        assert "regression" in text

    def test_beacon_section_rendered(self):
        pkt = PacketRecord(
            timestamp="2024-01-15T12:00:00+00:00",
            freq=869525000, sf=9, bw=125, rssi=-100, snr=2,
            raw_hex="00" * 17,
            mtype="Class B Beacon",
            is_downlink=True, is_beacon=True,
            beacon={"utc": "2026-01-01T00:00:00+00:00",
                    "gps_seconds": 1_400_000_000,
                    "crc1": 0x1234, "crc2": 0xABCD,
                    "info_desc": 1, "gw_info": "01AABBCCDDEEFF"},
        )
        text = _format_packet_detail(pkt)
        assert "CLASS B BEACON" in text
        assert "time-synchronised" in text
        assert "2026-01-01" in text

    def test_meshtastic_section_rendered(self):
        pkt = PacketRecord(
            timestamp="2024-01-15T12:00:00+00:00",
            freq=869525000, sf=11, bw=250, rssi=-85, snr=4,
            raw_hex="00" * 16,
            mtype="Meshtastic",
            is_meshtastic=True,
            meshtastic={"src": "DEADBEEF", "dst": "FFFFFFFF",
                        "packet_id": 0x12345678, "hop_limit": 2,
                        "want_ack": True, "via_mqtt": False,
                        "channel_hash": 0x08},
        )
        text = _format_packet_detail(pkt)
        assert "MESHTASTIC HEADER" in text
        assert "DEADBEEF" in text
        assert "FFFFFFFF" in text

    def test_lpp_section_rendered(self):
        pkt = self._uplink_base()
        pkt.lpp_sensors = ["ch1 temperature=23.5C", "ch2 humidity=46.5%"]
        text = _format_packet_detail(pkt)
        assert "CAYENNE LPP" in text
        assert "23.5C" in text
        assert "46.5%" in text
        # And the recon note should also flag plaintext
        assert "isn't encrypting" in text

    def test_helium_operator_shown(self):
        # Type-6 NetID DevAddr (Helium): 0xFC0014C1 → 11111100_0000... = Type 6, NwkID 0x53?
        # Recompute: top 7 bits 1111110, then 15 bits NwkID, then 10 bits addr.
        # We just check the operator string flows through to the detail.
        pkt = self._uplink_base()
        pkt.operator = "Helium"
        pkt.netid_type = 6
        text = _format_packet_detail(pkt)
        assert "Helium" in text


# ---------------------------------------------------------------------------
# _make_pkt with the new flags
# ---------------------------------------------------------------------------
class TestMakePktNewModes:
    def test_meshtastic_mode_skips_lorawan_parse(self):
        # Bytes are LE on the wire; hex bytes "EFBEADDE" → unpacked LE → 0xDEADBEEF
        import struct
        dst = struct.pack("<I", 0xFFFFFFFF)
        src = struct.pack("<I", 0xDEADBEEF)
        pid = struct.pack("<I", 0x12345678)
        flags = bytes([0x08])
        chh   = bytes([0x42])
        evt = {"rssi": -80, "snr": 5,
               "raw_hex": (dst + src + pid + flags + chh + b"\x00\x00").hex().upper()}
        pkt = _make_pkt(evt, 869525000, 11, bw=250, is_meshtastic=True)
        assert pkt.is_meshtastic is True
        assert pkt.mtype == "Meshtastic"
        assert pkt.meshtastic is not None
        assert pkt.meshtastic["src"] == "DEADBEEF"
        assert pkt.meshtastic["dst"] == "FFFFFFFF"

    def test_beacon_mode_uses_beacon_parser(self):
        # 17-byte beacon
        raw = ("0000" + "0094357D" + "1234" + "01AABBCCDDEEFF" + "ABCD").upper()
        evt = {"rssi": -100, "snr": 2, "raw_hex": raw}
        pkt = _make_pkt(evt, 869525000, 9, bw=125, is_beacon=True)
        assert pkt.is_beacon is True
        assert pkt.is_downlink is True
        assert pkt.mtype == "Class B Beacon"
        assert pkt.beacon is not None
        assert pkt.beacon["info_desc"] == 0x01

    def test_uplink_populates_new_fields(self):
        # Join request with Dragino DevEUI
        join_eui_le = bytes([0x01]*8)
        dev_eui_le  = bytes([0x55, 0x44, 0x33, 0x22, 0x11, 0x41, 0x40, 0xA8])
        frame = (bytes([0x00]) + join_eui_le + dev_eui_le
                 + b"\x42\x00"      # DevNonce 0x0042
                 + b"\xAA\xBB\xCC\xDD")
        evt = {"rssi": -80, "snr": 7, "raw_hex": frame.hex().upper()}
        pkt = _make_pkt(evt, 868100000, 7)
        assert pkt.dev_nonce == 0x0042
        assert pkt.dev_eui_vendor == "Dragino"
        assert pkt.is_meshtastic is False
        assert pkt.is_beacon is False


# ---------------------------------------------------------------------------
# CLI argparse for new flags
# ---------------------------------------------------------------------------
class TestTUICLI:
    def test_beacon_interval_flag(self):
        from lora_tui import build_parser
        args = build_parser().parse_args(["--beacon-interval", "5"])
        assert args.beacon_interval == 5

    def test_replay_state_flag(self):
        from lora_tui import build_parser
        args = build_parser().parse_args(["--replay-state", "/tmp/r.json"])
        assert args.replay_state == "/tmp/r.json"

    def test_defaults(self):
        from lora_tui import build_parser
        args = build_parser().parse_args([])
        assert args.beacon_interval == 0
        assert args.replay_state is None

    def test_meshtastic_flag(self):
        from lora_tui import build_parser
        args = build_parser().parse_args(["--meshtastic"])
        assert args.meshtastic is True
        assert args.meshtastic_preset == "LongFast"

    def test_meshtastic_preset_choices(self):
        from lora_tui import build_parser
        args = build_parser().parse_args(["--meshtastic", "--meshtastic-preset", "LongSlow"])
        assert args.meshtastic_preset == "LongSlow"


# ---------------------------------------------------------------------------
# HardwareScanner.start_meshtastic
# ---------------------------------------------------------------------------
class TestStartMeshtastic:
    def _scanner(self, readline_lines=None):
        s = HardwareScanner(_mock_unit(readline_lines or []))
        s._rx_overhead = 0
        return s

    def test_unknown_preset_raises(self):
        s = self._scanner()
        with pytest.raises(ValueError):
            s.start_meshtastic("Bogus", on_packet=lambda p: None)

    def test_sets_sync_word_on_entry(self):
        s = self._scanner()
        sync_calls = []
        s.unit.set_syncword = lambda w: sync_calls.append(w) or True

        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            s.start_meshtastic("LongFast", on_packet=lambda p: None)
            # Let one loop iteration happen, then stop
            time.sleep(0.1)
            s.stop()
        # The Meshtastic sync word was set at least once
        assert MESHTASTIC_SYNCWORD in sync_calls

    def test_restores_lorawan_sync_on_stop(self):
        s = self._scanner()
        sync_calls = []
        s.unit.set_syncword = lambda w: sync_calls.append(w) or True

        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            s.start_meshtastic("LongFast", on_packet=lambda p: None)
            time.sleep(0.1)
            s.stop()
        # Last call should restore the LoRaWAN sync word
        assert sync_calls[-1] == LORAWAN_SYNCWORD

    def test_configures_preset_frequency(self):
        s = self._scanner()
        cp_calls = []
        s.unit.set_syncword = lambda w: True
        original_cp = s.unit.configure_p2p
        def trace_cp(freq, sf, **kwargs):
            cp_calls.append((freq, sf, kwargs.get("bw", 125)))
            return original_cp(freq, sf, **kwargs)
        s.unit.configure_p2p = trace_cp

        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            s.start_meshtastic("LongFast", on_packet=lambda p: None)
            time.sleep(0.1)
            s.stop()
        assert cp_calls, "configure_p2p was never called"
        freq, sf, bw = cp_calls[0]
        assert (freq, sf, bw) == MESHTASTIC_EU_PRESETS["LongFast"]

    def test_delivers_meshtastic_packet(self):
        # Build a Meshtastic frame and feed it as an RXP2P event
        import struct
        frame = (struct.pack("<I", 0xFFFFFFFF)        # dst
                 + struct.pack("<I", 0xDEADBEEF)       # src
                 + struct.pack("<I", 0x12345678)       # packet_id
                 + bytes([0x08, 0x42, 0x00, 0x00]))
        lines = [f"+EVT:RXP2P:-90:5:{frame.hex().upper()}"]

        s = self._scanner(readline_lines=lines)
        s.unit.set_syncword = lambda w: True
        got = []
        stop = threading.Event()
        def on_pkt(p):
            got.append(p)
            stop.set()

        with patch.dict(lora_recon.SF_DWELL, FAST_DWELL):
            s.start_meshtastic("LongFast", on_packet=on_pkt)
            stop.wait(timeout=5)
            s.stop()
        assert got
        assert got[0].is_meshtastic is True
        assert got[0].meshtastic["src"] == "DEADBEEF"


# ---------------------------------------------------------------------------
# SweepScreen `M` key pushes MeshtasticScreen
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_sweep_screen_m_key_pushes_meshtastic_screen():
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.05)
        # Stop the LoRaWAN sweep scanner so it doesn't race with the test
        app._scanner.stop()
        # Press M
        await pilot.press("m")
        await pilot.pause(0.1)
        assert isinstance(app.screen, MeshtasticScreen)
        # Cleanup before fixture tears down
        app._scanner.stop()


@pytest.mark.asyncio
async def test_meshtastic_screen_esc_returns_to_sweep():
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.05)
        app._scanner.stop()
        await pilot.press("m")
        await pilot.pause(0.1)
        assert isinstance(app.screen, MeshtasticScreen)
        await pilot.press("escape")
        await pilot.pause(0.1)
        assert isinstance(app.screen, SweepScreen)
        app._scanner.stop()


@pytest.mark.asyncio
async def test_meshtastic_screen_renders_packet():
    """A Meshtastic packet posted to the screen appears in its table."""
    app, _ = _make_app()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.05)
        app._scanner.stop()
        await pilot.press("m")
        await pilot.pause(0.1)
        screen = app.screen
        assert isinstance(screen, MeshtasticScreen)
        # Stop the meshtastic loop so it doesn't compete with our direct call
        app._scanner.stop()

        pkt = PacketRecord(
            timestamp="2024-01-15T12:00:00+00:00",
            freq=869525000, sf=11, bw=250, rssi=-85, snr=4,
            raw_hex="00" * 16,
            mtype="Meshtastic", is_meshtastic=True,
            meshtastic={"src": "DEADBEEF", "dst": "FFFFFFFF",
                        "packet_id": 0x12345678, "hop_limit": 2,
                        "want_ack": True, "via_mqtt": False,
                        "channel_hash": 0x08},
        )
        screen._on_packet(pkt)
        await pilot.pause(0.05)
        t = screen.query_one("#mt_table", DataTable)
        assert t.row_count == 1


# ---------------------------------------------------------------------------
# CLI --meshtastic flag wires through to the App
# ---------------------------------------------------------------------------
def test_app_start_meshtastic_attribute():
    """LoRaTUIApp accepts start_meshtastic and stores it for on_mount."""
    mock_unit = MagicMock(spec=LoRaUnit)
    app = LoRaTUIApp(mock_unit, "v=test", start_meshtastic=True)
    assert app._start_meshtastic is True

    app2 = LoRaTUIApp(mock_unit, "v=test")
    assert app2._start_meshtastic is False


# ---------------------------------------------------------------------------
# Receiver / hardware section in the detail screen
# ---------------------------------------------------------------------------
class TestHardwareSection:
    def _pkt(self) -> PacketRecord:
        return PacketRecord(
            timestamp="2024-01-15T12:00:00+00:00",
            freq=868100000, sf=7, bw=125, rssi=-80, snr=7,
            raw_hex="40341234000000AA",
            mtype="Unconfirmed Data Up",
            dev_addr="260B1234", nwk_id="0x13", fcnt=10,
        )

    def test_no_hardware_info_means_no_section(self):
        text = _format_packet_detail(self._pkt())
        assert "RECEIVER / HARDWARE" not in text

    def test_hardware_info_renders_section(self):
        hw = {
            "module":   "M5Stack Unit LoRaWAN-EU868 (RAK3172 / STM32WLE5)",
            "version":  "RUI_4.0.5_RAK3172",
            "dev_eui":  "A8404118273645FF",
            "port":     "/dev/ttyUSB0",
            "baudrate": 115200,
            "region":   "EU868",
        }
        text = _format_packet_detail(self._pkt(), hardware_info=hw)
        assert "RECEIVER / HARDWARE" in text
        assert "RAK3172" in text
        assert "RUI_4.0.5_RAK3172" in text
        assert "A8404118273645FF" in text
        assert "/dev/ttyUSB0" in text
        assert "115200" in text
        assert "EU868" in text

    def test_hardware_section_does_vendor_lookup_on_receiver_eui(self):
        hw = {"dev_eui": "A8404100112233AA"}      # Dragino OUI
        text = _format_packet_detail(self._pkt(), hardware_info=hw)
        assert "Dragino" in text

    def test_unavailable_dev_eui_is_skipped(self):
        hw = {"version": "test", "dev_eui": "–"}   # P2P-mode placeholder
        text = _format_packet_detail(self._pkt(), hardware_info=hw)
        assert "RECEIVER / HARDWARE" in text
        assert "test" in text
        # The "Receiver DevEUI" row should NOT appear for the "–" placeholder
        assert "Receiver DevEUI" not in text

    def test_empty_hardware_info_still_safe(self):
        # An empty dict is falsy → no section shown
        text = _format_packet_detail(self._pkt(), hardware_info={})
        assert "RECEIVER / HARDWARE" not in text


# ---------------------------------------------------------------------------
# DEVICE HARDWARE section — explicit visibility into the sending device
# ---------------------------------------------------------------------------
class TestDeviceHardwareSection:
    def _data_frame_pkt(self) -> PacketRecord:
        return PacketRecord(
            timestamp="2024-01-15T12:34:56+00:00",
            freq=868100000, sf=9, bw=125, rssi=-90, snr=5,
            raw_hex=_uplink_frame(0x260B1234, fcnt=10),
            mtype="Unconfirmed Data Up",
            dev_addr="260B1234", nwk_id="0x13", fcnt=10,
            operator="TTN (The Things Network)",
        )

    def _join_request_pkt(self) -> PacketRecord:
        # Dragino DevEUI A84041…
        return PacketRecord(
            timestamp="2024-01-15T12:00:00+00:00",
            freq=868100000, sf=7, bw=125, rssi=-80, snr=7,
            raw_hex="00" + "01"*8 + "55443322114140A8" + "4200" + "AABBCCDD",
            mtype="Join Request",
            join_eui="0102030405060708",
            dev_eui="A84041AABBCCDD00",
            dev_eui_vendor="Dragino",
            dev_nonce=0x0042,
        )

    def test_section_header_present_for_data_frame(self):
        text = _format_packet_detail(self._data_frame_pkt())
        assert "DEVICE HARDWARE" in text

    def test_section_header_present_for_join_request(self):
        text = _format_packet_detail(self._join_request_pkt())
        assert "DEVICE HARDWARE" in text

    def test_data_frame_says_dev_eui_not_in_this_frame(self):
        text = _format_packet_detail(self._data_frame_pkt())
        assert "not in this frame" in text
        assert "Data frames carry only DevAddr" in text

    def test_data_frame_vendor_marked_unknown(self):
        text = _format_packet_detail(self._data_frame_pkt())
        # Slice from the DEVICE HARDWARE header to the next section header
        section = text.split("DEVICE HARDWARE", 1)[1].split("RECONNAISSANCE", 1)[0]
        assert "unknown" in section
        assert "can't look up the manufacturer" in section

    def test_join_request_shows_full_device_identity(self):
        text = _format_packet_detail(self._join_request_pkt())
        section = text.split("DEVICE HARDWARE", 1)[1].split("RECONNAISSANCE", 1)[0]
        assert "A84041AABBCCDD00" in section
        assert "A84041" in section           # OUI
        assert "Dragino" in section          # vendor
        assert "0102030405060708" in section # JoinEUI
        assert "0x0042" in section           # DevNonce

    def test_section_skipped_for_meshtastic_packet(self):
        pkt = PacketRecord(
            timestamp="2024-01-15T12:00:00+00:00",
            freq=869525000, sf=11, bw=250, rssi=-85, snr=4,
            raw_hex="00" * 16,
            mtype="Meshtastic",
            is_meshtastic=True,
            meshtastic={"src": "DEADBEEF", "dst": "FFFFFFFF",
                        "packet_id": 0x12345678, "hop_limit": 2,
                        "want_ack": False, "via_mqtt": False,
                        "channel_hash": 0x08},
        )
        text = _format_packet_detail(pkt)
        assert "DEVICE HARDWARE" not in text

    def test_section_skipped_for_beacon_packet(self):
        pkt = PacketRecord(
            timestamp="2024-01-15T12:00:00+00:00",
            freq=869525000, sf=9, bw=125, rssi=-100, snr=2,
            raw_hex="00" * 17,
            mtype="Class B Beacon",
            is_downlink=True, is_beacon=True,
            beacon={"utc": "2026-01-01T00:00:00+00:00",
                    "gps_seconds": 1_400_000_000,
                    "crc1": 0x1234, "crc2": 0xABCD,
                    "info_desc": 1, "gw_info": "01AABBCCDDEEFF"},
        )
        text = _format_packet_detail(pkt)
        assert "DEVICE HARDWARE" not in text

    def test_empty_frame_shows_no_identity_row(self):
        pkt = PacketRecord(
            timestamp="2024-01-15T12:00:00+00:00",
            freq=868100000, sf=7, bw=125, rssi=None, snr=None, raw_hex="",
        )
        text = _format_packet_detail(pkt)
        assert "DEVICE HARDWARE" in text
        assert "no DevEUI or DevAddr" in text

    def test_section_renders_without_hardware_info_arg(self):
        # The DEVICE HARDWARE section is for the sending device; it should
        # appear whether or not the receiver hardware_info is supplied.
        text_no_hw = _format_packet_detail(self._data_frame_pkt())
        text_with_hw = _format_packet_detail(self._data_frame_pkt(),
                                             hardware_info={"module": "test"})
        assert "DEVICE HARDWARE" in text_no_hw
        assert "DEVICE HARDWARE" in text_with_hw
        # And the two sections are distinct
        assert "RECEIVER / HARDWARE" not in text_no_hw
        assert "RECEIVER / HARDWARE" in text_with_hw


# ---------------------------------------------------------------------------
# Improved Unknown-operator hint
# ---------------------------------------------------------------------------
class TestUnknownOperatorHint:
    def test_unknown_operator_shows_netid_and_registry_pointer(self):
        # NwkID 0x08 (DevAddr 0x10000000 → top 7 bits = 0x08)
        # Build a real frame so the detail screen parses it the same way the TUI does
        import struct
        from lora_recon import parse_lorawan
        da = struct.pack("<I", 0x10000001)
        frame = bytes([0x60]) + da + bytes([0x00, 0x00, 0x00])
        r = parse_lorawan(frame.hex())
        # Sanity: it's still Type 0 with NwkID 0x08
        assert r["netid_type"] == 0
        assert r["nwk_id"] == "0x08"
        assert r["operator_hint"].startswith("Unknown commercial operator")
        assert "0x000008" in r["operator_hint"]
        assert "LoRa Alliance" in r["operator_hint"]

    def test_known_operator_unchanged(self):
        from lora_recon import parse_lorawan
        import struct
        da = struct.pack("<I", 0x26000001)             # NwkID 0x13 (TTN)
        frame = bytes([0x40]) + da + bytes([0x00, 0x00, 0x00, 0xAA])
        r = parse_lorawan(frame.hex())
        assert r["operator_hint"] == "TTN (The Things Network)"

    def test_unknown_operator_in_detail_screen(self):
        # End-to-end: a downlink with NwkID 0x08 renders the new hint text
        import struct
        from lora_recon import parse_lorawan
        da = struct.pack("<I", 0x10000001)
        raw = (bytes([0x60]) + da + bytes([0x00, 0x00, 0x00])).hex().upper()
        lw = parse_lorawan(raw)
        pkt = PacketRecord(
            timestamp="2024-01-15T12:00:00+00:00",
            freq=869525000, sf=12, bw=125, rssi=-101, snr=-7,
            raw_hex=raw,
            mtype=lw["mtype"], dev_addr=lw["dev_addr"], nwk_id=lw["nwk_id"],
            netid_type=lw["netid_type"], operator=lw["operator_hint"],
            is_downlink=True,
        )
        text = _format_packet_detail(pkt)
        assert "0x000008" in text
        assert "LoRa Alliance" in text
