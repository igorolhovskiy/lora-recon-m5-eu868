#!/usr/bin/env python3
"""
TUI interface for lora_recon — passive LoRa reconnaissance.

Usage:
    python lora_tui.py [--port /dev/ttyUSB0] [--baudrate 115200]

Controls — Sweep view:
    ↑ ↓     Navigate channel/SF rows
    Enter   Lock onto selected combination (passive monitor)
    R       Reset statistics
    Q       Quit

Controls — Lock view:
    Esc     Return to sweep
    Q       Quit
"""

import argparse
import sys
import time
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional, Callable

from textual.app import App, ComposeResult
from textual.widgets import DataTable, Header, Footer, Static
from textual.screen import Screen
from textual.binding import Binding

from lora_recon import (
    LoRaUnit, DeduplicationCache,
    parse_events, parse_lorawan, PacketRecord,
    EU868_CHANNELS, RX2_FREQ, RX2_SF, SPREADING_FACTORS, SF_DWELL,
    auto_detect_port,
)

# All 48 sweep combinations in scan order
ALL_COMBOS: list[tuple[int, int]] = [
    (freq, sf) for freq in EU868_CHANNELS for sf in SPREADING_FACTORS
]

# SX1262 receiver sensitivity floor (dBm) at BW=125 kHz, CR=4/5 per SF.
# Link margin = RSSI − floor: how many dB above the noise floor the packet arrived.
# Positive margin means reliably decoded; ≥30 dB suggests a nearby or high-power device.
SF_SENSITIVITY = {7: -123, 8: -126, 9: -129, 10: -132, 11: -135, 12: -137}


def _link_margin(rssi: Optional[int], sf: int) -> Optional[int]:
    """Return RSSI minus the SF sensitivity floor, or None if RSSI is unknown."""
    if rssi is None:
        return None
    return rssi - SF_SENSITIVITY[sf]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_pkt(evt: dict, freq: int, sf: int, is_downlink: bool = False) -> PacketRecord:
    raw_hex = evt.get("raw_hex", "")
    lw = parse_lorawan(raw_hex) if raw_hex else {}
    return PacketRecord(
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        freq=freq, sf=sf, bw=125,
        rssi=evt.get("rssi"),
        snr=evt.get("snr"),
        raw_hex=raw_hex,
        mtype=lw.get("mtype"),
        dev_addr=lw.get("dev_addr"),
        nwk_id=lw.get("nwk_id"),
        operator=lw.get("operator_hint"),
        fcnt=lw.get("fcnt"),
        join_eui=lw.get("join_eui"),
        dev_eui=lw.get("dev_eui"),
        is_downlink=is_downlink,
        mac_commands=lw.get("mac_commands"),
    )


# ---------------------------------------------------------------------------
# Hardware scanner (background thread)
# ---------------------------------------------------------------------------
class HardwareScanner:
    """Thin hardware scanner with callbacks. All callbacks are called from the
    background thread — callers must use call_from_thread() to touch the UI."""

    RX2_PRESETS  = [1, 2, 5, 10, 20]  # available RX2 check intervals (hops)

    def __init__(self, unit: LoRaUnit):
        self.unit = unit
        self.rx2_interval = 10         # check RX2 downlink channel every N lock cycles
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def stop(self, timeout: float = 5.0):
        """Signal stop; cancel active RX window so thread exits within 0.2 s."""
        self._stop.set()
        try:
            self.unit.stop_rx()
        except Exception:
            pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start_sweep(self, on_channel: Callable, on_packet: Callable):
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._sweep_loop,
            args=(on_channel, on_packet),
            daemon=True,
            name="lora-sweep",
        )
        self._thread.start()

    def start_lock(self, freq: Optional[int], sf: int, on_packet: Callable,
                   freq_hop: bool = False, on_channel: Optional[Callable] = None,
                   is_downlink: bool = False):
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._lock_loop,
            args=(freq, sf, on_packet, freq_hop, on_channel, is_downlink),
            daemon=True,
            name="lora-lock",
        )
        self._thread.start()

    # ---- internals ---------------------------------------------------------

    def _sweep_loop(self, on_channel: Callable, on_packet: Callable):
        dedup = DeduplicationCache()
        hop = 0
        while not self._stop.is_set():
            for freq, sf in ALL_COMBOS:
                if self._stop.is_set():
                    return
                on_channel(freq, sf)
                self._do_rx(freq, sf, on_packet, dedup)
                hop += 1
                if hop % self.rx2_interval == 0 and not self._stop.is_set():
                    on_channel(RX2_FREQ, RX2_SF)
                    self._do_rx(RX2_FREQ, RX2_SF, on_packet, dedup, is_downlink=True)
            dedup.purge()

    def _lock_loop(self, freq: Optional[int], sf: int, on_packet: Callable,
                   freq_hop: bool = False, on_channel: Optional[Callable] = None,
                   is_downlink: bool = False):
        dedup = DeduplicationCache()
        cycle = 0
        while not self._stop.is_set():
            channels = EU868_CHANNELS if freq_hop else [freq]
            for ch in channels:
                if self._stop.is_set():
                    return
                if on_channel:
                    on_channel(ch, sf)
                self._do_rx(ch, sf, on_packet, dedup, is_downlink=is_downlink)
            cycle += 1
            # Skip RX2 interleave when the main lock is already on RX2
            if not is_downlink and cycle % self.rx2_interval == 0:
                if on_channel:
                    on_channel(RX2_FREQ, RX2_SF)
                self._do_rx(RX2_FREQ, RX2_SF, on_packet, dedup, is_downlink=True)

    def _do_rx(self, freq: int, sf: int, on_packet: Callable,
               dedup: DeduplicationCache, is_downlink: bool = False):
        if self._stop.is_set():
            return
        dwell = SF_DWELL[sf]
        if not self.unit.configure_p2p(freq, sf):
            return
        self.unit.set_iq_inversion(is_downlink)  # downlinks need inverted IQ
        self.unit.start_rx()                      # continuous (65534); stop_rx() ends the window
        # Read in 0.2 s increments so stop_event is checked every tick
        lines: list[str] = []
        deadline = time.monotonic() + dwell + 0.5
        old_timeout = self.unit.ser.timeout
        self.unit.ser.timeout = 0.2
        while time.monotonic() < deadline and not self._stop.is_set():
            try:
                raw = self.unit.ser.readline()
                line = raw.decode(errors="replace").strip()
                if line:
                    lines.append(line)
            except Exception:
                break
        self.unit.ser.timeout = old_timeout
        if not self._stop.is_set():
            self.unit.stop_rx()
        for evt in parse_events(lines):
            if self._stop.is_set():
                return
            pkt = _make_pkt(evt, freq, sf, is_downlink)
            if not dedup.is_duplicate(pkt.dev_addr, pkt.fcnt):
                on_packet(pkt)


# ---------------------------------------------------------------------------
# Sweep Screen
# ---------------------------------------------------------------------------
class SweepScreen(Screen):

    CSS = """
    SweepScreen {
        layout: vertical;
    }
    #sw_status {
        height: 1;
        background: $primary-darken-2;
        padding: 0 1;
        color: $text;
    }
    """

    BINDINGS = [
        Binding("r", "reset",            "Reset stats",    show=True),
        Binding("l", "lock_single",      "Lock freq+SF",   show=True),
        Binding("i", "cycle_rx2",        "RX2 interval",   show=True),
        Binding("q", "app.quit",         "Quit",           show=True),
    ]

    def __init__(self, scanner: HardwareScanner, device_info: str):
        super().__init__()
        self._scanner = scanner
        self._device_info = device_info
        self._state: dict[tuple, dict] = {
            combo: {"pkts": 0, "rssi": None, "snr": None, "margin": None, "addr": "", "ts": ""}
            for combo in [*ALL_COMBOS, (RX2_FREQ, RX2_SF)]
        }
        self._current: Optional[tuple] = None
        self._pass_num = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", id="sw_status")
        yield DataTable(id="sw_table", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        t = self.query_one("#sw_table", DataTable)
        t.add_column("Freq MHz",  width=10)
        t.add_column("SF",        width=4)
        t.add_column("Status",    width=12, key="status")
        t.add_column("Pkts",      width=5,  key="pkts")
        t.add_column("RSSI dBm",  width=9,  key="rssi")
        t.add_column("SNR dB",    width=7,  key="snr")
        t.add_column("Margin",    width=8,  key="margin")
        t.add_column("DevAddr",   width=10, key="addr")
        t.add_column("Last seen", width=10, key="ts")
        for freq, sf in ALL_COMBOS:
            t.add_row(
                f"{freq/1e6:.3f}", f"SF{sf}",
                "·  idle", "0", "", "", "", "", "",
                key=f"{freq}_{sf}",
            )
        t.add_row(
            f"{RX2_FREQ/1e6:.3f}", f"SF{RX2_SF}",
            "·  RX2", "0", "", "", "", "", "",
            key=f"{RX2_FREQ}_{RX2_SF}",
        )

    def on_show(self) -> None:
        if not self._scanner.is_running():
            self._start_sweep()

    def _start_sweep(self):
        self._pass_num += 1
        self._scanner.start_sweep(
            on_channel=lambda f, s: self.app.call_from_thread(self._on_channel, f, s),
            on_packet=lambda p: self.app.call_from_thread(self._on_packet, p),
        )

    # ---- thread callbacks (called on main thread via call_from_thread) -----

    def _on_channel(self, freq: int, sf: int) -> None:
        try:
            t = self.query_one("#sw_table", DataTable)
            status_bar = self.query_one("#sw_status", Static)
        except Exception:
            return  # screen already unmounted
        prev = self._current
        self._current = (freq, sf)
        if prev and prev != self._current:
            self._refresh_row(prev)
        t.update_cell(f"{freq}_{sf}", "status", ">> scanning")
        status_bar.update(
            f"{self._device_info}  |  Pass #{self._pass_num}  "
            f"| {freq/1e6:.3f} MHz SF{sf}  dwell={SF_DWELL[sf]}s"
            f"  |  RX2 every {self._scanner.rx2_interval} hops  [I]"
        )

    def _on_packet(self, pkt: PacketRecord) -> None:
        combo = (pkt.freq, pkt.sf)
        if combo not in self._state:
            return
        s = self._state[combo]
        s["pkts"]   += 1
        s["rssi"]   = pkt.rssi
        s["snr"]    = pkt.snr
        s["margin"] = _link_margin(pkt.rssi, pkt.sf)
        s["addr"]   = pkt.dev_addr or pkt.join_eui or "?"
        s["ts"]     = pkt.timestamp[11:19]  # HH:MM:SS
        self._refresh_row(combo)

    def _refresh_row(self, combo: tuple) -> None:
        try:
            t = self.query_one("#sw_table", DataTable)
        except Exception:
            return
        freq, sf = combo
        s = self._state[combo]
        is_now = combo == self._current
        if is_now:
            status = ">> scanning"
        elif s["pkts"] > 0:
            status = "✓  active"
        elif combo == (RX2_FREQ, RX2_SF):
            status = "·  RX2"
        else:
            status = "·  idle"
        m = s["margin"]
        t.update_cell(f"{freq}_{sf}", "status", status)
        t.update_cell(f"{freq}_{sf}", "pkts",   str(s["pkts"]))
        t.update_cell(f"{freq}_{sf}", "rssi",   f"{s['rssi']}" if s["rssi"] is not None else "")
        t.update_cell(f"{freq}_{sf}", "snr",    f"{s['snr']}"  if s["snr"]  is not None else "")
        t.update_cell(f"{freq}_{sf}", "margin", f"{m:+d} dB"   if m is not None else "")
        t.update_cell(f"{freq}_{sf}", "addr",   s["addr"])
        t.update_cell(f"{freq}_{sf}", "ts",     s["ts"])

    # ---- event handlers ----------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Enter on EU868 row: SF-hop lock.  Enter on RX2 row: downlink lock."""
        idx = event.cursor_row
        self._scanner.stop()
        if idx == len(ALL_COMBOS):   # RX2 row
            self.app.push_screen(LockScreen(self._scanner, RX2_FREQ, RX2_SF, is_downlink=True))
        elif 0 <= idx < len(ALL_COMBOS):
            freq, sf = ALL_COMBOS[idx]
            self.app.push_screen(LockScreen(self._scanner, freq, sf, freq_hop=True))

    # ---- actions -----------------------------------------------------------

    def action_lock_single(self) -> None:
        """L on EU868 row: single-channel lock.  L on RX2 row: downlink lock."""
        t = self.query_one("#sw_table", DataTable)
        idx = t.cursor_row
        self._scanner.stop()
        if idx == len(ALL_COMBOS):   # RX2 row
            self.app.push_screen(LockScreen(self._scanner, RX2_FREQ, RX2_SF, is_downlink=True))
        elif 0 <= idx < len(ALL_COMBOS):
            freq, sf = ALL_COMBOS[idx]
            self.app.push_screen(LockScreen(self._scanner, freq, sf, freq_hop=False))

    def action_cycle_rx2(self) -> None:
        presets = HardwareScanner.RX2_PRESETS
        cur = self._scanner.rx2_interval
        nxt = presets[(presets.index(cur) + 1) % len(presets)] if cur in presets else presets[0]
        self._scanner.rx2_interval = nxt
        self.notify(f"RX2 check every {nxt} hops", timeout=2)

    def action_reset(self) -> None:
        self._current = None
        for combo in self._state:
            self._state[combo] = {"pkts": 0, "rssi": None, "snr": None, "margin": None, "addr": "", "ts": ""}
            self._refresh_row(combo)


# ---------------------------------------------------------------------------
# Lock Screen
# ---------------------------------------------------------------------------
class LockScreen(Screen):

    CSS = """
    LockScreen {
        layout: vertical;
    }
    #lk_header {
        height: 1;
        background: $warning-darken-1;
        color: $text;
        padding: 0 1;
    }
    #lk_status {
        height: 1;
        background: $primary-darken-2;
        padding: 0 1;
        color: $text;
    }
    #pkt_table {
        height: 2fr;
    }
    #stats_box {
        height: 1fr;
        background: $surface;
        border-top: solid $primary;
        padding: 1 2;
    }
    """

    BINDINGS = [
        Binding("escape", "back",       "Back to sweep",  show=True),
        Binding("i",      "cycle_rx2",  "RX2 interval",   show=True),
        Binding("q",      "app.quit",   "Quit",           show=True),
    ]

    def __init__(self, scanner: HardwareScanner, freq: int, sf: int,
                 freq_hop: bool = False, is_downlink: bool = False):
        super().__init__()
        self._scanner = scanner
        self._freq = freq
        self._sf = sf
        self._freq_hop = freq_hop
        self._is_downlink = is_downlink
        self._pkts: list[PacketRecord] = []
        self._addrs: set[str] = set()
        self._downlinks = 0
        self._fcnt_hist: dict[str, list[tuple[float, int]]] = defaultdict(list)
        self._rssi_hist: dict[str, list[int]] = defaultdict(list)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        if self._is_downlink:
            hdr = (f"RX2 LOCK  {self._freq/1e6:.3f} MHz  SF{self._sf}"
                   f"  ↓ downlinks only  BW=125 kHz  CR=4/5   [Esc] back to sweep")
        elif self._freq_hop:
            hdr = (f"SF-HOP  SF{self._sf}  all EU868 channels  BW=125 kHz  CR=4/5"
                   f"   [Esc] back to sweep")
        else:
            hdr = (f"LOCK  {self._freq/1e6:.3f} MHz  SF{self._sf}  BW=125 kHz  CR=4/5"
                   f"   [Esc] back to sweep")
        yield Static(hdr, id="lk_header")
        yield Static("", id="lk_status")
        yield DataTable(id="pkt_table", cursor_type="row", zebra_stripes=True)
        yield Static("Waiting for packets…", id="stats_box")
        yield Footer()

    def on_mount(self) -> None:
        t = self.query_one("#pkt_table", DataTable)
        t.add_column("Time UTC",  width=10)
        t.add_column("RSSI",      width=7)
        t.add_column("SNR",       width=6)
        t.add_column("Margin",    width=8)
        t.add_column("Type",      width=22)
        t.add_column("DevAddr",   width=10)
        t.add_column("FCnt",      width=6)
        t.add_column("Operator",  width=20)
        t.add_column("Flags",     width=6)
        t.add_column("MAC Cmds",  width=50)
        self._scanner.start_lock(
            freq=self._freq, sf=self._sf, freq_hop=self._freq_hop,
            is_downlink=self._is_downlink,
            on_packet=lambda p: self._post_to_ui(self._on_packet, p),
            on_channel=lambda f, s: self._post_to_ui(self._on_channel, f, s),
        )

    def _post_to_ui(self, fn, *args) -> None:
        """Safely schedule a UI update from the scanner thread.
        Guards against NoActiveAppError during app teardown."""
        try:
            self.app.call_from_thread(fn, *args)
        except Exception:
            pass

    # ---- thread callbacks --------------------------------------------------

    def _on_channel(self, freq: int, sf: int) -> None:
        try:
            status = self.query_one("#lk_status", Static)
        except Exception:
            return
        dwell = SF_DWELL[sf]
        if self._is_downlink:
            status.update(f"RX2  {freq/1e6:.3f} MHz  SF{sf}  dwell={dwell}s  IQINVER=1")
        else:
            label = "RX2 check" if (freq == RX2_FREQ and sf == RX2_SF) else "Scanning"
            status.update(
                f"{label}  {freq/1e6:.3f} MHz  SF{sf}  dwell={dwell}s"
                f"  |  RX2 every {self._scanner.rx2_interval} hops  [I]"
            )

    def _on_packet(self, pkt: PacketRecord) -> None:
        try:
            t = self.query_one("#pkt_table", DataTable)
            stats = self.query_one("#stats_box", Static)
        except Exception:
            return  # screen already unmounted
        self._pkts.append(pkt)
        if pkt.dev_addr:
            self._addrs.add(pkt.dev_addr)
            if pkt.fcnt is not None:
                self._fcnt_hist[pkt.dev_addr].append((time.monotonic(), pkt.fcnt))
            if pkt.rssi is not None:
                self._rssi_hist[pkt.dev_addr].append(pkt.rssi)
        if pkt.is_downlink:
            self._downlinks += 1

        flags = []
        if pkt.is_downlink:
            flags.append("DL")

        margin = _link_margin(pkt.rssi, pkt.sf)
        t.add_row(
            pkt.timestamp[11:19],
            str(pkt.rssi) if pkt.rssi is not None else "?",
            str(pkt.snr)  if pkt.snr  is not None else "?",
            f"{margin:+d} dB" if margin is not None else "?",
            (pkt.mtype or "?")[:22],
            pkt.dev_addr or pkt.join_eui or "?",
            str(pkt.fcnt) if pkt.fcnt is not None else "?",
            (pkt.operator or "?")[:20],
            " ".join(flags),
            ", ".join(pkt.mac_commands) if pkt.mac_commands else "",
        )
        t.scroll_end(animate=False)
        self._update_stats(stats)

    def _update_stats(self, stats: Static) -> None:
        gw = "  *** GATEWAY NEARBY! ***" if self._downlinks else ""
        lines = [
            f"Pkts: {len(self._pkts)}   "
            f"Unique DevAddrs: {len(self._addrs)}   "
            f"Downlinks (GW evidence): {self._downlinks}{gw}",
        ]
        for addr in sorted(self._addrs):
            rssi = self._rssi_hist.get(addr, [])
            fcnt = self._fcnt_hist.get(addr, [])
            parts = [f"  {addr}:"]
            if rssi:
                d = max(rssi) - min(rssi)
                motion = "possibly moving" if d > 10 else "likely stationary"
                parts.append(f"RSSI {min(rssi)}…{max(rssi)} dBm  Δ{d} ({motion})")
            if len(fcnt) >= 2:
                t0, f0 = fcnt[0];  t1, f1 = fcnt[-1]
                dt = t1 - t0
                rate = (f1 - f0) / dt * 60 if dt > 0 else 0
                parts.append(f"FCnt {f0}→{f1}  (~{rate:.1f} frames/min)")
            lines.append("   ".join(parts))
        stats.update("\n".join(lines))

    # ---- action ------------------------------------------------------------

    def action_cycle_rx2(self) -> None:
        presets = HardwareScanner.RX2_PRESETS
        cur = self._scanner.rx2_interval
        nxt = presets[(presets.index(cur) + 1) % len(presets)] if cur in presets else presets[0]
        self._scanner.rx2_interval = nxt
        self.notify(f"RX2 check every {nxt} hops", timeout=2)

    def action_back(self) -> None:
        self._scanner.stop()
        self.app.pop_screen()  # on_show on SweepScreen restarts sweep


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
class LoRaTUIApp(App):
    TITLE = "LoRa Passive Recon"
    CSS = """
    Header { height: 1; }
    Footer { height: 1; }
    """

    def __init__(self, unit: LoRaUnit, device_info: str):
        super().__init__()
        self._unit = unit
        self._scanner = HardwareScanner(unit)
        self._device_info = device_info

    def on_mount(self) -> None:
        self.push_screen(SweepScreen(self._scanner, self._device_info))

    def on_unmount(self) -> None:
        self._scanner.stop()
        try:
            self._unit.stop_rx()
            self._unit.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="TUI for passive LoRa recon (M5Stack/RAK3172, EU868)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--port",     default=None, help="Serial port (auto-detected)")
    p.add_argument("--baudrate", type=int, default=115200)
    return p


def main():
    args = build_parser().parse_args()

    port = args.port or auto_detect_port()
    if not port:
        print("ERROR: No serial port found. Use --port.", file=sys.stderr)
        sys.exit(1)

    print(f"Connecting to {port} @ {args.baudrate} baud…", flush=True)
    try:
        unit = LoRaUnit(port, baudrate=args.baudrate)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    if not unit.ping():
        print("ERROR: Device did not respond to AT ping.", file=sys.stderr)
        unit.close()
        sys.exit(1)

    version  = unit.get_version() or "unknown"
    nwm      = unit.get_nwm()
    dev_eui  = unit.get_deveui() if nwm == 1 else "–"
    device_info = f"{version}  DevEUI={dev_eui}"

    if not unit.set_p2p_mode():
        print("ERROR: Could not switch to P2P mode.", file=sys.stderr)
        unit.close()
        sys.exit(1)

    LoRaTUIApp(unit, device_info).run()


if __name__ == "__main__":
    main()
