#!/usr/bin/env python3
"""
TUI interface for lora_recon — passive LoRa reconnaissance.

Usage:
    python lora_tui.py [--port /dev/ttyUSB0] [--baudrate 115200]

Controls — Sweep view:
    ↑ ↓     Navigate channel/SF rows
    Enter   Lock onto selected combination (SF-hop mode)
    L       Lock onto selected combination (single-channel mode)
    R       Reset statistics
    I       Cycle RX2 check interval
    Q       Quit

Controls — Lock view:
    Enter   Open packet detail screen for selected packet
    Esc     Return to sweep
    I       Cycle RX2 check interval
    Q       Quit

Controls — Packet detail view:
    ← →     Navigate between captured packets
    Esc     Return to lock view
    Q       Quit
"""

import argparse
import math
import os
import re
import subprocess
import sys
import time
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional, Callable

from textual.app import App, ComposeResult
from textual.containers import VerticalScroll
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

_EU868_CHANNEL_NAMES = {
    868100000: "EU868 CH1", 868300000: "EU868 CH2", 868500000: "EU868 CH3",
    867100000: "EU868 CH4", 867300000: "EU868 CH5", 867500000: "EU868 CH6",
    867700000: "EU868 CH7", 867900000: "EU868 CH8",
    869525000: "RX2 fixed channel",
}

_SF_BIT_RATE = {7: "5.47 kbps", 8: "3.13 kbps", 9: "1.76 kbps",
                10: "0.98 kbps", 11: "0.54 kbps", 12: "0.29 kbps"}


def _strip_markup(text: str) -> str:
    """Remove Rich markup tags so clipboard text is plain."""
    return re.sub(r'\[/?[^\[\]]*\]', '', text)


def _copy_to_clipboard(text: str) -> str:
    """
    Write text to the system clipboard. Returns "" on success, or an
    install-hint string on failure.

    Textual's built-in copy_to_clipboard() sends an OSC 52 escape sequence
    which many terminal emulators ignore; shelling out is more reliable.

    - macOS  : pbcopy
    - Windows: clip  (stdin must be UTF-16 LE with BOM — clip.exe's native encoding)
    - Linux  : wl-copy (Wayland) → xclip → xsel (X11)
    """
    if sys.platform == "darwin":
        candidates: list[tuple[list[str], str]] = [(["pbcopy"], "utf-8")]
        missing_hint = "pbcopy not found (unexpected on macOS)"
    elif sys.platform == "win32":
        candidates = [(["clip"], "utf-16")]   # clip.exe expects UTF-16 LE + BOM
        missing_hint = "clip not found (unexpected on Windows)"
    else:
        cmds: list[list[str]] = []
        if os.environ.get("WAYLAND_DISPLAY"):
            cmds.append(["wl-copy"])
        if os.environ.get("DISPLAY"):
            cmds += [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
        if not cmds:
            cmds = [["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
        candidates = [(cmd, "utf-8") for cmd in cmds]
        missing_hint = "install wl-clipboard (Wayland) or xclip / xsel (X11)"

    for cmd, enc in candidates:
        try:
            subprocess.run(cmd, input=text.encode(enc), check=True,
                           capture_output=True, timeout=2)
            return ""
        except (FileNotFoundError, subprocess.SubprocessError, OSError):
            continue
    return missing_hint


def _link_margin(rssi: Optional[int], sf: int) -> Optional[int]:
    """Return RSSI minus the SF sensitivity floor, or None if RSSI is unknown."""
    if rssi is None:
        return None
    return rssi - SF_SENSITIVITY[sf]


# ---------------------------------------------------------------------------
# Packet detail helpers
# ---------------------------------------------------------------------------

def _lorawan_airtime_ms(payload_bytes: int, sf: int, bw_khz: int = 125) -> float:
    """Estimate LoRaWAN packet airtime in ms (Semtech formula, CR=4/5, explicit header, CRC on)."""
    de = 1 if (sf >= 11 and bw_khz == 125) else 0  # low data rate optimisation
    t_sym = (2 ** sf) / (bw_khz * 1000)
    t_preamble = (8 + 4.25) * t_sym
    n_payload = 8 + max(
        math.ceil((8 * payload_bytes - 4 * sf + 28 + 16) / (4 * (sf - 2 * de))) * 5, 0
    )
    return (t_preamble + n_payload * t_sym) * 1000


def _format_packet_detail(pkt: PacketRecord) -> str:
    """Return Rich-formatted detail + recon analysis text for a PacketRecord."""
    lines: list[str] = []
    lw = parse_lorawan(pkt.raw_hex) if pkt.raw_hex else {}

    def section(title: str) -> None:
        pad = "━" * max(0, 50 - len(title))
        lines.append(f"\n[bold cyan]━━━ {title} {pad}[/bold cyan]")

    def row(key: str, val: str, note: str = "") -> None:
        note_s = f"  [dim]{note}[/dim]" if note else ""
        lines.append(f"  [bold]{key:<22}[/bold] {val}{note_s}")

    # ── RF Layer ─────────────────────────────────────────────────────────────
    section("RF LAYER")
    row("Frequency", f"{pkt.freq / 1e6:.3f} MHz", _EU868_CHANNEL_NAMES.get(pkt.freq, ""))
    row("Spreading factor", f"SF{pkt.sf}", _SF_BIT_RATE.get(pkt.sf, ""))
    row("Bandwidth / CR", f"{pkt.bw} kHz / 4/5")
    row("IQ polarity", "inverted  (downlink)" if pkt.is_downlink else "normal  (uplink)")
    if pkt.rssi is not None:
        floor = SF_SENSITIVITY[pkt.sf]
        margin = _link_margin(pkt.rssi, pkt.sf)
        row("RSSI", f"{pkt.rssi} dBm", f"SF{pkt.sf} sensitivity floor: {floor} dBm")
        if pkt.snr is not None:
            snr_note = ("above noise floor" if pkt.snr >= 0
                        else "below noise floor — spread-spectrum FEC active")
            row("SNR", f"{pkt.snr} dB", snr_note)
        if margin is not None:
            if margin >= 20:
                m_note = "very strong — device likely within tens to ~200 m"
            elif margin >= 10:
                m_note = "strong — probably within a few hundred metres"
            elif margin >= 0:
                m_note = "marginal — device at range or obstructed"
            else:
                m_note = "weak — at noise floor; FEC is working hard"
            row("Link margin", f"{margin:+d} dB", m_note)
    if pkt.raw_hex:
        pl = len(pkt.raw_hex) // 2
        airtime = _lorawan_airtime_ms(pl, pkt.sf)
        duty = airtime / 36000  # % of 1% EU868 per-hour budget
        row("Frame length", f"{pl} bytes")
        row("Est. airtime", f"~{airtime:.0f} ms",
            f"uses ~{duty:.3f}% of the 1% EU868 duty-cycle budget")

    # ── LoRaWAN Frame ────────────────────────────────────────────────────────
    section("LORAWAN FRAME")
    row("Captured at", pkt.timestamp)
    if pkt.raw_hex:
        display_hex = pkt.raw_hex if len(pkt.raw_hex) <= 60 else pkt.raw_hex[:60] + "…"
        row("Raw hex", display_hex)
        row("MHDR byte", f"0x{pkt.raw_hex[:2]}")
    mtype = pkt.mtype or "unknown"
    direction = "↓ Network → Device (via gateway)" if pkt.is_downlink else "↑ Device → Network"
    mtype_col = ("bright_magenta" if pkt.is_downlink
                 else ("bright_green" if "Up" in mtype else "cyan"))
    lines.append(f"  [bold]{'Message type':<22}[/bold] [{mtype_col}]{mtype}[/{mtype_col}]")
    row("Direction", direction)

    if pkt.dev_addr:
        row("DevAddr", pkt.dev_addr,
            "32-bit address — assigned at join (OTAA) or provisioned (ABP)")
        if pkt.nwk_id:
            row("NwkID", pkt.nwk_id, "upper 7 bits of DevAddr — identifies operator network")
        if pkt.operator:
            row("Operator hint", pkt.operator)
        if pkt.fcnt is not None:
            fcnt_note = ""
            if pkt.fcnt < 10:
                fcnt_note = "very low — device just joined or was reset"
            elif pkt.fcnt > 60000:
                fcnt_note = "high — long-running device or ABP provisioning"
            row("FCnt (frame ctr)", str(pkt.fcnt), fcnt_note)
        adr = lw.get("adr")
        ack = lw.get("ack")
        if adr is not None:
            row("ADR flag", "ON" if adr else "OFF",
                "network manages SF/TX power" if adr else "device uses fixed parameters")
        if ack is not None:
            row("ACK flag", "ON" if ack else "OFF",
                "acknowledging a previous confirmed frame" if ack else "")

    elif pkt.join_eui or pkt.dev_eui:
        if pkt.join_eui:
            row("JoinEUI / AppEUI", pkt.join_eui,
                "identifies the application / network server")
        if pkt.dev_eui:
            row("DevEUI", pkt.dev_eui,
                "globally unique device ID (like a MAC address)")
            row("DevEUI OUI", pkt.dev_eui[:6],
                "first 3 bytes — IEEE-registered manufacturer/vendor (lookup at ieee.org)")

    if pkt.mac_commands:
        section("MAC COMMANDS (FOpts)")
        for cmd in pkt.mac_commands:
            lines.append(f"  [yellow]▸[/yellow]  {cmd}")

    # ── Recon Analysis ───────────────────────────────────────────────────────
    section("RECONNAISSANCE ANALYSIS")
    _add_recon_notes(pkt, lw, lines)

    return "\n".join(lines)


def _add_recon_notes(pkt: PacketRecord, lw: dict, lines: list[str]) -> None:
    """Append reconnaissance analysis bullet points to lines."""

    def note(text: str, col: str = "white") -> None:
        lines.append(f"  [bold {col}]▸[/bold {col}]  {text}")

    mtype = pkt.mtype or ""

    if pkt.is_downlink:
        note("Active gateway confirmed — this downlink was heard on RX2 (869.525 MHz / SF12).",
             "bright_magenta")
        note("Downlinks originate from a gateway, not from the end device.", "bright_magenta")
        note("The gateway is likely within 1–3 km outdoors or in the same building.", "white")
        if pkt.mac_commands:
            note("MAC commands present → network server is actively controlling this device.",
                 "yellow")
        return

    if "Join Request" in mtype:
        note("OTAA join attempt — device is requesting to join a LoRaWAN network.", "yellow")
        note("Join Request frames are NOT encrypted — DevEUI and JoinEUI are plaintext.",
             "bright_red")
        note("DevEUI is globally unique; the OUI (first 3 bytes) can identify the manufacturer.",
             "white")
        note("EU868 OTAA: device will try all 8 channels in sequence — watch other channels.",
             "white")
        note("If a Join Accept appears on RX2 (869.525 MHz / SF12) shortly after, join succeeded.",
             "white")
        return

    if "Join Accept" in mtype:
        note("Network accepted the join — device is being activated (OTAA).", "yellow")
        note("Join Accept is AES-128 encrypted — DevAddr and session keys are not visible.", "dim")
        note("Heard on RX2 → confirms an active gateway is nearby.", "bright_magenta")
        return

    if "Up" in mtype:
        note("Regular uplink: device is sending sensor/application data to the network.",
             "bright_green")
        note("Payload is AES-128 encrypted — content is not recoverable without the AppSKey.",
             "dim")
        if pkt.fcnt is not None:
            if pkt.fcnt < 10:
                note(f"Low FCnt ({pkt.fcnt}): device recently joined (OTAA) or reset / "
                     f"factory-provisioned (ABP).", "yellow")
            elif pkt.fcnt > 60000:
                note(f"High FCnt ({pkt.fcnt}): device has been running a long time without "
                     f"reset — possibly critical infrastructure.", "white")
        if lw.get("adr"):
            note("ADR ON: network server is actively managing SF and TX power for this device.",
                 "white")
        if lw.get("ack"):
            note("ACK set: confirming a previous confirmed downlink → bidirectional link active.",
                 "white")
        if pkt.mac_commands:
            note("MAC commands in uplink → device is responding to network configuration requests.",
                 "yellow")
        if pkt.operator:
            note(f"Operator hint: {pkt.operator}.", "white")

    elif "Down" in mtype:
        note("Downlink data frame: network server is sending data/commands to the device.",
             "bright_magenta")
        note("Downlink presence confirms an active gateway is within range.", "bright_magenta")

    elif "Proprietary" in mtype or "RFU" in mtype:
        note("Non-standard LoRaWAN frame — possibly a vendor-specific or private protocol.",
             "yellow")
        note("Some IoT devices (alarm panels, asset trackers, custom sensors) use proprietary "
             "LoRa framing.", "white")
        note("Raw payload may be decodable if the vendor protocol specification is known.", "white")

    else:
        note("Frame type not recognised — may be a malformed frame or non-LoRaWAN LoRa packet.",
             "dim")

    if pkt.rssi is not None:
        margin = _link_margin(pkt.rssi, pkt.sf)
        if margin is not None:
            if margin >= 20:
                note("Very strong link margin → device is probably close "
                     "(< 200 m or same building).", "bright_green")
            elif margin < 0:
                note("Signal below sensitivity floor — decoded by LoRa FEC; "
                     "device is at the range limit.", "yellow")
        if pkt.rssi > -60:
            note("Exceptionally high RSSI — consider a directional antenna to locate the device.",
                 "white")


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
    _rx_overhead = 0.5                 # extra seconds after dwell for command latency; patch to 0 in tests

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
        deadline = time.monotonic() + dwell + self._rx_overhead
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
        Binding("c", "copy",             "Copy row",       show=True),
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

    def action_copy(self) -> None:
        t = self.query_one("#sw_table", DataTable)
        idx = t.cursor_row
        if 0 <= idx < len(ALL_COMBOS):
            freq, sf = ALL_COMBOS[idx]
        elif idx == len(ALL_COMBOS):
            freq, sf = RX2_FREQ, RX2_SF
        else:
            return
        s = self._state[(freq, sf)]
        margin_str = f"{s['margin']:+d} dB" if s['margin'] is not None else "—"
        text = (
            f"Freq: {freq/1e6:.3f} MHz  SF: SF{sf}\n"
            f"Pkts: {s['pkts']}  RSSI: {s['rssi']} dBm  SNR: {s['snr']} dB  Margin: {margin_str}\n"
            f"DevAddr: {s['addr']}  Last seen: {s['ts']}"
        )
        err = _copy_to_clipboard(text)
        if err:
            self.notify(f"Clipboard failed — {err}", severity="error", timeout=5)
        else:
            self.notify("Row copied to clipboard", timeout=2)

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
        Binding("c",      "copy",       "Copy packet",    show=True),
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

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Enter on a packet row: push PacketDetailScreen for that packet."""
        idx = event.cursor_row
        if 0 <= idx < len(self._pkts):
            self.app.push_screen(PacketDetailScreen(self._pkts, idx))

    # ---- action ------------------------------------------------------------

    def action_copy(self) -> None:
        t = self.query_one("#pkt_table", DataTable)
        idx = t.cursor_row
        if 0 <= idx < len(self._pkts):
            err = _copy_to_clipboard(_strip_markup(_format_packet_detail(self._pkts[idx])))
            if err:
                self.notify(f"Clipboard failed — {err}", severity="error", timeout=5)
            else:
                self.notify("Packet detail copied to clipboard", timeout=2)

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
# Packet Detail Screen
# ---------------------------------------------------------------------------
class PacketDetailScreen(Screen):
    """Full decode + reconnaissance analysis for a single captured packet."""

    CSS = """
    PacketDetailScreen {
        layout: vertical;
    }
    #pd_header {
        height: 1;
        background: $accent-darken-2;
        color: $text;
        padding: 0 1;
    }
    #pd_scroll {
        height: 1fr;
    }
    #pd_body {
        padding: 1 2;
    }
    """

    BINDINGS = [
        Binding("escape", "back",     "Back to lock",   show=True),
        Binding("left",   "prev_pkt", "← Prev packet",  show=True),
        Binding("right",  "next_pkt", "→ Next packet",  show=True),
        Binding("c",      "copy",     "Copy detail",    show=True),
        Binding("q",      "app.quit", "Quit",           show=True),
    ]

    def __init__(self, pkts: list[PacketRecord], idx: int):
        super().__init__()
        self._pkts = pkts
        self._idx = idx

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", id="pd_header")
        yield VerticalScroll(
            Static("", id="pd_body"),
            id="pd_scroll",
        )
        yield Footer()

    def on_mount(self) -> None:
        self._refresh_detail()

    def _refresh_detail(self) -> None:
        if not self._pkts:
            return
        pkt = self._pkts[self._idx]
        try:
            self.query_one("#pd_header", Static).update(
                f"Packet {self._idx + 1} of {len(self._pkts)}"
                f"  —  {pkt.timestamp}"
                f"  |  ← → navigate  |  [Esc] back to lock"
            )
            self.query_one("#pd_body", Static).update(_format_packet_detail(pkt))
            self.query_one("#pd_scroll", VerticalScroll).scroll_home(animate=False)
        except Exception:
            pass

    def action_copy(self) -> None:
        if not self._pkts:
            return
        err = _copy_to_clipboard(_strip_markup(_format_packet_detail(self._pkts[self._idx])))
        if err:
            self.notify(f"Clipboard failed — {err}", severity="error", timeout=5)
        else:
            self.notify("Copied to clipboard", timeout=2)

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_prev_pkt(self) -> None:
        if self._idx > 0:
            self._idx -= 1
            self._refresh_detail()

    def action_next_pkt(self) -> None:
        if self._idx < len(self._pkts) - 1:
            self._idx += 1
            self._refresh_detail()


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
