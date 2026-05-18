#!/usr/bin/env python3
"""
LoRa Passive Reconnaissance PoC
M5Stack Unit LoRaWAN-EU868 (RAK3172 / STM32WLE5)

Two-phase passive scanner:
  Phase 1 — SWEEP: cycles through EU868 channels x spreading factors
  Phase 2 — LOCK:  stays on an active combo for deep monitoring
             + periodically parks on RX2 (869.525 MHz / SF12) to catch downlinks

Hardware: M5Stack Unit LoRaWAN-EU868 connected via USB-RS232 adapter
UART defaults: 115200 baud, 8-N-1 (no flow control)

AT command reference: RAK3172 AT Command Manual (firmware ≥ 1.0.4 / RUI3)
Key commands used:
  AT+NWM=0          → switch to P2P (LoRa raw) mode
  AT+PFREQ=<Hz>     → set P2P frequency
  AT+PSF=<7-12>     → set spreading factor
  AT+PBW=<125|250|500> → set bandwidth kHz
  AT+PCR=<0-3>      → coding rate (0=4/5, 1=4/6, 2=4/7, 3=4/8)
  AT+PPL=8          → preamble length
  AT+PRECV=<ms>     → open RX window; 65535 = continuous until packet or timeout
  AT+RSSI=?         → last packet RSSI
  AT+SNR=?          → last packet SNR
Async events from module:
  +EVT:RXP2P,RSSI <x>,SNR <y>
  +EVT:<hex payload>
"""

import serial
import serial.tools.list_ports
import time
import re
import argparse
import logging
import json
import csv
import struct
import threading
import signal
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional
from collections import defaultdict

# ---------------------------------------------------------------------------
# EU868 standard channels + RX2 fixed channel
# ---------------------------------------------------------------------------
EU868_CHANNELS = [868100000, 868300000, 868500000,
                  867100000, 867300000, 867500000, 867700000, 867900000]
RX2_FREQ       = 869525000   # EU868 RX2 fixed frequency
RX2_SF         = 12

SPREADING_FACTORS = [7, 8, 9, 10, 11, 12]

# Recommended dwell time per SF (seconds) — enough to catch one packet airtime
SF_DWELL = {7: 2, 8: 3, 9: 5, 10: 8, 11: 12, 12: 20}

# LoRaWAN MHDR message types (top 3 bits of first byte)
MTYPE = {
    0b000: "Join Request",
    0b001: "Join Accept",
    0b010: "Unconfirmed Data Up",
    0b011: "Unconfirmed Data Down",
    0b100: "Confirmed Data Up",
    0b101: "Confirmed Data Down",
    0b110: "RFU",
    0b111: "Proprietary",
}

# ---------------------------------------------------------------------------
# MAC command (FOpts) parser — LoRaWAN 1.0.x (unencrypted in-band commands)
# ---------------------------------------------------------------------------
_EU868_DR_SF = {0: "SF12", 1: "SF11", 2: "SF10", 3: "SF9",
                4: "SF8",  5: "SF7",  6: "SF7/BW250", 7: "FSK"}
_EU868_TXPOW = {0: 16, 1: 14, 2: 12, 3: 10, 4: 8, 5: 6}  # dBm ERP; 15=keep


def _hz_from_3bytes(b: bytes, offset: int) -> float:
    """3-byte LE frequency field (100 Hz steps) → MHz."""
    raw = b[offset] | (b[offset + 1] << 8) | (b[offset + 2] << 16)
    return raw * 100 / 1e6


def _parse_dl_cmd(cid: int, b: bytes) -> tuple[str, int]:
    """Decode one downlink MAC command. Returns (description, payload_bytes_consumed)."""
    if cid == 0x02:  # LinkCheckAns
        if len(b) < 2: raise ValueError
        return f"LinkCheckAns(margin={b[0]}dB gw={b[1]})", 2
    if cid == 0x03:  # LinkADRReq
        if len(b) < 4: raise ValueError
        dr, txpow = (b[0] >> 4) & 0x0F, b[0] & 0x0F
        mask = b[1] | (b[2] << 8)
        nb, ctrl = b[3] & 0x0F, (b[3] >> 4) & 0x07
        sf = _EU868_DR_SF.get(dr, f"DR{dr}")
        pw = (f"{_EU868_TXPOW[txpow]}dBm" if txpow in _EU868_TXPOW
              else ("keep" if txpow == 15 else f"txpow{txpow}"))
        return f"LinkADRReq({sf} pwr={pw} mask=0x{mask:04X} ctrl={ctrl} ntx={nb})", 4
    if cid == 0x04:  # DutyCycleReq
        if len(b) < 1: raise ValueError
        dc = b[0] & 0x0F
        return f"DutyCycleReq(max={'none' if dc == 0 else f'1/{2**dc}'})", 1
    if cid == 0x05:  # RXParamSetupReq
        if len(b) < 4: raise ValueError
        rx1_off, rx2_dr = (b[0] >> 4) & 0x07, b[0] & 0x0F
        freq = _hz_from_3bytes(b, 1)
        return f"RXParamSetupReq(RX1off={rx1_off} RX2={_EU868_DR_SF.get(rx2_dr, f'DR{rx2_dr}')}@{freq:.3f}MHz)", 4
    if cid == 0x06:  # DevStatusReq
        return "DevStatusReq", 0
    if cid == 0x07:  # NewChannelReq
        if len(b) < 5: raise ValueError
        freq = _hz_from_3bytes(b, 1)
        min_sf = _EU868_DR_SF.get(b[4] & 0x0F, f"DR{b[4] & 0x0F}")
        max_sf = _EU868_DR_SF.get((b[4] >> 4) & 0x0F, f"DR{(b[4] >> 4) & 0x0F}")
        return f"NewChannelReq(ch={b[0]} {freq:.3f}MHz {min_sf}-{max_sf})", 5
    if cid == 0x08:  # RXTimingSetupReq
        if len(b) < 1: raise ValueError
        delay = b[0] & 0x0F
        return f"RXTimingSetupReq(RX1_delay={delay or 1}s)", 1
    if cid == 0x09:  # TxParamSetupReq
        if len(b) < 1: raise ValueError
        _eirp = [8, 10, 12, 13, 14, 16, 18, 20, 21, 24, 26, 27, 29, 30, 33]
        eirp = _eirp[b[0] & 0x0F] if (b[0] & 0x0F) < len(_eirp) else b[0] & 0x0F
        return (f"TxParamSetupReq(maxEIRP={eirp}dBm "
                f"ul_dwell={int(bool(b[0] & 0x10))} dl_dwell={int(bool(b[0] & 0x20))})"), 1
    if cid == 0x0A:  # DlChannelReq
        if len(b) < 4: raise ValueError
        return f"DlChannelReq(ch={b[0]} {_hz_from_3bytes(b, 1):.3f}MHz)", 4
    if cid == 0x0D:  # DeviceTimeAns — GPS seconds; 18 leap-second offset as of 2024
        if len(b) < 5: raise ValueError
        gps_s = struct.unpack_from("<I", b, 0)[0]
        try:
            dt = datetime.fromtimestamp(gps_s + 315964800 - 18,
                                        tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            dt = f"GPS+{gps_s}s"
        return f"DeviceTimeAns({dt} +{b[4]}/256s)", 5
    return f"UnknownDL(0x{cid:02X})", 0


def _parse_ul_cmd(cid: int, b: bytes) -> tuple[str, int]:
    """Decode one uplink MAC command. Returns (description, payload_bytes_consumed)."""
    if cid == 0x02:  # LinkCheckReq
        return "LinkCheckReq", 0
    if cid == 0x03:  # LinkADRAns
        if len(b) < 1: raise ValueError
        s = b[0]
        return (f"LinkADRAns(pwr={'OK' if s & 4 else 'FAIL'} "
                f"dr={'OK' if s & 2 else 'FAIL'} ch={'OK' if s & 1 else 'FAIL'})"), 1
    if cid == 0x04:  # DutyCycleAns
        return "DutyCycleAns", 0
    if cid == 0x05:  # RXParamSetupAns
        if len(b) < 1: raise ValueError
        s = b[0]
        return (f"RXParamSetupAns(rx1_off={'OK' if s & 4 else 'FAIL'} "
                f"rx2_dr={'OK' if s & 2 else 'FAIL'} ch={'OK' if s & 1 else 'FAIL'})"), 1
    if cid == 0x06:  # DevStatusAns
        if len(b) < 2: raise ValueError
        batt = b[0]
        raw = b[1] & 0x3F
        margin = raw if raw < 32 else raw - 64   # 6-bit signed
        if batt == 0:       batt_str = "ext"
        elif batt == 255:   batt_str = "unknown"
        else:               batt_str = f"{round((batt - 1) / 253 * 100)}%"
        return f"DevStatusAns(batt={batt_str} snr_margin={margin}dB)", 2
    if cid == 0x07:  # NewChannelAns
        if len(b) < 1: raise ValueError
        s = b[0]
        return (f"NewChannelAns(dr={'OK' if s & 2 else 'FAIL'} "
                f"ch={'OK' if s & 1 else 'FAIL'})"), 1
    if cid == 0x08:  # RXTimingSetupAns
        return "RXTimingSetupAns", 0
    if cid == 0x09:  # TxParamSetupAns
        return "TxParamSetupAns", 0
    if cid == 0x0A:  # DlChannelAns
        if len(b) < 1: raise ValueError
        s = b[0]
        return (f"DlChannelAns(ul_freq={'OK' if s & 2 else 'FAIL'} "
                f"ch={'OK' if s & 1 else 'FAIL'})"), 1
    if cid == 0x0D:  # DeviceTimeReq
        return "DeviceTimeReq", 0
    return f"UnknownUL(0x{cid:02X})", 0


def parse_fopts(fopts: bytes, is_uplink: bool) -> list[str]:
    """
    Decode LoRaWAN 1.0.x MAC commands from FOpts bytes.
    FOpts are unencrypted in LoRaWAN 1.0.x; returns garbage for 1.1 networks.
    """
    results = []
    i = 0
    _parse = _parse_ul_cmd if is_uplink else _parse_dl_cmd
    while i < len(fopts):
        cid = fopts[i]
        i += 1
        try:
            desc, length = _parse(cid, fopts[i:])
            results.append(desc)
            i += length
            if length == 0 and "Unknown" in desc:
                break  # can't determine payload length for unknown CID
        except (ValueError, IndexError):
            results.append(f"CID=0x{cid:02X}(truncated)")
            break
    return results


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class PacketRecord:
    timestamp:  str
    freq:       int
    sf:         int
    bw:         int
    rssi:       Optional[int]
    snr:        Optional[int]
    raw_hex:    str
    mtype:      Optional[str]  = None
    dev_addr:   Optional[str]  = None
    nwk_id:     Optional[str]  = None
    operator:   Optional[str]  = None
    fcnt:       Optional[int]  = None
    join_eui:   Optional[str]  = None
    dev_eui:    Optional[str]  = None
    is_downlink:  bool               = False   # True if heard on RX2
    mac_commands: Optional[list[str]] = None

    def summary(self) -> str:
        dl  = " [DOWNLINK→GATEWAY EVIDENCE]" if self.is_downlink else ""
        mac = (f"  MAC=[{', '.join(self.mac_commands)}]"
               if self.mac_commands else "")
        addr_part = f"DevAddr={self.dev_addr}" if self.dev_addr else (
            f"JoinEUI={self.join_eui}" if self.join_eui else "DevAddr=?")
        return (f"{self.timestamp}  {self.freq/1e6:.3f}MHz SF{self.sf} BW{self.bw} "
                f"RSSI={self.rssi}dBm SNR={self.snr}dB  "
                f"mtype={self.mtype or '?'}  {addr_part}  "
                f"FCnt={self.fcnt if self.fcnt is not None else '?'}{dl}{mac}")


# ---------------------------------------------------------------------------
# LoRaWAN frame parser (physical layer only — no decryption)
# ---------------------------------------------------------------------------
def parse_lorawan(raw_hex: str) -> dict:
    result = {}
    try:
        data = bytes.fromhex(raw_hex)
        if len(data) < 4:
            return result
        mhdr = data[0]
        mtype_bits = (mhdr >> 5) & 0x07
        result["mtype"] = MTYPE.get(mtype_bits, f"Unknown({mtype_bits})")
        # Data frames have DevAddr at bytes 1-4 (little-endian)
        if mtype_bits in (0b010, 0b011, 0b100, 0b101) and len(data) >= 8:
            dev_addr = struct.unpack_from("<I", data, 1)[0]
            result["dev_addr"] = f"{dev_addr:08X}"
            nwk_id = (dev_addr >> 25) & 0x7F
            result["nwk_id"] = f"0x{nwk_id:02X}"
            if nwk_id == 0x13:
                result["operator_hint"] = "TTN (The Things Network)"
            elif nwk_id == 0x24:
                result["operator_hint"] = "Actility/ThingPark"
            elif nwk_id == 0x00:
                result["operator_hint"] = "Private/ChirpStack"
            else:
                result["operator_hint"] = f"Unknown (NwkID=0x{nwk_id:02X})"
            fctrl = data[5]
            result["fcnt"] = struct.unpack_from("<H", data, 6)[0]
            result["ack"]  = bool(fctrl & 0x20)
            result["adr"]  = bool(fctrl & 0x80)
            fopts_len = fctrl & 0x0F
            if fopts_len > 0 and len(data) >= 8 + fopts_len:
                is_uplink = mtype_bits in (0b010, 0b100)
                cmds = parse_fopts(data[8:8 + fopts_len], is_uplink)
                if cmds:
                    result["mac_commands"] = cmds
        elif mtype_bits == 0b000:   # Join Request
            if len(data) >= 19:
                join_eui = data[1:9][::-1].hex().upper()
                dev_eui  = data[9:17][::-1].hex().upper()
                result["join_eui"] = join_eui
                result["dev_eui"]  = dev_eui
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Serial / AT command interface
# ---------------------------------------------------------------------------
class LoRaUnit:
    def __init__(self, port: str, baudrate: int = 115200, timeout: float = 2.0):
        self.ser = serial.Serial(port, baudrate=baudrate,
                                 bytesize=8, parity='N', stopbits=1,
                                 timeout=timeout)
        self.log = logging.getLogger("LoRaUnit")
        time.sleep(0.5)
        self.ser.reset_input_buffer()

    def close(self):
        try:
            self.ser.close()
        except Exception:
            pass

    def _send(self, cmd: str) -> str:
        """Send AT command, return raw response string."""
        self.ser.reset_input_buffer()
        payload = (cmd + "\r\n").encode()
        self.log.debug(f">>> {cmd}")
        self.ser.write(payload)
        time.sleep(0.05)
        response = self._read_until_status(timeout=3.0)
        self.log.debug(f"<<< {response!r}")
        return response

    def _read_until_status(self, timeout: float = 3.0) -> str:
        """Read lines until OK/ERROR or timeout."""
        lines = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.ser.readline().decode(errors="replace").strip()
            if line:
                lines.append(line)
                if line in ("OK", "AT_ERROR", "AT_PARAM_ERROR",
                            "AT_BUSY_ERROR", "AT_NO_NETWORK_JOINED"):
                    break
        return "\n".join(lines)

    def cmd_ok(self, cmd: str) -> bool:
        return "OK" in self._send(cmd)

    def query(self, cmd: str) -> Optional[str]:
        resp = self._send(cmd)
        # RAK3172 echoes the command first, then replies AT+CMD=<value>\r\nOK
        # Skip the echo (ends with '?') and status lines; extract value after '='
        for line in resp.splitlines():
            if line in ("OK", "AT_ERROR", "AT_PARAM_ERROR", ""):
                continue
            if line.upper().startswith("AT+") and "=" in line:
                value = line.split("=", 1)[1].strip()
                if value and value != "?":   # skip the query echo (AT+CMD=?)
                    return value
            elif not line.startswith("AT"):
                return line.strip()
        return None

    def ping(self) -> bool:
        return self.cmd_ok("AT")

    def get_version(self) -> str:
        return self.query("AT+VER=?") or "unknown"

    def get_deveui(self) -> str:
        return self.query("AT+DEVEUI=?") or "unknown"

    def get_nwm(self) -> Optional[int]:
        """Return current network mode: 0=P2P, 1=LoRaWAN."""
        val = self.query("AT+NWM=?")
        try:
            return int(val)
        except (TypeError, ValueError):
            return None

    def set_p2p_mode(self) -> bool:
        """Switch to raw LoRa P2P mode (AT+NWM=0). Module may reboot."""
        if self.get_nwm() == 0:
            self.log.info("Already in P2P mode.")
            return True
        self.log.info("Switching to P2P mode...")
        self.ser.write(b"AT+NWM=0\r\n")
        time.sleep(2.0)
        self.ser.reset_input_buffer()
        return self.ping()

    def configure_p2p(self, freq: int, sf: int, bw: int = 125,
                       cr: int = 0, preamble: int = 8) -> bool:
        """Set all P2P radio parameters atomically."""
        cmd = f"AT+P2P={freq}:{sf}:{bw}:{cr}:{preamble}:14"
        return self.cmd_ok(cmd)

    def start_rx(self, window_ms: int = 65535) -> bool:
        """Open P2P receive window. 65535 = continuous until packet."""
        return self.cmd_ok(f"AT+PRECV={window_ms}")

    def stop_rx(self) -> bool:
        """Cancel ongoing RX window."""
        return self.cmd_ok("AT+PRECV=0")

    def get_rssi(self) -> Optional[int]:
        val = self.query("AT+RSSI=?")
        try:
            return int(val)
        except (TypeError, ValueError):
            return None

    def get_snr(self) -> Optional[int]:
        val = self.query("AT+SNR=?")
        try:
            return int(val)
        except (TypeError, ValueError):
            return None

    def read_async_events(self, duration: float) -> list[str]:
        """
        Read all unsolicited lines from UART for `duration` seconds.
        Returns list of raw lines (may contain +EVT: events).
        """
        lines = []
        deadline = time.time() + duration
        self.ser.timeout = 0.2
        while time.time() < deadline:
            line = self.ser.readline().decode(errors="replace").strip()
            if line:
                lines.append(line)
                self.log.debug(f"[ASYNC] {line}")
        self.ser.timeout = 2.0
        return lines


# ---------------------------------------------------------------------------
# Event parser
# ---------------------------------------------------------------------------
def parse_events(lines: list[str]) -> list[dict]:
    """
    Parse async UART lines for P2P receive events.
    RAK3172 P2P RX produces two lines:
      +EVT:RXP2P,RSSI <x>,SNR <y>
      +EVT:<hex data>

    Handles edge cases:
      - extra lines between signal and payload lines
      - payload line appearing before signal line (reordering)
      - multiple events in one batch
      - orphan payload lines (no preceding signal line)
    """
    results = []
    # First pass: index all signal lines and payload lines
    signal_lines = {}   # index → (rssi, snr)
    payload_lines = {}  # index → raw_hex

    for i, line in enumerate(lines):
        m = re.match(r'\+EVT:RXP2P,RSSI\s*(-?\d+),SNR\s*(-?\d+)', line, re.I)
        if m:
            signal_lines[i] = (int(m.group(1)), int(m.group(2)))
            continue
        m2 = re.match(r'\+EVT:([0-9A-Fa-f]{4,})$', line.strip())
        if m2:
            payload_lines[i] = m2.group(1).upper()

    # Match each signal line with the nearest subsequent payload line
    used_payloads = set()
    sorted_signals = sorted(signal_lines.keys())
    sorted_payloads = sorted(payload_lines.keys())

    for sig_idx in sorted_signals:
        rssi, snr = signal_lines[sig_idx]
        # Find closest payload after this signal that hasn't been claimed
        best = None
        for pay_idx in sorted_payloads:
            if pay_idx > sig_idx and pay_idx not in used_payloads:
                best = pay_idx
                break
        raw_hex = ""
        if best is not None:
            raw_hex = payload_lines[best]
            used_payloads.add(best)
        results.append({"rssi": rssi, "snr": snr, "raw_hex": raw_hex})

    # Orphan payload lines (payload without a preceding signal)
    for pay_idx in sorted_payloads:
        if pay_idx not in used_payloads:
            results.append({"rssi": None, "snr": None, "raw_hex": payload_lines[pay_idx]})

    return results


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------
class DeduplicationCache:
    """Deduplicate packets by (DevAddr, FCnt) within a time window."""
    def __init__(self, window_seconds: float = 30.0):
        self.window = window_seconds
        self._seen: dict[tuple, float] = {}  # (dev_addr, fcnt) → timestamp

    def is_duplicate(self, dev_addr: Optional[str], fcnt: Optional[int]) -> bool:
        if dev_addr is None or fcnt is None:
            return False
        key = (dev_addr, fcnt)
        now = time.time()
        if key in self._seen and (now - self._seen[key]) < self.window:
            return True
        self._seen[key] = now
        return False

    def purge(self):
        """Remove expired entries."""
        now = time.time()
        self._seen = {k: v for k, v in self._seen.items() if now - v < self.window}


# ---------------------------------------------------------------------------
# Output / logging
# ---------------------------------------------------------------------------
class OutputManager:
    def __init__(self, output_base: Optional[str], use_rich: bool = True, verbose: bool = False):
        self.records: list[PacketRecord] = []
        self.json_path = f"{output_base}.json" if output_base else None
        self.csv_path  = f"{output_base}.csv"  if output_base else None
        self._csv_file = None
        self._csv_writer = None
        self._lock = threading.Lock()
        self.use_rich = use_rich
        self.verbose = verbose

        if use_rich:
            try:
                from rich.console import Console
                self.console = Console()
                self._rich_ok = True
            except ImportError:
                self._rich_ok = False
        else:
            self._rich_ok = False

        if self.csv_path:
            self._csv_file = open(self.csv_path, "w", newline="")
            fieldnames = list(PacketRecord.__dataclass_fields__.keys())
            self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=fieldnames)
            self._csv_writer.writeheader()

    def record(self, pkt: PacketRecord):
        with self._lock:
            self.records.append(pkt)
            self._print_packet(pkt)
            if self._csv_writer:
                row = asdict(pkt)
                if row.get("mac_commands"):
                    row["mac_commands"] = " | ".join(row["mac_commands"])
                self._csv_writer.writerow(row)
                self._csv_file.flush()

    def _print_packet(self, pkt: PacketRecord):
        if self._rich_ok:
            from rich.text import Text
            color = "bright_magenta" if pkt.is_downlink else (
                "bright_green" if pkt.mtype and "Up" in pkt.mtype else "cyan")
            self.console.print(f"[{color}]{pkt.summary()}[/{color}]")
        else:
            print(pkt.summary(), flush=True)

    def status(self, msg: str):
        if self._rich_ok:
            self.console.print(f"[yellow]{msg}[/yellow]")
        else:
            print(f"[STATUS] {msg}", flush=True)

    def info(self, msg: str):
        if self.verbose:
            if self._rich_ok:
                self.console.print(f"[dim]{msg}[/dim]")
            else:
                print(f"[INFO] {msg}", flush=True)

    def save_json(self):
        if self.json_path:
            with open(self.json_path, "w") as f:
                json.dump([asdict(r) for r in self.records], f, indent=2)

    def print_summary(self):
        records = self.records
        active_combos = {(r.freq, r.sf) for r in records}
        unique_addrs  = {r.dev_addr for r in records if r.dev_addr}
        downlinks     = [r for r in records if r.is_downlink]

        # RSSI per device
        rssi_map: dict[str, list[int]] = defaultdict(list)
        for r in records:
            if r.dev_addr and r.rssi is not None:
                rssi_map[r.dev_addr].append(r.rssi)

        # Operator guesses
        operator_map: dict[str, str] = {}
        for r in records:
            if r.dev_addr and r.operator:
                operator_map[r.dev_addr] = r.operator

        lines = [
            "",
            "=" * 60,
            "  RECONNAISSANCE SUMMARY",
            "=" * 60,
            f"  Total packets captured : {len(records)}",
            f"  Active freq/SF combos  : {len(active_combos)}",
        ]
        for freq, sf in sorted(active_combos):
            lines.append(f"    {freq/1e6:.3f} MHz  SF{sf}")

        lines.append(f"  Unique DevAddrs        : {len(unique_addrs)}")
        for addr in sorted(unique_addrs):
            op = operator_map.get(addr, "?")
            rssi_vals = rssi_map.get(addr, [])
            rssi_str = f"RSSI {min(rssi_vals)}…{max(rssi_vals)} dBm" if rssi_vals else ""
            lines.append(f"    {addr}  [{op}]  {rssi_str}")

        lines.append(f"  Gateway downlinks heard: {len(downlinks)}")
        if downlinks:
            lines.append("    *** Gateway confirmed nearby! ***")
        lines.append("=" * 60)

        summary = "\n".join(lines)
        if self._rich_ok:
            self.console.print(summary, style="bold white")
        else:
            print(summary, flush=True)

        if self.json_path:
            self.save_json()
            print(f"JSON log saved to: {self.json_path}", flush=True)
        if self.csv_path:
            print(f"CSV  log saved to: {self.csv_path}", flush=True)

    def close(self):
        if self._csv_file:
            self._csv_file.close()


# ---------------------------------------------------------------------------
# Phase 1 — Sweep Scanner
# ---------------------------------------------------------------------------
class SweepScanner:
    """
    Cycles through all EU868 channel × SF combinations.
    Returns immediately when a packet is heard; caller decides whether to lock.
    """
    def __init__(self, unit: LoRaUnit, output: OutputManager,
                 dedup: DeduplicationCache,
                 rx2_interval: int = 10,
                 stop_event: threading.Event = None):
        self.unit = unit
        self.output = output
        self.dedup = dedup
        self.rx2_interval = rx2_interval      # check RX2 every N channel-hops
        self.stop_event = stop_event or threading.Event()
        self.active_combos: list[tuple[int, int]] = []
        self._hop_count = 0
        self.log = logging.getLogger("Sweep")

    def run(self) -> list[tuple[int, int]]:
        """
        Run one full sweep pass.
        Returns list of (freq, sf) combos where packets were heard THIS pass.
        """
        self.active_combos = []   # reset each pass so caller gets fresh results
        self.output.status("=== Phase 1: SWEEP MODE ===")
        for freq in EU868_CHANNELS:
            for sf in SPREADING_FACTORS:
                if self.stop_event.is_set():
                    return self.active_combos
                self._sweep_one(freq, sf)
                self._hop_count += 1
                if self._hop_count % self.rx2_interval == 0:
                    self._check_rx2()
        return self.active_combos

    def _sweep_one(self, freq: int, sf: int):
        dwell = SF_DWELL[sf]
        self.output.info(f"Sweep {freq/1e6:.3f} MHz SF{sf} dwell={dwell}s")
        if not self.unit.configure_p2p(freq, sf):
            self.log.warning(f"Failed to configure {freq} SF{sf}")
            return
        window_ms = int(dwell * 1000)
        self.unit.start_rx(window_ms)
        lines = self.unit.read_async_events(dwell + 0.5)
        self.unit.stop_rx()

        packets = parse_events(lines)
        for pkt_dict in packets:
            pkt = self._make_record(pkt_dict, freq, sf, is_downlink=False)
            if not self.dedup.is_duplicate(pkt.dev_addr, pkt.fcnt):
                self.output.record(pkt)
                combo = (freq, sf)
                if combo not in self.active_combos:
                    self.active_combos.append(combo)
                    self.output.status(f"  ★ Active combo found: {freq/1e6:.3f} MHz SF{sf}")

    def _check_rx2(self):
        self.output.info(f"RX2 check: {RX2_FREQ/1e6:.3f} MHz SF{RX2_SF}")
        if not self.unit.configure_p2p(RX2_FREQ, RX2_SF):
            return
        dwell = SF_DWELL[RX2_SF]
        self.unit.start_rx(int(dwell * 1000))
        lines = self.unit.read_async_events(dwell + 0.5)
        self.unit.stop_rx()
        for pkt_dict in parse_events(lines):
            pkt = self._make_record(pkt_dict, RX2_FREQ, RX2_SF, is_downlink=True)
            self.output.record(pkt)
            self.output.status("  *** GATEWAY DOWNLINK on RX2! Gateway confirmed nearby! ***")

    @staticmethod
    def _make_record(pkt_dict: dict, freq: int, sf: int, is_downlink: bool) -> PacketRecord:
        raw_hex = pkt_dict.get("raw_hex", "")
        lw = parse_lorawan(raw_hex) if raw_hex else {}
        return PacketRecord(
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            freq=freq,
            sf=sf,
            bw=125,
            rssi=pkt_dict.get("rssi"),
            snr=pkt_dict.get("snr"),
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
# Phase 2 — Lock Monitor
# ---------------------------------------------------------------------------
class LockMonitor:
    """
    Phase 2 deep monitoring. Two modes:
      freq_hop=False  — fixed freq + SF (single-channel lock, original behaviour)
      freq_hop=True   — fixed SF, cycles all 8 EU868 uplink channels each pass;
                        follows mandatory channel-hopping and captures ~8× more packets
    Interleaves RX2 downlink checks in both modes.
    """
    def __init__(self, unit: LoRaUnit, output: OutputManager,
                 dedup: DeduplicationCache,
                 freq: Optional[int], sf: int,
                 freq_hop: bool = False,
                 duration_minutes: float = 10.0,
                 rx2_interval: int = 10,
                 stop_event: threading.Event = None):
        if not freq_hop and freq is None:
            raise ValueError("freq is required when freq_hop=False")
        self.unit = unit
        self.output = output
        self.dedup = dedup
        self.freq = freq
        self.sf = sf
        self.freq_hop = freq_hop
        self.duration = duration_minutes * 60
        self.rx2_interval = rx2_interval
        self.stop_event = stop_event or threading.Event()
        self._cycle = 0
        self.log = logging.getLogger("Lock")

        self._fcnt_history: dict[str, list[tuple[float, int]]] = defaultdict(list)
        self._rssi_history: dict[str, list[int]] = defaultdict(list)

    def run(self):
        if self.freq_hop:
            label = f"SF-HOP MODE SF{self.sf} all EU868 channels"
        else:
            label = f"LOCK MODE {self.freq/1e6:.3f} MHz SF{self.sf}"
        self.output.status(
            f"=== Phase 2: {label} for {self.duration/60:.1f} min ==="
        )
        deadline = time.time() + self.duration
        while time.time() < deadline and not self.stop_event.is_set():
            self._lock_cycle()

        self._report_lock_stats()

    def _lock_cycle(self):
        channels = EU868_CHANNELS if self.freq_hop else [self.freq]
        for freq in channels:
            if self.stop_event.is_set():
                return
            dwell = SF_DWELL[self.sf]
            self.unit.configure_p2p(freq, self.sf)
            self.unit.start_rx(int(dwell * 1000))
            lines = self.unit.read_async_events(dwell + 0.5)
            self.unit.stop_rx()
            for pkt_dict in parse_events(lines):
                pkt = SweepScanner._make_record(pkt_dict, freq, self.sf, is_downlink=False)
                if not self.dedup.is_duplicate(pkt.dev_addr, pkt.fcnt):
                    self.output.record(pkt)
                    if pkt.dev_addr:
                        now = time.time()
                        if pkt.fcnt is not None:
                            self._fcnt_history[pkt.dev_addr].append((now, pkt.fcnt))
                        if pkt.rssi is not None:
                            self._rssi_history[pkt.dev_addr].append(pkt.rssi)

        self._cycle += 1
        if self._cycle % self.rx2_interval == 0:
            self._check_rx2()

    def _check_rx2(self):
        self.output.info(f"RX2 interleave check: {RX2_FREQ/1e6:.3f} MHz SF{RX2_SF}")
        self.unit.configure_p2p(RX2_FREQ, RX2_SF)
        dwell = SF_DWELL[RX2_SF]
        self.unit.start_rx(int(dwell * 1000))
        lines = self.unit.read_async_events(dwell + 0.5)
        self.unit.stop_rx()
        for pkt_dict in parse_events(lines):
            pkt = SweepScanner._make_record(pkt_dict, RX2_FREQ, RX2_SF, is_downlink=True)
            self.output.record(pkt)
            self.output.status("  *** GATEWAY DOWNLINK on RX2! ***")

    def _report_lock_stats(self):
        self.output.status("=== Lock Monitor Stats ===")
        for addr, fcnt_list in self._fcnt_history.items():
            if len(fcnt_list) >= 2:
                t0, f0 = fcnt_list[0]
                t1, f1 = fcnt_list[-1]
                dt = t1 - t0
                df = f1 - f0
                rate = df / dt * 60 if dt > 0 else 0
                self.output.status(
                    f"  {addr}: FCnt {f0}→{f1} ({df} frames in {dt:.0f}s, ~{rate:.1f}/min)")
            rssi_vals = self._rssi_history.get(addr, [])
            if rssi_vals:
                variance = max(rssi_vals) - min(rssi_vals)
                moving = "possibly moving" if variance > 10 else "likely stationary"
                self.output.status(
                    f"  {addr}: RSSI range {min(rssi_vals)}…{max(rssi_vals)} dBm "
                    f"(Δ{variance} dBm → {moving})")


# ---------------------------------------------------------------------------
# Auto port detection
# ---------------------------------------------------------------------------
def auto_detect_port() -> Optional[str]:
    """Pick most likely USB-serial port on Linux."""
    ports = list(serial.tools.list_ports.comports())
    # Prefer ttyUSB*, then ttyACM*, then anything with USB in description
    for p in ports:
        if "ttyUSB" in p.device:
            return p.device
    for p in ports:
        if "ttyACM" in p.device:
            return p.device
    for p in ports:
        if "USB" in (p.description or "").upper():
            return p.device
    if ports:
        return ports[0].device
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Passive LoRa reconnaissance for M5Stack/RAK3172 (EU868)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--port",           default=None,
                   help="Serial port (auto-detected if omitted)")
    p.add_argument("--baudrate",       type=int, default=115200)
    p.add_argument("--sweep-only",     action="store_true",
                   help="Only run Phase 1 sweep, never enter lock mode")
    p.add_argument("--lock-freq",      type=int, default=None,
                   help="Skip sweep, lock on this frequency (Hz)")
    p.add_argument("--freq-hop",       action="store_true",
                   help="Lock mode: hop all EU868 channels at fixed SF (better for tracking devices)")
    p.add_argument("--lock-sf",        type=int, default=7,
                   choices=SPREADING_FACTORS,
                   help="SF for direct lock mode")
    p.add_argument("--lock-duration",  type=float, default=10.0,
                   help="Lock mode duration (minutes)")
    p.add_argument("--rx2-interval",   type=int, default=10,
                   help="Check RX2 downlink channel every N channel-hops")
    p.add_argument("--output",         default=None,
                   help="Base name for output files (e.g. recon_2024 → .json + .csv)")
    p.add_argument("--verbose",        action="store_true")
    p.add_argument("--no-rich",        action="store_true",
                   help="Disable rich terminal output")
    p.add_argument("--dedup-window",   type=float, default=30.0,
                   help="Deduplication window in seconds")
    return p


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = build_parser().parse_args()

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")

    # Auto-detect port
    port = args.port
    if not port:
        port = auto_detect_port()
        if not port:
            print("ERROR: No serial port found. Specify --port.", file=sys.stderr)
            sys.exit(1)
        print(f"Auto-detected port: {port}")

    output = OutputManager(
        output_base=args.output,
        use_rich=not args.no_rich,
        verbose=args.verbose)

    dedup = DeduplicationCache(window_seconds=args.dedup_window)
    stop_event = threading.Event()

    # Graceful Ctrl+C
    unit_ref: list[Optional[LoRaUnit]] = [None]

    def _sigint(sig, frame):
        print("\nInterrupt received — stopping cleanly...", flush=True)
        stop_event.set()
        u = unit_ref[0]
        if u:
            try:
                u.stop_rx()
            except Exception:
                pass

    signal.signal(signal.SIGINT, _sigint)

    try:
        output.status(f"Opening {port} at {args.baudrate} baud...")
        unit = LoRaUnit(port, baudrate=args.baudrate)
        unit_ref[0] = unit

        if not unit.ping():
            print("ERROR: Device did not respond to AT ping.", file=sys.stderr)
            sys.exit(1)

        output.status(f"Device version : {unit.get_version()}")
        # DevEUI query only works in LoRaWAN mode (NWM=1)
        if unit.get_nwm() == 1:
            output.status(f"Device DevEUI  : {unit.get_deveui()}")
        else:
            output.status("Device DevEUI  : (unavailable in P2P mode)")

        if not unit.set_p2p_mode():
            print("ERROR: Could not switch to P2P mode.", file=sys.stderr)
            sys.exit(1)

        # Direct lock mode (skip sweep)
        if args.lock_freq:
            monitor = LockMonitor(
                unit=unit, output=output, dedup=dedup,
                freq=args.lock_freq, sf=args.lock_sf,
                freq_hop=args.freq_hop,
                duration_minutes=args.lock_duration,
                rx2_interval=args.rx2_interval,
                stop_event=stop_event)
            monitor.run()

        elif args.sweep_only:
            scanner = SweepScanner(
                unit=unit, output=output, dedup=dedup,
                rx2_interval=args.rx2_interval,
                stop_event=stop_event)
            # Run sweep passes until interrupted
            pass_num = 0
            while not stop_event.is_set():
                pass_num += 1
                output.status(f"--- Sweep pass #{pass_num} ---")
                scanner.run()
                dedup.purge()

        else:
            # Full two-phase mode
            scanner = SweepScanner(
                unit=unit, output=output, dedup=dedup,
                rx2_interval=args.rx2_interval,
                stop_event=stop_event)
            pass_num = 0
            while not stop_event.is_set():
                pass_num += 1
                output.status(f"--- Sweep pass #{pass_num} ---")
                active = scanner.run()
                dedup.purge()
                if active and not stop_event.is_set():
                    freq, sf = active[0]
                    monitor = LockMonitor(
                        unit=unit, output=output, dedup=dedup,
                        freq=freq, sf=sf,
                        freq_hop=args.freq_hop,
                        duration_minutes=args.lock_duration,
                        rx2_interval=args.rx2_interval,
                        stop_event=stop_event)
                    monitor.run()
                    dedup.purge()

    except serial.SerialException as e:
        print(f"Serial error: {e}", file=sys.stderr)
    finally:
        if unit_ref[0]:
            try:
                unit_ref[0].stop_rx()
                unit_ref[0].close()
            except Exception:
                pass
        output.close()
        output.print_summary()


if __name__ == "__main__":
    main()
