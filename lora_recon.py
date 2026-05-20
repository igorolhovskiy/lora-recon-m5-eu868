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
  AT+PRECV=<ms>     → open RX window; 65534 = continuous until packet or timeout
  AT+SYNCWORD=3444  → LoRaWAN public sync word (default 0x1234 drops all LoRaWAN frames)
  AT+IQINVER=0/1   → IQ polarity: 0=normal (uplinks), 1=inverted (RX2 downlinks)
Async events (RUI3 v4.x single-line format):
  +EVT:RXP2P:<RSSI>:<SNR>:<hex payload>
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

# Class B beacon (EU868): broadcast every 128 s on RX2 frequency at SF9 BW125.
# Beacon PHYPayload is 17 bytes: 2 RFU + 4 Time + 2 CRC1 + 7 GwSpecific + 2 CRC2.
BEACON_FREQ_EU868 = 869525000
BEACON_SF         = 9
BEACON_BW         = 125
BEACON_PERIOD_S   = 128

# LoRa sync words. LoRaWAN public networks use 0x34 (sent as 0x3444 in the
# RAK3172 register field). Meshtastic uses 0x2B (sent as 0x2B44). Private LoRa
# P2P defaults to 0x12.
LORAWAN_SYNCWORD    = "3444"
MESHTASTIC_SYNCWORD = "2B44"

# Meshtastic EU presets. PSK is independent of these RF parameters.
MESHTASTIC_EU_PRESETS = {
    "LongFast":  (869525000, 11, 250),   # default in EU community channels
    "LongSlow":  (869525000, 12, 125),
    "VLongSlow": (869525000, 12, 125),   # different coding rate; same RF tuning
    "MediumFast": (869525000, 9, 250),
    "ShortFast": (869525000, 7, 250),
}

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
# NetID layout (LoRaWAN Backend Spec 1.0, §6.1.4).
# DevAddr layout per Type, most-significant bits first:
#   Type 0:  0         | NwkID(6)  | NwkAddr(25)
#   Type 1:  10        | NwkID(6)  | NwkAddr(24)
#   Type 2:  110       | NwkID(9)  | NwkAddr(20)
#   Type 3:  1110      | NwkID(11) | NwkAddr(17)
#   Type 4:  11110     | NwkID(12) | NwkAddr(15)
#   Type 5:  111110    | NwkID(13) | NwkAddr(13)
#   Type 6:  1111110   | NwkID(15) | NwkAddr(10)
#   Type 7:  11111110  | NwkID(17) | NwkAddr(7)
# ---------------------------------------------------------------------------
_NETID_LAYOUT: dict[int, tuple[int, int]] = {
    0: (6, 25), 1: (6, 24), 2: (9, 20), 3: (11, 17),
    4: (12, 15), 5: (13, 13), 6: (15, 10), 7: (17, 7),
}

# Curated operator names from publicly documented LoRa Alliance NetID
# assignments. Keyed by (NetID type, NwkID). Add more locally as needed —
# the spec allocates up to 17 bits of NwkID so this list will never be
# exhaustive.
NETID_OPERATORS: dict[tuple[int, int], str] = {
    (0, 0x00): "Private / ChirpStack",
    (0, 0x01): "Experimental",
    (0, 0x13): "TTN (The Things Network)",
    (0, 0x24): "Actility / ThingPark",
    (6, 0x0053): "Helium",
}

# Curated OUI database for DevEUI / JoinEUI manufacturer lookup. Supports
# both 24-bit (IEEE OUI) and 36-bit (IEEE MA-S sub-allocation) prefixes;
# longest match wins. All keys are uppercase hex with no separators.
#
# The 70:B3:D5 prefix is IEEE Registration Authority's MA-S block used by
# many small LoRa makers via sub-allocations — see the 9-char entries below.
OUI_VENDORS: dict[str, str] = {
    # 24-bit IEEE OUIs (LoRa-relevant)
    "0004A3": "Microchip",
    "000800": "Multi-Tech Systems",
    "0018B2": "Adeunis",
    "001DC9": "Murata",
    "00250C": "Semtech",
    "0080E1": "STMicroelectronics",
    "247EBD": "Semtech",
    "24E124": "Milesight IoT",
    "58A0CB": "Browan / Compal",
    "7CC525": "Kerlink",
    "A84041": "Dragino",
    "AC1F09": "RAK Wireless",
    # 24-bit IEEE-RA MA-S parent block — note its presence, then fall back to
    # 9-char keys below for finer attribution.
    "70B3D5": "IEEE-RA MA-S (multi-vendor; see 36-bit sub-allocations)",
    # 36-bit IEEE MA-S sub-allocations under 70:B3:D5 (LoRa-relevant)
    "70B3D526": "Adeunis (newer batches)",
    "70B3D538": "Tabs / Browan trackers",
    "70B3D549": "Globalsat",
    "70B3D557": "Sensative",
    "70B3D567": "Tektelic",
    "70B3D580": "Abeeway",
    "70B3D582": "Strega",
    "70B3D588": "Microchip (LoRa modules)",
    "70B3D59B": "Lansitec",
    "70B3D5B0": "Bosch Connected Devices",
    "70B3D5CF": "Dragino (newer)",
    "70B3D5E1": "Sagemcom Energy & Telecom",
}

# ---------------------------------------------------------------------------
# NetID / DevAddr / vendor helpers
# ---------------------------------------------------------------------------
def parse_netid(dev_addr: int) -> tuple[int, int]:
    """
    Decode (NetID type, NwkID) from a 32-bit DevAddr per LoRaWAN spec.

    Type is determined by the count of leading 1-bits (0..7); the bit after
    the run of 1s is always 0. NwkID and NwkAddr widths come from _NETID_LAYOUT.
    """
    da = dev_addr & 0xFFFFFFFF
    netid_type = 0
    for bit in range(31, 23, -1):           # Type 7 has 7 leading 1s, then a 0
        if (da >> bit) & 1:
            netid_type += 1
        else:
            break
    if netid_type > 7:                      # spec defines Type 0..7 only
        netid_type = 7
    nwk_bits, addr_bits = _NETID_LAYOUT[netid_type]
    nwk_id = (da >> addr_bits) & ((1 << nwk_bits) - 1)
    return netid_type, nwk_id


def lookup_operator(netid_type: int, nwk_id: int) -> Optional[str]:
    """Return the operator name for a given (NetID type, NwkID), or None."""
    return NETID_OPERATORS.get((netid_type, nwk_id))


def lookup_vendor(eui: str) -> Optional[str]:
    """
    Best-effort manufacturer lookup for a DevEUI / JoinEUI / MAC.

    Tries progressively shorter prefixes so a 36-bit MA-S sub-allocation wins
    over its parent 24-bit MA-L block. Recognises 24-bit (IEEE OUI), 28-bit
    (IEEE MA-M), 32-bit (common community-DB shorthand within 70:B3:D5), and
    36-bit (IEEE MA-S) prefixes.
    """
    if not eui:
        return None
    e = eui.strip().upper().replace(":", "").replace("-", "")
    for length in (9, 8, 7, 6):
        if len(e) >= length and e[:length] in OUI_VENDORS:
            return OUI_VENDORS[e[:length]]
    return None


def is_multicast_devaddr(dev_addr: int) -> bool:
    """
    LoRaWAN does not strictly bind multicast DevAddrs to a specific range —
    networks assign them via Remote Multicast Setup (TS005). By convention,
    the upper end of the address space (0xFF000000..0xFFFFFFFF) is reserved
    for multicast groups (Class C broadcasts, FUOTA), with 0xFFFFFFFF as
    the broadcast address. This is a heuristic, not a definitive marker.
    """
    return (dev_addr & 0xFFFFFFFF) >= 0xFF000000


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
# Cayenne Low Power Payload (LPP) decoder.
# Format: each measurement is [Channel(1), Type(1), Data(N)]. Useful only on
# private/ChirpStack networks where AppSKey isn't used; on commercial networks
# FRMPayload is AES-128 encrypted and the LPP bytes will look random.
# Spec: https://docs.mydevices.com/docs/lorawan/cayenne-lpp
# ---------------------------------------------------------------------------
_LPP_TYPES: dict[int, tuple[int, str]] = {
    # type → (data_bytes, decoder_label)
    0x00: (1,  "digital_in"),
    0x01: (1,  "digital_out"),
    0x02: (2,  "analog_in"),
    0x03: (2,  "analog_out"),
    0x65: (2,  "illuminance"),
    0x66: (1,  "presence"),
    0x67: (2,  "temperature"),
    0x68: (1,  "humidity"),
    0x71: (6,  "accelerometer"),
    0x73: (2,  "barometer"),
    0x86: (6,  "gyrometer"),
    0x88: (9,  "gps"),
}


def parse_lpp(payload: bytes) -> list[str]:
    """
    Best-effort Cayenne LPP decode. Returns a list of human-readable strings
    like "ch1 temperature=23.5C" / "ch2 humidity=46.5%". Stops at the first
    type byte it doesn't recognise to avoid producing fictional readings
    from random AES-encrypted bytes.
    """
    out: list[str] = []
    i = 0
    while i + 2 <= len(payload):
        ch, typ = payload[i], payload[i + 1]
        i += 2
        spec = _LPP_TYPES.get(typ)
        if not spec:
            break
        size, label = spec
        if i + size > len(payload):
            break
        data = payload[i:i + size]
        i += size
        try:
            if typ == 0x00 or typ == 0x01:
                out.append(f"ch{ch} {label}={data[0]}")
            elif typ == 0x02 or typ == 0x03:                       # signed 0.01 V
                val = struct.unpack(">h", data)[0] / 100.0
                out.append(f"ch{ch} {label}={val:.2f}V")
            elif typ == 0x65:                                      # illuminance, lux
                val = struct.unpack(">H", data)[0]
                out.append(f"ch{ch} {label}={val}lux")
            elif typ == 0x66:
                out.append(f"ch{ch} {label}={data[0]}")
            elif typ == 0x67:                                      # signed 0.1 °C
                val = struct.unpack(">h", data)[0] / 10.0
                out.append(f"ch{ch} {label}={val:.1f}C")
            elif typ == 0x68:                                      # unsigned 0.5 %
                out.append(f"ch{ch} {label}={data[0] / 2.0:.1f}%")
            elif typ == 0x71:                                      # 3 × signed 0.001 g
                x, y, z = struct.unpack(">hhh", data)
                out.append(f"ch{ch} {label}=({x/1000:.3f},{y/1000:.3f},{z/1000:.3f})g")
            elif typ == 0x73:                                      # unsigned 0.1 hPa
                val = struct.unpack(">H", data)[0] / 10.0
                out.append(f"ch{ch} {label}={val:.1f}hPa")
            elif typ == 0x86:                                      # 3 × signed 0.01 °/s
                x, y, z = struct.unpack(">hhh", data)
                out.append(f"ch{ch} {label}=({x/100:.2f},{y/100:.2f},{z/100:.2f})dps")
            elif typ == 0x88:                                      # GPS, 24-bit signed
                lat = int.from_bytes(data[0:3], "big", signed=True) / 10000.0
                lon = int.from_bytes(data[3:6], "big", signed=True) / 10000.0
                alt = int.from_bytes(data[6:9], "big", signed=True) / 100.0
                out.append(f"ch{ch} {label}=({lat:.4f},{lon:.4f},{alt:.2f}m)")
        except (struct.error, ValueError):
            break
    return out


# ---------------------------------------------------------------------------
# Class B beacon frame parser (EU868: 17-byte payload).
# Layout per LoRaWAN v1.0.4 §15.2:
#   RFU(2) | Time(4 LE GPS sec) | CRC1(2) | GwSpecific(7) | CRC2(2)
# We don't verify CRCs — passive recon just notes structural fit.
# ---------------------------------------------------------------------------
def parse_beacon(raw_hex: str) -> dict:
    """Decode a Class B beacon PHYPayload. Returns {} if length is wrong."""
    try:
        data = bytes.fromhex(raw_hex)
    except ValueError:
        return {}
    if len(data) != 17:
        return {}
    gps_seconds = struct.unpack_from("<I", data, 2)[0]
    crc1 = struct.unpack_from("<H", data, 6)[0]
    gw_info = data[8:15]
    crc2 = struct.unpack_from("<H", data, 15)[0]
    info_desc = gw_info[0]
    try:
        utc = datetime.fromtimestamp(gps_seconds + 315964800 - 18,
                                     tz=timezone.utc).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        utc = f"GPS+{gps_seconds}s"
    return {
        "gps_seconds": gps_seconds,
        "utc":         utc,
        "crc1":        crc1,
        "info_desc":   info_desc,
        "gw_info":     gw_info.hex().upper(),
        "crc2":        crc2,
    }


# ---------------------------------------------------------------------------
# Meshtastic packet header parser.
# Layout (LoRa PHY payload, post-FEC, big-endian fields):
#   dest(4) | src(4) | packet_id(4) | flags(1) | channel_hash(1) | next_hop(1) | relay_node(1) | ...
# We decode the first 16 bytes only — anything after is encrypted unless on
# the public PSK with the right channel name.
# ---------------------------------------------------------------------------
def parse_meshtastic(raw_hex: str) -> dict:
    """Parse the unencrypted Meshtastic packet header. Returns {} on short input."""
    try:
        data = bytes.fromhex(raw_hex)
    except ValueError:
        return {}
    if len(data) < 16:
        return {}
    dst = struct.unpack_from("<I", data, 0)[0]
    src = struct.unpack_from("<I", data, 4)[0]
    pid = struct.unpack_from("<I", data, 8)[0]
    flags = data[12]
    hop_limit = flags & 0x07
    want_ack  = bool(flags & 0x08)
    via_mqtt  = bool(flags & 0x10)
    channel_hash = data[13]
    return {
        "src":          f"{src:08X}",
        "dst":          f"{dst:08X}",
        "packet_id":    pid,
        "hop_limit":    hop_limit,
        "want_ack":     want_ack,
        "via_mqtt":     via_mqtt,
        "channel_hash": channel_hash,
    }


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
    netid_type: Optional[int]  = None          # 0..7 per LoRaWAN spec
    operator:   Optional[str]  = None
    fcnt:       Optional[int]  = None
    join_eui:   Optional[str]  = None
    dev_eui:    Optional[str]  = None
    dev_nonce:  Optional[int]  = None          # 16-bit from join request
    join_eui_vendor: Optional[str] = None
    dev_eui_vendor:  Optional[str] = None
    is_downlink:    bool = False               # True if heard on RX2
    is_multicast:   bool = False               # DevAddr in 0xFF000000+ range
    is_beacon:      bool = False               # Class B beacon
    is_meshtastic:  bool = False               # detected via sync word
    is_retransmit:  bool = False               # repeat (DevAddr,FCnt) within window
    replay_alert:   Optional[str] = None       # DevNonce/FCnt anomaly text
    mac_commands:   Optional[list[str]] = None
    lpp_sensors:    Optional[list[str]]  = None   # Cayenne LPP decode (private nets)
    meshtastic:     Optional[dict]       = None   # Meshtastic header fields
    beacon:         Optional[dict]       = None   # Class B beacon decode

    def summary(self) -> str:
        dl  = " [DOWNLINK→GATEWAY EVIDENCE]" if self.is_downlink else ""
        bcn = " [BEACON]" if self.is_beacon else ""
        mc  = " [MULTICAST]" if self.is_multicast else ""
        rt  = " [RETRANSMIT]" if self.is_retransmit else ""
        mt  = " [MESHTASTIC]" if self.is_meshtastic else ""
        mac = (f"  MAC=[{', '.join(self.mac_commands)}]"
               if self.mac_commands else "")
        addr_part = f"DevAddr={self.dev_addr}" if self.dev_addr else (
            f"JoinEUI={self.join_eui}" if self.join_eui else "DevAddr=?")
        return (f"{self.timestamp}  {self.freq/1e6:.3f}MHz SF{self.sf} BW{self.bw} "
                f"RSSI={self.rssi}dBm SNR={self.snr}dB  "
                f"mtype={self.mtype or '?'}  {addr_part}  "
                f"FCnt={self.fcnt if self.fcnt is not None else '?'}"
                f"{dl}{bcn}{mc}{rt}{mt}{mac}")


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
            dev_addr_int = struct.unpack_from("<I", data, 1)[0]
            result["dev_addr"] = f"{dev_addr_int:08X}"
            netid_type, nwk_id_val = parse_netid(dev_addr_int)
            result["netid_type"] = netid_type
            # Keep the legacy 7-bit display form for Type 0 / Type 1 so existing
            # users (and existing tests) keep working; widen for higher types.
            if netid_type <= 1:
                result["nwk_id"] = f"0x{nwk_id_val:02X}"
            else:
                result["nwk_id"] = f"0x{nwk_id_val:0{(_NETID_LAYOUT[netid_type][0] + 3) // 4}X}"
            op = lookup_operator(netid_type, nwk_id_val)
            if op:
                result["operator_hint"] = op
            else:
                # Reconstruct the 24-bit NetID for the LoRa Alliance registry
                # lookup. The registry is at lora-alliance.org/lorawan-for-developers.
                netid_24 = (netid_type << 21) | nwk_id_val
                result["operator_hint"] = (
                    f"Unknown commercial operator "
                    f"(Type {netid_type}, NwkID={result['nwk_id']}, "
                    f"NetID=0x{netid_24:06X}) — look up in LoRa Alliance NetID registry"
                )
            result["is_multicast"] = is_multicast_devaddr(dev_addr_int)
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
            # Best-effort Cayenne LPP decode of FRMPayload on private/ChirpStack
            # uplinks (NwkID 0x00 Type 0). Skipped on other networks because
            # FRMPayload is AES-encrypted by spec.
            is_uplink = mtype_bits in (0b010, 0b100)
            if (is_uplink and netid_type == 0 and nwk_id_val == 0x00
                    and len(data) > 8 + fopts_len + 5):                # MIC(4)+FPort(1)
                frm_start = 8 + fopts_len + 1                          # skip FPort
                frm_end   = len(data) - 4                              # drop MIC
                if frm_end > frm_start:
                    sensors = parse_lpp(data[frm_start:frm_end])
                    if sensors:
                        result["lpp_sensors"] = sensors
        elif mtype_bits == 0b000:   # Join Request
            # MHDR(1) + JoinEUI(8) + DevEUI(8) + DevNonce(2) + MIC(4) = 23
            if len(data) >= 19:
                join_eui = data[1:9][::-1].hex().upper()
                dev_eui  = data[9:17][::-1].hex().upper()
                result["join_eui"] = join_eui
                result["dev_eui"]  = dev_eui
                result["join_eui_vendor"] = lookup_vendor(join_eui)
                result["dev_eui_vendor"]  = lookup_vendor(dev_eui)
            if len(data) >= 19:                                        # DevNonce LE
                result["dev_nonce"] = struct.unpack_from("<H", data, 17)[0]
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

    def set_p2p_mode(self, syncword: str = LORAWAN_SYNCWORD) -> bool:
        """Switch to raw LoRa P2P mode (AT+NWM=0). Module may reboot."""
        if self.get_nwm() != 0:
            self.log.info("Switching to P2P mode...")
            self.ser.write(b"AT+NWM=0\r\n")
            time.sleep(2.0)
            self.ser.reset_input_buffer()
            if not self.ping():
                return False
        # Default P2P sync word (0x1234) and IQ polarity silently discard all
        # LoRaWAN frames at the SX1262 correlator before firmware sees them.
        ok = self.set_syncword(syncword)
        ok = ok and self.cmd_ok("AT+IQINVER=0") # normal IQ for uplinks (default)
        return ok

    def set_syncword(self, syncword: str) -> bool:
        """
        Set the LoRa sync word (4 hex chars). LORAWAN_SYNCWORD for LoRaWAN
        traffic, MESHTASTIC_SYNCWORD for Meshtastic. The default P2P sync word
        of 0x1234 filters out everything we care about.
        """
        return self.cmd_ok(f"AT+SYNCWORD={syncword}")

    def set_iq_inversion(self, inverted: bool) -> bool:
        """Set IQ polarity. Uplinks use normal (False); RX2 downlinks use inverted (True)."""
        return self.cmd_ok(f"AT+IQINVER={1 if inverted else 0}")

    def configure_p2p(self, freq: int, sf: int, bw: int = 125,
                       cr: int = 0, preamble: int = 8) -> bool:
        """Set all P2P radio parameters atomically.

        AT+P2P bandwidth field is an index: 0=125kHz, 1=250kHz, 2=500kHz.
        """
        _BW_IDX = {125: 0, 250: 1, 500: 2}
        cmd = f"AT+P2P={freq}:{sf}:{_BW_IDX[bw]}:{cr}:{preamble}:14"
        return self.cmd_ok(cmd)

    def start_rx(self, window_ms: int = 65534) -> bool:
        """Open P2P receive window.
        65534 = continuous; device listens until a packet arrives or stop_rx() is called.
        Arbitrary ms values exist in the AT spec but are unreliable on RUI3 v4.x —
        always pass the default (65534) and control dwell time via stop_rx()."""
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

    RUI3 v4.x (current) — single-line format:
      +EVT:RXP2P:<RSSI>:<SNR>:<hex payload>

    Legacy format (older firmware) — two lines:
      +EVT:RXP2P,RSSI <x>,SNR <y>
      +EVT:<hex data>

    Both formats are handled. Multiple events per batch are supported.
    """
    results = []
    # First pass: index all signal lines and payload lines
    signal_lines = {}   # index → (rssi, snr)
    payload_lines = {}  # index → raw_hex

    for i, line in enumerate(lines):
        # RUI3 v4.x single-line: +EVT:RXP2P:<RSSI>:<SNR>:<HEX>
        m = re.match(r'\+EVT:RXP2P:(-?\d+):(-?\d+):([0-9A-Fa-f]+)$', line.strip(), re.I)
        if m:
            results.append({
                "rssi": int(m.group(1)),
                "snr":  int(m.group(2)),
                "raw_hex": m.group(3).upper(),
            })
            continue
        # Legacy two-line signal header: +EVT:RXP2P,RSSI <x>,SNR <y>
        m = re.match(r'\+EVT:RXP2P,RSSI\s*(-?\d+),SNR\s*(-?\d+)', line, re.I)
        if m:
            signal_lines[i] = (int(m.group(1)), int(m.group(2)))
            continue
        m2 = re.match(r'\+EVT:([0-9A-Fa-f]{4,})$', line.strip())
        if m2:
            payload_lines[i] = m2.group(1).upper()

    # Match each legacy signal line with the nearest subsequent payload line
    used_payloads = set()
    sorted_signals = sorted(signal_lines.keys())
    sorted_payloads = sorted(payload_lines.keys())

    for sig_idx in sorted_signals:
        rssi, snr = signal_lines[sig_idx]
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

    # Orphan legacy payload lines (payload without a preceding signal)
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
# Retransmission detection
# ---------------------------------------------------------------------------
class RetransmissionTracker:
    """
    Spots repeated (DevAddr, FCnt) within a short retransmit window — a sign
    the device didn't receive an ACK and is re-sending the same confirmed
    frame. Distinct from DeduplicationCache: that one *suppresses* repeats,
    this one *counts* them.
    """
    def __init__(self, window_seconds: float = 5.0):
        self.window = window_seconds
        self._first_seen: dict[tuple, float] = {}
        self._count:      dict[tuple, int]   = {}

    def observe(self, dev_addr: Optional[str], fcnt: Optional[int]) -> int:
        """Record an occurrence. Returns the retry count (0 = first sighting)."""
        if dev_addr is None or fcnt is None:
            return 0
        key = (dev_addr, fcnt)
        now = time.time()
        first = self._first_seen.get(key)
        if first is None or (now - first) > self.window:
            self._first_seen[key] = now
            self._count[key] = 0
            return 0
        self._count[key] += 1
        return self._count[key]

    def purge(self):
        now = time.time()
        self._first_seen = {k: t for k, t in self._first_seen.items()
                            if now - t < self.window}
        self._count = {k: v for k, v in self._count.items() if k in self._first_seen}


# ---------------------------------------------------------------------------
# Replay / anomaly tracker — persists across runs via a JSON sidecar.
# Detects two LoRaWAN security smells:
#   1. (DevEUI, DevNonce) collision → potential join-replay attack or stack reset
#   2. FCnt that decreased or jumped back to 0 for a known DevAddr → ABP reset
#      or DevNonce/DevAddr reuse
# ---------------------------------------------------------------------------
class ReplayTracker:
    def __init__(self, state_path: Optional[str] = None):
        self.state_path = state_path
        # dev_eui → list[dev_nonce]
        self.nonces: dict[str, list[int]] = defaultdict(list)
        # dev_addr → highest FCnt seen
        self.fcnt_max: dict[str, int] = {}
        if state_path:
            self._load()

    def _load(self):
        try:
            with open(self.state_path, "r") as f:
                state = json.load(f)
            for dev_eui, nonces in state.get("nonces", {}).items():
                self.nonces[dev_eui] = list(nonces)
            self.fcnt_max = {k: int(v) for k, v in state.get("fcnt_max", {}).items()}
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass

    def save(self):
        if not self.state_path:
            return
        try:
            with open(self.state_path, "w") as f:
                json.dump({"nonces": dict(self.nonces), "fcnt_max": self.fcnt_max},
                          f, indent=2)
        except OSError:
            pass

    def check_join(self, dev_eui: Optional[str], dev_nonce: Optional[int]) -> Optional[str]:
        """Returns an alert string when DevNonce is a repeat for this DevEUI."""
        if not dev_eui or dev_nonce is None:
            return None
        history = self.nonces[dev_eui]
        alert = None
        if dev_nonce in history:
            alert = (f"DevNonce 0x{dev_nonce:04X} repeated for DevEUI {dev_eui} "
                     f"(seen {history.count(dev_nonce) + 1}× total) — "
                     f"possible replay or device reset")
        history.append(dev_nonce)
        return alert

    def check_fcnt(self, dev_addr: Optional[str], fcnt: Optional[int]) -> Optional[str]:
        """Returns an alert when FCnt decreased / reset for a known DevAddr."""
        if not dev_addr or fcnt is None:
            return None
        prev = self.fcnt_max.get(dev_addr)
        alert = None
        if prev is not None and fcnt < prev:
            alert = (f"FCnt regression for {dev_addr}: {prev} → {fcnt} "
                     f"(device reset, ABP rejoin, or counter manipulation)")
        if prev is None or fcnt > prev:
            self.fcnt_max[dev_addr] = fcnt
        return alert


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
                # Flatten list/dict fields so the CSV stays single-cell per column
                if row.get("mac_commands"):
                    row["mac_commands"] = " | ".join(row["mac_commands"])
                if row.get("lpp_sensors"):
                    row["lpp_sensors"] = " | ".join(row["lpp_sensors"])
                for k in ("beacon", "meshtastic"):
                    if row.get(k):
                        row[k] = json.dumps(row[k], separators=(",", ":"))
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
                 stop_event: threading.Event = None,
                 beacon_interval: int = 0,
                 replay_tracker: Optional["ReplayTracker"] = None):
        self.unit = unit
        self.output = output
        self.dedup = dedup
        self.rx2_interval = rx2_interval      # check RX2 every N channel-hops
        self.beacon_interval = beacon_interval  # 0 disables; N>0 checks every N hops
        self.replay_tracker = replay_tracker
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
                if (self.beacon_interval > 0
                        and self._hop_count % self.beacon_interval == 0):
                    self._check_beacon()
        return self.active_combos

    def _sweep_one(self, freq: int, sf: int):
        dwell = SF_DWELL[sf]
        self.output.info(f"Sweep {freq/1e6:.3f} MHz SF{sf} dwell={dwell}s")
        if not self.unit.configure_p2p(freq, sf):
            self.log.warning(f"Failed to configure {freq} SF{sf}")
            return
        self.unit.start_rx()
        lines = self.unit.read_async_events(dwell + 0.5)
        self.unit.stop_rx()

        packets = parse_events(lines)
        for pkt_dict in packets:
            pkt = self._make_record(pkt_dict, freq, sf, is_downlink=False)
            self._annotate_replay(pkt)
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
        self.unit.set_iq_inversion(True)   # downlinks use inverted IQ
        dwell = SF_DWELL[RX2_SF]
        self.unit.start_rx()
        lines = self.unit.read_async_events(dwell + 0.5)
        self.unit.stop_rx()
        self.unit.set_iq_inversion(False)  # restore normal IQ for uplinks
        for pkt_dict in parse_events(lines):
            pkt = self._make_record(pkt_dict, RX2_FREQ, RX2_SF, is_downlink=True)
            self.output.record(pkt)
            self.output.status("  *** GATEWAY DOWNLINK on RX2! Gateway confirmed nearby! ***")

    def _check_beacon(self):
        """Listen for a Class B beacon on 869.525 MHz / SF9 / BW125 for one slot."""
        self.output.info(f"Beacon check: {BEACON_FREQ_EU868/1e6:.3f} MHz SF{BEACON_SF}")
        if not self.unit.configure_p2p(BEACON_FREQ_EU868, BEACON_SF, bw=BEACON_BW):
            return
        # Beacons use the normal LoRaWAN public sync word and non-inverted IQ.
        dwell = SF_DWELL.get(BEACON_SF, 5)
        self.unit.start_rx()
        lines = self.unit.read_async_events(dwell + 0.5)
        self.unit.stop_rx()
        for pkt_dict in parse_events(lines):
            raw = pkt_dict.get("raw_hex", "")
            if len(raw) // 2 == 17:                                    # beacon PHY length
                pkt = self._make_record(pkt_dict, BEACON_FREQ_EU868,
                                        BEACON_SF, is_downlink=True,
                                        is_beacon=True)
                self.output.record(pkt)
                self.output.status("  ♢ CLASS B BEACON heard — gateway is time-synchronised")

    def _annotate_replay(self, pkt: PacketRecord) -> None:
        """If a ReplayTracker is wired up, set pkt.replay_alert on anomalies."""
        if not self.replay_tracker:
            return
        if pkt.dev_eui and pkt.dev_nonce is not None:
            alert = self.replay_tracker.check_join(pkt.dev_eui, pkt.dev_nonce)
            if alert:
                pkt.replay_alert = alert
                self.output.status(f"  ! REPLAY ALERT: {alert}")
        if pkt.dev_addr and pkt.fcnt is not None:
            alert = self.replay_tracker.check_fcnt(pkt.dev_addr, pkt.fcnt)
            if alert:
                pkt.replay_alert = alert
                self.output.status(f"  ! FCNT ANOMALY: {alert}")

    @staticmethod
    def _make_record(pkt_dict: dict, freq: int, sf: int, is_downlink: bool,
                     bw: int = 125, is_beacon: bool = False,
                     is_meshtastic: bool = False) -> PacketRecord:
        raw_hex = pkt_dict.get("raw_hex", "")
        if is_meshtastic:
            mesh = parse_meshtastic(raw_hex) if raw_hex else {}
            return PacketRecord(
                timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                freq=freq, sf=sf, bw=bw,
                rssi=pkt_dict.get("rssi"),
                snr=pkt_dict.get("snr"),
                raw_hex=raw_hex,
                mtype="Meshtastic",
                is_downlink=is_downlink,
                is_meshtastic=True,
                meshtastic=mesh or None,
            )
        if is_beacon:
            bcn = parse_beacon(raw_hex) if raw_hex else {}
            return PacketRecord(
                timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                freq=freq, sf=sf, bw=bw,
                rssi=pkt_dict.get("rssi"),
                snr=pkt_dict.get("snr"),
                raw_hex=raw_hex,
                mtype="Class B Beacon",
                is_downlink=True,
                is_beacon=True,
                beacon=bcn or None,
            )
        lw = parse_lorawan(raw_hex) if raw_hex else {}
        return PacketRecord(
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            freq=freq,
            sf=sf,
            bw=bw,
            rssi=pkt_dict.get("rssi"),
            snr=pkt_dict.get("snr"),
            raw_hex=raw_hex,
            mtype=lw.get("mtype"),
            dev_addr=lw.get("dev_addr"),
            nwk_id=lw.get("nwk_id"),
            netid_type=lw.get("netid_type"),
            operator=lw.get("operator_hint"),
            fcnt=lw.get("fcnt"),
            join_eui=lw.get("join_eui"),
            dev_eui=lw.get("dev_eui"),
            dev_nonce=lw.get("dev_nonce"),
            join_eui_vendor=lw.get("join_eui_vendor"),
            dev_eui_vendor=lw.get("dev_eui_vendor"),
            is_downlink=is_downlink,
            is_multicast=lw.get("is_multicast", False),
            mac_commands=lw.get("mac_commands"),
            lpp_sensors=lw.get("lpp_sensors"),
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
                 stop_event: threading.Event = None,
                 retransmit_tracker: Optional[RetransmissionTracker] = None,
                 replay_tracker: Optional[ReplayTracker] = None,
                 beacon_interval: int = 0):
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
        self.beacon_interval = beacon_interval
        self.stop_event = stop_event or threading.Event()
        self.retransmit_tracker = retransmit_tracker or RetransmissionTracker()
        self.replay_tracker = replay_tracker
        self._cycle = 0
        self.log = logging.getLogger("Lock")

        self._fcnt_history: dict[str, list[tuple[float, int]]] = defaultdict(list)
        self._rssi_history: dict[str, list[int]] = defaultdict(list)
        self._retransmit_counts: dict[str, int] = defaultdict(int)

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
            self.unit.start_rx()
            lines = self.unit.read_async_events(dwell + 0.5)
            self.unit.stop_rx()
            for pkt_dict in parse_events(lines):
                pkt = SweepScanner._make_record(pkt_dict, freq, self.sf, is_downlink=False)
                self._annotate_retransmit_and_replay(pkt)
                if not self.dedup.is_duplicate(pkt.dev_addr, pkt.fcnt):
                    self.output.record(pkt)
                    if pkt.dev_addr:
                        now = time.time()
                        if pkt.fcnt is not None:
                            self._fcnt_history[pkt.dev_addr].append((now, pkt.fcnt))
                        if pkt.rssi is not None:
                            self._rssi_history[pkt.dev_addr].append(pkt.rssi)
                elif pkt.is_retransmit and pkt.dev_addr:
                    # log retransmissions even if dedup would suppress them
                    self.output.info(f"Retransmit #{self._retransmit_counts[pkt.dev_addr]} "
                                     f"of {pkt.dev_addr} FCnt={pkt.fcnt}")

        self._cycle += 1
        if self._cycle % self.rx2_interval == 0:
            self._check_rx2()
        if (self.beacon_interval > 0
                and self._cycle % self.beacon_interval == 0):
            self._check_beacon()

    def _annotate_retransmit_and_replay(self, pkt: PacketRecord) -> None:
        if pkt.dev_addr and pkt.fcnt is not None:
            retry = self.retransmit_tracker.observe(pkt.dev_addr, pkt.fcnt)
            if retry > 0:
                pkt.is_retransmit = True
                self._retransmit_counts[pkt.dev_addr] = retry
        if not self.replay_tracker:
            return
        if pkt.dev_addr and pkt.fcnt is not None:
            alert = self.replay_tracker.check_fcnt(pkt.dev_addr, pkt.fcnt)
            if alert:
                pkt.replay_alert = alert
                self.output.status(f"  ! FCNT ANOMALY: {alert}")
        if pkt.dev_eui and pkt.dev_nonce is not None:
            alert = self.replay_tracker.check_join(pkt.dev_eui, pkt.dev_nonce)
            if alert:
                pkt.replay_alert = alert
                self.output.status(f"  ! REPLAY ALERT: {alert}")

    def _check_beacon(self):
        self.output.info(f"Beacon check: {BEACON_FREQ_EU868/1e6:.3f} MHz SF{BEACON_SF}")
        if not self.unit.configure_p2p(BEACON_FREQ_EU868, BEACON_SF, bw=BEACON_BW):
            return
        dwell = SF_DWELL.get(BEACON_SF, 5)
        self.unit.start_rx()
        lines = self.unit.read_async_events(dwell + 0.5)
        self.unit.stop_rx()
        for pkt_dict in parse_events(lines):
            raw = pkt_dict.get("raw_hex", "")
            if len(raw) // 2 == 17:
                pkt = SweepScanner._make_record(pkt_dict, BEACON_FREQ_EU868,
                                                BEACON_SF, is_downlink=True,
                                                is_beacon=True)
                self.output.record(pkt)
                self.output.status("  ♢ CLASS B BEACON heard")

    def _check_rx2(self):
        self.output.info(f"RX2 interleave check: {RX2_FREQ/1e6:.3f} MHz SF{RX2_SF}")
        self.unit.configure_p2p(RX2_FREQ, RX2_SF)
        self.unit.set_iq_inversion(True)   # downlinks use inverted IQ
        dwell = SF_DWELL[RX2_SF]
        self.unit.start_rx()
        lines = self.unit.read_async_events(dwell + 0.5)
        self.unit.stop_rx()
        self.unit.set_iq_inversion(False)  # restore normal IQ for uplinks
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
            retries = self._retransmit_counts.get(addr, 0)
            if retries > 0:
                self.output.status(
                    f"  {addr}: {retries} retransmission(s) — no ACK received "
                    f"or link is at the edge of coverage")


# ---------------------------------------------------------------------------
# Meshtastic monitor (different sync word + RF preset). Single-channel by
# design — Meshtastic uses one fixed primary channel per region/preset.
# ---------------------------------------------------------------------------
class MeshtasticScanner:
    def __init__(self, unit: LoRaUnit, output: OutputManager,
                 preset: str = "LongFast",
                 stop_event: threading.Event = None):
        if preset not in MESHTASTIC_EU_PRESETS:
            raise ValueError(f"unknown Meshtastic preset {preset!r}")
        self.unit = unit
        self.output = output
        self.freq, self.sf, self.bw = MESHTASTIC_EU_PRESETS[preset]
        self.preset = preset
        self.stop_event = stop_event or threading.Event()
        self.log = logging.getLogger("Meshtastic")

    def run(self):
        self.output.status(
            f"=== MESHTASTIC MODE ({self.preset}: {self.freq/1e6:.3f} MHz "
            f"SF{self.sf} BW{self.bw}) ===")
        if not self.unit.set_syncword(MESHTASTIC_SYNCWORD):
            self.output.status("WARNING: could not set Meshtastic sync word")
        self.unit.configure_p2p(self.freq, self.sf, bw=self.bw)
        self.unit.set_iq_inversion(False)
        dwell = max(SF_DWELL.get(self.sf, 5), 4)
        try:
            while not self.stop_event.is_set():
                self.unit.start_rx()
                lines = self.unit.read_async_events(dwell + 0.5)
                self.unit.stop_rx()
                for pkt_dict in parse_events(lines):
                    pkt = SweepScanner._make_record(
                        pkt_dict, self.freq, self.sf, is_downlink=False,
                        bw=self.bw, is_meshtastic=True)
                    self.output.record(pkt)
        finally:
            # Restore the LoRaWAN sync word so the next module user isn't deaf
            self.unit.set_syncword(LORAWAN_SYNCWORD)


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
    p.add_argument("--beacon-interval", type=int, default=0,
                   help="Class B beacon check interval in sweep/lock cycles (0=disabled)")
    p.add_argument("--meshtastic",      action="store_true",
                   help="Listen for Meshtastic traffic (sync 0x2B) on EU LongFast preset "
                        "(869.525 MHz SF11 BW250) instead of LoRaWAN scanning")
    p.add_argument("--meshtastic-preset", default="LongFast",
                   choices=list(MESHTASTIC_EU_PRESETS.keys()),
                   help="Meshtastic EU preset (freq/SF/BW)")
    p.add_argument("--replay-state",   default=None,
                   help="JSON sidecar to persist DevNonce/FCnt history across runs "
                        "for replay/anomaly detection")
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
    replay_tracker = (ReplayTracker(args.replay_state)
                      if args.replay_state else None)
    retransmit_tracker = RetransmissionTracker()
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

        # Meshtastic mode is mutually exclusive with LoRaWAN sweep/lock
        if args.meshtastic:
            scanner = MeshtasticScanner(
                unit=unit, output=output,
                preset=args.meshtastic_preset,
                stop_event=stop_event)
            scanner.run()

        # Direct lock mode (skip sweep)
        elif args.lock_freq:
            monitor = LockMonitor(
                unit=unit, output=output, dedup=dedup,
                freq=args.lock_freq, sf=args.lock_sf,
                freq_hop=args.freq_hop,
                duration_minutes=args.lock_duration,
                rx2_interval=args.rx2_interval,
                beacon_interval=args.beacon_interval,
                retransmit_tracker=retransmit_tracker,
                replay_tracker=replay_tracker,
                stop_event=stop_event)
            monitor.run()

        elif args.sweep_only:
            scanner = SweepScanner(
                unit=unit, output=output, dedup=dedup,
                rx2_interval=args.rx2_interval,
                beacon_interval=args.beacon_interval,
                replay_tracker=replay_tracker,
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
                beacon_interval=args.beacon_interval,
                replay_tracker=replay_tracker,
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
                        beacon_interval=args.beacon_interval,
                        retransmit_tracker=retransmit_tracker,
                        replay_tracker=replay_tracker,
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
        if replay_tracker:
            replay_tracker.save()


if __name__ == "__main__":
    main()
