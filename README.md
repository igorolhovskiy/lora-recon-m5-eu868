# LoRa Passive Reconnaissance

Passive two-phase scanner for EU868 LoRa / LoRaWAN traffic using an M5Stack Unit LoRaWAN-EU868 (RAK3172 / STM32WLE5) connected over USB. No transmission, no association — listen only.

Two interfaces are provided:
- **`lora_recon.py`** — headless CLI, logs packets to console/JSON/CSV
- **`lora_tui.py`** — interactive Textual TUI with a live sweep table and per-combo packet monitor

## Hardware

- M5Stack Unit LoRaWAN-EU868 (RAK3172 module, firmware RUI3 ≥ 1.0.4)
- USB-RS232 adapter connecting the unit's UART to your host
- EU868 antenna

The module is auto-detected by scanning for known RAK3172 USB VID/PIDs. Pass `--port` explicitly if auto-detection misses it.

### Serial port permissions (Linux)

```bash
sudo usermod -aG dialout $USER
# log out and back in, or: newgrp dialout
```

## Installation

```bash
git clone <repo>
cd Lora-recon
python -m venv venv
source venv/bin/activate          # fish: source venv/bin/activate.fish
pip install pyserial rich textual pytest pytest-asyncio
```

## CLI usage — `lora_recon.py`

```
python lora_recon.py [options]
```

| Option | Default | Description |
|---|---|---|
| `--port` | auto | Serial port (`/dev/ttyUSB0`, etc.) |
| `--baudrate` | 115200 | UART baud rate |
| `--sweep-only` | off | Phase 1 only — never enter lock mode |
| `--lock-freq HZ` | — | Skip sweep, lock directly on this frequency |
| `--lock-sf SF` | 7 | Spreading factor for direct lock (7–12) |
| `--lock-duration MIN` | 10.0 | How long to stay in lock mode (minutes) |
| `--rx2-interval N` | 10 | Check RX2 downlink channel every N hops |
| `--output BASENAME` | — | Save results to `BASENAME.json` + `BASENAME.csv` |
| `--dedup-window SEC` | 30.0 | Suppress duplicate `(DevAddr, FCnt)` within this window |
| `--verbose` | off | Debug-level logging |
| `--no-rich` | off | Plain text output (useful for piping) |

### Examples

```bash
# Auto-detect port, full sweep then lock
python lora_recon.py

# Save to files
python lora_recon.py --output recon_$(date +%F)

# Sweep only, no lock phase
python lora_recon.py --sweep-only

# Jump straight to a known active combo
python lora_recon.py --lock-freq 868100000 --lock-sf 7 --lock-duration 30
```

### Two-phase operation

**Phase 1 — Sweep**: Cycles all 48 EU868 channel × SF combinations (8 channels × SF 7–12). Every N hops it briefly parks on the RX2 downlink channel (869.525 MHz / SF12) to detect gateway traffic — a packet there is strong evidence of a nearby gateway. Any combo that receives a packet is flagged active and queued for Phase 2.

**Phase 2 — Lock**: Stays on the first active combo for `--lock-duration` minutes, collecting packets and periodically checking RX2 for downlinks. Tracks per-device FCnt rate and RSSI.

### Dwell times

The scanner listens on each combination for a fixed dwell period before moving on. Dwell times are set per spreading factor:

| SF | Dwell | Approx max packet airtime |
|---|---|---|
| SF7 | 2 s | ~0.05–0.13 s |
| SF8 | 3 s | ~0.10–0.25 s |
| SF9 | 5 s | ~0.19–0.50 s |
| SF10 | 8 s | ~0.37–1.0 s |
| SF11 | 12 s | ~0.75–2.0 s |
| SF12 | 20 s | ~1.5–4.0 s |

Higher SFs use longer symbols, so packets take longer to transmit. The dwell values are conservative multiples of max airtime (~3–5×) to ensure that even a packet that started transmitting before the scanner arrived can still be decoded from its tail.

One full sweep pass takes 50 s × 8 channels = **~400 s (≈ 6.7 minutes)**. Increasing dwell times improves the per-visit catch probability but lengthens the cycle proportionally, reducing how often each combo is revisited. EU868 nodes are limited to 1% duty cycle, so most devices transmit infrequently; the scanner relies on visiting each combo many times across multiple passes.

If you already know which combo is active, skip the sweep entirely with `--lock-freq` + `--lock-sf` rather than increasing global dwell times.

## TUI usage — `lora_tui.py`

```bash
python lora_tui.py [--port /dev/ttyUSB0] [--baudrate 115200]
```

The TUI launches directly into the sweep view — no further arguments needed.

### Sweep view

A live 48-row table (one row per frequency × SF combination). Columns:

| Column | Meaning |
|---|---|
| Freq | Channel frequency in MHz |
| SF | Spreading factor (7–12) |
| Pkts | Total packets received |
| Last RSSI | Signal strength of most recent packet (dBm) |
| Last SNR | Signal-to-noise ratio (dB) |
| Last seen | Timestamp of most recent packet |

**Controls:**

| Key | Action |
|---|---|
| ↑ / ↓ | Navigate rows |
| Enter | Lock onto selected combination |
| R | Reset all statistics |
| Q | Quit |

### Lock view

Opens when you press Enter on a row (or automatically when sweep finds activity). Displays a scrolling packet log table and a live statistics panel (packet count, unique DevAddrs, FCnt rate, RSSI range).

**Controls:**

| Key | Action |
|---|---|
| Esc | Return to sweep view |
| Q | Quit |

## Understanding the output

### Packet fields

| Field | Notes |
|---|---|
| `rssi` | Received signal strength in dBm. −80 or better = strong nearby device |
| `snr` | Signal-to-noise ratio in dB. Positive = good |
| `mtype` | LoRaWAN message type decoded from MHDR (Unconfirmed Data Up, Join Request, …) |
| `dev_addr` | 4-byte DevAddr in hex (present on data frames, absent on join requests) |
| `nwk_id` | Upper 7 bits of DevAddr — identifies the network operator |
| `operator` | Best-effort operator guess from NwkID |
| `fcnt` | Frame counter (uplinks only) — gaps indicate missed packets |
| `is_downlink` | True for packets received on RX2 (gateway → device) |

### Operator guesses from NwkID

| NwkID | Operator |
|---|---|
| 0x00 | Private / unknown |
| 0x13 (19) | The Things Network |
| 0x24 (36) | Actility / ThingPark |

Other values indicate other commercial or private networks.

### RX2 downlink activity

A packet captured on 869.525 MHz / SF12 is a confirmed downlink from a LoRaWAN gateway. Seeing downlinks means a gateway is within range even if you have not yet caught any uplinks.

## Running tests

```bash
source venv/bin/activate
pytest                        # all tests
pytest test_lora_recon.py     # headless logic only (fast, no hardware)
pytest test_lora_tui.py       # TUI tests (headless Textual pilot)
pytest -k TestHardwareScanner # single class
```

All tests mock the serial port — no hardware required.

## File overview

| File | Purpose |
|---|---|
| `lora_recon.py` | Core logic: AT driver, parser, sweep/lock engines, CLI |
| `lora_tui.py` | Textual TUI wrapping `lora_recon` |
| `test_lora_recon.py` | Unit tests for core logic |
| `test_lora_tui.py` | Unit + integration tests for TUI |
| `pytest.ini` | `asyncio_mode = auto` for pytest-asyncio |
| `CLAUDE.md` | Developer notes for Claude Code |
