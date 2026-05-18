# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Environment

All Python work requires the local virtual environment:

```bash
source .pyproject/bin/activate          # activate
python -m pip install pyserial rich textual pytest pytest-asyncio  # if rebuilding
```

The venv lives at `./.pyproject/` and must be activated before any `python` or `pytest` call. Python 3.11+ is required (3.12 is in use).

## Commands

```bash
# Run all tests (no hardware needed — serial I/O is fully mocked)
source .pyproject/bin/activate && python -m pytest

# Run a single test file
python -m pytest test_lora_recon.py -v
python -m pytest test_lora_tui.py -v

# Run a single test by name
python -m pytest test_lora_recon.py::TestParseEvents::test_multiple_events -v
python -m pytest test_lora_tui.py::test_enter_pushes_lock_screen -v

# Run the CLI recon tool against hardware
python lora_recon.py --port /dev/ttyUSB0 --sweep-only --verbose
python lora_recon.py --port /dev/ttyUSB0 --output recon_$(date +%Y%m%d)

# Run the TUI
python lora_tui.py --port /dev/ttyUSB0
```

Hardware port is `/dev/ttyUSB0`; user must be in the `dialout` group. `pytest.ini` sets `asyncio_mode = auto` so `@pytest.mark.asyncio` is not needed on individual tests.

## Architecture

### Two entry points

| File | Purpose |
|---|---|
| `lora_recon.py` | Headless CLI: sweep + lock + JSON/CSV output |
| `lora_tui.py` | Textual TUI wrapping the same hardware logic |

`lora_tui.py` imports from `lora_recon.py` but replaces the `OutputManager` / `SweepScanner` / `LockMonitor` classes with its own `HardwareScanner` that uses callbacks instead of blocking loops.

### lora_recon.py layers

```
AT serial layer      LoRaUnit           raw AT commands over pyserial
Frame parsing        parse_lorawan()    physical-layer LoRaWAN decode (no crypto)
Event parsing        parse_events()     unsolicited UART line parser (+EVT:…)
Deduplication        DeduplicationCache (DevAddr, FCnt) time-window filter
Scan logic           SweepScanner       Phase 1 — 8 channels × 6 SFs
                     LockMonitor        Phase 2 — fixed combo + RX2 interleave
Output               OutputManager      rich/plain console + JSON + CSV
```

The module reboots on `AT+NWM=0` (P2P mode switch), so `set_p2p_mode()` sleeps 2 s and pings. `AT+DEVEUI=?` only works in LoRaWAN mode (NWM=1) — always query it before calling `set_p2p_mode()`.

### lora_tui.py layers

```
HardwareScanner      Thin wrapper around LoRaUnit; runs sweep or lock in a
                     background daemon thread; reports via callbacks
                     (called from thread → use call_from_thread to touch UI)

SweepScreen          Textual Screen; 48-row DataTable (all EU868 freq×SF combos);
                     on_data_table_row_selected fires when Enter pressed on a row

LockScreen           Textual Screen; packet log table + live stats panel;
                     Escape pops screen → on_show on SweepScreen restarts sweep
```

**Thread → UI boundary**: all scanner callbacks (`on_channel`, `on_packet`) wrap the real UI call in `self.app.call_from_thread(method, *args)`. The screen methods (`_on_channel`, `_on_packet`) must guard against a `NoMatches` exception because the scanner thread may fire one last callback just as the test context or app is shutting down.

### EU868 parameters (constants in lora_recon.py)

- 8 standard channels: 868.1, 868.3, 868.5, 867.1–867.9 MHz
- Spreading factors: SF7–SF12; dwell times `SF_DWELL` = {7:2s … 12:20s}
- RX2 fixed channel: 869.525 MHz / SF12 (gateway downlink evidence)
- BW=125 kHz, CR=4/5 throughout

### Testing notes

- All tests mock `serial.Serial`; no hardware required.
- Async (Textual) tests use `app.run_test(size=(120,40))` as an async context manager with a `Pilot`.
- To test UI callbacks without timing races, stop the background scanner first (`app._scanner.stop()`), then call `screen._on_channel(...)` / `screen._on_packet(...)` directly.
- `SF_DWELL` is patched to 20 ms in async tests via `patch.dict(lora_recon.SF_DWELL, FAST_DWELL)` (autouse fixture `fast_dwell_fixture`).
- DataTable needs focus before Enter fires `RowSelected`: use `await pilot.click("#sw_table")` before `await pilot.press("enter")`.
