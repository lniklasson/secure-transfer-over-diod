# secure-transfer-over-diod

Unidirectional log transfer over a data diode (UDP), with a Sender and a Receiver in one script.

**Version:** 21.0.0 · **Requires:** Python 3.7+ (standard library only)

## Features

**Sender**
- Directory scanning with rotation-safe offsets (inode tracking), complete-lines-only and a configurable ignore list
- TCP syslog listener (LF framing and RFC 6587 octet counting, auto-detected)
- Primary + secondary diode streams (redundancy), rate limiting, fragmentation of large messages

**Receiver**
- Deduplication across both diode paths
- Sequence-based estimate of loss on *all* paths (`[LOSS]` / `[STATS]` in the log)
- Fragment reassembly, SIEM forwarding (UDP syslog), mirrored output files

## Quick start

```bash
python3 secure_transfer.py --create-config-file transfer.ini
python3 secure_transfer.py --show-config          # validate the config
python3 secure_transfer.py --sender               # on the sending side
python3 secure_transfer.py --receiver             # on the receiving side
python3 secure_transfer.py --sender --send-test   # send a test message
```

Config precedence: command line > `transfer.ini` > built-in default.
Run `python3 secure_transfer.py --help` for all options and a hardened systemd unit example.

## Packet format (protocol v2)

One JSON object per UDP datagram: `v`, `id`, `src`, `seq`, `file`, `data`, plus optional `part`/`parts` for fragmented messages.
A v2 Receiver accepts v1 packets and raw syslog datagrams. **Upgrade the Receiver before the Sender.**

## Operational notes

- If the diode cannot pass IP fragments, set `max_datagram_size = 1400`.
- On the receiving side, raise `net.core.rmem_max` so that `recv_buffer_bytes` takes effect (the Receiver logs a warning if it is capped).
- Change history is kept in the script header.
