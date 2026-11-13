#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
Script Name   : secure_transfer.py
Description   : Combined Sender and Receiver for unidirectional (data diode)
                log transfer over UDP, with dual-diode redundancy,
                deduplication, sequence-based loss detection, fragmentation
                and reassembly of large messages, rotation-safe directory
                scanning, TCP syslog intake (LF and RFC 6587 octet-counting),
                SIEM forwarding and mirrored file output.
Author        : Enterprise Security Team
Version       : 21.0.0
Date          : 2026-11-13
Requires      : Python 3.7+ (standard library only)
-------------------------------------------------------------------------------
Change Log:
  21.0.0  2026-11-13
    Fixed
      - Directory scanner sent incomplete trailing lines (file still being
        written) and advanced the offset past them -> split events. Only
        complete lines are sent now; a trailing partial line is sent after
        'partial_line_timeout' seconds without modification.
      - Log rotation (rename + new file) caused either data loss (new file
        larger than old offset) or full re-send of the renamed file. State is
        now tracked per inode, and offsets follow renamed files.
      - Directory scanner blocked the asyncio loop on large files, starving
        the TCP listener. Scanner now yields regularly.
      - Packets larger than the UDP maximum were silently lost (EMSGSIZE).
        Messages are now fragmented to 'max_datagram_size' and reassembled
        by the Receiver.
      - Non-UTF-8 bytes were silently dropped (errors="ignore"). Payloads are
        now transported losslessly (surrogateescape).
      - A failed send to the primary diode skipped the secondary diode.
      - TCP lines over 64 KiB killed the connection (asyncio limit).
      - Receiver stripped leading spaces from payloads; only trailing
        CR/LF/NUL are removed now.
      - Receiver crashed on JSON that was not an object.
      - Receiver output file name sanitising allowed '.'/'..' names.
      - "Swap-file ignore" was documented but not implemented; now handled
        through configurable 'ignore_patterns'.
      - Log file was force-rotated on every start (only one backup kept),
        losing history during systemd restart loops.
      - Sender with no enabled inputs exited immediately (restart loop);
        now a configuration error.
      - argparse prefix abbreviation made e.g. '-Send' ambiguous; disabled.
      - '-Helg' typo; '-Help' added (old alias kept).
    Added
      - Sequence numbers per sender session; Receiver estimates packets lost
        on BOTH diode paths and logs gaps.
      - Periodic statistics in both modes ('stats_interval').
      - Rate limiting on the Sender ('max_packets_per_second').
      - RFC 6587 octet-counting framing on the TCP listener (auto-detect).
      - 'listen_address' for both modes, 'state_file' CLI flag.
      - Graceful shutdown on SIGTERM/SIGINT (state saved, files closed).
      - WARNING+ log messages also go to stderr (visible in journald).
      - Config precedence documented and unified: CLI > INI > default.
      - INI inline comments ('key = value  # comment') supported.
      - '-CreateConfigFile' refuses to overwrite unless '-Force' is given.
      - Config file is also searched next to the script.
      - ANSI colours only when stdout is a TTY.
      - Hardened systemd unit example (non-root user, sandboxing).
    Changed
      - Config handling refactored into a single schema (no duplication
        between -ShowConfig and run mode). -ShowConfig now also validates.
      - Receiver -SendTest sends a raw syslog line (same format as real
        forwarding) instead of a JSON packet.
      - Packet format v2 (adds v/src/seq and optional part/parts). The v2
        Receiver accepts v1 packets. Upgrade the Receiver first.
  20.0.0  2026-09-16
      - Combined Sender/Receiver, enable/disable flags, dual diodes, INI
        configuration, -ShowConfig with systemd status, mirrored file
        output, debug logging, log rotation.
===============================================================================
"""

import argparse
import asyncio
import configparser
import fnmatch
import json
import logging
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid
from collections import OrderedDict
from logging.handlers import RotatingFileHandler

SCRIPT_VERSION = "21.0.0"
PROTOCOL_VERSION = 2

DEFAULT_CONFIG_NAME = "transfer.ini"
UDP_MAX_DATAGRAM = 65507          # IPv4 UDP payload maximum
MIN_DATAGRAM_SIZE = 512
TCP_STREAM_LIMIT = 1024 * 1024    # max bytes for a single TCP syslog message
MAX_PENDING_LINE = 1024 * 1024    # max bytes buffered for a line without LF
SCANNER_YIELD_EVERY = 200         # lines between event-loop yields
STATE_SAVE_EVERY = 1000           # lines between state checkpoints

USE_COLOR = sys.stdout.isatty()
COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_RESET = "\033[0m"


def colorize(text, color):
    return f"{color}{text}{COLOR_RESET}" if USE_COLOR else text


# ============================================================================
# CONFIGURATION
# ============================================================================
DEFAULT_CONFIG = """# secure_transfer.py configuration (v21)
# Precedence: command line > this file > built-in default.
# Inline comments are allowed:  key = value   # comment

[SENDER]
# --- INPUT: DIRECTORY SCAN ---
# Enable (true) or disable (false) scanning the input directory for log files
input_dir_enabled = true
# Directory where log files to be sent are placed (not recursive)
input_dir = ./sender_input
# State file with per-file offsets (prevents re-sending after restart)
state_file = ./sender_state.json
# Comma-separated glob patterns for files to ignore (swap/temp/compressed)
ignore_patterns = .*, *.swp, *.swo, *.swx, *~, *.tmp, *.part, *.json, *.gz, *.bz2, *.xz, *.zip
# Seconds between directory scans
scan_interval = 5
# A trailing line without newline is sent once the file has been unchanged
# for this many seconds
partial_line_timeout = 60

# --- INPUT: TCP SYSLOG LISTENER ---
# Enable (true) or disable (false) the TCP syslog listener
tcp_listener_enabled = true
# Address to bind the TCP listener to (0.0.0.0 = all interfaces)
listen_address = 0.0.0.0
# TCP port for incoming syslog (LF framing or RFC 6587 octet counting)
listening_port = 50666

# --- OUTPUT: DATA DIODE STREAMS ---
# Enable (true) or disable (false) the primary data diode stream
primary_enabled = true
primary_ip = 192.168.1.100
primary_port = 50666

# Enable (true) or disable (false) the secondary (redundant) diode stream
secondary_enabled = true
secondary_ip = 192.168.1.98
secondary_port = 50666

# Max UDP datagram size in bytes (512-65507). Larger messages are fragmented
# and reassembled by the Receiver. Use ~1400 if the diode cannot pass
# IP fragments.
max_datagram_size = 65000
# Max datagrams per second per stream (0 = unlimited). Protects the diode
# and the Receiver socket buffer from bursts when large files are dropped in.
max_packets_per_second = 0

# --- INTERNAL LOGGING ---
log_file = sender.log
# INFO or DEBUG
log_level = INFO
# Number of rotated log files to keep (100 MB each)
log_backup_count = 5
# Seconds between statistics log lines (0 = disabled)
stats_interval = 60


[RECEIVER]
# --- INPUT: DATA DIODE ---
# Address to bind the UDP listener to (0.0.0.0 = all interfaces)
listen_address = 0.0.0.0
# UDP port for incoming data diode streams
listening_port = 50666
# Requested socket receive buffer in bytes. Linux caps this at
# net.core.rmem_max - raise it with sysctl if needed.
recv_buffer_bytes = 8388608
# Number of message IDs remembered for duplicate detection
dedup_capacity = 200000

# --- OUTPUT: SIEM FORWARDING (UDP syslog) ---
# Enable (true) or disable (false) forwarding deduplicated logs to the SIEM
siem_forward_enabled = true
siem_ip = 192.168.1.98
siem_port = 50666

# --- OUTPUT: LOCAL FILE STORAGE ---
# Enable (true) or disable (false) writing received logs to mirrored files
output_dir_enabled = true
output_dir = ./receiver_output

# --- INTERNAL LOGGING ---
log_file = receiver.log
# INFO or DEBUG
log_level = INFO
# Number of rotated log files to keep (100 MB each)
log_backup_count = 5
# Seconds between statistics log lines (0 = disabled)
stats_interval = 60
"""

DEFAULT_IGNORE = [".*", "*.swp", "*.swo", "*.swx", "*~", "*.tmp", "*.part",
                  "*.json", "*.gz", "*.bz2", "*.xz", "*.zip"]

# key -> (type, default)
CONFIG_SCHEMA = {
    "SENDER": OrderedDict([
        ("input_dir_enabled", ("bool", True)),
        ("input_dir", ("str", "./sender_input")),
        ("state_file", ("str", "./sender_state.json")),
        ("ignore_patterns", ("list", DEFAULT_IGNORE)),
        ("scan_interval", ("float", 5.0)),
        ("partial_line_timeout", ("int", 60)),
        ("tcp_listener_enabled", ("bool", True)),
        ("listen_address", ("str", "0.0.0.0")),
        ("listening_port", ("int", 50666)),
        ("primary_enabled", ("bool", True)),
        ("primary_ip", ("str", None)),
        ("primary_port", ("int", 50666)),
        ("secondary_enabled", ("bool", True)),
        ("secondary_ip", ("str", None)),
        ("secondary_port", ("int", 50666)),
        ("max_datagram_size", ("int", 65000)),
        ("max_packets_per_second", ("int", 0)),
        ("log_file", ("str", "sender.log")),
        ("log_level", ("str", "INFO")),
        ("log_backup_count", ("int", 5)),
        ("stats_interval", ("int", 60)),
    ]),
    "RECEIVER": OrderedDict([
        ("listen_address", ("str", "0.0.0.0")),
        ("listening_port", ("int", 50666)),
        ("recv_buffer_bytes", ("int", 8 * 1024 * 1024)),
        ("dedup_capacity", ("int", 200000)),
        ("siem_forward_enabled", ("bool", True)),
        ("siem_ip", ("str", None)),
        ("siem_port", ("int", 50666)),
        ("output_dir_enabled", ("bool", True)),
        ("output_dir", ("str", "./receiver_output")),
        ("log_file", ("str", "receiver.log")),
        ("log_level", ("str", "INFO")),
        ("log_backup_count", ("int", 5)),
        ("stats_interval", ("int", 60)),
    ]),
}

SERVICE_HELP_TEXT = """
-------------------------------------------------------------------------------
CONFIG PRECEDENCE: command line > INI file > built-in default.
Config file lookup: -ConfigFile, else ./transfer.ini, else transfer.ini next
to the script.

LINUX SYSTEMD SERVICE SETUP:
-------------------------------------------------------------------------------
1. Service account and installation directory:
   sudo useradd --system --no-create-home --shell /sbin/nologin securetransfer
   sudo mkdir -p /opt/securetransfer
   sudo cp secure_transfer.py /opt/securetransfer/
   sudo chmod 755 /opt/securetransfer/secure_transfer.py

2. Default config file:
   cd /opt/securetransfer
   sudo python3 secure_transfer.py --create-config-file transfer.ini
   sudo chown -R securetransfer: /opt/securetransfer

3. /etc/systemd/system/secure_transfer_receiver.service
   (use --sender and a different unit name on the Sender side):

   [Unit]
   Description=Secure Transfer Service (Receiver Mode)
   Wants=network-online.target
   After=network-online.target

   [Service]
   Type=simple
   User=securetransfer
   Group=securetransfer
   WorkingDirectory=/opt/securetransfer
   ExecStart=/usr/bin/python3 /opt/securetransfer/secure_transfer.py --receiver
   Restart=always
   RestartSec=5
   NoNewPrivileges=yes
   ProtectSystem=strict
   ProtectHome=yes
   PrivateTmp=yes
   ReadWritePaths=/opt/securetransfer

   [Install]
   WantedBy=multi-user.target

   Ports < 1024 additionally require:
   AmbientCapabilities=CAP_NET_BIND_SERVICE

4. Enable and start (RHEL / Rocky / Fedora / SLES):
   sudo systemctl daemon-reload
   sudo systemctl enable --now secure_transfer_receiver.service
   sudo systemctl status secure_transfer_receiver.service
   journalctl -u secure_transfer_receiver.service -f
-------------------------------------------------------------------------------
"""


class ConfigError(Exception):
    pass


class Config(object):
    """Simple attribute container for resolved configuration."""

    def __init__(self, section, values, config_path):
        self.section = section
        self.config_path = config_path
        for k, v in values.items():
            setattr(self, k, v)


def parse_bool(val):
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("true", "yes", "on", "1"):
        return True
    if s in ("false", "no", "off", "0"):
        return False
    raise ValueError(f"invalid boolean '{val}'")


def convert_value(key, typ, raw):
    if raw is None:
        return None
    try:
        if typ == "bool":
            return parse_bool(raw)
        if typ == "int":
            return int(str(raw).strip())
        if typ == "float":
            return float(str(raw).strip())
        if typ == "list":
            if isinstance(raw, (list, tuple)):
                return list(raw)
            return [p.strip() for p in str(raw).split(",") if p.strip()]
        s = str(raw).strip()
        return s if s else None
    except ValueError as e:
        raise ConfigError(f"Invalid value for '{key}': {e}")


def find_config_path(cli_path):
    if cli_path:
        return cli_path
    candidates = [
        os.path.join(os.getcwd(), DEFAULT_CONFIG_NAME),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), DEFAULT_CONFIG_NAME),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def load_ini(path):
    cfg = configparser.ConfigParser(
        interpolation=None, inline_comment_prefixes=("#", ";")
    )
    if path:
        if not os.path.isfile(path):
            raise ConfigError(f"Config file '{path}' not found.")
        with open(path, "r", encoding="utf-8") as f:
            cfg.read_file(f)
    return cfg


def resolve_config(section, cli_args, ini, config_path):
    """Resolve one section: CLI > INI > default."""
    ini_values = dict(ini[section]) if ini.has_section(section) else {}
    schema = CONFIG_SCHEMA[section]
    values = {}
    for key, (typ, default) in schema.items():
        cli_val = getattr(cli_args, key, None)
        if cli_val is not None:
            values[key] = convert_value(key, typ, cli_val)
        elif key in ini_values:
            values[key] = convert_value(key, typ, ini_values[key])
        else:
            values[key] = default
    if getattr(cli_args, "debug_mode", False):
        values["log_level"] = "DEBUG"
    values["log_level"] = (values.get("log_level") or "INFO").upper()

    unknown = set(ini_values) - set(schema)
    cfg = Config(section, values, config_path)
    cfg.unknown_keys = sorted(unknown)
    return cfg


def _check_port(errors, name, port):
    if port is None or not (1 <= port <= 65535):
        errors.append(f"{name} must be 1-65535 (got {port}).")


def validate_config(cfg):
    errors = []
    if cfg.log_level not in ("INFO", "DEBUG"):
        errors.append(f"log_level must be INFO or DEBUG (got {cfg.log_level}).")
    if cfg.log_backup_count < 1:
        errors.append("log_backup_count must be >= 1.")
    if cfg.stats_interval < 0:
        errors.append("stats_interval must be >= 0.")

    if cfg.section == "SENDER":
        if cfg.tcp_listener_enabled:
            _check_port(errors, "listening_port", cfg.listening_port)
        if cfg.input_dir_enabled and not cfg.input_dir:
            errors.append("input_dir must be set when input_dir_enabled = true.")
        if not cfg.input_dir_enabled and not cfg.tcp_listener_enabled:
            errors.append("At least one input (input_dir_enabled or tcp_listener_enabled) must be enabled.")
        for stream in ("primary", "secondary"):
            if getattr(cfg, f"{stream}_enabled"):
                if not getattr(cfg, f"{stream}_ip"):
                    errors.append(f"{stream}_ip must be set when {stream}_enabled = true.")
                _check_port(errors, f"{stream}_port", getattr(cfg, f"{stream}_port"))
        if not cfg.primary_enabled and not cfg.secondary_enabled:
            errors.append("At least one stream (primary or secondary) must be enabled.")
        if not (MIN_DATAGRAM_SIZE <= cfg.max_datagram_size <= UDP_MAX_DATAGRAM):
            errors.append(f"max_datagram_size must be {MIN_DATAGRAM_SIZE}-{UDP_MAX_DATAGRAM}.")
        if cfg.max_packets_per_second < 0:
            errors.append("max_packets_per_second must be >= 0.")
        if cfg.scan_interval <= 0:
            errors.append("scan_interval must be > 0.")
        if cfg.partial_line_timeout < 0:
            errors.append("partial_line_timeout must be >= 0.")
    else:
        _check_port(errors, "listening_port", cfg.listening_port)
        if cfg.siem_forward_enabled:
            if not cfg.siem_ip:
                errors.append("siem_ip must be set when siem_forward_enabled = true.")
            _check_port(errors, "siem_port", cfg.siem_port)
        if cfg.output_dir_enabled and not cfg.output_dir:
            errors.append("output_dir must be set when output_dir_enabled = true.")
        if not cfg.siem_forward_enabled and not cfg.output_dir_enabled:
            errors.append("At least one output (siem_forward_enabled or output_dir_enabled) must be enabled.")
        if cfg.dedup_capacity < 1000:
            errors.append("dedup_capacity must be >= 1000.")
    return errors


def create_default_config(path, force=False):
    if os.path.exists(path) and not force:
        print(f"Error: '{path}' already exists. Use -Force to overwrite.", file=sys.stderr)
        sys.exit(1)
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(DEFAULT_CONFIG)
    print(f"Default configuration file created at: {path}")


# ============================================================================
# LOGGING / BANNER
# ============================================================================
def setup_logging(log_file, level_str, logger_name, backup_count):
    level = logging.DEBUG if level_str == "DEBUG" else logging.INFO
    logger = logging.getLogger(logger_name)
    logger.setLevel(level)
    logger.propagate = False
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s - %(name)s - [%(levelname)s] - %(message)s")

    log_dir = os.path.dirname(os.path.abspath(log_file))
    os.makedirs(log_dir, exist_ok=True)
    fh = RotatingFileHandler(
        log_file, maxBytes=100 * 1024 * 1024, backupCount=backup_count, encoding="utf-8"
    )
    fh.setFormatter(fmt)
    fh.setLevel(level)
    logger.addHandler(fh)

    # Warnings and errors also to stderr -> journald under systemd
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(logging.Formatter("%(name)s [%(levelname)s] %(message)s"))
    sh.setLevel(logging.WARNING)
    logger.addHandler(sh)
    return logger


class ThrottledLog(object):
    """Emit a given log key at most once per 'interval' seconds."""

    def __init__(self, logger, interval=10.0):
        self.logger = logger
        self.interval = interval
        self.last = {}
        self.suppressed = {}

    def error(self, key, msg):
        now = time.monotonic()
        if now - self.last.get(key, 0) >= self.interval:
            n = self.suppressed.pop(key, 0)
            suffix = f" ({n} similar messages suppressed)" if n else ""
            self.logger.error(msg + suffix)
            self.last[key] = now
        else:
            self.suppressed[key] = self.suppressed.get(key, 0) + 1


def get_systemd_service_status():
    try:
        cmd = ["systemctl", "list-units", "--type=service", "--all",
               "--no-legend", "--plain", "*secure_transfer*"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=3)
        services = []
        if res.returncode == 0 and res.stdout.strip():
            for line in res.stdout.strip().splitlines():
                parts = line.split()
                if not parts:
                    continue
                svc_name = parts[0]
                load_state = parts[1] if len(parts) > 1 else ""
                active_state = parts[2] if len(parts) > 2 else "dead"
                sub_state = parts[3] if len(parts) > 3 else "stopped"
                color = COLOR_GREEN if active_state.lower() == "active" else COLOR_RED
                services.append(
                    f"{svc_name} (Active: {colorize(active_state + '/' + sub_state, color)}, Load: {load_state})"
                )
        if not services:
            cmd2 = ["systemctl", "list-unit-files", "--no-legend", "*secure_transfer*"]
            res2 = subprocess.run(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  universal_newlines=True, timeout=3)
            if res2.returncode == 0 and res2.stdout.strip():
                for line in res2.stdout.strip().splitlines():
                    parts = line.split()
                    if parts:
                        state_val = parts[1] if len(parts) > 1 else "disabled"
                        services.append(f"{parts[0]} (State: {colorize(state_val, COLOR_RED)})")
        if not services:
            return [colorize("No systemd service matching '*secure_transfer*' (not installed)", COLOR_RED)]
        return services
    except Exception as e:
        return [colorize(f"Could not query systemd status ({e})", COLOR_RED)]


def _feat(enabled, detail=""):
    if enabled:
        return colorize("ENABLED", COLOR_GREEN) + (f" {detail}" if detail else "")
    return colorize("DISABLED", COLOR_RED)


def print_banner(cfg, errors=None):
    w = 74
    print("=" * w)
    print(f" SECURE TRANSFER SERVICE - {cfg.section} MODE (v{SCRIPT_VERSION}, protocol v{PROTOCOL_VERSION})")
    print("=" * w)
    print(f" Config File Used        : {cfg.config_path or 'None (CLI / defaults)'}")
    print(f" Internal Log File       : {cfg.log_file} (Level: {cfg.log_level}, backups: {cfg.log_backup_count})")
    print("-" * w)
    print(" ACTIVE FEATURES & DESTINATIONS:")
    if cfg.section == "SENDER":
        rate = "unlimited" if not cfg.max_packets_per_second else f"{cfg.max_packets_per_second} datagrams/s per stream"
        rows = [
            ("Input Directory Scan", _feat(cfg.input_dir_enabled, f"({cfg.input_dir}, every {cfg.scan_interval:g}s)")),
            ("State Tracking File", cfg.state_file),
            ("Ignore Patterns", ", ".join(cfg.ignore_patterns) or "-"),
            ("TCP Syslog Listener", _feat(cfg.tcp_listener_enabled, f"({cfg.listen_address}:{cfg.listening_port}/tcp)")),
            ("Primary Diode Stream", _feat(cfg.primary_enabled, f"-> {cfg.primary_ip}:{cfg.primary_port}/udp")),
            ("Secondary Diode Stream", _feat(cfg.secondary_enabled, f"-> {cfg.secondary_ip}:{cfg.secondary_port}/udp")),
            ("Max Datagram Size", f"{cfg.max_datagram_size} bytes"),
            ("Rate Limit", rate),
        ]
    else:
        rows = [
            ("UDP Listener", f"{cfg.listen_address}:{cfg.listening_port}/udp"),
            ("Dedup Capacity", f"{cfg.dedup_capacity} message IDs"),
            ("SIEM Forwarding", _feat(cfg.siem_forward_enabled, f"-> {cfg.siem_ip}:{cfg.siem_port}/udp")),
            ("Output File Storage", _feat(cfg.output_dir_enabled, f"({cfg.output_dir})")),
        ]
    for label, value in rows:
        print(f" - {label:<22}: {value}")
    if getattr(cfg, "unknown_keys", None):
        print(colorize(f" ! Unknown keys in [{cfg.section}] ignored: {', '.join(cfg.unknown_keys)}", COLOR_YELLOW))
    if errors:
        print("-" * w)
        print(colorize(" CONFIGURATION ERRORS:", COLOR_RED))
        for e in errors:
            print(colorize(f" ! {e}", COLOR_RED))
    print("-" * w)
    print(" SYSTEMD SERVICE STATUS:")
    for status_line in get_systemd_service_status():
        print(f" - {status_line}")
    print("=" * w)


# ============================================================================
# ARGUMENT PARSING
# ============================================================================
def build_parser():
    parser = argparse.ArgumentParser(
        description="Secure Transfer Service (Sender & Receiver)" + SERVICE_HELP_TEXT,
        formatter_class=argparse.RawTextHelpFormatter,
        allow_abbrev=False,
    )
    bool_choices = ["true", "false", "True", "False"]

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("-Sender", "--sender", "-s", dest="mode_sender", action="store_true",
                      help="Run in SENDER mode")
    mode.add_argument("-Receiver", "--receiver", "-r", dest="mode_receiver", action="store_true",
                      help="Run in RECEIVER mode")

    g = parser.add_argument_group("general")
    g.add_argument("-Version", "--version", "-v", dest="show_version", action="store_true",
                   help="Show script version and exit")
    g.add_argument("-ShowConfig", "--show-config", "-sc", dest="show_config", action="store_true",
                   help="Display resolved configuration, validate it, and exit")
    g.add_argument("-Debug", "--debug", "-d", dest="debug_mode", action="store_true",
                   help="Force DEBUG logging (every line and packet)")
    g.add_argument("-SendTest", "--send-test", "-st", dest="send_test", action="store_true",
                   help="Send one test message to configured destinations and exit")
    g.add_argument("-ConfigFile", "--config-file", "-f", dest="config_file",
                   help=f"Config file (default: ./{DEFAULT_CONFIG_NAME} or next to the script)")
    g.add_argument("-CreateConfigFile", "--create-config-file", "-cc", dest="create_config_file",
                   nargs="?", const=DEFAULT_CONFIG_NAME,
                   help="Create a documented default config file and exit")
    g.add_argument("-Force", "--force", dest="force", action="store_true",
                   help="Allow -CreateConfigFile to overwrite an existing file")

    s = parser.add_argument_group("sender")
    s.add_argument("-InputDirEnabled", "--input-dir-enabled", dest="input_dir_enabled", choices=bool_choices)
    s.add_argument("-InputDir", "--input-dir", "-id", dest="input_dir")
    s.add_argument("-StateFile", "--state-file", dest="state_file")
    s.add_argument("-TcpListenerEnabled", "--tcp-listener-enabled", dest="tcp_listener_enabled", choices=bool_choices)
    s.add_argument("-PrimaryEnabled", "--primary-enabled", dest="primary_enabled", choices=bool_choices)
    s.add_argument("-PrimaryIp", "--primary-ip", "--pi", dest="primary_ip")
    s.add_argument("-PrimaryPort", "--primary-port", "--pp", dest="primary_port", type=int)
    s.add_argument("-SecondaryEnabled", "--secondary-enabled", dest="secondary_enabled", choices=bool_choices)
    s.add_argument("-SecondaryIp", "--secondary-ip", "--si", dest="secondary_ip")
    s.add_argument("-SecondaryPort", "--secondary-port", "--sp", dest="secondary_port", type=int)

    r = parser.add_argument_group("receiver")
    r.add_argument("-SiemForwardEnabled", "--siem-forward-enabled", dest="siem_forward_enabled", choices=bool_choices)
    r.add_argument("-SiemIp", "--siem-ip", "--sip", dest="siem_ip")
    r.add_argument("-SiemPort", "--siem-port", "--spt", dest="siem_port", type=int)
    r.add_argument("-OutputDir", "--output-dir", "-od", dest="output_dir")
    r.add_argument("-OutputDirEnabled", "--output-dir-enabled", "-ode", dest="output_dir_enabled", choices=bool_choices)

    c = parser.add_argument_group("common")
    c.add_argument("-ListenAddress", "--listen-address", "-la", dest="listen_address",
                   help="Bind address (TCP for Sender, UDP for Receiver)")
    c.add_argument("-ListeningPort", "--listening-port", "-lp", dest="listening_port", type=int,
                   help="Listening port (TCP for Sender, UDP for Receiver)")
    c.add_argument("-LogFile", "--log-file", "-lf", dest="log_file")
    c.add_argument("-LogLevel", "--log-level", "-ll", dest="log_level", choices=["INFO", "DEBUG"])
    return parser


def parse_args(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    argv = ["--help" if a in ("-Help", "-Helg") else a for a in argv]

    parser = build_parser()
    if not argv:
        parser.print_help(sys.stderr)
        sys.exit(1)
    args = parser.parse_args(argv)

    if args.show_version:
        print(f"secure_transfer.py version {SCRIPT_VERSION} (protocol v{PROTOCOL_VERSION})")
        sys.exit(0)

    if args.create_config_file is not None:
        create_default_config(args.create_config_file, args.force)
        sys.exit(0)

    config_path = find_config_path(args.config_file)
    try:
        ini = load_ini(config_path)
    except (ConfigError, configparser.Error) as e:
        parser.error(str(e))

    if args.show_config:
        sections = [sec for sec in ("SENDER", "RECEIVER") if ini.has_section(sec)] or ["SENDER", "RECEIVER"]
        if args.mode_sender:
            sections = ["SENDER"]
        elif args.mode_receiver:
            sections = ["RECEIVER"]
        rc = 0
        for sec in sections:
            try:
                cfg = resolve_config(sec, args, ini, config_path)
                errs = validate_config(cfg)
            except ConfigError as e:
                print(colorize(f"[{sec}] {e}", COLOR_RED))
                rc = 1
                continue
            rc = rc or (1 if errs else 0)
            print_banner(cfg, errs)
            print()
        sys.exit(rc)

    if not args.mode_sender and not args.mode_receiver:
        parser.error("Specify -Sender (-s) or -Receiver (-r), or use -ShowConfig (-sc).")

    mode = "SENDER" if args.mode_sender else "RECEIVER"
    try:
        cfg = resolve_config(mode, args, ini, config_path)
    except ConfigError as e:
        parser.error(str(e))
    errors = validate_config(cfg)
    if errors:
        parser.error(" ".join(errors))
    return cfg, mode, args


# ============================================================================
# PROTOCOL
# ============================================================================
# v2 packet (JSON object, one per UDP datagram):
#   v     : protocol version (2)
#   id    : message id (hex). Identical on primary and secondary path.
#   src   : sender session id (new on every Sender start)
#   seq   : datagram sequence number within the session
#   file  : source file name (basename)
#   data  : payload, UTF-8 with surrogateescape (lossless for any bytes)
#   part  : (optional) fragment index, 0-based
#   parts : (optional) total number of fragments
# v1 packets (id/file/data only) and raw non-JSON datagrams are accepted.

def bytes_to_wire(b):
    return b.decode("utf-8", errors="surrogateescape")


def wire_to_bytes(s):
    return s.encode("utf-8", errors="surrogateescape")


def encode_packet(d):
    # ensure_ascii=True escapes lone surrogates as \\udcXX -> valid UTF-8 JSON
    return json.dumps(d, separators=(",", ":"), ensure_ascii=True).encode("ascii")


# ============================================================================
# SENDER
# ============================================================================
class StateManager(object):
    """Per-file offsets, tracked with (dev, inode) so rotation is detected."""

    def __init__(self, path, logger):
        self.path = path
        self.logger = logger
        self.files = {}
        self.dirty = False
        self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            bad = f"{self.path}.corrupt.{int(time.time())}"
            self.logger.error(f"State file unreadable ({e}); moved to {bad}, starting fresh")
            try:
                os.replace(self.path, bad)
            except OSError:
                pass
            return
        if isinstance(data, dict) and data.get("version") == 2:
            self.files = data.get("files", {})
        elif isinstance(data, dict):
            # v20 format: {path: {"offset": n}}
            self.files = {p: {"offset": int(v.get("offset", 0))}
                          for p, v in data.items() if isinstance(v, dict)}
            self.logger.info(f"Migrated v1 state file with {len(self.files)} entries")
            self.dirty = True

    def save(self):
        if not self.dirty:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".", exist_ok=True)
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"version": 2, "files": self.files}, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        self.dirty = False

    def get(self, path):
        return self.files.get(path)

    def inode_snapshot(self):
        """(dev, inode) -> (path, offset), taken once per scan cycle so that
        renames are resolved before any record is overwritten."""
        return {(r.get("dev"), r.get("inode")): (p, int(r.get("offset", 0)))
                for p, r in self.files.items() if r.get("inode") is not None}

    def set(self, path, offset, st):
        self.files[path] = {"offset": offset, "inode": st.st_ino, "dev": st.st_dev}
        self.dirty = True

    def prune(self, existing):
        gone = [p for p in self.files if p not in existing]
        for p in gone:
            del self.files[p]
        if gone:
            self.dirty = True


class RateLimiter(object):
    def __init__(self, rate):
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self.next_t = time.monotonic()

    async def wait(self):
        if not self.interval:
            return
        now = time.monotonic()
        if self.next_t > now:
            await asyncio.sleep(self.next_t - now)
            now = time.monotonic()
        self.next_t = max(self.next_t, now) + self.interval


class UDPTransmitter(object):
    def __init__(self, cfg, logger):
        self.logger = logger
        self.tlog = ThrottledLog(logger)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        self.destinations = []
        if cfg.primary_enabled:
            self.destinations.append(("primary", (cfg.primary_ip, cfg.primary_port)))
        if cfg.secondary_enabled:
            self.destinations.append(("secondary", (cfg.secondary_ip, cfg.secondary_port)))
        self.max_size = cfg.max_datagram_size
        self.limiter = RateLimiter(cfg.max_packets_per_second)
        self.session = uuid.uuid4().hex[:16]
        self.seq = 0
        self.stats = {"messages": 0, "datagrams": 0, "fragmented": 0}
        for name, _ in self.destinations:
            self.stats[f"{name}_sent"] = 0
            self.stats[f"{name}_errors"] = 0

    def _build_packets(self, filename, line):
        msg_id = uuid.uuid4().hex
        base = {"v": PROTOCOL_VERSION, "id": msg_id, "src": self.session,
                "file": os.path.basename(filename)}
        # Reserve seq digits; real seq assigned below
        probe = encode_packet(dict(base, seq=10 ** 12, data=bytes_to_wire(line)))
        if len(probe) <= self.max_size:
            return [dict(base, data=bytes_to_wire(line))]

        overhead = len(encode_packet(dict(base, seq=10 ** 12, part=99999, parts=99999, data="")))
        chunk = max(64, self.max_size - overhead)
        while True:
            chunks = [line[i:i + chunk] for i in range(0, len(line), chunk)]
            pkts = [dict(base, part=i, parts=len(chunks), data=bytes_to_wire(c))
                    for i, c in enumerate(chunks)]
            if all(len(encode_packet(dict(p, seq=10 ** 12))) <= self.max_size for p in pkts):
                self.stats["fragmented"] += 1
                return pkts
            chunk = max(16, chunk // 2)   # JSON escaping expanded data; retry smaller

    async def send(self, filename, line):
        self.stats["messages"] += 1
        for pkt in self._build_packets(filename, line):
            self.seq += 1
            pkt["seq"] = self.seq
            raw = encode_packet(pkt)
            await self.limiter.wait()
            self.stats["datagrams"] += 1
            for name, dest in self.destinations:
                try:
                    self.sock.sendto(raw, dest)
                    self.stats[f"{name}_sent"] += 1
                    if self.logger.isEnabledFor(logging.DEBUG):
                        self.logger.debug(
                            f"[SEND-{name.upper()}] id={pkt['id']} seq={pkt['seq']} "
                            f"part={pkt.get('part', 0)}/{pkt.get('parts', 1)} file={filename} "
                            f"bytes={len(raw)} -> {dest}")
                except OSError as e:
                    self.stats[f"{name}_errors"] += 1
                    self.tlog.error(name, f"Send to {name} diode {dest} failed: {e}")


class SyslogTCPServer(object):
    """TCP syslog intake: LF framing and RFC 6587 octet counting (auto-detected per message)."""

    def __init__(self, transmitter, logger):
        self.transmitter = transmitter
        self.logger = logger
        self.writers = set()
        self.stats = {"connections": 0, "messages": 0}

    async def _read_message(self, reader):
        first = await reader.readexactly(1)
        if first.isdigit():
            hdr = first + await reader.readuntil(b" ")
            try:
                n = int(hdr[:-1])
            except ValueError:
                return hdr.strip()
            if n > TCP_STREAM_LIMIT:
                raise ValueError(f"octet count {n} exceeds limit")
            return await reader.readexactly(n)
        if first == b"\n":
            return b""
        try:
            return first + await reader.readuntil(b"\n")
        except asyncio.LimitOverrunError as e:
            # Oversized line: forward what we have; remainder becomes next message
            return first + await reader.read(e.consumed)

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername")
        self.writers.add(writer)
        self.stats["connections"] += 1
        self.logger.info(f"TCP syslog connection from {peer}")
        try:
            while True:
                try:
                    msg = await self._read_message(reader)
                except asyncio.IncompleteReadError as e:
                    msg = e.partial
                    if msg.strip():
                        await self._forward(peer, msg)
                    break
                await self._forward(peer, msg)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.error(f"TCP syslog stream error from {peer}: {e}")
        finally:
            self.writers.discard(writer)
            writer.close()
            self.logger.info(f"TCP syslog connection closed: {peer}")

    async def _forward(self, peer, msg):
        line = msg.rstrip(b"\r\n\x00")
        if not line:
            return
        self.stats["messages"] += 1
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f"[TCP-RECV] {peer}: {line[:500]!r}")
        await self.transmitter.send("tcp_stream.log", line)


def is_ignored(name, patterns):
    return any(fnmatch.fnmatch(name, p) for p in patterns)


async def scan_file(path, entry, st, cfg, state_mgr, inodes, transmitter, logger, stats):
    rec = state_mgr.get(path)
    offset = 0
    same_inode = rec is not None and (rec.get("inode") is None or
                                      (rec.get("dev"), rec.get("inode")) == (st.st_dev, st.st_ino))
    if same_inode:
        offset = int(rec.get("offset", 0))      # unchanged file (or v1 state without inode)
    else:
        moved = inodes.get((st.st_dev, st.st_ino))
        if moved is not None and moved[0] != path:
            offset = moved[1]
            logger.info(f"[FILE-SCAN] '{entry}' is renamed '{os.path.basename(moved[0])}' - continuing at offset {offset}")
        elif rec is not None:
            logger.info(f"[FILE-SCAN] '{entry}' replaced (new inode) - reading from start")

    if st.st_size < offset:
        logger.info(f"[FILE-SCAN] '{entry}' truncated ({st.st_size} < {offset}) - reading from start")
        offset = 0
    if st.st_size == offset:
        if rec is None or rec.get("inode") != st.st_ino or rec.get("offset") != offset:
            state_mgr.set(path, offset, st)
        return

    logger.debug(f"[FILE-SCAN] Reading '{entry}' from offset {offset} (size {st.st_size})")
    sent = 0
    with open(path, "rb") as f:
        f.seek(offset)
        pending = b""
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            buf = pending + chunk
            parts = buf.split(b"\n")
            pending = parts.pop()
            for raw in parts:
                offset += len(raw) + 1
                line = raw.rstrip(b"\r")
                if line:
                    await transmitter.send(entry, line)
                    sent += 1
                    if sent % SCANNER_YIELD_EVERY == 0:
                        await asyncio.sleep(0)
                    if sent % STATE_SAVE_EVERY == 0:
                        state_mgr.set(path, offset, st)
                        state_mgr.save()
            if len(pending) > MAX_PENDING_LINE:
                logger.warning(f"[FILE-SCAN] '{entry}': line > {MAX_PENDING_LINE} bytes without LF - sending as-is")
                offset += len(pending)
                await transmitter.send(entry, pending.rstrip(b"\r"))
                sent += 1
                pending = b""

        if pending:
            age = time.time() - os.fstat(f.fileno()).st_mtime
            if age >= cfg.partial_line_timeout:
                offset += len(pending)
                line = pending.rstrip(b"\r")
                if line:
                    await transmitter.send(entry, line)
                    sent += 1
                logger.debug(f"[FILE-SCAN] '{entry}': sent trailing line without LF (idle {age:.0f}s)")

    stats["lines"] += sent
    state_mgr.set(path, offset, st)
    state_mgr.save()
    if sent:
        logger.debug(f"[FILE-SCAN] '{entry}': {sent} lines sent, offset now {offset}")


async def directory_scanner_loop(cfg, state_mgr, transmitter, logger, stats):
    input_dir = cfg.input_dir
    state_abs = os.path.abspath(cfg.state_file)
    logger.info(f"Input directory scanner active for: {input_dir}")
    while True:
        try:
            seen = set()
            inodes = state_mgr.inode_snapshot()
            for entry in sorted(os.listdir(input_dir)):
                if is_ignored(entry, cfg.ignore_patterns):
                    continue
                path = os.path.join(input_dir, entry)
                if os.path.abspath(path) in (state_abs, state_abs + ".tmp"):
                    continue
                try:
                    st = os.stat(path)
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                seen.add(path)
                try:
                    await scan_file(path, entry, st, cfg, state_mgr, inodes, transmitter, logger, stats)
                except (FileNotFoundError, PermissionError) as e:
                    logger.warning(f"[FILE-SCAN] Cannot read '{entry}': {e}")
            state_mgr.prune(seen)
            state_mgr.save()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Error scanning input directory: {e}", exc_info=True)
        await asyncio.sleep(cfg.scan_interval)


async def sender_stats_loop(cfg, transmitter, tcp, scan_stats, logger):
    while True:
        await asyncio.sleep(cfg.stats_interval)
        s = dict(transmitter.stats)
        s["file_lines"] = scan_stats["lines"]
        if tcp:
            s["tcp_messages"] = tcp.stats["messages"]
            s["tcp_active_conns"] = len(tcp.writers)
        logger.info("[STATS] " + " ".join(f"{k}={v}" for k, v in s.items()))


async def run_sender(cfg, logger, send_test):
    print_banner(cfg)
    transmitter = UDPTransmitter(cfg, logger)

    if send_test:
        msg = (f"<14>{time.strftime('%b %d %H:%M:%S')} {socket.gethostname()} "
               f"secure_transfer: TEST-MESSAGE-SENDER-LOCATION v{SCRIPT_VERSION}").encode()
        await transmitter.send("test_packet.log", msg)
        logger.info(f"Test message sent to {[d for _, d in transmitter.destinations]}")
        errs = sum(v for k, v in transmitter.stats.items() if k.endswith("_errors"))
        print("Test message sent." if not errs else f"Test message: {errs} send error(s), see log.")
        return

    logger.info(f"Starting sender v{SCRIPT_VERSION}, session {transmitter.session}")
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass

    state_mgr = StateManager(cfg.state_file, logger)
    scan_stats = {"lines": 0}
    tasks = []
    server = None
    tcp = None

    if cfg.input_dir_enabled:
        os.makedirs(cfg.input_dir, exist_ok=True)
        tasks.append(asyncio.ensure_future(
            directory_scanner_loop(cfg, state_mgr, transmitter, logger, scan_stats)))
    else:
        logger.info("Feature disabled: input directory scanning")

    if cfg.tcp_listener_enabled:
        tcp = SyslogTCPServer(transmitter, logger)
        server = await asyncio.start_server(
            tcp.handle, cfg.listen_address, cfg.listening_port, limit=TCP_STREAM_LIMIT)
        logger.info(f"TCP syslog listener on {cfg.listen_address}:{cfg.listening_port}")
    else:
        logger.info("Feature disabled: TCP syslog listener")

    if cfg.stats_interval:
        tasks.append(asyncio.ensure_future(
            sender_stats_loop(cfg, transmitter, tcp, scan_stats, logger)))

    await stop.wait()
    logger.info("Shutdown requested - stopping sender")
    if server:
        server.close()
        for w in list(tcp.writers):
            w.close()
        try:
            await asyncio.wait_for(server.wait_closed(), 5)
        except asyncio.TimeoutError:
            pass
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    state_mgr.save()
    logger.info("[STATS] final " + " ".join(f"{k}={v}" for k, v in transmitter.stats.items()))
    print("\nSENDER stopped.")


# ============================================================================
# RECEIVER
# ============================================================================
class Deduplicator(object):
    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = OrderedDict()

    def is_duplicate(self, key):
        if key in self.cache:
            self.cache.move_to_end(key)
            return True
        self.cache[key] = None
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)
        return False


class Reassembler(object):
    def __init__(self, timeout=30.0, max_pending=10000):
        self.timeout = timeout
        self.max_pending = max_pending
        self.pending = OrderedDict()   # msg_id -> [created, parts, {idx: bytes}, filename]
        self.expired = 0

    def add(self, msg_id, part, parts, data, filename):
        entry = self.pending.get(msg_id)
        if entry is None:
            entry = [time.monotonic(), parts, {}, filename]
            self.pending[msg_id] = entry
            if len(self.pending) > self.max_pending:
                self.pending.popitem(last=False)
                self.expired += 1
        entry[2][part] = data
        if len(entry[2]) == entry[1]:
            del self.pending[msg_id]
            return b"".join(entry[2][i] for i in range(entry[1]))
        return None

    def expire(self):
        now = time.monotonic()
        while self.pending:
            msg_id, entry = next(iter(self.pending.items()))
            if now - entry[0] < self.timeout:
                break
            del self.pending[msg_id]
            self.expired += 1


class SequenceTracker(object):
    """Estimates datagrams lost on ALL paths (gaps after deduplication)."""

    def __init__(self, logger, max_sources=100):
        self.logger = logger
        self.max_sources = max_sources
        self.last = OrderedDict()
        self.lost = 0
        self.late = 0

    def observe(self, src, seq):
        last = self.last.get(src)
        if last is None:
            self.logger.info(f"New sender session {src} (first seq {seq})")
            self.last[src] = seq
            if len(self.last) > self.max_sources:
                self.last.popitem(last=False)
            return
        self.last.move_to_end(src)
        if seq == last + 1:
            self.last[src] = seq
        elif seq > last + 1:
            gap = seq - last - 1
            self.lost += gap
            self.last[src] = seq
            self.logger.warning(f"[LOSS] session {src}: {gap} datagram(s) missing on all paths (seq {last + 1}-{seq - 1})")
        else:
            # late arrival of an earlier gap (other diode path was slower)
            self.late += 1
            if self.lost > 0:
                self.lost -= 1


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


def safe_filename(name):
    base = os.path.basename(str(name or ""))
    base = _SAFE_NAME.sub("_", base).lstrip(".")[:128]
    return base or "received.log"


class OutputWriter(object):
    def __init__(self, output_dir, logger, max_open=64):
        self.output_dir = output_dir
        self.logger = logger
        self.max_open = max_open
        self.handles = OrderedDict()
        self.tlog = ThrottledLog(logger)
        self.errors = 0
        os.makedirs(output_dir, exist_ok=True)

    def write(self, filename, payload):
        name = safe_filename(filename)
        try:
            f = self.handles.get(name)
            if f is None:
                f = open(os.path.join(self.output_dir, name), "ab")
                self.handles[name] = f
                if len(self.handles) > self.max_open:
                    _, old = self.handles.popitem(last=False)
                    old.close()
            else:
                self.handles.move_to_end(name)
            f.write(payload + b"\n")
            f.flush()
        except OSError as e:
            self.errors += 1
            self.handles.pop(name, None)
            self.tlog.error("write", f"Error writing output file '{name}': {e}")

    def close(self):
        for f in self.handles.values():
            try:
                f.close()
            except OSError:
                pass
        self.handles.clear()


_STOP = False


def _request_stop(signum, frame):
    global _STOP
    _STOP = True


def run_receiver(cfg, logger, send_test):
    print_banner(cfg)
    siem_target = (cfg.siem_ip, cfg.siem_port) if cfg.siem_forward_enabled else None

    if send_test:
        if not siem_target:
            print("Error: SIEM forwarding must be enabled to send a test message.", file=sys.stderr)
            sys.exit(1)
        msg = (f"<14>{time.strftime('%b %d %H:%M:%S')} {socket.gethostname()} "
               f"secure_transfer: TEST-MESSAGE-RECEIVER-LOCATION v{SCRIPT_VERSION}").encode()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(msg, siem_target)
        logger.info(f"Test message sent to SIEM {siem_target}")
        print(f"Test message sent to SIEM {siem_target[0]}:{siem_target[1]}.")
        return

    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)

    logger.info(f"Starting receiver v{SCRIPT_VERSION}")
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, cfg.recv_buffer_bytes)
    actual = recv_sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    if actual < cfg.recv_buffer_bytes:   # Linux reports 2x the granted value
        logger.warning(f"SO_RCVBUF capped at {actual} bytes (requested {cfg.recv_buffer_bytes}). "
                       f"Raise with: sysctl -w net.core.rmem_max={cfg.recv_buffer_bytes}")
    recv_sock.bind((cfg.listen_address, cfg.listening_port))
    recv_sock.settimeout(1.0)
    logger.info(f"Listening on {cfg.listen_address}:{cfg.listening_port}/udp")

    forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if siem_target else None
    writer = OutputWriter(cfg.output_dir, logger) if cfg.output_dir_enabled else None
    deduper = Deduplicator(cfg.dedup_capacity)
    reasm = Reassembler()
    seqs = SequenceTracker(logger)
    tlog = ThrottledLog(logger)
    stats = OrderedDict([("datagrams", 0), ("duplicates", 0), ("messages", 0), ("legacy", 0),
                         ("siem_errors", 0)])
    debug = logger.isEnabledFor(logging.DEBUG)
    next_stats = time.monotonic() + (cfg.stats_interval or 10 ** 9)

    def log_stats(prefix="[STATS]"):
        s = dict(stats)
        s.update(lost_est=seqs.lost, late=seqs.late, reasm_pending=len(reasm.pending),
                 reasm_expired=reasm.expired, write_errors=writer.errors if writer else 0)
        logger.info(prefix + " " + " ".join(f"{k}={v}" for k, v in s.items()))

    try:
        while not _STOP:
            now = time.monotonic()
            if now >= next_stats:
                reasm.expire()
                log_stats()
                next_stats = now + cfg.stats_interval
            try:
                data, addr = recv_sock.recvfrom(UDP_MAX_DATAGRAM + 1)
            except socket.timeout:
                reasm.expire()
                continue
            except InterruptedError:
                continue
            if not data:
                continue
            stats["datagrams"] += 1

            packet = None
            try:
                packet = json.loads(data.decode("utf-8", errors="surrogateescape"))
            except ValueError:
                pass

            if isinstance(packet, dict) and "data" in packet:
                msg_id = str(packet.get("id") or uuid.uuid4().hex)
                filename = packet.get("file") or "received.log"
                payload = wire_to_bytes(str(packet.get("data", "")))
                part = packet.get("part")
                parts = packet.get("parts")
                dedup_key = f"{msg_id}:{part}" if part is not None else msg_id
                if deduper.is_duplicate(dedup_key):
                    stats["duplicates"] += 1
                    if debug:
                        logger.debug(f"[DUPLICATE] {dedup_key} from {addr}")
                    continue
                src, seq = packet.get("src"), packet.get("seq")
                if src is not None and isinstance(seq, int):
                    seqs.observe(src, seq)
                else:
                    stats["legacy"] += 1
                if part is not None:
                    try:
                        part, parts = int(part), int(parts)
                        if not (0 <= part < parts <= 100000):
                            raise ValueError
                    except (TypeError, ValueError):
                        tlog.error("frag", f"Invalid fragment header from {addr}")
                        continue
                    payload = reasm.add(msg_id, part, parts, payload, filename)
                    if payload is None:
                        continue
            else:
                # Raw (non-JSON) datagram: forward as-is, no dedup possible
                filename = "received.log"
                payload = data
                msg_id = "raw"
                stats["legacy"] += 1

            payload = payload.rstrip(b"\r\n\x00")
            if not payload:
                continue
            stats["messages"] += 1
            if debug:
                logger.debug(f"[PROCESS] id={msg_id} file={filename} bytes={len(payload)}: {payload[:300]!r}")

            if forward_sock:
                try:
                    forward_sock.sendto(payload, siem_target)
                except OSError as e:
                    stats["siem_errors"] += 1
                    tlog.error("siem", f"Forward to SIEM {siem_target} failed: {e}")
            if writer:
                writer.write(filename, payload)
    finally:
        log_stats("[STATS] final")
        if writer:
            writer.close()
        recv_sock.close()
        if forward_sock:
            forward_sock.close()
        logger.info("Receiver stopped")
        print("\nRECEIVER stopped.")


# ============================================================================
# MAIN
# ============================================================================
def main():
    cfg, mode, args = parse_args()
    logger = setup_logging(cfg.log_file, cfg.log_level, mode, cfg.log_backup_count)
    try:
        if mode == "SENDER":
            asyncio.run(run_sender(cfg, logger, args.send_test))
        else:
            run_receiver(cfg, logger, args.send_test)
    except KeyboardInterrupt:
        print(f"\n{mode} stopped by user.")
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
