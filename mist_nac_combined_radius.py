#!/usr/bin/env python3
"""
Mist NAC Combined Webhook → FortiGate RADIUS Accounting Forwarder
====================================================================
Receives BOTH nac-accounting and nac-events webhooks from Juniper
Mist on a single listener and correlates them per client session
before sending RFC-2866 RADIUS Accounting-Request packets to a
FortiGate, so a single, enriched record reaches RSSO instead of two
independent, incomplete ones.

Why: nac-accounting carries session lifecycle (Start/Update/Stop) and
the client IP, but no NAC role or VLAN. nac-events carries the role
(group_role → Filter-Id) and VLAN, but only ever fires once per
authorization decision — no Update/Stop, no client IP. Running the
two original single-purpose forwarders (mist_nac_radius.py,
mist_nac_events_radius.py) independently means FortiGate gets two
separate, each-incomplete streams. This service correlates them by
session_id instead:

  - When both a NAC_CLIENT_PERMIT (nac-events) and a
    NAC_ACCOUNTING_START (nac-accounting) have arrived for the same
    session_id, a single merged Start packet is sent, combining
    Filter-Id/VLAN with the normal session/NAS fields.
  - If only one of the two arrives, a correlation timeout (default 5s,
    see [correlation] start_correlation_timeout_seconds) fires and
    whatever is available is sent anyway — a client that never gets a
    matching event on the other topic (e.g. a NAC_CLIENT_DENY with no
    accounting Start) shouldn't wait forever or never appear at all.
  - Once group_role/vlan are learned for a session_id, they're cached
    in memory and attached to that session's later
    NAC_ACCOUNTING_UPDATE/STOP packets too, since nac-events never
    fires again for the same session.
  - A session_id that has already had its initial Start sent won't be
    sent a second one by a late/duplicate webhook delivery.

Usage:
  python3 mist_nac_combined_radius.py [-c /path/to/mist-combined-radius.ini]

Configuration:
  All settings live in mist-combined-radius.ini (see
  mist-combined-radius.ini.example). Resolved via -c/--config, the
  MIST_COMBINED_RADIUS_CONFIG environment variable, or a file of that
  name next to the script.

Mist webhook setup:
  Point Mist at this service for BOTH topics on the same URL/port —
  either a single webhook subscribed to both nac-accounting and
  nac-events (if your Mist tenant's webhook UI allows multi-topic
  selection), or two separate webhooks both delivering to this same
  URL. Dispatch is by the "topic" field in each payload, so either
  setup works.

Requirements:
  Python 3.8+ — no third-party packages needed.
"""

import argparse
import configparser
import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import random
import socket
import struct
import sys
import threading
import time
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _resolve_config_path() -> str:
    """Determine which config file to load: -c flag > env var > script directory."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-c", "--config")
    args, _ = parser.parse_known_args()

    if args.config:
        return args.config
    if os.environ.get("MIST_COMBINED_RADIUS_CONFIG"):
        return os.environ["MIST_COMBINED_RADIUS_CONFIG"]
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "mist-combined-radius.ini")


def load_config(path: str) -> configparser.ConfigParser:
    if not os.path.isfile(path):
        sys.exit(
            f"Config file not found: {path}\n"
            "Copy mist-combined-radius.ini.example to mist-combined-radius.ini and edit it."
        )
    parser = configparser.ConfigParser()
    parser.read(path)
    return parser


CONFIG_PATH = _resolve_config_path()
_cfg = load_config(CONFIG_PATH)

LISTEN_HOST = _cfg.get("server", "listen_host", fallback="0.0.0.0")
LISTEN_PORT = _cfg.getint("server", "listen_port", fallback=8080)

RADIUS_HOST   = _cfg.get("radius", "radius_host")
RADIUS_PORT   = _cfg.getint("radius", "radius_port", fallback=1813)
RADIUS_SECRET = _cfg.get("radius", "radius_secret")
RADIUS_SECRET_BYTES = RADIUS_SECRET.encode()

LOG_DIR = _cfg.get("logging", "log_dir", fallback="./logs")

WEBHOOK_SECRET = _cfg.get("server", "webhook_secret", fallback="") or None

SEND_FILTER_ID  = _cfg.getboolean("attributes", "send_filter_id", fallback=True)
SEND_CLASS      = _cfg.getboolean("attributes", "send_class", fallback=True)
SEND_VLAN_ATTRS = _cfg.getboolean("attributes", "send_vlan_attrs", fallback=True)

CORRELATION_TIMEOUT_SECONDS = _cfg.getfloat("correlation", "start_correlation_timeout_seconds", fallback=5.0)
ENRICHMENT_CACHE_TTL_HOURS  = _cfg.getfloat("correlation", "enrichment_cache_ttl_hours", fallback=12.0)
CLEANUP_INTERVAL_SECONDS    = _cfg.getfloat("correlation", "cleanup_interval_seconds", fallback=300.0)

# ---------------------------------------------------------------------------
# RADIUS attribute type constants  (RFC 2865 / 2866 / 2868 / 2869)
# ---------------------------------------------------------------------------

ATTR_USER_NAME               =  1
ATTR_NAS_IP_ADDRESS          =  4
ATTR_SERVICE_TYPE            =  6
ATTR_FRAMED_IP_ADDRESS       =  8
ATTR_FILTER_ID               = 11   # NAC role, from group_role
ATTR_CLASS                   = 25   # NAC role, from group_role — sent alongside Filter-Id;
                                     # a known-working non-Mist NAS on this network conveys
                                     # role via Class rather than Filter-Id
ATTR_CALLED_STATION_ID       = 30   # SSID
ATTR_CALLING_STATION_ID      = 31   # Client MAC
ATTR_ACCT_STATUS_TYPE        = 40
ATTR_ACCT_INPUT_OCTETS       = 42
ATTR_ACCT_OUTPUT_OCTETS      = 43
ATTR_ACCT_SESSION_ID         = 44
ATTR_ACCT_SESSION_TIME       = 46
ATTR_ACCT_INPUT_PACKETS      = 47
ATTR_ACCT_OUTPUT_PACKETS     = 48
ATTR_ACCT_TERMINATE_CAUSE    = 49
ATTR_ACCT_INPUT_GIGAWORDS    = 52   # RFC 2869 — high 32 bits of Acct-Input-Octets
ATTR_ACCT_OUTPUT_GIGAWORDS   = 53   # RFC 2869 — high 32 bits of Acct-Output-Octets
ATTR_NAS_PORT_TYPE           = 61
ATTR_TUNNEL_TYPE             = 64   # RFC 2868 — tagged
ATTR_TUNNEL_MEDIUM_TYPE      = 65   # RFC 2868 — tagged
ATTR_TUNNEL_PRIVATE_GROUP_ID = 81   # RFC 2868 — tagged, VLAN ID as string

ACCT_STATUS_START   = 1
ACCT_STATUS_STOP    = 2
ACCT_STATUS_INTERIM = 3
SERVICE_TYPE_FRAMED = 2   # RFC 2865 §5.6

NAS_PORT_TYPE_MAP = {
    "wireless": 19,   # IEEE 802.11
    "wired":    15,   # Ethernet
}
NAS_PORT_TYPE_DEFAULT = NAS_PORT_TYPE_MAP["wireless"]

TUNNEL_TYPE_VLAN        = 13   # RFC 2868 Tunnel-Type value for VLAN
TUNNEL_MEDIUM_TYPE_8023 = 6    # RFC 2868 Tunnel-Medium-Type value for IEEE-802
TUNNEL_TAG              = 1    # Single-tunnel-per-packet convention (RFC 2868 §3.1)

# Mist terminate_cause string → RFC 2866 Acct-Terminate-Cause code
TERMINATE_CAUSE_MAP = {
    "User-Request": 1, "Lost-Carrier": 2, "Lost-Service": 3, "Idle-Timeout": 4,
    "Session-Timeout": 5, "Admin-Reset": 6, "Admin-Reboot": 7, "Port-Error": 8,
    "NAS-Error": 9, "NAS-Request": 10, "NAS-Reboot": 11, "Port-Unneeded": 12,
    "Port-Preempted": 13, "Port-Suspended": 14, "Service-Unavailable": 15,
    "Callback": 16, "User-Error": 17, "Host-Request": 18,
}

# Mist event type → RADIUS Acct-Status-Type, for nac-accounting events
ACCOUNTING_EVENT_TYPE_MAP = {
    "NAC_ACCOUNTING_START":  ACCT_STATUS_START,
    "NAC_ACCOUNTING_UPDATE": ACCT_STATUS_INTERIM,
    "NAC_ACCOUNTING_STOP":   ACCT_STATUS_STOP,
}

EVENT_TYPE_PERMIT = "NAC_CLIENT_PERMIT"
EVENT_TYPE_DENY   = "NAC_CLIENT_DENY"

# ---------------------------------------------------------------------------
# Daily rotating log handler
# ---------------------------------------------------------------------------

class DailyFileHandler(logging.FileHandler):
    """Writes log records to a date-stamped file in LOG_DIR, rolling over at midnight."""

    def __init__(self, log_dir: str, prefix: str):
        self._log_dir     = log_dir
        self._prefix      = prefix
        self._current_day = None
        os.makedirs(log_dir, exist_ok=True)
        super().__init__(self._day_path(), mode="a", encoding="utf-8", delay=False)

    def _day_path(self) -> str:
        self._current_day = date.today().isoformat()
        return os.path.join(self._log_dir, f"{self._prefix}_{self._current_day}.log")

    def emit(self, record: logging.LogRecord) -> None:
        if date.today().isoformat() != self._current_day:
            self.close()
            self.baseFilename = os.path.abspath(self._day_path())
            self.stream = self._open()
        super().emit(record)


def setup_logging(log_dir: str) -> None:
    fmt = logging.Formatter(
        fmt="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)

    daily = DailyFileHandler(log_dir, "nac_combined")
    daily.setFormatter(fmt)
    root.addHandler(daily)

    errors = DailyFileHandler(log_dir, "errors")
    errors.setLevel(logging.ERROR)
    errors.setFormatter(fmt)
    root.addHandler(errors)

    def _log_uncaught_exception(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        logging.critical("Uncaught exception in main thread",
                          exc_info=(exc_type, exc_value, exc_tb))

    def _log_thread_exception(args: threading.ExceptHookArgs) -> None:
        logging.error("Unhandled exception in thread %s",
                       args.thread.name if args.thread else "?",
                       exc_info=(args.exc_type, args.exc_value, args.exc_traceback))

    sys.excepthook = _log_uncaught_exception
    threading.excepthook = _log_thread_exception

# ---------------------------------------------------------------------------
# Per-session correlation and enrichment state
# ---------------------------------------------------------------------------
#
# _pending:    session_id -> {"permit": event|None, "start": event|None, "timer": Timer|None}
#              Exists only while waiting for the other half of an initial Start.
# _enrichment: session_id -> {"group_role": str, "vlan": str, "cached_at": float}
#              Learned from a NAC_CLIENT_PERMIT; applied to that session's later
#              Update/Stop packets. Cleared on Stop, swept by TTL otherwise.
# _started:    session_id -> float (time.monotonic() when the initial Start was sent)
#              Prevents a duplicate/late webhook delivery from sending a second
#              initial Start for the same session. Cleared on Stop, swept by TTL.

_state_lock = threading.Lock()
_pending    = {}
_enrichment = {}
_started    = {}


def _cleanup_sweep() -> None:
    """Periodically purge enrichment/started entries older than the TTL, for
    sessions that never received a Stop (roamed away, device went dark, etc.)."""
    max_age = ENRICHMENT_CACHE_TTL_HOURS * 3600
    while True:
        time.sleep(CLEANUP_INTERVAL_SECONDS)
        now = time.monotonic()
        with _state_lock:
            stale_enrichment = [sid for sid, v in _enrichment.items() if now - v["cached_at"] > max_age]
            for sid in stale_enrichment:
                del _enrichment[sid]
            stale_started = [sid for sid, ts in _started.items() if now - ts > max_age]
            for sid in stale_started:
                del _started[sid]
        if stale_enrichment or stale_started:
            logging.debug("Cleanup swept %d enrichment / %d started entries",
                           len(stale_enrichment), len(stale_started))

# ---------------------------------------------------------------------------
# RADIUS packet builder
# ---------------------------------------------------------------------------

def _attr(attr_type: int, value: bytes) -> bytes:
    return struct.pack("BB", attr_type, 2 + len(value)) + value


def _tagged_attr(attr_type: int, tag: int, value: bytes) -> bytes:
    return struct.pack("BBB", attr_type, 3 + len(value), tag) + value


def _coerce_uint(value):
    """Best-effort coercion of a Mist-supplied numeric field to a non-negative int."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value.is_integer() and value >= 0:
        return int(value)
    return None


def _uint32_attr(attr_type: int, value, field_name: str) -> bytes:
    coerced = _coerce_uint(value)
    if coerced is None or coerced > 0xFFFFFFFF:
        logging.warning("Ignoring out-of-range %s value %r", field_name, value)
        return b""
    return _attr(attr_type, struct.pack(">I", coerced))


def _octets_attr(attr_low: int, attr_high: int, value, field_name: str) -> bytes:
    """Byte counter via Acct-Input/Output-Octets + Gigawords (RFC 2869) for
    values that exceed 32 bits — Mist's counters aren't capped at 4GB."""
    coerced = _coerce_uint(value)
    if coerced is None:
        logging.warning("Ignoring invalid %s value %r", field_name, value)
        return b""
    gigawords, remainder = divmod(coerced, 1 << 32)
    attrs = _attr(attr_low, struct.pack(">I", remainder))
    if gigawords:
        if gigawords > 0xFFFFFFFF:
            logging.warning("%s value %r exceeds Gigawords range — truncating", field_name, value)
            gigawords &= 0xFFFFFFFF
        attrs += _attr(attr_high, struct.pack(">I", gigawords))
    return attrs


def _session_identity(event: dict):
    """Fields common to both event types (same names in both Mist webhooks)."""
    user = (
        event.get("username")
        or event.get("idp_username")
        or event.get("cert_cn")
        or "unknown"
    )
    mac        = event.get("mac", "")
    nas_ip_str = event.get("nas_ip", "0.0.0.0")
    session_id = event.get("session_id") or f"mist-{random.randint(0, 0xFFFFFFFF):08x}"
    ssid       = event.get("ssid", "")
    return user, mac, nas_ip_str, session_id, ssid


def _mac_fmt(mac: str) -> str:
    return (
        "-".join(mac[i:i+2].upper() for i in range(0, 12, 2))
        if len(mac) == 12 else mac
    )


def _role_vlan_attrs(group_role: str, vlan_str: str) -> bytes:
    attrs = b""
    if group_role:
        # Class is sent alongside Filter-Id because a confirmed-working
        # non-Mist NAS on this network conveys role via Class (echoing the
        # value from its own RADIUS Access-Accept, per RFC 2865 §5.25)
        # rather than Filter-Id.
        if SEND_FILTER_ID:
            attrs += _attr(ATTR_FILTER_ID, group_role.encode())
        if SEND_CLASS:
            attrs += _attr(ATTR_CLASS, group_role.encode())
    if SEND_VLAN_ATTRS and vlan_str:
        try:
            vlan_id = int(vlan_str)
        except ValueError:
            logging.warning("Non-numeric vlan '%s' — omitting Tunnel attributes", vlan_str)
        else:
            attrs += _tagged_attr(ATTR_TUNNEL_TYPE, TUNNEL_TAG, TUNNEL_TYPE_VLAN.to_bytes(3, "big"))
            attrs += _tagged_attr(ATTR_TUNNEL_MEDIUM_TYPE, TUNNEL_TAG, TUNNEL_MEDIUM_TYPE_8023.to_bytes(3, "big"))
            attrs += _tagged_attr(ATTR_TUNNEL_PRIVATE_GROUP_ID, TUNNEL_TAG, str(vlan_id).encode())
    return attrs


def _finish_packet(attrs: bytes) -> bytes:
    code       = 4   # Accounting-Request
    identifier = random.randint(0, 255)
    length     = 20 + len(attrs)
    pre_auth = struct.pack(">BBH", code, identifier, length) + b"\x00" * 16 + attrs
    authenticator = hashlib.md5(pre_auth + RADIUS_SECRET_BYTES).digest()
    header = struct.pack(">BBH16s", code, identifier, length, authenticator)
    return header + attrs


def build_start_packet(accounting_event: dict, permit_event: dict) -> bytes:
    """
    Build the initial Start packet. At least one of accounting_event /
    permit_event is provided; when both are, fields shared by both use the
    nac-accounting copy (the canonical session-lifecycle record), and
    role/VLAN come from the permit event.
    """
    primary = accounting_event or permit_event
    user, mac, nas_ip_str, session_id, ssid = _session_identity(primary)

    client_type = (permit_event or {}).get("client_type", "wireless")
    group_role  = (permit_event or {}).get("group_role", "")
    vlan_str    = (permit_event or {}).get("vlan", "")
    nas_port_type = NAS_PORT_TYPE_MAP.get(client_type, NAS_PORT_TYPE_DEFAULT)

    attrs = b""
    attrs += _attr(ATTR_ACCT_STATUS_TYPE,   struct.pack(">I", ACCT_STATUS_START))
    attrs += _attr(ATTR_SERVICE_TYPE,       struct.pack(">I", SERVICE_TYPE_FRAMED))
    attrs += _attr(ATTR_USER_NAME,          user.encode())
    attrs += _attr(ATTR_NAS_IP_ADDRESS,     socket.inet_aton(nas_ip_str))
    attrs += _attr(ATTR_CALLING_STATION_ID, _mac_fmt(mac).encode())
    attrs += _attr(ATTR_ACCT_SESSION_ID,    session_id.encode())
    attrs += _attr(ATTR_NAS_PORT_TYPE,      struct.pack(">I", nas_port_type))
    if ssid:
        attrs += _attr(ATTR_CALLED_STATION_ID, ssid.encode())
    attrs += _role_vlan_attrs(group_role, vlan_str)

    return _finish_packet(attrs)


def build_update_stop_packet(event: dict, enrichment: dict) -> bytes:
    """Build an Update/Stop packet from a nac-accounting event, same shape as
    mist_nac_radius.py, with Filter-Id/Class/VLAN appended from cached
    enrichment if this session ever had a NAC_CLIENT_PERMIT."""
    event_type  = event.get("type", "")
    acct_status = ACCOUNTING_EVENT_TYPE_MAP[event_type]

    user, mac, nas_ip_str, session_id, ssid = _session_identity(event)
    client_ip = event.get("client_ip")

    attrs = b""
    attrs += _attr(ATTR_ACCT_STATUS_TYPE,   struct.pack(">I", acct_status))
    attrs += _attr(ATTR_SERVICE_TYPE,       struct.pack(">I", SERVICE_TYPE_FRAMED))
    attrs += _attr(ATTR_USER_NAME,          user.encode())
    attrs += _attr(ATTR_NAS_IP_ADDRESS,     socket.inet_aton(nas_ip_str))
    attrs += _attr(ATTR_CALLING_STATION_ID, _mac_fmt(mac).encode())
    attrs += _attr(ATTR_ACCT_SESSION_ID,    session_id.encode())
    attrs += _attr(ATTR_NAS_PORT_TYPE,      struct.pack(">I", NAS_PORT_TYPE_DEFAULT))
    if ssid:
        attrs += _attr(ATTR_CALLED_STATION_ID, ssid.encode())

    if enrichment:
        attrs += _role_vlan_attrs(enrichment.get("group_role", ""), enrichment.get("vlan", ""))

    if client_ip:
        try:
            attrs += _attr(ATTR_FRAMED_IP_ADDRESS, socket.inet_aton(client_ip))
        except OSError:
            logging.warning("Invalid client_ip '%s' — omitting Framed-IP-Address", client_ip)

    rx_bytes = event.get("rx_bytes")
    tx_bytes = event.get("tx_bytes")
    rx_pkts  = event.get("rx_pkts")
    tx_pkts  = event.get("tx_pkts")
    if rx_bytes is not None:
        attrs += _octets_attr(ATTR_ACCT_INPUT_OCTETS, ATTR_ACCT_INPUT_GIGAWORDS, rx_bytes, "rx_bytes")
    if tx_bytes is not None:
        attrs += _octets_attr(ATTR_ACCT_OUTPUT_OCTETS, ATTR_ACCT_OUTPUT_GIGAWORDS, tx_bytes, "tx_bytes")
    if rx_pkts is not None:
        attrs += _uint32_attr(ATTR_ACCT_INPUT_PACKETS, rx_pkts, "rx_pkts")
    if tx_pkts is not None:
        attrs += _uint32_attr(ATTR_ACCT_OUTPUT_PACKETS, tx_pkts, "tx_pkts")

    duration_mins = event.get("session_duration_in_mins")
    if duration_mins is not None:
        try:
            duration_secs = round(float(duration_mins) * 60)
        except (TypeError, ValueError):
            logging.warning("Invalid session_duration_in_mins %r — omitting Acct-Session-Time", duration_mins)
        else:
            attrs += _uint32_attr(ATTR_ACCT_SESSION_TIME, duration_secs, "session_duration_in_mins")

    terminate_cause_str = event.get("terminate_cause")
    if terminate_cause_str:
        cause_code = TERMINATE_CAUSE_MAP.get(terminate_cause_str, 0)
        if cause_code:
            attrs += _attr(ATTR_ACCT_TERMINATE_CAUSE, struct.pack(">I", cause_code))
        else:
            logging.warning("Unknown terminate_cause '%s' — omitting attribute", terminate_cause_str)

    return _finish_packet(attrs)


_radius_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def send_radius(packet: bytes) -> None:
    _radius_socket.sendto(packet, (RADIUS_HOST, RADIUS_PORT))

# ---------------------------------------------------------------------------
# Correlation logic
# ---------------------------------------------------------------------------

def _send_start_and_log(session_id: str, accounting_event, permit_event, reason: str) -> None:
    try:
        packet = build_start_packet(accounting_event, permit_event)
        send_radius(packet)
        source = "accounting+permit" if (accounting_event and permit_event) else \
                 ("accounting-only" if accounting_event else "permit-only")
        primary = accounting_event or permit_event
        logging.info(
            "RADIUS → %s:%d  type=Start(%s, %s)  session=%s  user=%s  group_role=%s  (%d bytes)",
            RADIUS_HOST, RADIUS_PORT, source, reason, session_id,
            primary.get("username", "?"), (permit_event or {}).get("group_role", "?"),
            len(packet),
        )
    except Exception as exc:
        logging.error("Failed to send Start RADIUS for session %s: %s", session_id, exc)


def _fallback_send(session_id: str) -> None:
    """Timer callback: correlation window expired with only one half present."""
    with _state_lock:
        entry = _pending.pop(session_id, None)
        if entry is None:
            return  # the other half arrived and handled this already
        if session_id in _started:
            return  # shouldn't happen, but never double-send
        _started[session_id] = time.monotonic()
    _send_start_and_log(session_id, entry["start"], entry["permit"], "timeout")


def _handle_permit(event: dict) -> None:
    session_id = event.get("session_id")
    group_role = event.get("group_role", "")
    vlan       = event.get("vlan", "")

    if not session_id:
        logging.warning("PERMIT event with no session_id — sending standalone, no correlation possible")
        _send_start_and_log(f"mist-{random.randint(0, 0xFFFFFFFF):08x}", None, event, "no-session-id")
        return

    with _state_lock:
        _enrichment[session_id] = {"group_role": group_role, "vlan": vlan, "cached_at": time.monotonic()}

        if session_id in _started:
            # Late permit for an already-started session — enrichment is now
            # cached for future Update/Stop packets, nothing more to send.
            return

        entry = _pending.setdefault(session_id, {"permit": None, "start": None, "timer": None})
        entry["permit"] = event

        if entry["start"] is not None:
            if entry["timer"]:
                entry["timer"].cancel()
            del _pending[session_id]
            _started[session_id] = time.monotonic()
            accounting_event, permit_event = entry["start"], entry["permit"]
        else:
            if entry["timer"] is None:
                entry["timer"] = threading.Timer(CORRELATION_TIMEOUT_SECONDS, _fallback_send, args=[session_id])
                entry["timer"].daemon = True
                entry["timer"].start()
            return

    _send_start_and_log(session_id, accounting_event, permit_event, "correlated")


def _handle_deny(event: dict) -> None:
    session_id = event.get("session_id")
    if session_id:
        with _state_lock:
            entry = _pending.pop(session_id, None)
            if entry and entry["timer"]:
                entry["timer"].cancel()
    logging.warning(
        "type=%s  user=%s  mac=%s  session=%s  nacrule=%s",
        event.get("type"), event.get("username", "?"), event.get("mac", "?"),
        session_id or "?", event.get("nacrule_name", "?"),
    )


def _handle_accounting_start(event: dict) -> None:
    session_id = event.get("session_id")

    if not session_id:
        logging.warning("Accounting START with no session_id — sending standalone, no correlation possible")
        _send_start_and_log(f"mist-{random.randint(0, 0xFFFFFFFF):08x}", event, None, "no-session-id")
        return

    with _state_lock:
        if session_id in _started:
            logging.debug("Duplicate accounting START for already-started session %s — ignoring", session_id)
            return

        entry = _pending.setdefault(session_id, {"permit": None, "start": None, "timer": None})
        entry["start"] = event

        if entry["permit"] is not None:
            if entry["timer"]:
                entry["timer"].cancel()
            del _pending[session_id]
            _started[session_id] = time.monotonic()
            accounting_event, permit_event = entry["start"], entry["permit"]
        else:
            if entry["timer"] is None:
                entry["timer"] = threading.Timer(CORRELATION_TIMEOUT_SECONDS, _fallback_send, args=[session_id])
                entry["timer"].daemon = True
                entry["timer"].start()
            return

    _send_start_and_log(session_id, accounting_event, permit_event, "correlated")


def _handle_accounting_update_stop(event: dict) -> None:
    session_id = event.get("session_id", "?")
    event_type = event.get("type", "")

    with _state_lock:
        enrichment = dict(_enrichment.get(session_id, {}))

    try:
        packet = build_update_stop_packet(event, enrichment)
        send_radius(packet)
        logging.info(
            "RADIUS → %s:%d  type=%s  session=%s  user=%s  group_role=%s  (%d bytes)",
            RADIUS_HOST, RADIUS_PORT, event_type, session_id,
            event.get("username", "?"), enrichment.get("group_role", "?"), len(packet),
        )
    except Exception as exc:
        logging.error("Failed to send RADIUS for session %s: %s", session_id, exc)

    if event_type == "NAC_ACCOUNTING_STOP":
        with _state_lock:
            _enrichment.pop(session_id, None)
            _started.pop(session_id, None)
            _pending.pop(session_id, None)


def log_accounting_event(event: dict) -> None:
    parts = [
        f"type={event.get('type', 'UNKNOWN')}",
        f"user={event.get('username', '?')}",
        f"mac={event.get('mac', '?')}",
        f"ip={event.get('client_ip', '-')}",
        f"session={event.get('session_id', '?')}",
        f"ssid={event.get('ssid', '?')}",
    ]
    if event.get("rx_bytes") is not None:
        parts.append(f"rx_bytes={event['rx_bytes']} rx_pkts={event.get('rx_pkts')}")
        parts.append(f"tx_bytes={event['tx_bytes']} tx_pkts={event.get('tx_pkts')}")
    if event.get("session_duration_in_mins") is not None:
        parts.append(f"duration={event['session_duration_in_mins']}m")
    if event.get("terminate_cause"):
        parts.append(f"cause={event['terminate_cause']}")
    logging.info("  ".join(parts))


def log_permit_event(event: dict) -> None:
    parts = [
        f"type={event.get('type', 'UNKNOWN')}",
        f"user={event.get('username', '?')}",
        f"mac={event.get('mac', '?')}",
        f"session={event.get('session_id', '?')}",
        f"ssid={event.get('ssid', '?')}",
        f"vlan={event.get('vlan', '?')}",
        f"group_role={event.get('group_role', '?')}",
        f"nacrule={event.get('nacrule_name', '?')}",
        f"auth_type={event.get('auth_type', '?')}",
    ]
    logging.info("  ".join(parts))

# ---------------------------------------------------------------------------
# Webhook signature verification
# ---------------------------------------------------------------------------

def _valid_signature(raw_body: bytes, signature_header: str) -> bool:
    """Verify Mist's X-Mist-Signature header: hex HMAC-SHA1 of the raw body."""
    expected = hmac.new(WEBHOOK_SECRET.encode(), raw_body, hashlib.sha1).hexdigest()
    return hmac.compare_digest(expected, signature_header.strip().lower())

# ---------------------------------------------------------------------------
# HTTP webhook handler
# ---------------------------------------------------------------------------

class WebhookHandler(BaseHTTPRequestHandler):
    """Handles inbound HTTP POST requests from the Mist webhook service, for
    both nac-accounting and nac-events topics."""

    def do_POST(self):
        try:
            self._handle_post()
        except Exception:
            logging.exception("Unhandled error processing webhook from %s",
                               self.client_address[0])
            self._respond(500, "Internal Server Error")

    def _handle_post(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)

        if WEBHOOK_SECRET is not None:
            signature = self.headers.get("X-Mist-Signature", "")
            if not signature or not _valid_signature(raw_body, signature):
                logging.warning("Rejected request with invalid X-Mist-Signature from %s",
                                self.client_address[0])
                self._respond(401, "Unauthorized")
                return

        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            logging.warning("Malformed JSON from %s: %s", self.client_address[0], exc)
            self._respond(400, "Bad Request")
            return

        topic = payload.get("topic", "")
        events = payload.get("events", [])

        if topic == "nac-accounting":
            for event in events:
                event_type = event.get("type", "")
                if event_type not in ACCOUNTING_EVENT_TYPE_MAP:
                    logging.debug("Skipped unrecognised nac-accounting event type '%s'", event_type)
                    continue
                log_accounting_event(event)
                if event_type == "NAC_ACCOUNTING_START":
                    _handle_accounting_start(event)
                else:
                    _handle_accounting_update_stop(event)

        elif topic == "nac-events":
            for event in events:
                event_type = event.get("type", "")
                if event_type == EVENT_TYPE_PERMIT:
                    log_permit_event(event)
                    _handle_permit(event)
                elif event_type == EVENT_TYPE_DENY:
                    _handle_deny(event)
                else:
                    logging.debug("Skipped unrecognised nac-events event type '%s'", event_type)

        else:
            logging.debug("Ignored topic '%s'", topic)

        self._respond(200, "OK")

    def _respond(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, fmt, *args):
        logging.debug("HTTP %s — %s", self.client_address[0], fmt % args)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

class ForwarderServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        logging.exception("Unhandled exception while handling request from %s",
                           client_address)


def main():
    setup_logging(LOG_DIR)
    logging.info("Config file           : %s", CONFIG_PATH)
    logging.info("Webhook receiver      : %s:%d", LISTEN_HOST, LISTEN_PORT)
    logging.info("RADIUS Accounting     : %s:%d", RADIUS_HOST, RADIUS_PORT)
    logging.info("Log directory         : %s", os.path.abspath(LOG_DIR))
    logging.info("Filter-Id (role)      : %s", "enabled" if SEND_FILTER_ID else "disabled")
    logging.info("Class (role)          : %s", "enabled" if SEND_CLASS else "disabled")
    logging.info("VLAN attributes       : %s", "enabled" if SEND_VLAN_ATTRS else "disabled")
    logging.info("Correlation timeout   : %.1fs", CORRELATION_TIMEOUT_SECONDS)
    logging.info("Enrichment cache TTL  : %.1fh", ENRICHMENT_CACHE_TTL_HOURS)

    cleanup_thread = threading.Thread(target=_cleanup_sweep, daemon=True, name="cleanup-sweep")
    cleanup_thread.start()

    backoff = 1
    while True:
        server = None
        try:
            server = ForwarderServer((LISTEN_HOST, LISTEN_PORT), WebhookHandler)
            logging.info("Server started.")
            backoff = 1
            server.serve_forever()
            break
        except KeyboardInterrupt:
            logging.info("Shutting down.")
            break
        except Exception:
            logging.exception("Server crashed unexpectedly — restarting in %ds", backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
        finally:
            if server is not None:
                server.server_close()


if __name__ == "__main__":
    main()
