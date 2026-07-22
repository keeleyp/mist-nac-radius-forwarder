#!/usr/bin/env python3
"""
Mist NAC Accounting Webhook → FortiGate RADIUS Accounting Forwarder
====================================================================
Receives nac-accounting webhooks from Juniper Mist and forwards them
as RFC-2866 RADIUS Accounting-Request packets to a FortiGate firewall
so its RADIUS SSO (RSSO) feature can establish and track user identity.

Supported Mist event types → RADIUS Acct-Status-Type mapping:
  NAC_ACCOUNTING_START  → 1  (Start)
  NAC_ACCOUNTING_UPDATE → 3  (Interim-Update)
  NAC_ACCOUNTING_STOP   → 2  (Stop)

Usage:
  python3 mist_nac_radius.py [-c /path/to/mist-radius.ini]

Configuration:
  All settings live in mist-radius.ini (see mist-radius.ini.example).
  By default the script looks for mist-radius.ini in its own directory,
  or at the path given by the MIST_RADIUS_CONFIG environment variable,
  or via the -c/--config command-line flag.

Requirements:
  Python 3.8+ — no third-party packages needed.

FortiGate RSSO configuration:
  User & Authentication → RADIUS SSO → Create New
    - Primary RADIUS server: this host's IP
    - Shared secret: must match radius_secret in mist-radius.ini
    - Accounting port: 1813
    - RSSO attribute: User-Name
"""

import argparse
import configparser
import hashlib
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
from datetime import date, datetime, timezone
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
    if os.environ.get("MIST_RADIUS_CONFIG"):
        return os.environ["MIST_RADIUS_CONFIG"]
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "mist-radius.ini")


def load_config(path: str) -> configparser.ConfigParser:
    if not os.path.isfile(path):
        sys.exit(
            f"Config file not found: {path}\n"
            "Copy mist-radius.ini.example to mist-radius.ini and edit it."
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

# Directory where daily log files are written.
# Files are named: nac_accounting_YYYY-MM-DD.log
LOG_DIR = _cfg.get("logging", "log_dir", fallback="./logs")

# Optional Mist webhook secret (sent as X-Mist-Secret header). Empty/absent = disabled.
WEBHOOK_SECRET = _cfg.get("server", "webhook_secret", fallback="") or None

# ---------------------------------------------------------------------------
# RADIUS attribute type constants  (RFC 2865 / 2866)
# ---------------------------------------------------------------------------

ATTR_USER_NAME            =  1
ATTR_NAS_IP_ADDRESS       =  4
ATTR_FRAMED_IP_ADDRESS    =  8
ATTR_FILTER_ID            = 11   # Role / user group, for FortiGate policy matching
ATTR_CALLING_STATION_ID   = 31   # Client MAC
ATTR_CALLED_STATION_ID    = 30   # SSID
ATTR_NAS_IDENTIFIER       = 32
ATTR_ACCT_STATUS_TYPE     = 40
ATTR_ACCT_SESSION_ID      = 44
ATTR_ACCT_SESSION_TIME    = 46   # seconds
ATTR_ACCT_INPUT_OCTETS    = 42   # bytes NAS received from client
ATTR_ACCT_OUTPUT_OCTETS   = 43   # bytes NAS sent to client
ATTR_ACCT_INPUT_PACKETS   = 47
ATTR_ACCT_OUTPUT_PACKETS  = 48
ATTR_ACCT_TERMINATE_CAUSE = 49
ATTR_NAS_PORT_TYPE        = 61
ATTR_ACCT_INPUT_GIGAWORDS  = 52   # RFC 2869 — high 32 bits of Acct-Input-Octets
ATTR_ACCT_OUTPUT_GIGAWORDS = 53   # RFC 2869 — high 32 bits of Acct-Output-Octets

ACCT_STATUS_START         = 1
ACCT_STATUS_STOP          = 2
ACCT_STATUS_INTERIM       = 3

NAS_PORT_TYPE_WIRELESS    = 19   # IEEE 802.11

# Mist terminate_cause string → RFC 2866 Acct-Terminate-Cause code
TERMINATE_CAUSE_MAP = {
    "User-Request":        1,
    "Lost-Carrier":        2,
    "Lost-Service":        3,
    "Idle-Timeout":        4,
    "Session-Timeout":     5,
    "Admin-Reset":         6,
    "Admin-Reboot":        7,
    "Port-Error":          8,
    "NAS-Error":           9,
    "NAS-Request":        10,
    "NAS-Reboot":         11,
    "Port-Unneeded":      12,
    "Port-Preempted":     13,
    "Port-Suspended":     14,
    "Service-Unavailable":15,
    "Callback":           16,
    "User-Error":         17,
    "Host-Request":       18,
}

# Mist event type → RADIUS Acct-Status-Type
EVENT_TYPE_MAP = {
    "NAC_ACCOUNTING_START":  ACCT_STATUS_START,
    "NAC_ACCOUNTING_UPDATE": ACCT_STATUS_INTERIM,
    "NAC_ACCOUNTING_STOP":   ACCT_STATUS_STOP,
}

# ---------------------------------------------------------------------------
# Daily rotating log handler
# ---------------------------------------------------------------------------

class DailyFileHandler(logging.FileHandler):
    """
    Writes log records to a date-stamped file in LOG_DIR.
    At midnight it transparently closes the old file and opens a new one.
    The file is created if it doesn't exist, or appended to if it does.
    """

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
        # Roll over to a new file if the calendar date has changed
        if date.today().isoformat() != self._current_day:
            self.close()
            self.baseFilename = os.path.abspath(self._day_path())
            self.stream = self._open()
        super().emit(record)


def setup_logging(log_dir: str) -> None:
    """
    Configure root logger to write to stdout, a daily activity log, and a
    daily error log. The error log exists so that when this runs headless
    (as a service, with no console attached) nothing that would normally
    show up on screen — tracebacks, unhandled exceptions from worker
    threads — gets silently lost.
    """
    fmt = logging.Formatter(
        fmt="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)

    daily = DailyFileHandler(log_dir, "nac_accounting")
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
# RADIUS packet builder
# ---------------------------------------------------------------------------

def _attr(attr_type: int, value: bytes) -> bytes:
    """Encode one RADIUS TLV attribute: Type (1 byte), Length (1 byte), Value."""
    return struct.pack("BB", attr_type, 2 + len(value)) + value


def _coerce_uint(value):
    """
    Best-effort coercion of a Mist-supplied numeric field to a non-negative
    Python int. Returns None for anything that isn't a whole, non-negative
    number (wrong type, negative "unknown" sentinel, non-integral float).
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value.is_integer() and value >= 0:
        return int(value)
    return None


def _uint32_attr(attr_type: int, value, field_name: str) -> bytes:
    """
    Encode a single-attribute unsigned-32 field, guarding against values
    Mist can send that don't fit RADIUS's 32-bit range (e.g. a negative
    "unknown" sentinel). Invalid values are logged and omitted rather than
    aborting the whole packet.
    """
    coerced = _coerce_uint(value)
    if coerced is None or coerced > 0xFFFFFFFF:
        logging.warning("Ignoring out-of-range %s value %r", field_name, value)
        return b""
    return _attr(attr_type, struct.pack(">I", coerced))


def _octets_attr(attr_low: int, attr_high: int, value, field_name: str) -> bytes:
    """
    Encode a byte counter as Acct-Input/Output-Octets, plus the matching
    Gigawords attribute (RFC 2869 §5.1/5.2) when the value exceeds 32 bits
    — Mist's raw counters aren't capped at 4GB, but a single RADIUS
    attribute is. Negative/non-integer values are logged and omitted.
    """
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


def build_accounting_request(event: dict) -> bytes:
    """
    Build a complete RFC-2866 RADIUS Accounting-Request packet.

    Attributes included vary by event type:
      START  — User-Name, NAS-IP, MAC, Session-Id, SSID, Filter-Id, NAS-Port-Type
      UPDATE — as above + Framed-IP-Address, byte/packet counters
      STOP   — as above + Session-Time, Terminate-Cause

    The packet authenticator is:
      MD5(Code + ID + Length + 16×0x00 + Attributes + Secret)   [RFC 2866 §3]

    Args:
        event: Single event dict from the Mist nac-accounting webhook.

    Returns:
        Raw bytes of a RADIUS Accounting-Request packet.
    """
    event_type  = event.get("type", "")
    acct_status = EVENT_TYPE_MAP[event_type]   # KeyError intentional — validated before calling

    user       = event.get("username", "unknown")
    mac        = event.get("mac", "")
    nas_ip_str = event.get("nas_ip", "0.0.0.0")
    client_ip  = event.get("client_ip")         # present on UPDATE and STOP
    session_id = event.get("session_id", f"mist-{random.randint(0, 0xFFFFFFFF):08x}")
    ssid       = event.get("ssid", "")
    usergroup  = event.get("usergroup", "")     # NAC role — mapped to Filter-Id

    # Calling-Station-Id format: "2A-5B-B8-14-DA-3D"
    mac_fmt = (
        "-".join(mac[i:i+2].upper() for i in range(0, 12, 2))
        if len(mac) == 12 else mac
    )

    attrs = b""

    # --- Attributes present in all event types ---
    attrs += _attr(ATTR_ACCT_STATUS_TYPE,    struct.pack(">I", acct_status))
    attrs += _attr(ATTR_USER_NAME,           user.encode())
    attrs += _attr(ATTR_NAS_IP_ADDRESS,      socket.inet_aton(nas_ip_str))
    attrs += _attr(ATTR_CALLING_STATION_ID,  mac_fmt.encode())
    attrs += _attr(ATTR_ACCT_SESSION_ID,     session_id.encode())
    attrs += _attr(ATTR_NAS_PORT_TYPE,       struct.pack(">I", NAS_PORT_TYPE_WIRELESS))

    if ssid:
        attrs += _attr(ATTR_CALLED_STATION_ID, ssid.encode())

    if usergroup:
        attrs += _attr(ATTR_FILTER_ID, usergroup.encode())

    # --- Framed-IP-Address (present on UPDATE and STOP) ---
    if client_ip:
        try:
            attrs += _attr(ATTR_FRAMED_IP_ADDRESS, socket.inet_aton(client_ip))
        except OSError:
            logging.warning("Invalid client_ip '%s' — omitting Framed-IP-Address", client_ip)

    # --- Traffic counters (UPDATE and STOP) ---
    # Byte counters use Gigawords (RFC 2869) since Mist doesn't cap these at
    # 4GB but a single RADIUS attribute can't hold more than that.
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

    # --- Session duration and terminate cause (STOP only) ---
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

    # --- Assemble packet ---
    code       = 4   # Accounting-Request
    identifier = random.randint(0, 255)
    length     = 20 + len(attrs)   # 20 = fixed header size

    # Authenticator: MD5 over header (with zeroed auth field) + attrs + secret
    pre_auth = struct.pack(">BBH", code, identifier, length) + b"\x00" * 16 + attrs
    authenticator = hashlib.md5(pre_auth + RADIUS_SECRET_BYTES).digest()

    header = struct.pack(">BBH16s", code, identifier, length, authenticator)
    return header + attrs


# A single UDP socket is opened once and reused for every packet — avoids
# a socket create/destroy syscall pair on every webhook event.
_radius_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def send_radius(packet: bytes) -> None:
    """Send a RADIUS packet to the FortiGate via UDP."""
    _radius_socket.sendto(packet, (RADIUS_HOST, RADIUS_PORT))


def log_event(event: dict) -> None:
    """Write a structured summary of the event to the daily log file."""
    event_type = event.get("type", "UNKNOWN")
    user       = event.get("username", "?")
    mac        = event.get("mac", "?")
    client_ip  = event.get("client_ip", "-")
    session_id = event.get("session_id", "?")
    ssid       = event.get("ssid", "?")
    usergroup  = event.get("usergroup", "?")

    # Build a compact one-line summary; include stats when present
    parts = [
        f"type={event_type}",
        f"user={user}",
        f"mac={mac}",
        f"ip={client_ip}",
        f"session={session_id}",
        f"ssid={ssid}",
        f"usergroup={usergroup}",
    ]

    if event.get("rx_bytes") is not None:
        parts.append(f"rx_bytes={event['rx_bytes']} rx_pkts={event['rx_pkts']}")
        parts.append(f"tx_bytes={event['tx_bytes']} tx_pkts={event['tx_pkts']}")

    if event.get("session_duration_in_mins") is not None:
        parts.append(f"duration={event['session_duration_in_mins']}m")

    if event.get("terminate_cause"):
        parts.append(f"cause={event['terminate_cause']}")

    logging.info("  ".join(parts))

# ---------------------------------------------------------------------------
# HTTP webhook handler
# ---------------------------------------------------------------------------

class WebhookHandler(BaseHTTPRequestHandler):
    """Handles inbound HTTP POST requests from the Mist webhook service."""

    def do_POST(self):
        try:
            self._handle_post()
        except Exception:
            logging.exception("Unhandled error processing webhook from %s",
                               self.client_address[0])
            self._respond(500, "Internal Server Error")

    def _handle_post(self):
        # Validate optional shared secret
        if WEBHOOK_SECRET is not None:
            if self.headers.get("X-Mist-Secret", "") != WEBHOOK_SECRET:
                logging.warning("Rejected request with invalid secret from %s",
                                self.client_address[0])
                self._respond(401, "Unauthorized")
                return

        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)

        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            logging.warning("Malformed JSON from %s: %s", self.client_address[0], exc)
            self._respond(400, "Bad Request")
            return

        topic = payload.get("topic", "")
        if topic != "nac-accounting":
            logging.debug("Ignored topic '%s'", topic)
            self._respond(200, "OK")
            return

        events    = payload.get("events", [])
        forwarded = 0

        for event in events:
            event_type = event.get("type", "")
            if event_type not in EVENT_TYPE_MAP:
                logging.debug("Skipped unrecognised event type '%s'", event_type)
                continue

            log_event(event)

            try:
                packet = build_accounting_request(event)
                send_radius(packet)
                logging.info("RADIUS → %s:%d  type=%s  session=%s  usergroup=%s  (%d bytes)",
                             RADIUS_HOST, RADIUS_PORT,
                             event_type, event.get("session_id", "?"),
                             event.get("usergroup", "?"),
                             len(packet))
                forwarded += 1
            except Exception as exc:
                logging.error("Failed to send RADIUS for session %s (usergroup=%s): %s",
                              event.get("session_id", "?"), event.get("usergroup", "?"), exc)

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
    """Handles each webhook POST on its own thread so a slow RADIUS send
    (or a burst of events) doesn't stall other incoming requests."""

    daemon_threads = True

    def handle_error(self, request, client_address):
        # Default socketserver behaviour prints the traceback to stderr,
        # which is lost when running headless. Send it to the error log
        # instead. The server keeps serving other requests either way.
        logging.exception("Unhandled exception while handling request from %s",
                           client_address)


def main():
    setup_logging(LOG_DIR)
    logging.info("Config file       : %s", CONFIG_PATH)
    logging.info("Webhook receiver  : %s:%d", LISTEN_HOST, LISTEN_PORT)
    logging.info("RADIUS Accounting : %s:%d", RADIUS_HOST, RADIUS_PORT)
    logging.info("Log directory     : %s", os.path.abspath(LOG_DIR))

    # If the server loop itself dies unexpectedly (as opposed to a single
    # request failing, which handle_error already contains) log it and
    # restart rather than letting the process exit, since this runs as an
    # unattended service.
    backoff = 1
    while True:
        server = None
        try:
            server = ForwarderServer((LISTEN_HOST, LISTEN_PORT), WebhookHandler)
            logging.info("Server started.")
            backoff = 1
            server.serve_forever()
            break  # serve_forever only returns after shutdown() is called
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
