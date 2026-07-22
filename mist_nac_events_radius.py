#!/usr/bin/env python3
"""
Mist NAC Events Webhook → FortiGate RADIUS Accounting Forwarder
====================================================================
Receives nac-events webhooks from Juniper Mist and forwards each
NAC_CLIENT_PERMIT decision as an RFC-2866 RADIUS Accounting-Request
(Start) packet to a FortiGate firewall, so its RADIUS SSO (RSSO)
feature can establish user identity — including the client's NAC
role, via the Filter-Id and Class attributes, and VLAN, via the
RFC-2868 Tunnel attributes.

This is a separate integration from the original nac-accounting-based
forwarder (mist_nac_radius.py). nac-events fires once per
authorization decision rather than per session lifecycle stage, which
has real consequences:

  - Every forwarded record is Acct-Status-Type=Start. There is no
    Interim-Update or Stop counterpart in this event stream — Mist
    does not send a corresponding "session ended" nac-events event,
    so this service cannot tell FortiGate when a client disconnects.
    RSSO entries created from these records will only ever expire via
    FortiGate's own idle/session timeout, not via an explicit Stop.
  - There is no client IP in a nac-events payload (auth happens before
    DHCP), so Framed-IP-Address is never sent. FortiGate RSSO must
    learn the IP some other way (e.g. DHCP snooping) if you need one.
  - There are no traffic counters or session duration in this event
    type, so those RADIUS attributes are never sent either.

Supported Mist nac-events event types:
  NAC_CLIENT_PERMIT → forwarded as an Acct-Status-Type=Start record
  NAC_CLIENT_DENY   → logged (WARNING) for visibility, not forwarded
                       to RADIUS — there is no session to account for
  anything else     → logged at DEBUG and skipped

Usage:
  python3 mist_nac_events_radius.py [-c /path/to/mist-events-radius.ini]

Configuration:
  All settings live in mist-events-radius.ini (see
  mist-events-radius.ini.example). Resolved via -c/--config, the
  MIST_EVENTS_RADIUS_CONFIG environment variable, or a file of that
  name next to the script.

Requirements:
  Python 3.8+ — no third-party packages needed.

FortiGate RSSO configuration:
  User & Authentication → RADIUS SSO → Create New
    - Primary RADIUS server: this host's IP
    - Shared secret: must match radius_secret in mist-events-radius.ini
    - Accounting port: 1813
    - RSSO attribute: User-Name
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
    if os.environ.get("MIST_EVENTS_RADIUS_CONFIG"):
        return os.environ["MIST_EVENTS_RADIUS_CONFIG"]
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "mist-events-radius.ini")


def load_config(path: str) -> configparser.ConfigParser:
    if not os.path.isfile(path):
        sys.exit(
            f"Config file not found: {path}\n"
            "Copy mist-events-radius.ini.example to mist-events-radius.ini and edit it."
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
LOG_DIR = _cfg.get("logging", "log_dir", fallback="./logs")

# Optional Mist webhook secret. Empty/absent = signature verification disabled.
WEBHOOK_SECRET = _cfg.get("server", "webhook_secret", fallback="") or None

# Which optional attribute groups to include, derived from fields that are
# only present in nac-events (not the older nac-accounting stream).
SEND_FILTER_ID   = _cfg.getboolean("attributes", "send_filter_id", fallback=True)
SEND_CLASS       = _cfg.getboolean("attributes", "send_class", fallback=True)
SEND_VLAN_ATTRS  = _cfg.getboolean("attributes", "send_vlan_attrs", fallback=True)

# ---------------------------------------------------------------------------
# RADIUS attribute type constants  (RFC 2865 / 2866 / 2868)
# ---------------------------------------------------------------------------

ATTR_USER_NAME               =  1
ATTR_NAS_IP_ADDRESS          =  4
ATTR_SERVICE_TYPE            =  6
ATTR_FILTER_ID               = 11   # NAC role, from group_role
ATTR_CLASS                   = 25   # NAC role, from group_role — sent alongside Filter-Id;
                                     # a known-working non-Mist NAS on this network conveys
                                     # role via Class rather than Filter-Id
ATTR_CALLED_STATION_ID       = 30   # SSID
ATTR_CALLING_STATION_ID      = 31   # Client MAC
ATTR_ACCT_STATUS_TYPE        = 40
ATTR_ACCT_SESSION_ID         = 44
ATTR_NAS_PORT_TYPE           = 61
ATTR_TUNNEL_TYPE             = 64   # RFC 2868 — tagged
ATTR_TUNNEL_MEDIUM_TYPE      = 65   # RFC 2868 — tagged
ATTR_TUNNEL_PRIVATE_GROUP_ID = 81   # RFC 2868 — tagged, VLAN ID as string

ACCT_STATUS_START  = 1   # The only status this service ever sends — see module docstring
SERVICE_TYPE_FRAMED = 2  # RFC 2865 §5.6

NAS_PORT_TYPE_MAP = {
    "wireless": 19,   # IEEE 802.11
    "wired":    15,   # Ethernet
}
NAS_PORT_TYPE_DEFAULT = NAS_PORT_TYPE_MAP["wireless"]

TUNNEL_TYPE_VLAN        = 13   # RFC 2868 Tunnel-Type value for VLAN
TUNNEL_MEDIUM_TYPE_8023 = 6    # RFC 2868 Tunnel-Medium-Type value for IEEE-802
TUNNEL_TAG              = 1    # Single-tunnel-per-packet convention (RFC 2868 §3.1)

# Mist nac-events event types this service acts on
EVENT_TYPE_PERMIT = "NAC_CLIENT_PERMIT"
EVENT_TYPE_DENY   = "NAC_CLIENT_DENY"

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
        if date.today().isoformat() != self._current_day:
            self.close()
            self.baseFilename = os.path.abspath(self._day_path())
            self.stream = self._open()
        super().emit(record)


def setup_logging(log_dir: str) -> None:
    """
    Configure root logger to write to stdout, a daily activity log, and a
    daily error log — so tracebacks and unhandled exceptions are captured
    even when this runs headless with no console attached.
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

    daily = DailyFileHandler(log_dir, "nac_events")
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
    """Encode a plain RADIUS TLV attribute: Type (1 byte), Length (1 byte), Value."""
    return struct.pack("BB", attr_type, 2 + len(value)) + value


def _tagged_attr(attr_type: int, tag: int, value: bytes) -> bytes:
    """Encode an RFC-2868 tunnel attribute: Type, Length, Tag, Value."""
    return struct.pack("BBB", attr_type, 3 + len(value), tag) + value


def build_accounting_request(event: dict) -> bytes:
    """
    Build an RFC-2866 RADIUS Accounting-Request (Start) packet from a
    NAC_CLIENT_PERMIT nac-events event.

    Always Acct-Status-Type=Start — see module docstring for why there's
    no Interim-Update/Stop equivalent and no Framed-IP-Address.

    Args:
        event: Single NAC_CLIENT_PERMIT event dict from the Mist
            nac-events webhook.

    Returns:
        Raw bytes of a RADIUS Accounting-Request packet.
    """
    user = (
        event.get("username")
        or event.get("idp_username")
        or event.get("cert_cn")
        or "unknown"
    )
    mac         = event.get("mac", "")
    nas_ip_str  = event.get("nas_ip", "0.0.0.0")
    session_id  = event.get("session_id", f"mist-{random.randint(0, 0xFFFFFFFF):08x}")
    ssid        = event.get("ssid", "")
    group_role  = event.get("group_role", "")
    vlan_str    = event.get("vlan", "")
    client_type = event.get("client_type", "wireless")

    # Calling-Station-Id format: "2A-5B-B8-14-DA-3D"
    mac_fmt = (
        "-".join(mac[i:i+2].upper() for i in range(0, 12, 2))
        if len(mac) == 12 else mac
    )

    nas_port_type = NAS_PORT_TYPE_MAP.get(client_type, NAS_PORT_TYPE_DEFAULT)

    attrs = b""
    attrs += _attr(ATTR_ACCT_STATUS_TYPE,   struct.pack(">I", ACCT_STATUS_START))
    attrs += _attr(ATTR_SERVICE_TYPE,       struct.pack(">I", SERVICE_TYPE_FRAMED))
    attrs += _attr(ATTR_USER_NAME,          user.encode())
    attrs += _attr(ATTR_NAS_IP_ADDRESS,     socket.inet_aton(nas_ip_str))
    attrs += _attr(ATTR_CALLING_STATION_ID, mac_fmt.encode())
    attrs += _attr(ATTR_ACCT_SESSION_ID,    session_id.encode())
    attrs += _attr(ATTR_NAS_PORT_TYPE,      struct.pack(">I", nas_port_type))

    if ssid:
        attrs += _attr(ATTR_CALLED_STATION_ID, ssid.encode())

    # --- NAC role (Filter-Id and Class) ---
    # group_role is the field Mist itself uses to compute the Filter-Id it
    # returns to the NAS (visible in resp_attrs) — idp_role is a separate,
    # possibly multi-valued IdP group list and is not a reliable substitute.
    # Class is sent alongside Filter-Id because a confirmed-working non-Mist
    # NAS on this network conveys role via Class (echoing the value from its
    # own RADIUS Access-Accept, per RFC 2865 §5.25) rather than Filter-Id.
    if group_role:
        if SEND_FILTER_ID:
            attrs += _attr(ATTR_FILTER_ID, group_role.encode())
        if SEND_CLASS:
            attrs += _attr(ATTR_CLASS, group_role.encode())

    # --- VLAN (RFC 2868 tunnel attributes) ---
    if SEND_VLAN_ATTRS and vlan_str:
        try:
            vlan_id = int(vlan_str)
        except ValueError:
            logging.warning("Non-numeric vlan '%s' — omitting Tunnel attributes", vlan_str)
        else:
            attrs += _tagged_attr(ATTR_TUNNEL_TYPE, TUNNEL_TAG,
                                   TUNNEL_TYPE_VLAN.to_bytes(3, "big"))
            attrs += _tagged_attr(ATTR_TUNNEL_MEDIUM_TYPE, TUNNEL_TAG,
                                   TUNNEL_MEDIUM_TYPE_8023.to_bytes(3, "big"))
            attrs += _tagged_attr(ATTR_TUNNEL_PRIVATE_GROUP_ID, TUNNEL_TAG,
                                   str(vlan_id).encode())

    # --- Assemble packet ---
    code       = 4   # Accounting-Request
    identifier = random.randint(0, 255)
    length     = 20 + len(attrs)   # 20 = fixed header size

    # Authenticator: MD5 over header (with zeroed auth field) + attrs + secret
    pre_auth = struct.pack(">BBH", code, identifier, length) + b"\x00" * 16 + attrs
    authenticator = hashlib.md5(pre_auth + RADIUS_SECRET_BYTES).digest()

    header = struct.pack(">BBH16s", code, identifier, length, authenticator)
    return header + attrs


# A single UDP socket is opened once and reused for every packet.
_radius_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def send_radius(packet: bytes) -> None:
    """Send a RADIUS packet to the FortiGate via UDP."""
    _radius_socket.sendto(packet, (RADIUS_HOST, RADIUS_PORT))


def log_event(event: dict, level: int = logging.INFO) -> None:
    """Write a structured summary of the event to the daily log file."""
    user = (
        event.get("username")
        or event.get("idp_username")
        or event.get("cert_cn")
        or "?"
    )
    parts = [
        f"type={event.get('type', 'UNKNOWN')}",
        f"user={user}",
        f"mac={event.get('mac', '?')}",
        f"session={event.get('session_id', '?')}",
        f"ssid={event.get('ssid', '?')}",
        f"vlan={event.get('vlan', '?')}",
        f"group_role={event.get('group_role', '?')}",
        f"nacrule={event.get('nacrule_name', '?')}",
        f"auth_type={event.get('auth_type', '?')}",
    ]
    logging.log(level, "  ".join(parts))

# ---------------------------------------------------------------------------
# Webhook signature verification
# ---------------------------------------------------------------------------

def _valid_signature(raw_body: bytes, signature_header: str) -> bool:
    """
    Verify Mist's X-Mist-Signature header: hex-encoded HMAC-SHA1 of the raw
    request body, keyed with the webhook secret configured on both sides.
    """
    expected = hmac.new(WEBHOOK_SECRET.encode(), raw_body, hashlib.sha1).hexdigest()
    return hmac.compare_digest(expected, signature_header.strip().lower())

# ---------------------------------------------------------------------------
# HTTP webhook handler
# ---------------------------------------------------------------------------

class WebhookHandler(BaseHTTPRequestHandler):
    """Handles inbound HTTP POST requests from the Mist webhook service."""

    def do_POST(self):
        try:
            self._handle_post()
        except (BrokenPipeError, ConnectionResetError):
            # Client disconnected before we finished writing a response —
            # a normal network condition, not an application bug. Don't try
            # to write a 500 here too; that write would fail the same way.
            logging.info("Client %s disconnected before response could be sent",
                         self.client_address[0])
        except Exception:
            logging.exception("Unhandled error processing webhook from %s",
                               self.client_address[0])
            try:
                self._respond(500, "Internal Server Error")
            except (BrokenPipeError, ConnectionResetError):
                pass

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
        if topic != "nac-events":
            logging.debug("Ignored topic '%s'", topic)
            self._respond(200, "OK")
            return

        events    = payload.get("events", [])
        forwarded = 0

        for event in events:
            event_type = event.get("type", "")

            if event_type == EVENT_TYPE_PERMIT:
                log_event(event)
                try:
                    packet = build_accounting_request(event)
                    send_radius(packet)
                    logging.info(
                        "RADIUS → %s:%d  type=%s  session=%s  user=%s  group_role=%s  (%d bytes)",
                        RADIUS_HOST, RADIUS_PORT, event_type,
                        event.get("session_id", "?"), event.get("username", "?"),
                        event.get("group_role", "?"), len(packet),
                    )
                    forwarded += 1
                except Exception as exc:
                    logging.error(
                        "Failed to send RADIUS for session %s (user=%s): %s",
                        event.get("session_id", "?"), event.get("username", "?"), exc,
                    )
            elif event_type == EVENT_TYPE_DENY:
                # Denied — no session was established, nothing to send to
                # RADIUS, but worth logging for visibility.
                log_event(event, level=logging.WARNING)
            else:
                logging.debug("Skipped unrecognised event type '%s'", event_type)

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
    """Handles each webhook POST on its own thread so a burst of events
    doesn't stall other incoming requests."""

    daemon_threads = True

    def handle_error(self, request, client_address):
        # A client disconnecting before we finish writing a response (e.g.
        # Mist's webhook sender closing the connection early) surfaces here
        # as BrokenPipeError/ConnectionResetError. That's a normal network
        # condition, not an application bug — log it quietly instead of as
        # an ERROR with a full traceback, so errors_*.log stays meaningful.
        exc_type = sys.exc_info()[0]
        if exc_type is not None and issubclass(exc_type, (BrokenPipeError, ConnectionResetError)):
            logging.info("Client %s disconnected before response could be sent", client_address)
            return
        logging.exception("Unhandled exception while handling request from %s",
                           client_address)


def main():
    setup_logging(LOG_DIR)
    logging.info("Config file       : %s", CONFIG_PATH)
    logging.info("Webhook receiver  : %s:%d", LISTEN_HOST, LISTEN_PORT)
    logging.info("RADIUS Accounting : %s:%d", RADIUS_HOST, RADIUS_PORT)
    logging.info("Log directory     : %s", os.path.abspath(LOG_DIR))
    logging.info("Filter-Id (role)  : %s", "enabled" if SEND_FILTER_ID else "disabled")
    logging.info("Class (role)      : %s", "enabled" if SEND_CLASS else "disabled")
    logging.info("VLAN attributes   : %s", "enabled" if SEND_VLAN_ATTRS else "disabled")

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
