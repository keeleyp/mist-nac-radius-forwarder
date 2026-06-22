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
  python3 mist_nac_radius.py

Requirements:
  Python 3.8+ — no third-party packages needed.

FortiGate RSSO configuration:
  User & Authentication → RADIUS SSO → Create New
    - Primary RADIUS server: this host's IP
    - Shared secret: must match RADIUS_SECRET below
    - Accounting port: 1813
    - RSSO attribute: User-Name
"""

import hashlib
import json
import logging
import logging.handlers
import os
import random
import socket
import struct
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LISTEN_HOST  = "0.0.0.0"       # Bind to all interfaces
LISTEN_PORT  = 8080             # Port forwarded through your firewall to this host

RADIUS_HOST   = "172.16.0.12"  # FortiGate IP address
RADIUS_PORT   = 1813            # RADIUS Accounting port (RFC 2866 default)
RADIUS_SECRET = "changeme"     # Shared secret — must match FortiGate RSSO config

# Directory where daily log files are written.
# Files are named: nac_accounting_YYYY-MM-DD.log
LOG_DIR = "./logs"

# Optional Mist webhook secret (sent as X-Mist-Secret header). None = disabled.
WEBHOOK_SECRET = None

# ---------------------------------------------------------------------------
# RADIUS attribute type constants  (RFC 2865 / 2866)
# ---------------------------------------------------------------------------

ATTR_USER_NAME            =  1
ATTR_NAS_IP_ADDRESS       =  4
ATTR_FRAMED_IP_ADDRESS    =  8
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

    def __init__(self, log_dir: str):
        self._log_dir     = log_dir
        self._current_day = None
        os.makedirs(log_dir, exist_ok=True)
        super().__init__(self._day_path(), mode="a", encoding="utf-8", delay=False)

    def _day_path(self) -> str:
        self._current_day = date.today().isoformat()
        return os.path.join(self._log_dir, f"nac_accounting_{self._current_day}.log")

    def emit(self, record: logging.LogRecord) -> None:
        # Roll over to a new file if the calendar date has changed
        if date.today().isoformat() != self._current_day:
            self.close()
            self.baseFilename = os.path.abspath(self._day_path())
            self.stream = self._open()
        super().emit(record)


def setup_logging(log_dir: str) -> None:
    """Configure root logger to write to both stdout and a daily log file."""
    fmt = logging.Formatter(
        fmt="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)

    daily = DailyFileHandler(log_dir)
    daily.setFormatter(fmt)
    root.addHandler(daily)

# ---------------------------------------------------------------------------
# RADIUS packet builder
# ---------------------------------------------------------------------------

def _attr(attr_type: int, value: bytes) -> bytes:
    """Encode one RADIUS TLV attribute: Type (1 byte), Length (1 byte), Value."""
    return struct.pack("BB", attr_type, 2 + len(value)) + value


def build_accounting_request(event: dict) -> bytes:
    """
    Build a complete RFC-2866 RADIUS Accounting-Request packet.

    Attributes included vary by event type:
      START  — User-Name, NAS-IP, MAC, Session-Id, SSID, NAS-Port-Type
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

    # --- Framed-IP-Address (present on UPDATE and STOP) ---
    if client_ip:
        try:
            attrs += _attr(ATTR_FRAMED_IP_ADDRESS, socket.inet_aton(client_ip))
        except OSError:
            logging.warning("Invalid client_ip '%s' — omitting Framed-IP-Address", client_ip)

    # --- Traffic counters (UPDATE and STOP) ---
    rx_bytes = event.get("rx_bytes")
    tx_bytes = event.get("tx_bytes")
    rx_pkts  = event.get("rx_pkts")
    tx_pkts  = event.get("tx_pkts")

    if rx_bytes is not None:
        attrs += _attr(ATTR_ACCT_INPUT_OCTETS,   struct.pack(">I", rx_bytes))
    if tx_bytes is not None:
        attrs += _attr(ATTR_ACCT_OUTPUT_OCTETS,  struct.pack(">I", tx_bytes))
    if rx_pkts is not None:
        attrs += _attr(ATTR_ACCT_INPUT_PACKETS,  struct.pack(">I", rx_pkts))
    if tx_pkts is not None:
        attrs += _attr(ATTR_ACCT_OUTPUT_PACKETS, struct.pack(">I", tx_pkts))

    # --- Session duration and terminate cause (STOP only) ---
    duration_mins = event.get("session_duration_in_mins")
    if duration_mins is not None:
        attrs += _attr(ATTR_ACCT_SESSION_TIME, struct.pack(">I", duration_mins * 60))

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
    # Encode secret to bytes if it was set as a plain string in the config
    secret   = RADIUS_SECRET.encode() if isinstance(RADIUS_SECRET, str) else RADIUS_SECRET
    pre_auth = struct.pack(">BBH", code, identifier, length) + b"\x00" * 16 + attrs
    authenticator = hashlib.md5(pre_auth + secret).digest()

    header = struct.pack(">BBH16s", code, identifier, length, authenticator)
    return header + attrs


def send_radius(packet: bytes) -> None:
    """Send a RADIUS packet to the FortiGate via UDP."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(packet, (RADIUS_HOST, RADIUS_PORT))


def log_event(event: dict) -> None:
    """Write a structured summary of the event to the daily log file."""
    event_type = event.get("type", "UNKNOWN")
    user       = event.get("username", "?")
    mac        = event.get("mac", "?")
    client_ip  = event.get("client_ip", "-")
    session_id = event.get("session_id", "?")
    ssid       = event.get("ssid", "?")

    # Build a compact one-line summary; include stats when present
    parts = [
        f"type={event_type}",
        f"user={user}",
        f"mac={mac}",
        f"ip={client_ip}",
        f"session={session_id}",
        f"ssid={ssid}",
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
                logging.info("RADIUS → %s:%d  type=%s  session=%s  (%d bytes)",
                             RADIUS_HOST, RADIUS_PORT,
                             event_type, event.get("session_id", "?"),
                             len(packet))
                forwarded += 1
            except Exception as exc:
                logging.error("Failed to send RADIUS for session %s: %s",
                              event.get("session_id", "?"), exc)

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

def main():
    setup_logging(LOG_DIR)
    logging.info("Webhook receiver  : %s:%d", LISTEN_HOST, LISTEN_PORT)
    logging.info("RADIUS Accounting : %s:%d", RADIUS_HOST, RADIUS_PORT)
    logging.info("Log directory     : %s", os.path.abspath(LOG_DIR))

    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), WebhookHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
