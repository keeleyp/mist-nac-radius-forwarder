# mist-nac-radius-forwarder

Three services that forward Juniper Mist NAC webhooks as RFC-2866 RADIUS Accounting-Request packets to a FortiGate, so FortiGate RADIUS SSO (RSSO) can track authenticated identities. See the comparison below to pick one.

Full installation, configuration, and deployment guide: [Mist_NAC_RADIUS_Guide.docx](Mist_NAC_RADIUS_Guide.docx).

## Requirements

Python 3.8+, standard library only — no third-party packages.

## Which one do I need?

| | `mist_nac_radius.py` (nac-accounting) | `mist_nac_events_radius.py` (nac-events) | `mist_nac_combined_radius.py` (both, correlated) |
|---|---|---|---|
| Fires on | Session lifecycle stages | Each authorization decision | Both, merged per `session_id` |
| Acct-Status-Type | Start, Interim-Update, Stop | Start only | Start, Interim-Update, Stop |
| Framed-IP-Address (client IP) | Yes — from Update/Stop | No — never present in nac-events | Yes — from Update/Stop |
| Traffic counters / session duration | Yes | No | Yes |
| NAC role (Filter-Id / Class) | No | Yes — from `group_role` | Yes — carried onto later Update/Stop too |
| VLAN (Tunnel attributes) | No | Yes — from `vlan` | Yes |
| Denied clients visible | No | Yes — logged only | Yes — logged only |
| Webhooks to configure | One (nac-accounting) | One (nac-events) | Two topics, same URL/port |

**`mist_nac_combined_radius.py` is the recommended choice** when you need both role/VLAN and a full session lifecycle with client IP — it correlates the two webhook topics per session instead of requiring you to run and reconcile two separate streams yourself. For a role/VLAN-only deployment, running `mist_nac_events_radius.py` alone is simpler than standing up correlation state you don't need.

## Combined forwarder — quick start (recommended)

```bash
cp mist-combined-radius.ini.example mist-combined-radius.ini
$EDITOR mist-combined-radius.ini   # set radius_host and radius_secret at minimum
python3 mist_nac_combined_radius.py
```

Point Mist at this single URL/port for **both** the `nac-accounting` and `nac-events` topics — one webhook with both selected, or two webhooks pointing at the same URL. It correlates `NAC_CLIENT_PERMIT` (role/VLAN) with `NAC_ACCOUNTING_START` (session/IP) by `session_id`, sending one merged Start packet — waiting up to `start_correlation_timeout_seconds` (default 5s) for both halves before sending with whatever's available. Learned role/VLAN is cached in memory and attached to that session's later Update/Stop packets too. Guide sections 22–31.

Config resolution order: `-c/--config` flag → `MIST_COMBINED_RADIUS_CONFIG` env var → `mist-combined-radius.ini` next to the script.

## nac-accounting forwarder — quick start

```bash
cp mist-radius.ini.example mist-radius.ini
$EDITOR mist-radius.ini   # set radius_host and radius_secret at minimum
python3 mist_nac_radius.py
```

Config resolution order: `-c/--config` flag → `MIST_RADIUS_CONFIG` env var → `mist-radius.ini` next to the script.

## nac-events forwarder — quick start

```bash
cp mist-events-radius.ini.example mist-events-radius.ini
$EDITOR mist-events-radius.ini   # set radius_host and radius_secret at minimum
python3 mist_nac_events_radius.py
```

Config resolution order: `-c/--config` flag → `MIST_EVENTS_RADIUS_CONFIG` env var → `mist-events-radius.ini` next to the script. Verifies Mist's `X-Mist-Signature` header (hex HMAC-SHA1 of the request body) when `webhook_secret` is set.

All `.ini` files are gitignored — they hold the RADIUS shared secret.

## Role attribute: Filter-Id and Class

The nac-events and combined forwarders send the client's NAC role (`group_role`) as **both** RADIUS `Filter-Id` (11) and `Class` (25), each independently toggleable (`send_filter_id`, `send_class` in `[attributes]`). Both were added after comparing this project's output against a packet capture of a known-working, non-Mist 802.1X deployment on the same FortiGate: that NAS conveys role via `Class` rather than `Filter-Id`, because RFC 2865 §5.25 requires a NAS to echo back whatever `Class` value it received in its own RADIUS Access-Accept. Sending both covers a FortiGate/RSSO configuration keyed on either one. `Service-Type = Framed` is also always sent on every packet, matching that same reference capture.

## Running as a service on Ubuntu

All three follow the same pattern — dedicated system account, `/opt/<name>` layout, a hardened systemd unit. Full step-by-step for each (including the unit file) is in the guide, sections 8, 18, and 28. Summary for the combined forwarder:

```bash
sudo mkdir -p /opt/mist-combined-radius
sudo cp mist_nac_combined_radius.py mist-combined-radius.ini.example /opt/mist-combined-radius/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mist-combined-radius
sudo chown -R mist-combined-radius:mist-combined-radius /opt/mist-combined-radius
sudo cp /opt/mist-combined-radius/mist-combined-radius.ini.example /opt/mist-combined-radius/mist-combined-radius.ini
sudo chmod 640 /opt/mist-combined-radius/mist-combined-radius.ini   # edit it first
sudo chown mist-combined-radius:mist-combined-radius /opt/mist-combined-radius/mist-combined-radius.ini
```

`/etc/systemd/system/mist-combined-radius.service`:

```ini
[Unit]
Description=Mist NAC Combined (accounting + events) to FortiGate RADIUS Forwarder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mist-combined-radius
Group=mist-combined-radius
WorkingDirectory=/opt/mist-combined-radius
ExecStart=/usr/bin/python3 /opt/mist-combined-radius/mist_nac_combined_radius.py -c /opt/mist-combined-radius/mist-combined-radius.ini
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/opt/mist-combined-radius/logs

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mist-combined-radius
sudo systemctl status mist-combined-radius
sudo journalctl -u mist-combined-radius -f
```

The other two forwarders are identical in shape — `/opt/mist-radius` + `mist-radius.service`, and `/opt/mist-events-radius` + `mist-events-radius.service` — see guide sections 8 and 18. **If running the two standalone forwarders together on the same host** (guide §32, an alternative to the combined forwarder), give them different `listen_port` values — they can't share a port. The combined forwarder doesn't have this concern; it's one process on one port.

## Logging and reliability

All three services share the same model:

- A daily activity log (`nac_accounting_*.log` / `nac_events_*.log` / `nac_combined_*.log`) — every event received and forwarded.
- A daily `errors_YYYY-MM-DD.log` — ERROR-level and above only, including full tracebacks from unhandled exceptions. Check this first when troubleshooting a headless deployment.
- A threaded HTTP listener and an in-process auto-restart with backoff if the server loop crashes unexpectedly, independent of systemd's `Restart=on-failure`.
- Byte counters (`rx_bytes`/`tx_bytes`) are encoded with RFC 2869 Gigawords when they exceed 32 bits, instead of failing the whole packet — a real production issue on long-lived, high-traffic sessions, fixed in v3.1.

## Known limitations of the nac-events forwarder

Read before deploying — see guide section 12.4. (The combined forwarder doesn't have either of these, since it also sources from nac-accounting.)

- **No Stop.** nac-events fires once per authorization decision; Mist doesn't emit a corresponding disconnect event. RSSO entries created from this forwarder only expire via FortiGate's own idle timeout.
- **No client IP.** nac-events never includes one (auth happens before DHCP), so this forwarder can never populate Framed-IP-Address.

## Combined forwarder: correlation behavior

- **Merge**: a `NAC_CLIENT_PERMIT` and `NAC_ACCOUNTING_START` sharing a `session_id` are merged into one Start packet.
- **Timeout fallback**: if only one arrives within `start_correlation_timeout_seconds` (default 5s), it's sent alone rather than waiting indefinitely — important for clients that get denied (no accounting Start will ever follow) or a webhook that's lost.
- **Enrichment persists**: once learned, role/VLAN are cached in memory (`enrichment_cache_ttl_hours`, default 12h) and attached to that session's later Update/Stop packets.
- **Dedup**: a session that already had its initial Start sent won't get a second one from a late or duplicate webhook delivery.
- **In-memory only**: a restart clears any mid-correlation sessions and cached enrichment — see guide §29.
