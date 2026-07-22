# mist-nac-radius-forwarder

Two independent services that forward Juniper Mist NAC webhooks as RFC-2866 RADIUS Accounting-Request packets to a FortiGate, so FortiGate RADIUS SSO (RSSO) can track authenticated identities. They subscribe to different Mist webhook topics and are not interchangeable — see the comparison below, or run both together.

Full installation, configuration, and deployment guide: [Mist_NAC_RADIUS_Guide.docx](Mist_NAC_RADIUS_Guide.docx).

## Requirements

Python 3.8+, standard library only — no third-party packages.

## Which one do I need?

| | `mist_nac_radius.py` (nac-accounting) | `mist_nac_events_radius.py` (nac-events) |
|---|---|---|
| Fires on | Session lifecycle stages | Each authorization decision |
| Acct-Status-Type | Start, Interim-Update, Stop | Start only — no Interim/Stop exists in this event stream |
| Framed-IP-Address (client IP) | Yes — from Update/Stop | No — never present in nac-events |
| Traffic counters / session duration | Yes | No |
| NAC role (Filter-Id) | No — not present in nac-accounting despite the field existing in the config | Yes — from `group_role` |
| VLAN (Tunnel attributes) | No | Yes — from `vlan` |
| Denied clients visible | No | Yes — `NAC_CLIENT_DENY`, logged only |

The nac-accounting forwarder gives you the more complete session record (a real Stop, and a client IP) but no role or VLAN. The nac-events forwarder gives you role and VLAN but only ever sends a Start-equivalent, and never a client IP. Run both together (section 22 of the guide) for the full picture — both send to the same FortiGate/RSSO entry.

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

Both `.ini` files are gitignored — they hold the RADIUS shared secret.

## Running as a service on Ubuntu

Both follow the same pattern — dedicated system account, `/opt/<name>` layout, a hardened systemd unit. Full step-by-step for each (including the unit file) is in the guide, sections 8 and 18. Summary for the nac-accounting forwarder:

```bash
sudo mkdir -p /opt/mist-radius
sudo cp mist_nac_radius.py mist-radius.ini.example /opt/mist-radius/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mist-radius
sudo chown -R mist-radius:mist-radius /opt/mist-radius
sudo cp /opt/mist-radius/mist-radius.ini.example /opt/mist-radius/mist-radius.ini
sudo chmod 640 /opt/mist-radius/mist-radius.ini   # edit it first
sudo chown mist-radius:mist-radius /opt/mist-radius/mist-radius.ini
```

`/etc/systemd/system/mist-radius.service`:

```ini
[Unit]
Description=Mist NAC to FortiGate RADIUS Accounting Forwarder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mist-radius
Group=mist-radius
WorkingDirectory=/opt/mist-radius
ExecStart=/usr/bin/python3 /opt/mist-radius/mist_nac_radius.py -c /opt/mist-radius/mist-radius.ini
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/opt/mist-radius/logs

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mist-radius
sudo systemctl status mist-radius
sudo journalctl -u mist-radius -f
```

The nac-events forwarder is identical in shape — `/opt/mist-events-radius`, a `mist-events-radius` system user, and `mist-events-radius.service` — see guide section 18. **If running both on the same host, give them different `listen_port` values** (they can't share a port).

## Logging and reliability

Both services share the same model:

- A daily activity log (`nac_accounting_YYYY-MM-DD.log` / `nac_events_YYYY-MM-DD.log`) — every event received and forwarded.
- A daily `errors_YYYY-MM-DD.log` — ERROR-level and above only, including full tracebacks from unhandled exceptions. Check this first when troubleshooting a headless deployment.
- A threaded HTTP listener and an in-process auto-restart with backoff if the server loop crashes unexpectedly, independent of systemd's `Restart=on-failure`.

## Known limitations of the nac-events forwarder

Read before deploying — see guide section 12.4:

- **No Stop.** nac-events fires once per authorization decision; Mist doesn't emit a corresponding disconnect event. RSSO entries created from this forwarder only expire via FortiGate's own idle timeout.
- **No client IP.** nac-events never includes one (auth happens before DHCP), so this forwarder can never populate Framed-IP-Address. Run the nac-accounting forwarder too if you need FortiGate to learn the client IP.
