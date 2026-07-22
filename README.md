# mist-nac-radius-forwarder

Forwards Juniper Mist NAC accounting webhooks as RFC-2866 RADIUS Accounting packets to a FortiGate, so FortiGate RADIUS SSO (RSSO) can track authenticated wireless identities. The client's Mist NAC role (`usergroup`) is forwarded too, as the standard RADIUS `Filter-Id` attribute.

Full installation, configuration, and deployment guide: [Mist_NAC_RADIUS_Guide.docx](Mist_NAC_RADIUS_Guide.docx).

## Requirements

Python 3.8+, standard library only — no third-party packages.

## Quick start

```bash
cp mist-radius.ini.example mist-radius.ini
$EDITOR mist-radius.ini   # set radius_host and radius_secret at minimum
python3 mist_nac_radius.py
```

`mist-radius.ini` is gitignored — it holds the RADIUS shared secret. Config file resolution order: `-c/--config` flag → `MIST_RADIUS_CONFIG` env var → `mist-radius.ini` next to the script.

## Running as a service on Ubuntu

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

See the [full guide](Mist_NAC_RADIUS_Guide.docx) for FortiGate RSSO setup, the Mist webhook configuration, log file layout, and troubleshooting.

## Logging and reliability

- `logs/nac_accounting_YYYY-MM-DD.log` — daily activity log (every event received and forwarded), including each session's `usergroup`.
- `logs/errors_YYYY-MM-DD.log` — ERROR-level and above only, including full tracebacks from unhandled exceptions and the `usergroup` of any session whose RADIUS send failed. Check this first when troubleshooting a headless deployment.
- The HTTP listener is threaded and the server auto-restarts in-process with backoff if it crashes unexpectedly, independent of systemd's `Restart=on-failure`.
