# LANtern

LANtern is a read-only network switch audit tool. It connects to Cisco IOS / IOS-XE switches over SSH (or reads offline config backups), collects inventory, estimates hardening on a 0–100 scale, tracks remediation status per check, and keeps scan history.

> Scores are grep-based estimates, not a full security review.

## Features

- **Setting:** scan groups, live SSH scan, password change.
- **Offline Audit:** upload a switch config backup (txt/cfg); no network access needed.
- **Devices:** inventory with platform, IOS version, score, and history sparkline.
- **Audit Report:** printable per-switch report with check results and fix suggestions (placeholders such as `<...>`; never applied automatically).
- **Hardening:** all devices side by side, with a donut chart per category.
- **VLANs, MACs, Link quality, Port problems:** built from collected interface, MAC, and counter data. Vendor names come from an OUI list.
- **Remediation statuses:** open, in progress, fixed pending, accepted risk, false positive; re-evaluate from stored config.

### Security principles
- Read-only: LANtern never pushes configuration to switches.
- Scan credentials are used once, kept in memory, and never stored.
- Fix suggestions are for human review only.

## Requirements

- Linux with systemd (examples use Debian/Ubuntu commands)
- Python 3.10 or newer, with `venv`
- nginx (reverse proxy)
- TCP 22 reachability to switches (only for live scans)
- Optional: a DNS name and TLS certificate (recommended)

## Install (step by step)

Run the commands as a user with `sudo`. Paths used:

| Item | Path |
|---|---|
| Application | `/opt/lantern` |
| Data (database, admin hash) | `/opt/lantern/data` |
| Environment file | `/etc/lantern.env` |
| systemd unit | `/etc/systemd/system/lantern.service` |
| nginx site | `/etc/nginx/sites-available/lantern` |
| App port (localhost only) | `8001` |

### 1. Install system packages
```
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nginx git
```

### 2. Create the service user and download the code
```
sudo useradd -r -m -d /opt/lantern -s /usr/sbin/nologin lantern
sudo git clone https://github.com/<your-user>/lantern.git /opt/lantern
sudo mkdir -p /opt/lantern/data
```
Without git, copy the project folder (or the zip, extracted) to `/opt/lantern`.

### 3. Python virtual environment
```
cd /opt/lantern
sudo python3 -m venv venv
sudo venv/bin/pip install -r requirements.txt
sudo chown -R lantern: /opt/lantern
```

### 4. Create the environment file `/etc/lantern.env`
Generate a secret key:
```
openssl rand -hex 32
```
Generate the admin password hash (you will type the password; it is not shown on screen):
```
/opt/lantern/venv/bin/python -c "from werkzeug.security import generate_password_hash as g; import getpass; print(g(getpass.getpass('Admin password: ')))"
```
Create the file:
```
sudo nano /etc/lantern.env
```
Content:
```
SECRET_KEY=<output of openssl>
ADMIN_USER=admin
ADMIN_PASS_HASH='<output of the hash command>'
DATA_DIR=/opt/lantern/data
COOKIE_SECURE=1
LANTERN_GITHUB=https://github.com/<your-user>/lantern
```
Lock it down:
```
sudo chmod 600 /etc/lantern.env
```
Use `COOKIE_SECURE=0` only for a plain-HTTP test.

### 5. Default login
The default login is **username `admin`, password `admin`** if you use `admin` in step 4. Use this only for the first login.

Change it right away: **Setting → Change password**. The new hash is saved in `/opt/lantern/data/admin.hash` and overrides `ADMIN_PASS_HASH`.

Do not leave `admin` / `admin` on a reachable server.

### 6. Install the systemd service
```
sudo cp /opt/lantern/deploy/lantern.service /etc/systemd/system/lantern.service
sudo systemctl daemon-reload
sudo systemctl enable --now lantern
sudo systemctl is-active lantern             # expect: active
curl -sI http://127.0.0.1:8001/ | head -1    # expect: HTTP/1.1 302
```

### 7. Configure nginx
```
sudo cp /opt/lantern/deploy/nginx.conf /etc/nginx/sites-available/lantern
sudo nano /etc/nginx/sites-available/lantern     # set server_name to your hostname
sudo ln -sf /etc/nginx/sites-available/lantern /etc/nginx/sites-enabled/lantern
sudo nginx -t && sudo systemctl reload nginx
```
Optionally restrict access by adding `allow 10.0.0.0/8; deny all;` in the server block.

### 8. TLS (recommended)
Point your DNS name to the server, then:
```
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d lantern.example.com
```

### 9. First use
1. Open `https://lantern.example.com` (or `http://<server-ip>` for a test).
2. Log in as `admin`, then change the password in **Setting**.
3. In **Setting → Step 1**, create a scan group with switch IPs or a subnet.
4. In **Step 2**, enter the SSH username and password, choose the group, and start the scan. Credentials are not saved.
5. Or use **Offline Audit** and upload a config backup.

## Updating

```
sudo cp -a /opt/lantern/data /root/lantern-data-backup-$(date +%F)
cd /opt/lantern
sudo git pull
sudo venv/bin/pip install -r requirements.txt
sudo systemctl restart lantern
```
The database (`data/audit.db`) and `data/admin.hash` are not in git and are kept.

## Troubleshooting

| Symptom | Check |
|---|---|
| 502 Bad Gateway | `sudo systemctl status lantern`; `sudo journalctl -u lantern -n 60 --no-pager` |
| Login fails | `ADMIN_PASS_HASH` is correct; `/opt/lantern/data/admin.hash` exists; username matches `ADMIN_USER` |
| Login cookie not kept over HTTP | Set `COOKIE_SECURE=0` for plain-HTTP tests |
| SSH scan fails | Port 22 reachable; SSH enabled on the switch; legacy SSH algorithms are flagged as weak |
| "Too many open files" | Confirm `LimitNOFILE=65535` in the service file |

## Project layout

```
app.py               Flask app, routes, auth
settings.py          Configuration (environment variables)
audit/               Collector (SSH), parsers, checks, inventory
core/                Risk scoring, link quality, OUI vendor lookup
vendors/             Vendor adapter framework (Cisco ready; others are stubs)
templates/, static/  Web UI
data/oui.csv         MAC vendor list
deploy/              systemd unit and nginx site
scripts/             update_oui.py (refresh vendor list)
docs/                Architecture, roadmap, screenshots
tests/               Unit tests
```

## Status and limitations

- Cisco IOS / IOS-XE is the only supported platform. Tested live on one Catalyst 2960X; other models are parsed but not fully verified.
- MikroTik, Juniper, Fortinet, Aruba, and HPE are planned (see `docs/ROADMAP.md`).
- Scoring is a simplified, explainable estimate. It does not replace a professional security audit.

## License

No license file yet. Add one (for example MIT, or a private all-rights-reserved notice) before publishing.
