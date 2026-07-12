# Anti-Missile — WiFi Device Monitor & Alert

Scan all devices on your local WiFi/LAN, classify them by MAC OUI, and receive email alerts when a target device joins or leaves the network.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure
# Edit src/config.yaml — set target-mac, SMTP email credentials, and alert parameters

# 3. Run
cd src
python main.py
```

Open **http://localhost:8081** in your browser for the live dashboard.

## Features

| Feature | Description |
|---------|-------------|
| **Device Scanning** | ICMP ping sweep + TCP probe + mDNS/SSDP discovery |
| **MAC Classification** | OUI vendor lookup + hardware vs randomized MAC detection |
| **Live Dashboard** | Auto-refreshing web UI (`GET /`) every 45s |
| **REST API** | `GET /api/devices` returns JSON device list with timestamps |
| **Email Alerts** | Notifies when a target MAC joins (`access`) or leaves (`quit`) the network |
| **Permissionless** | No admin/root needed — works on Windows via ARP table |

## API

```
GET /api/devices?probe=true&tcp=false
```

Response:
```json
{
  "timestamp": "2026-07-12T14:30:00",
  "network": "192.168.124.0/24",
  "router": "H3C TX1802",
  "wifi_stations": 2,
  "device_count": 6,
  "devices": [
    {
      "ip": "192.168.124.1",
      "mac": "30-C6-D7-20-A8-BF",
      "type": "dynamic",
      "classification": "H3C [hardware]",
      "first_seen": "2026-07-12T14:25:00.123456",
      "last_seen": "2026-07-12T14:30:00.123456",
      "duration_seconds": 300.0,
      "seen_count": 5
    }
  ]
}
```

## Configuration (`src/config.yaml`)

```yaml
target-mac: "AA-BB-CC-DD-EE-FF"        # MAC to monitor

remind-emails:                          # Alert recipients
  - "you@example.com"

smtp:                                   # Outgoing mail server
  host: "smtp.example.com"
  port: 465
  user: "you@example.com"
  password: "your_auth_code"            # Use SMTP auth code, not login password
  use_ssl: true

alert:
  scan_interval_seconds: 30             # Background scan frequency
  alert_window_minutes: 1               # "Just joined" threshold
  cooldown_minutes: 5                   # Suppress duplicate alerts
```

## CLI Tool

```bash
# List all devices on current network
python scripts/search_mac_inwlan.py

```

## Limitations

- **AP isolation** — routers with client isolation block device-to-device ARP; you'll only see the station count from BSS load, not individual MACs
- **Phone sleep** — phones in deep sleep may not respond to ICMP/TCP probes
- **MAC randomization** — modern devices use per-network random MACs (flagged as `[randomized]`)
