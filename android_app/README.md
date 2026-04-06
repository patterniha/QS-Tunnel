# QS-Tunnel Android App

A simple Android app for the QS-Tunnel DNS tunnel client.

Built with [Flet](https://flet.dev) — a modern Python framework for building cross-platform apps, powered by Flutter. Flet supports the latest Python versions and provides native Android APK builds.

## Features

- **Toggle switch** to start/stop the DNS tunnel
- **JSON config editor** with save/reset functionality
- **Live log output** from the tunnel client
- Dark theme UI

## Prerequisites

- Python 3.9 or later
- Flet CLI

## Install Flet

```bash
pip install flet
```

## Run on Desktop (for testing)

```bash
cd android_app
flet run main.py
```

## Build APK

```bash
cd android_app
flet build apk
```

The APK will be generated in `build/apk/`.

## Android Permissions

The following permissions are configured in `pyproject.toml`:

| Permission | Reason |
|---|---|
| `INTERNET` | Required for sending DNS queries and receiving responses |
| `FOREGROUND_SERVICE` | Keeps the tunnel running when the app is in the background |
| `FOREGROUND_SERVICE_DATA_SYNC` | Required on Android 14+ for foreground service type declaration |
| `POST_NOTIFICATIONS` | Required on Android 13+ to show the foreground service notification |
| `WAKE_LOCK` | Prevents the device from sleeping while the tunnel is active |
| `ACCESS_NETWORK_STATE` | Checks network connectivity before starting the tunnel |

## Configuration

Edit the JSON configuration in the app. Fields:

| Field | Description |
|---|---|
| `mode` | `"1-1"` (single client) or `"n-1"` (multi-client) |
| `dns_ips` | List of DNS server IPs to send queries to |
| `send_domain` | Domain name to encode data into |
| `fake_send_ip` | IP for NAT keepalive packets |
| `fake_send_port` | Port for NAT keepalive (default: 443) |
| `h_in_address` | Local address to listen for H service data |
| `max_domain_len` | Maximum domain length (≤253) |
| `max_sub_len` | Maximum DNS label length (≤63) |
| `retries` | Number of retry attempts for DNS queries |
| `send_sock_numbers` | Number of UDP sockets for sending (lower on mobile, default: 64) |
| `my_public_ip` | Public IP or `"ezping"` to auto-detect |
| `send_query_type_int` | DNS query type (1=A, 28=AAAA) |
| `info_encryption_pass` | Password for encrypting client info |

## Project Structure

```
android_app/
├── main.py              # Flet UI (app entry point)
├── tunnel_client.py     # Refactored client logic (start/stop)
├── data_cap.py          # Data encoding/chunking
├── utility/
│   ├── __init__.py
│   ├── base32.py        # Base32 encoding
│   └── dns.py           # DNS protocol utilities
├── requirements.txt     # Dependencies (flet + aiohttp)
├── pyproject.toml       # Build configuration
└── README.md            # This file
```

## Notes

- The default `send_sock_numbers` is set to 64 (vs 512 on desktop) to be compatible with Android's file descriptor limits.
- Server-side files (`main_server.py`, `config_server.json`, `packets.py`, `numba_checksum.py`) are not included.
- Only `aiohttp` is required as an external dependency (no `numba`).
