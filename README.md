# HermitStash Sync

Desktop file sync client for [HermitStash](https://github.com/dotCooCoo/hermitstash) — post-quantum encrypted, self-hosted file sync.

## What it does

Watches a local folder and keeps it in sync with a HermitStash server:

- **New files** are uploaded automatically
- **Modified files** are re-uploaded (server detects and replaces)
- **Deleted files** are removed from the server
- **Server-side changes** are downloaded in real-time via WebSocket

All connections use PQC TLS (X25519MLKEM768 hybrid key exchange) with optional mTLS client certificates.

## Requirements

- Node.js 24+ (for `node:sqlite` and OpenSSL 3.5+ PQC support)
- HermitStash server v1.3.4+ with sync features enabled

## Install

```bash
# From source
git clone https://github.com/dotCooCoo/hermitstash-sync.git
cd hermitstash-sync

# Or use pre-built binary (no Node.js required)
# Download from Releases for your platform
```

## Quick Start

```bash
# 1. Set up the connection
hermitstash-sync init

# 2. Start syncing (foreground)
hermitstash-sync start

# 3. Or run as a background daemon
hermitstash-sync start --daemon

# 4. Check status
hermitstash-sync status

# 5. Stop the daemon
hermitstash-sync stop
```

## Commands

| Command | Description |
|---------|-------------|
| `init` | Interactive setup — server URL, API key, sync folder |
| `start` | Start sync in foreground |
| `start --daemon` | Start sync as background daemon |
| `status` | Show sync status (running/stopped, file count, errors) |
| `stop` | Stop the background daemon |
| `log` | Show last 50 log lines |
| `log --follow` | Tail the log file in real-time |
| `resync` | Force a full re-sync from scratch |
| `version` | Show version and OpenSSL info |

## Configuration

Config file: `~/.hermitstash-sync/config.json`

```json
{
  "server": "https://hermitstash.com",
  "bundleId": "your-sync-bundle-id",
  "shareId": "your-share-id",
  "syncFolder": "/home/user/Documents/synced",
  "mtls": {
    "cert": "/path/to/client.crt",
    "key": "/path/to/client.key",
    "ca": "/path/to/ca.crt"
  },
  "ignore": ["*.log", "build/**"],
  "logLevel": "info"
}
```

### Ignore Patterns

Default ignore patterns are always applied (`.DS_Store`, `.git/**`, `node_modules/**`, etc.). Add custom patterns in:
- `config.json` → `ignore` array
- `.hermitstash-ignore` file in the sync folder root (gitignore-style)

### API Key Storage

The API key is stored in your OS keychain:
- **macOS:** Keychain Access
- **Linux:** GNOME Keyring / KDE Wallet (via `secret-tool`)
- **Windows:** Windows Credential Manager

Falls back to `~/.hermitstash-sync/credentials` (permissions `0600`) on headless systems.

## Security

- **PQC TLS** on every connection (X25519MLKEM768 hybrid key exchange)
- **mTLS** client certificates for server authentication (optional)
- **SHA3-512** checksums verified after every download
- **API key** in OS keychain, never in plaintext config
- **Atomic writes** — downloads write to `.tmp` file then rename
- **Zero npm dependencies** — entire codebase is auditable

## Auto-start (Optional)

### Linux (systemd)

```ini
# ~/.config/systemd/user/hermitstash-sync.service
[Unit]
Description=HermitStash Sync
After=network-online.target

[Service]
ExecStart=/usr/local/bin/hermitstash-sync start
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
```

```bash
systemctl --user enable hermitstash-sync
systemctl --user start hermitstash-sync
```

### macOS (launchd)

```xml
<!-- ~/Library/LaunchAgents/com.hermitstash.sync.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.hermitstash.sync</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/hermitstash-sync</string>
    <string>start</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
```

## Building SEA Binary

```bash
# Requires Node.js 22+ and postject
node --experimental-sea-config build/sea-config.json
cp $(which node) build/hermitstash-sync
npx postject build/hermitstash-sync NODE_SEA_BLOB build/hermitstash-sync.blob \
  --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
```

## License

MIT
