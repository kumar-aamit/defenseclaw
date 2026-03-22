# Quick Start Guide

Get DefenseClaw running in under 5 minutes.

## Prerequisites

- **Go 1.22+** — to build from source
- **Python 3.11+** — for scanner dependencies
- **[uv](https://docs.astral.sh/uv/)** (recommended) or pip

## 1. Build

```bash
git clone https://github.com/defenseclaw/defenseclaw.git
cd defenseclaw
make build
```

For DGX Spark (linux/arm64):

```bash
make build-linux-arm64
scp defenseclaw-linux-arm64 spark:/usr/local/bin/defenseclaw
```

## 2. Initialize

```bash
defenseclaw init
```

This creates `~/.defenseclaw/` with:
- `config.yaml` — scanner paths, policy settings
- `audit.db` — SQLite audit log
- `quarantine/` — blocked skill storage
- `plugins/` — custom scanner plugins
- `policies/` — OpenShell policy files

Scanner dependencies are installed automatically during init.
Use `--skip-install` to skip this step.

## 3. First Scan

```bash
# Scan a skill
defenseclaw scan skill ./path/to/skill/

# Scan an MCP server
defenseclaw scan mcp https://mcp-server.example.com

# Generate AI bill of materials
defenseclaw scan aibom .

# Run all scanners against current directory
defenseclaw scan
```

## 4. Block/Allow Enforcement

```bash
# Block a skill (quarantines files + updates sandbox policy)
defenseclaw block skill ./malicious-skill --reason "exfil pattern"

# Block an MCP server (adds to network deny-list)
defenseclaw block mcp https://shady.example.com --reason "hidden instructions"

# View what's blocked
defenseclaw list blocked

# Allow a previously blocked skill (re-scans first, rejects if still HIGH/CRITICAL)
defenseclaw allow skill ./malicious-skill

# Allow without re-scanning
defenseclaw allow skill ./malicious-skill --skip-rescan --reason "manually verified"

# View allow list
defenseclaw list allowed

# Emergency quarantine (block + move files in one step)
defenseclaw quarantine ./risky-skill
```

## 5. Audit Log

```bash
# View recent audit events
defenseclaw audit

# Show more events
defenseclaw audit -n 50
```

Every action (scan, block, allow, quarantine, init) is logged.

## 6. Terminal Dashboard

```bash
# Launch the interactive TUI
defenseclaw tui
```

The TUI has three tabs:
- **Alerts** — color-coded severity, dismiss with `d`, view detail with `enter`
- **Skills** — block/allow toggle with `b`/`a`, view detail with `enter`
- **MCP Servers** — block/allow toggle with `b`/`a`, view detail with `enter`

Navigation: `tab`/`shift-tab` between tabs, `j`/`k` or arrows to move, `r` to refresh, `q` to quit.

Auto-refreshes every 5 seconds from SQLite.

## 7. Deploy (Full Orchestrated Flow)

```bash
# Full deploy: init → scan → auto-block → policy → sandbox
defenseclaw deploy

# Deploy a specific target directory
defenseclaw deploy ./my-project/

# Skip init if already configured
defenseclaw deploy --skip-init
```

This runs all 5 steps automatically:
1. **Init** — ensures `~/.defenseclaw/` exists
2. **Scan** — runs skill-scanner, mcp-scanner, aibom, and CodeGuard
3. **Enforce** — auto-blocks anything HIGH/CRITICAL
4. **Policy** — generates OpenShell sandbox policy from scan results
5. **Sandbox** — starts OpenClaw in OpenShell (DGX Spark only)

## 8. Code Scanning (CodeGuard)

```bash
# Scan code for security issues
defenseclaw scan code ./path/to/code/
```

Built-in rules detect: hardcoded credentials, unsafe command execution,
SQL injection, unsafe deserialization, weak crypto, path traversal, and more.

## 9. Status & Lifecycle

```bash
# Check deployment health
defenseclaw status

# Re-scan all known targets, auto-block/unblock based on results
defenseclaw rescan

# View security alerts
defenseclaw alerts
defenseclaw alerts -n 50

# Stop the sandbox
defenseclaw stop
```

## 10. SIEM Integration (Splunk)

DefenseClaw can forward audit events to Splunk for enterprise visibility.

### Batch Export

```bash
# Export events as JSON
defenseclaw audit export -f json -o audit.json

# Export as CSV
defenseclaw audit export -f csv -o audit.csv

# Send to Splunk via HEC
DEFENSECLAW_SPLUNK_HEC_TOKEN=<your-token> defenseclaw audit export -f splunk -n 500
```

### Real-Time Forwarding

Add to `~/.defenseclaw/config.yaml`:

```yaml
splunk:
  hec_endpoint: https://your-splunk:8088/services/collector/event
  hec_token: ""
  index: defenseclaw
  source: defenseclaw
  sourcetype: _json
  verify_tls: false
  enabled: true
  batch_size: 50
  flush_interval_s: 5
```

Set the token via environment variable (recommended):

```bash
export DEFENSECLAW_SPLUNK_HEC_TOKEN="your-hec-token"
```

With `enabled: true`, every scan, block, allow, deploy, and quarantine event is
streamed to Splunk as it happens.

## 11. Next Steps

- `defenseclaw tui` — interactive terminal dashboard
- See [CLI Reference](CLI.md) for all commands and flags.
- See [Architecture](ARCHITECTURE.md) for system design details.
