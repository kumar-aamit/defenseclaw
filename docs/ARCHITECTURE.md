# Architecture

DefenseClaw is a governance gateway that sits between developers and the OpenClaw runtime. It does not replace any component — it orchestrates scanning, enforcement, and auditing across existing tools.

## Layers

```
Developer (CLI / TUI)
       |
DefenseClaw Gateway
       |
+---- Discovery Plane ----+
|  aibom                   |
+--------------------------+
       |
+---- Admission Plane ----+
|  skill-scanner           |
|  mcp-scanner             |
|  CodeGuard               |
|  [custom plugins]        |
+--------------------------+
       |
+---- Enforcement ---------+
|  Block/Allow engine      |
|  OpenShell policy sync   |
|  Quarantine              |
+---------------------------+
       |
+---- Runtime --------------+
|  NVIDIA OpenShell         |
|    +-- OpenClaw           |
+----------------------------+
       |
+---- Audit ----------------+
|  SQLite event store       |
|  JSON/CSV export          |
|  Splunk HEC (SIEM/SOAR)   |
+----------------------------+
```

## Data Flow

1. **Discovery** — `aibom` generates an inventory of all skills, MCP servers, and dependencies in the environment.
2. **Admission** — Every skill install or MCP registration passes through the admission gate: block list check, then allow list check, then scanner pipeline.
3. **Enforcement** — Blocked items are quarantined (skills) or disconnected (MCP servers). OpenShell sandbox policy is updated to revoke permissions and network access.
4. **Runtime** — OpenClaw runs inside an NVIDIA OpenShell sandbox. DefenseClaw writes the sandbox policy; OpenShell enforces it at the kernel level.
5. **Audit** — Every action (scan, block, allow, quarantine, deploy, stop) is logged to SQLite with timestamp, actor, target, and details. Events can be exported as JSON/CSV or forwarded to Splunk via HEC for SIEM/SOAR integration (batch or real-time).

## Cross-Platform Behavior

| Capability | DGX Spark (full) | macOS (degraded) |
|------------|-------------------|-------------------|
| Scanning | All scanners | All scanners |
| Block/allow lists | Full enforcement | Lists maintained |
| Quarantine | Files moved + sandbox policy | Files moved only |
| OpenShell sandbox | Active | Not available |
| Network enforcement | Via OpenShell | Not enforced |
| Audit log | Full | Full |
| TUI | Full | Full |
| Splunk SIEM | Full | Full |

## Key Packages

| Package | Responsibility |
|---------|---------------|
| `internal/scanner` | Scanner interface and wrappers for Python CLI tools |
| `internal/enforce` | Block/allow lists, quarantine, sandbox policy sync |
| `internal/audit` | SQLite event store, scan result storage, JSON/CSV/Splunk export |
| `internal/config` | Viper config loader, environment detection |
| `internal/tui` | Bubbletea four-panel dashboard |
| `internal/sandbox` | OpenShell CLI wrapper and YAML policy generation |
| `internal/inventory` | AIBOM integration and dependency graph |
| `plugins` | Plugin interface, discovery, and registry |
