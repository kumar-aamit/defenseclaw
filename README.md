```
     ____         __                       ____  _
    / __ \ ___   / /___   ___   ___  ___  / ___|| | __ _ __      __
   / / / // _ \ / // _ \ / _ \ / __|/ _ \| |    | |/ _` |\ \ /\ / /
  / /_/ //  __// //  __/| | | |\__ \  __/| |___ | | (_| | \ V  V /
 /_____/ \___//_/ \___/ |_| |_||___/\___| \____||_|\__,_|  \_/\_/

  ╔═══════════════════════════════════════════════════════════════╗
  ║  Cisco DefenseClaw — Security Governance for Agentic AI      ║
  ╚═══════════════════════════════════════════════════════════════╝
```

# DefenseClaw

**AI agents are powerful. Unchecked, they're dangerous.**

Large language model agents — like those built on [OpenClaw](https://github.com/nvidia/openclaw) — can install skills, call MCP servers, execute code, and reach the network. Every one of those actions is an attack surface. A single malicious skill can exfiltrate data. A compromised MCP server can inject hidden instructions. Generated code can contain hardcoded secrets or command injection.

Most teams discover these risks *after* deployment. DefenseClaw moves security *before* execution.

**DefenseClaw is the enterprise governance layer for OpenClaw.** It sits between your AI agents and the infrastructure they run on, enforcing a simple principle: **nothing runs until it's scanned, and anything dangerous is blocked automatically.**

```
  Developer / Operator
         │
    ┌────▼─────────────────────┐
    │   DefenseClaw Gateway    │  scan ─► block ─► enforce ─► audit
    └────┬─────────────────────┘
         │
    ┌────▼─────────────────────┐
    │   NVIDIA OpenShell       │  kernel isolation + network policy
    │     └── OpenClaw Agent   │  skills, MCP servers, code
    └──────────────────────────┘
```

**What you get:**

- Every skill, MCP server, and code file is scanned before it can execute
- HIGH and CRITICAL findings are auto-blocked — no manual triage required
- Block/allow lists give operators explicit control over what runs
- A terminal dashboard surfaces alerts and enforcement status in real time
- A durable audit trail logs every action with who, what, when, and why
- On NVIDIA DGX Spark, sandbox enforcement is kernel-level via OpenShell

**Single binary. No Docker dependency. No external database. Runs in userspace.**

---

## Quick Start

```bash
git clone https://github.com/defenseclaw/defenseclaw.git
cd defenseclaw
make build
defenseclaw init
defenseclaw deploy ./your-project/
defenseclaw tui
```

## What It Does

- **Scan before run** — skills, MCP servers, code, and AI dependencies
- **Block/allow lists** — operator-managed enforcement with auto-blocking for HIGH/CRITICAL findings
- **Terminal dashboard** — three-tab TUI with alerts, skills, MCP servers, and a status bar
- **Audit trail** — every action logged to SQLite with timestamps and context
- **Splunk SIEM** — batch export or real-time forwarding via HTTP Event Collector
- **Sandbox orchestration** — generates and enforces NVIDIA OpenShell policy (DGX Spark)

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation Guide](docs/INSTALL.md) | Step-by-step setup for DGX Spark and macOS, both existing and fresh OpenClaw deployments. Covers OpenShell, OpenClaw, and DefenseClaw installation, upgrading, and troubleshooting. |
| [Quick Start](docs/QUICKSTART.md) | 5-minute walkthrough of every command: init, scan, block/allow, audit, TUI, deploy, CodeGuard, status, rescan, and stop. |
| [CLI Reference](docs/CLI.md) | Complete command reference with flags, arguments, and usage examples for all subcommands. |
| [Architecture](docs/ARCHITECTURE.md) | System diagram and data flow: Discovery, Admission, Enforcement, Runtime, and Audit layers. Splunk SIEM integration. Cross-platform behavior matrix and key package responsibilities. |
| [TUI Guide](docs/TUI.md) | Terminal dashboard usage: Alerts, Skills, and MCP Servers panels, keybindings, and navigation. |
| [Plugin Development](docs/PLUGINS.md) | How to write a custom scanner plugin using the Go Scanner interface. Plugin discovery and gRPC protocol. |
| [Testing](docs/TESTING.md) | How to run unit and E2E tests, manual testing on DGX Spark and macOS, and test fixture descriptions. |
| [Contributing](docs/CONTRIBUTING.md) | Fork/PR workflow, code style, `golangci-lint`, and DCO sign-off requirements. |

## Scanner Dependencies

DefenseClaw wraps four open-source security scanners. They are installed automatically by `defenseclaw init`, or you can install them manually:

| Scanner | Package | What It Detects |
|---------|---------|-----------------|
| [Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner) | `cisco-ai-skill-scanner` | Prompt injection, data exfiltration, malicious code in AI skills |
| [MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) | `cisco-ai-mcp-scanner` | Malicious MCP tools, hidden instructions, SSRF |
| [AI BOM](https://github.com/cisco-ai-defense/aibom) | `cisco-aibom` | AI framework inventory (models, agents, tools, prompts) |
| [CodeGuard](https://github.com/cosai-oasis/project-codeguard) | Built-in | Hardcoded credentials, unsafe exec, SQLi, weak crypto, path traversal |

```bash
# Auto-install all scanners
defenseclaw init

# Or install manually with uv
uv tool install cisco-ai-skill-scanner
uv tool install --python 3.13 cisco-ai-mcp-scanner
uv tool install --python 3.13 cisco-aibom
```

## Building from Source

Requires Go 1.22+ and Python 3.11+.

```bash
make build              # Current platform
make build-linux-arm64  # DGX Spark (aarch64)
make build-linux-amd64  # Linux x86_64
make build-darwin-arm64 # Apple Silicon
make build-darwin-amd64 # Intel Mac
make test               # Unit tests with race detector
make lint               # golangci-lint
```

## Platform Support

| Capability | DGX Spark | macOS |
|------------|-----------|-------|
| Scanning (all scanners) | Full | Full |
| Block/allow lists | Full enforcement | Lists maintained |
| Quarantine | Files + sandbox policy | Files only |
| OpenShell sandbox | Active | Not available |
| Network enforcement | Via OpenShell | Not enforced |
| Audit log | Full | Full |
| TUI dashboard | Full | Full |
| CodeGuard code scan | Full | Full |
| Splunk SIEM export | Full | Full |

## License

Apache 2.0 — see [LICENSE](LICENSE).
