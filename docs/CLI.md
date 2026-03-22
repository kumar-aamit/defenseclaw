# CLI Reference

All subcommands are registered on `defenseclaw`. Use `defenseclaw help <command>` for flags and examples.

## Commands

| Command | Description | Iteration |
|--------|-------------|-----------|
| `init` | Create `~/.defenseclaw` config and SQLite audit database | 1 |
| `scan skill <path>` | Run skill-scanner on a skill directory | 1 |
| `scan mcp <path-or-url>` | Run mcp-scanner on MCP manifest or endpoint | 1 |
| `scan aibom <path>` | Run aibom inventory on a project path | 1 |
| `scan code <path>` | Run CodeGuard security rules on code files | 4 |
| `scan [path]` | Run all scanners against a target | 1 |
| `deploy [path]` | Full orchestrated deploy: init → scan → block → policy → sandbox | 4 |
| `block skill <id>` | Add a skill to the block list | 2 |
| `block mcp <id>` | Add an MCP server to the block list | 2 |
| `allow skill <id>` | Add a skill to the allow list | 2 |
| `allow mcp <id>` | Add an MCP server to the allow list | 2 |
| `list blocked` | List blocked skills and MCP servers | 2 |
| `list allowed` | List allowed skills and MCP servers | 2 |
| `quarantine <skill>` | Immediately block + quarantine a skill | 2 |
| `rescan` | Re-scan all known targets, auto-block/unblock by results | 4 |
| `alerts` | Show recent security alerts | 4 |
| `status` | Show environment, sandbox health, and counts | 4 |
| `stop` | Stop the OpenShell sandbox | 4 |
| `tui` | Launch the interactive terminal dashboard | 3 |
| `audit` | View audit log events | 1 |

## deploy

```
defenseclaw deploy [path] [flags]
```

Full orchestrated deployment:
1. Initialize if needed
2. Run all scanners (skills + MCP + AIBOM + CodeGuard)
3. Auto-block anything HIGH/CRITICAL
4. Generate OpenShell sandbox policy
5. Start OpenClaw in sandbox
6. Print summary

**Flags:**
- `--skip-init` — skip initialization step

## scan code

```
defenseclaw scan code <path>
```

Scans code files using built-in CodeGuard security rules. Detects:
- Hardcoded credentials (API keys, AWS keys, private keys)
- Unsafe command execution (`eval`, `exec`, `system`, `subprocess`)
- SQL injection (string formatting in queries)
- Unsafe deserialization (`pickle`, `yaml.load`)
- Weak cryptography (MD5, SHA1)
- Path traversal
- Outbound HTTP to variable URLs

## status

```
defenseclaw status
```

Shows environment, data directory, sandbox state, scanner availability,
enforcement counts, and activity summary.

## rescan

```
defenseclaw rescan
```

Re-scans all items on block and allow lists. Targets with HIGH/CRITICAL
findings are auto-blocked. Previously blocked items that are now clean
are moved to the allow list.

## stop

```
defenseclaw stop
```

Gracefully stops the OpenShell sandbox process started by `defenseclaw deploy`.

## alerts

```
defenseclaw alerts [-n limit]
```

Displays recent security alerts (events with severity CRITICAL, HIGH, MEDIUM, or LOW).

**Flags:**
- `-n, --limit` — number of alerts to show (default: 25)
