"""Plugin scanner — shells out to defenseclaw-plugin-scanner (Node.js).

The scanner lives in extensions/defenseclaw and is installed as a Node binary.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from defenseclaw.models import Finding, ScanResult

SCANNER_NAME = "defenseclaw-plugin-scanner"


class PluginScannerWrapper:
    def __init__(self, binary: str = SCANNER_NAME) -> None:
        self.binary = binary

    def name(self) -> str:
        return "plugin-scanner"

    def scan(self, target: str) -> ScanResult:
        import time

        start = time.monotonic()

        try:
            proc = subprocess.run(
                [self.binary, target],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            print(
                f"error: {self.binary} not found.\n"
                "  Build and link the extension:\n"
                "    cd extensions/defenseclaw && npm run build && npm link",
                file=sys.stderr,
            )
            raise SystemExit(1)

        elapsed = time.monotonic() - start
        findings: list[Finding] = []

        if proc.stdout.strip():
            try:
                # The TS plugin scanner outputs a full ScanResult object with
                # scanner, target, timestamp, findings[], duration_ns, metadata,
                # and assessment fields (see extensions/defenseclaw/src/types.ts).
                data = json.loads(proc.stdout)
                for f in data.get("findings", []):
                    if f.get("suppressed", False):
                        continue
                    findings.append(Finding(
                        id=f.get("id", ""),
                        severity=f.get("severity", "INFO"),
                        title=f.get("title", ""),
                        description=f.get("description", ""),
                        location=f.get("location", ""),
                        remediation=f.get("remediation", ""),
                        scanner="plugin-scanner",
                        tags=f.get("tags", []),
                    ))
            except json.JSONDecodeError:
                pass

        if proc.returncode != 0 and not findings:
            stderr = proc.stderr.strip()
            if stderr:
                print(f"warning: plugin scanner: {stderr}", file=sys.stderr)

        return ScanResult(
            scanner="plugin-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
            duration=timedelta(seconds=elapsed),
        )
