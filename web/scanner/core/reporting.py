from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from rich.console import Console
from rich.table import Table


SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


@dataclass
class ScanFinding:
    check_id: str
    severity: str
    endpoint: str
    summary: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def serialize(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "summary": self.summary,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
        }


@dataclass
class ScanSummary:
    stats: Dict[str, int] = field(default_factory=lambda: {sev: 0 for sev in SEVERITY_ORDER})
    total_requests: int = 0
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None

    def finalize(self) -> None:
        self.end_time = datetime.now(timezone.utc)

    def serialize(self) -> Dict[str, Any]:
        return {
            "stats": self.stats,
            "total_requests": self.total_requests,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds() if self.end_time else None,
        }


class ScanReport:
    def __init__(self) -> None:
        self.summary = ScanSummary()
        self.findings: List[ScanFinding] = []
        self.log_messages: List[str] = []

    def add_finding(self, finding: ScanFinding) -> None:
        severity = finding.severity if finding.severity in SEVERITY_ORDER else "info"
        self.summary.stats[severity] += 1
        self.findings.append(finding)

    def add_log(self, message: str) -> None:
        self.log_messages.append(message)

    def render(self, console: Console) -> None:
        totals = Table(title="Özet")
        totals.add_column("Seviye")
        totals.add_column("Adet", justify="right")
        for severity in SEVERITY_ORDER:
            totals.add_row(severity.title(), str(self.summary.stats[severity]))
        console.print(totals)

        if not self.findings:
            console.print("[green]Bulgu bulunamadı.[/green]")
            return

        by_severity: Dict[str, List[ScanFinding]] = defaultdict(list)
        for finding in sorted(self.findings, key=lambda f: SEVERITY_ORDER.index(f.severity)):
            by_severity[finding.severity].append(finding)

        for severity in SEVERITY_ORDER:
            findings = by_severity.get(severity)
            if not findings:
                continue
            console.rule(f"[bold]{severity.title()}[/bold]")
            table = Table(title=None, show_lines=True)
            table.add_column("Endpoint", no_wrap=True)
            table.add_column("Özet")
            table.add_column("Delil")
            for finding in findings:
                evidence_str = json.dumps(finding.evidence, ensure_ascii=False, indent=2)[:500]
                table.add_row(finding.endpoint, finding.summary, evidence_str)
            console.print(table)

    def write_json(self, path: Path) -> None:
        payload = {
            "summary": self.summary.serialize(),
            "findings": [finding.serialize() for finding in self.findings],
            "logs": self.log_messages,
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


