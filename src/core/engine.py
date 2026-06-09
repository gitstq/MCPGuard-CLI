"""
Core scanning engine — orchestrates all security scanners and aggregates results.
核心扫描引擎 — 编排所有安全扫描器并聚合结果。
"""

import os
import sys
import time
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def color(self) -> str:
        colors = {
            "critical": "\033[91m",  # Red
            "high": "\033[93m",       # Yellow
            "medium": "\033[96m",     # Cyan
            "low": "\033[92m",        # Green
            "info": "\033[94m",       # Blue
        }
        return colors.get(self.value, "\033[0m")

    @property
    def symbol(self) -> str:
        symbols = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }
        return symbols.get(self.value, "⚪")

    @property
    def weight(self) -> int:
        """Weight for risk score calculation."""
        weights = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 2,
            "info": 0,
        }
        return weights.get(self.value, 0)


@dataclass
class Finding:
    """A single security finding."""
    scanner_id: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    remediation: str = ""
    cwe_id: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    """Aggregated scan result from a single scanner."""
    scanner_id: str
    scanner_name: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    scan_duration_ms: float = 0.0
    error: Optional[str] = None

    @property
    def risk_score(self) -> float:
        """Calculate risk score (0-100) based on findings."""
        if not self.findings:
            return 0.0
        total_weight = sum(f.severity.weight for f in self.findings)
        max_possible = len(self.findings) * 10  # All critical
        return min(100.0, (total_weight / max_possible) * 100)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner_id": self.scanner_id,
            "scanner_name": self.scanner_name,
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "risk_score": round(self.risk_score, 1),
            "error": self.error,
        }


@dataclass
class ScanReport:
    """Complete scan report with all scanner results."""
    target_path: str
    scan_timestamp: str
    total_findings: int = 0
    total_files_scanned: int = 0
    total_duration_ms: float = 0.0
    overall_risk_score: float = 0.0
    scanner_results: List[ScanResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_path": self.target_path,
            "scan_timestamp": self.scan_timestamp,
            "total_findings": self.total_findings,
            "total_files_scanned": self.total_files_scanned,
            "total_duration_ms": round(self.total_duration_ms, 2),
            "overall_risk_score": round(self.overall_risk_score, 1),
            "scanner_results": [r.to_dict() for r in self.scanner_results],
            "severity_breakdown": self._severity_breakdown(),
        }

    def _severity_breakdown(self) -> Dict[str, int]:
        breakdown = {}
        for result in self.scanner_results:
            for finding in result.findings:
                sev = finding.severity.value
                breakdown[sev] = breakdown.get(sev, 0) + 1
        return breakdown


class BaseScanner:
    """Base class for all security scanners."""

    scanner_id: str = "base"
    scanner_name: str = "Base Scanner"
    description: str = ""

    # File patterns this scanner targets
    target_patterns: List[str] = []

    def __init__(self, target_path: str):
        self.target_path = Path(target_path).resolve()
        self.findings: List[Finding] = []
        self.files_scanned = 0

    def should_scan_file(self, file_path: Path) -> bool:
        """Check if this scanner should process the given file."""
        if not self.target_patterns:
            return False
        return any(
            file_path.match(pattern) or file_path.suffix == pattern
            for pattern in self.target_patterns
        )

    def scan(self) -> ScanResult:
        """Execute the scan. Override in subclasses."""
        raise NotImplementedError

    def add_finding(
        self,
        severity: Severity,
        title: str,
        description: str,
        file_path: str,
        line_number: Optional[int] = None,
        remediation: str = "",
        cwe_id: Optional[str] = None,
        raw_data: Optional[Dict[str, Any]] = None,
    ):
        """Add a security finding."""
        self.findings.append(Finding(
            scanner_id=self.scanner_id,
            severity=severity,
            title=title,
            description=description,
            file_path=file_path,
            line_number=line_number,
            remediation=remediation,
            cwe_id=cwe_id,
            raw_data=raw_data or {},
        ))

    def _walk_files(self) -> List[Path]:
        """Walk the target directory and return matching files."""
        files = []
        if not self.target_path.exists():
            return files
        if self.target_path.is_file():
            if self.should_scan_file(self.target_path):
                files.append(self.target_path)
            return files
        for root, dirs, filenames in os.walk(self.target_path):
            # Skip common non-relevant directories
            dirs[:] = [d for d in dirs if d not in {
                "node_modules", ".git", "__pycache__", ".venv",
                "venv", ".tox", ".mypy_cache", ".pytest_cache",
                "dist", "build", ".next", ".nuxt", "target",
                ".gradle", ".idea", ".vscode",
            }]
            for filename in filenames:
                file_path = Path(root) / filename
                if self.should_scan_file(file_path):
                    files.append(file_path)
        return files


class ScanEngine:
    """Main scanning engine that orchestrates all scanners."""

    def __init__(self, target_path: str, scanners: Optional[List[BaseScanner]] = None):
        self.target_path = target_path
        self.scanners = scanners or []
        self.report: Optional[ScanReport] = None

    def register_scanner(self, scanner: BaseScanner):
        """Register a scanner with the engine."""
        self.scanners.append(scanner)

    def run(self) -> ScanReport:
        """Run all registered scanners and generate a comprehensive report."""
        from datetime import datetime, timezone

        start_time = time.time()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        report = ScanReport(
            target_path=str(self.target_path),
            scan_timestamp=timestamp,
        )

        for scanner in self.scanners:
            scanner_start = time.time()
            try:
                result = scanner.scan()
                report.scanner_results.append(result)
                report.total_files_scanned += result.files_scanned
                report.total_findings += len(result.findings)
            except Exception as e:
                report.scanner_results.append(ScanResult(
                    scanner_id=scanner.scanner_id,
                    scanner_name=scanner.scanner_name,
                    error=str(e),
                ))
            scanner_end = time.time()

        total_end = time.time()
        report.total_duration_ms = (total_end - start_time) * 1000

        # Calculate overall risk score
        if report.scanner_results:
            scores = [r.risk_score for r in report.scanner_results if r.findings]
            report.overall_risk_score = max(scores) if scores else 0.0

        self.report = report
        return report
