"""
Report generators — output scan results in various formats.
报告生成器 — 以多种格式输出扫描结果。
"""

import json
import os
from pathlib import Path
from typing import Optional
from ..core.engine import ScanReport, Severity


class BaseReporter:
    """Base class for report generators."""

    def __init__(self, report: ScanReport):
        self.report = report

    def generate(self) -> str:
        raise NotImplementedError

    def save(self, output_path: str):
        """Save report to file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate(), encoding="utf-8")


class TerminalReporter(BaseReporter):
    """Generates a rich terminal report with colors and symbols."""

    SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

    def generate(self) -> str:
        lines = []
        r = self.report

        # Header
        lines.append("")
        lines.append("╔══════════════════════════════════════════════════════════════╗")
        lines.append("║  🛡️  MCPGuard-CLI — MCP Ecosystem Security Scan Report     ║")
        lines.append("╚══════════════════════════════════════════════════════════════╝")
        lines.append("")
        lines.append(f"  📁 Target:     {r.target_path}")
        lines.append(f"  🕐 Scanned at:  {r.scan_timestamp}")
        lines.append(f"  📊 Files:       {r.total_files_scanned} files scanned")
        lines.append(f"  ⏱️  Duration:   {r.total_duration_ms:.0f}ms")
        lines.append(f"  🔍 Findings:    {r.total_findings} total")
        lines.append("")

        # Risk score
        risk_color = self._risk_color(r.overall_risk_score)
        risk_label = self._risk_label(r.overall_risk_score)
        lines.append(f"  {risk_color}  Overall Risk Score: {r.overall_risk_score:.1f}/100 — {risk_label}\033[0m")
        lines.append("")

        # Severity breakdown
        breakdown = r._severity_breakdown()
        if breakdown:
            lines.append("  ── Severity Breakdown ──────────────────────────────────")
            for sev in self.SEVERITY_ORDER:
                count = breakdown.get(sev.value, 0)
                if count > 0:
                    lines.append(f"    {sev.symbol} {sev.value.upper():<10} {count:>3} finding{'s' if count > 1 else ''}")
            lines.append("")

        # Scanner results
        lines.append("  ── Scanner Results ───────────────────────────────────────")
        for result in r.scanner_results:
            if result.error:
                lines.append(f"    ❌ {result.scanner_name}: ERROR — {result.error}")
                continue
            status = "✅ CLEAN" if not result.findings else f"⚠️  {len(result.findings)} finding(s)"
            lines.append(f"    {status} — {result.scanner_name} ({result.files_scanned} files, {result.scan_duration_ms:.0f}ms)")
        lines.append("")

        # Detailed findings
        if r.total_findings > 0:
            lines.append("  ── Detailed Findings ────────────────────────────────────")
            for result in r.scanner_results:
                if not result.findings:
                    continue
                lines.append(f"")
                lines.append(f"  📋 {result.scanner_name}:")
                lines.append(f"  {'─' * 56}")

                # Sort findings by severity
                sorted_findings = sorted(result.findings, key=lambda f: self.SEVERITY_ORDER.index(f.severity))
                for finding in sorted_findings:
                    sev = finding.severity
                    loc = f":{finding.line_number}" if finding.line_number else ""
                    lines.append(f"    {sev.symbol} [{sev.value.upper()}] {finding.title}")
                    lines.append(f"       📄 {finding.file_path}{loc}")
                    lines.append(f"       💬 {finding.description}")
                    if finding.remediation:
                        lines.append(f"       🔧 {finding.remediation}")
                    if finding.cwe_id:
                        lines.append(f"       🏷️  {finding.cwe_id}")
                    lines.append("")

        # Summary
        lines.append("  ── Summary ──────────────────────────────────────────────")
        if r.total_findings == 0:
            lines.append("  ✅ No security issues found. Your MCP ecosystem looks clean!")
        else:
            critical = breakdown.get("critical", 0)
            high = breakdown.get("high", 0)
            if critical > 0 or high > 0:
                lines.append(f"  🚨 {critical + high} critical/high severity issues require immediate attention!")
            else:
                lines.append(f"  ⚠️  {r.total_findings} issues found. Review and address them at your convenience.")
        lines.append("")

        return "\n".join(lines)

    def _risk_color(self, score: float) -> str:
        if score >= 70:
            return "\033[91m"
        elif score >= 40:
            return "\033[93m"
        elif score >= 20:
            return "\033[96m"
        return "\033[92m"

    def _risk_label(self, score: float) -> str:
        if score >= 70:
            return "CRITICAL"
        elif score >= 40:
            return "HIGH RISK"
        elif score >= 20:
            return "MODERATE"
        elif score > 0:
            return "LOW RISK"
        return "CLEAN"


class JSONReporter(BaseReporter):
    """Generates a JSON report."""

    def generate(self) -> str:
        return json.dumps(self.report.to_dict(), indent=2, ensure_ascii=False)


class MarkdownReporter(BaseReporter):
    """Generates a Markdown report."""

    SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

    def generate(self) -> str:
        lines = []
        r = self.report

        lines.append("# 🛡️ MCPGuard-CLI Security Scan Report")
        lines.append("")
        lines.append(f"| Property | Value |")
        lines.append(f"|---|---|")
        lines.append(f"| **Target** | `{r.target_path}` |")
        lines.append(f"| **Scan Time** | {r.scan_timestamp} |")
        lines.append(f"| **Files Scanned** | {r.total_files_scanned} |")
        lines.append(f"| **Duration** | {r.total_duration_ms:.0f}ms |")
        lines.append(f"| **Total Findings** | {r.total_findings} |")
        lines.append(f"| **Risk Score** | {r.overall_risk_score:.1f}/100 |")
        lines.append("")

        # Severity breakdown
        breakdown = r._severity_breakdown()
        if breakdown:
            lines.append("## Severity Breakdown")
            lines.append("")
            for sev in self.SEVERITY_ORDER:
                count = breakdown.get(sev.value, 0)
                if count > 0:
                    lines.append(f"- {sev.symbol} **{sev.value.upper()}**: {count}")
            lines.append("")

        # Scanner results
        lines.append("## Scanner Results")
        lines.append("")
        for result in r.scanner_results:
            if result.error:
                lines.append(f"### ❌ {result.scanner_name}")
                lines.append(f"Error: `{result.error}`")
                lines.append("")
                continue
            status = "✅ Clean" if not result.findings else f"⚠️ {len(result.findings)} finding(s)"
            lines.append(f"### {status} — {result.scanner_name}")
            lines.append(f"- Files scanned: {result.files_scanned}")
            lines.append(f"- Duration: {result.scan_duration_ms:.0f}ms")
            lines.append(f"- Risk score: {result.risk_score:.1f}/100")
            lines.append("")

        # Detailed findings
        if r.total_findings > 0:
            lines.append("## Detailed Findings")
            lines.append("")
            for result in r.scanner_results:
                if not result.findings:
                    continue
                lines.append(f"### {result.scanner_name}")
                lines.append("")
                sorted_findings = sorted(result.findings, key=lambda f: self.SEVERITY_ORDER.index(f.severity))
                for i, finding in enumerate(sorted_findings, 1):
                    sev = finding.severity
                    loc = f":L{finding.line_number}" if finding.line_number else ""
                    lines.append(f"#### {i}. {sev.symbol} [{sev.value.upper()}] {finding.title}")
                    lines.append("")
                    lines.append(f"- **File**: `{finding.file_path}{loc}`")
                    lines.append(f"- **Description**: {finding.description}")
                    if finding.remediation:
                        lines.append(f"- **Remediation**: {finding.remediation}")
                    if finding.cwe_id:
                        lines.append(f"- **CWE**: {finding.cwe_id}")
                    lines.append("")

        return "\n".join(lines)
