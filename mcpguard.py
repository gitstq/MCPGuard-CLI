"""
MCPGuard-CLI — Lightweight Terminal MCP Ecosystem Security Intelligent Scanning Engine
轻量级终端MCP生态安全智能扫描引擎

Usage:
    python -m mcpguard scan <target_path> [options]
    mcpguard scan <target_path> [options]
"""

import sys
import os
import argparse
from pathlib import Path

# Add src to path for direct execution
sys.path.insert(0, str(Path(__file__).parent))

from src.core.engine import ScanEngine
from src.scanners.mcp_scanner import MCPServerScanner
from src.scanners.dependency_scanner import DependencyScanner
from src.scanners.editor_scanner import EditorExtensionScanner
from src.scanners.secret_scanner import SecretLeakScanner
from src.scanners.config_scanner import JSONConfigScanner
from src.reporters import TerminalReporter, JSONReporter, MarkdownReporter


def create_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcpguard",
        description="🛡️ MCPGuard-CLI — Lightweight Terminal MCP Ecosystem Security Intelligent Scanning Engine",
        epilog="Examples:\n"
               "  mcpguard scan ./my-project\n"
               "  mcpguard scan ./my-project --format json --output report.json\n"
               "  mcpguard scan ./my-project --scanners mcp,secret\n"
               "  mcpguard scan ./my-project --severity high\n"
               "  mcpguard scan ~/.config/claude --format markdown --output report.md",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan target for security issues")
    scan_parser.add_argument(
        "target",
        help="Target directory or file to scan",
    )
    scan_parser.add_argument(
        "--format", "-f",
        choices=["terminal", "json", "markdown"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    scan_parser.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout)",
    )
    scan_parser.add_argument(
        "--scanners", "-s",
        help="Comma-separated list of scanners to use (default: all). "
             "Available: mcp,dependency,editor,secret,config",
    )
    scan_parser.add_argument(
        "--severity", "-l",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="Minimum severity level to report (default: info)",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    scan_parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress all output except findings",
    )
    scan_parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"MCPGuard-CLI v{__import__('src').__version__}",
    )

    # Doctor command
    doctor_parser = subparsers.add_parser("doctor", help="Check MCPGuard-CLI environment and configuration")
    doctor_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )

    return parser


def get_scanner_map() -> dict:
    """Return a mapping of scanner short names to scanner classes."""
    return {
        "mcp": MCPServerScanner,
        "dependency": DependencyScanner,
        "editor": EditorExtensionScanner,
        "secret": SecretLeakScanner,
        "config": JSONConfigScanner,
    }


def filter_findings_by_severity(report, min_severity: str):
    """Filter findings below the minimum severity threshold."""
    severity_order = ["critical", "high", "medium", "low", "info"]
    min_idx = severity_order.index(min_severity)

    for result in report.scanner_results:
        filtered = []
        for finding in result.findings:
            finding_idx = severity_order.index(finding.severity.value)
            if finding_idx <= min_idx:
                filtered.append(finding)
        result.findings = filtered

    # Recalculate totals
    report.total_findings = sum(len(r.findings) for r in report.scanner_results)
    report.overall_risk_score = max(
        (r.risk_score for r in report.scanner_results if r.findings), default=0.0
    )


def run_doctor(args):
    """Run environment diagnostics."""
    no_color = args.no_color

    def c(text, code):
        return text if no_color else f"\033[{code}m{text}\033[0m"

    print("")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  🛡️  MCPGuard-CLI — Environment Diagnostics                 ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print("")

    # Python version
    py_version = sys.version.split()[0]
    py_ok = sys.version_info >= (3, 8)
    status = c("✅", "92") if py_ok else c("❌", "91")
    print(f"  {status} Python {py_version} (requires 3.8+)")

    # OS info
    import platform
    print(f"  ℹ️  OS: {platform.system()} {platform.release()}")

    # Architecture
    print(f"  ℹ️  Architecture: {platform.machine()}")

    # Available scanners
    scanner_map = get_scanner_map()
    print(f"  ✅ Available scanners: {', '.join(scanner_map.keys())}")

    # Target path check
    print("")
    print("  ── Common MCP Config Paths ─────────────────────────────────")
    config_paths = [
        ("Claude Desktop", Path.home() / ".config" / "Claude" / "claude_desktop_config.json"),
        ("Cursor", Path.home() / ".cursor" / "mcp.json"),
        ("VS Code", Path.home() / ".vscode" / "settings.json"),
        ("Windsurf", Path.home() / ".codeium" / "windsurf" / "mcp_config.json"),
    ]

    for name, path in config_paths:
        if path.exists():
            print(f"  ✅ {name}: {path} (found)")
        else:
            print(f"  ⚪ {name}: {path} (not found)")

    print("")
    print("  💡 Tip: Run 'mcpguard scan <path>' to scan a specific directory.")
    print("")


def run_scan(args):
    """Execute the security scan."""
    target = Path(args.target).resolve()

    if not target.exists():
        print(f"❌ Error: Target path does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(f"🛡️ MCPGuard-CLI v{__import__('src').__version__}")
        print(f"🔍 Scanning: {target}")
        print("")

    # Create engine
    engine = ScanEngine(str(target))

    # Register scanners
    scanner_map = get_scanner_map()
    if args.scanners:
        selected = [s.strip() for s in args.scanners.split(",")]
        for name in selected:
            if name in scanner_map:
                engine.register_scanner(scanner_map[name](str(target)))
            else:
                print(f"⚠️  Unknown scanner: {name}. Available: {', '.join(scanner_map.keys())}", file=sys.stderr)
    else:
        for scanner_cls in scanner_map.values():
            engine.register_scanner(scanner_cls(str(target)))

    # Run scan
    report = engine.run()

    # Filter by severity
    filter_findings_by_severity(report, args.severity)

    # Generate report
    if args.format == "terminal":
        reporter = TerminalReporter(report)
    elif args.format == "json":
        reporter = JSONReporter(report)
    elif args.format == "markdown":
        reporter = MarkdownReporter(report)
    else:
        reporter = TerminalReporter(report)

    output = reporter.generate()

    if args.output:
        reporter.save(args.output)
        if not args.quiet:
            print(f"📄 Report saved to: {args.output}")
    else:
        print(output)

    # Exit with non-zero code if critical/high findings
    critical_count = sum(
        1 for r in report.scanner_results
        for f in r.findings
        if f.severity.value in ("critical", "high")
    )
    if critical_count > 0:
        sys.exit(1)


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args)
    elif args.command == "doctor":
        run_doctor(args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
