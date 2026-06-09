"""
AI Editor Extension Security Scanner
AI编辑器扩展安全扫描器

Scans VS Code / Cursor / Windsurf extension configurations for:
- Excessive permission requests
- Suspicious marketplace sources
- Risky activation events
- Unsafe content script patterns
"""

import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from ..core.engine import BaseScanner, ScanResult, Severity


class EditorExtensionScanner(BaseScanner):
    """Scans AI editor extension configurations for security risks."""

    scanner_id = "editor-ext"
    scanner_name = "AI Editor Extension Security Scanner"
    description = "Scans VS Code/Cursor/Windsurf extension configs for excessive permissions and security risks"
    target_patterns = [
        "package.json",  # VS Code extensions use package.json
        "*.code-workspace",
    ]

    # Permissions that require careful review
    RISKY_CAPABILITIES = {
        "workspace.fs": ("Full filesystem access", Severity.HIGH, "CWE-732"),
        "terminal": ("Terminal/shell access", Severity.HIGH, "CWE-78"),
        "process": ("Process management", Severity.HIGH, "CWE-78"),
        "clipboard": ("Clipboard read/write", Severity.MEDIUM, "CWE-200"),
        "network": ("Network access", Severity.MEDIUM, "CWE-400"),
        "webview": ("WebView content injection", Severity.MEDIUM, "CWE-79"),
        "authentication": ("Authentication token access", Severity.HIGH, "CWE-798"),
        "secretStorage": ("Secret storage access", Severity.HIGH, "CWE-798"),
    }

    # Risky activation events
    RISKY_ACTIVATIONS = [
        (r"onCommand:", "Command activation"),
        (r"onLanguage:", "Language-specific activation"),
        (r"onFileSystem:", "Filesystem watcher activation"),
        (r"onTerminal:", "Terminal activation"),
        (r"\*", "Universal activation (activates on everything)"),
    ]

    def _is_extension(self, content: str, file_path: Path) -> bool:
        """Check if this package.json is a VS Code extension."""
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                return False
            # VS Code extension markers
            if "activationEvents" in data or "contributes" in data:
                return True
            if data.get("engines", {}).get("vscode"):
                return True
            # Cursor-specific markers
            if "cursor" in str(data.get("engines", {})).lower():
                return True
            return False
        except (json.JSONDecodeError, TypeError):
            return False

    def _scan_extension(self, data: Dict[str, Any], file_path: Path):
        """Scan a VS Code extension configuration."""
        extension_name = data.get("name", "unknown")
        display_name = data.get("displayName", extension_name)
        publisher = data.get("publisher", "unknown")

        # Check for universal activation
        activation_events = data.get("activationEvents", [])
        if isinstance(activation_events, list):
            if "*" in activation_events:
                self.add_finding(
                    severity=Severity.HIGH,
                    title=f"Universal activation in extension '{display_name}'",
                    description=f"Extension '{display_name}' activates on all events with '*'. This increases attack surface unnecessarily.",
                    file_path=str(file_path),
                    remediation="Restrict activation events to specific triggers relevant to the extension's functionality.",
                    cwe_id="CWE-400",
                    raw_data={"extension": extension_name, "activation": "*"},
                )

        # Check main entry point
        main_entry = data.get("main", "") or data.get("browser", "")
        if main_entry:
            if "eval" in main_entry or "Function(" in main_entry:
                self.add_finding(
                    severity=Severity.CRITICAL,
                    title=f"Suspicious entry point in extension '{display_name}'",
                    description=f"Extension entry point '{main_entry}' contains suspicious code patterns.",
                    file_path=str(file_path),
                    remediation="Review the extension source code carefully before installing.",
                    cwe_id="CWE-94",
                    raw_data={"extension": extension_name, "main": main_entry},
                )

        # Check contributes for risky features
        contributes = data.get("contributes", {})
        if isinstance(contributes, dict):
            # Check for custom terminal commands
            if "terminal" in contributes:
                self.add_finding(
                    severity=Severity.MEDIUM,
                    title=f"Terminal integration in extension '{display_name}'",
                    description="Extension registers terminal commands/profiles which could execute arbitrary shell commands.",
                    file_path=str(file_path),
                    remediation="Review terminal commands registered by this extension.",
                    cwe_id="CWE-78",
                    raw_data={"extension": extension_name},
                )

            # Check for custom editors
            if "customEditors" in contributes:
                self.add_finding(
                    severity=Severity.MEDIUM,
                    title=f"Custom editor in extension '{display_name}'",
                    description="Extension registers custom editors which handle file content directly.",
                    file_path=str(file_path),
                    remediation="Verify the custom editor handles file content safely.",
                    cwe_id="CWE-79",
                    raw_data={"extension": extension_name},
                )

            # Check for webview views (can execute JS)
            if "viewsContainers" in contributes:
                self.add_finding(
                    severity=Severity.LOW,
                    title=f"WebView in extension '{display_name}'",
                    description="Extension uses WebViews which can execute JavaScript.",
                    file_path=str(file_path),
                    remediation="Ensure WebView content is loaded from trusted sources only.",
                    cwe_id="CWE-79",
                    raw_data={"extension": extension_name},
                )

            # Check for commands
            commands = contributes.get("commands", [])
            if isinstance(commands, list):
                for cmd in commands:
                    if isinstance(cmd, dict):
                        cmd_title = cmd.get("title", "")
                        cmd_command = cmd.get("command", "")
                        # Flag commands with suspicious names
                        suspicious_keywords = ["shell", "exec", "run", "sudo", "admin", "root", "delete all"]
                        if any(kw in cmd_title.lower() for kw in suspicious_keywords):
                            self.add_finding(
                                severity=Severity.MEDIUM,
                                title=f"Suspicious command in extension '{display_name}'",
                                description=f"Extension registers command '{cmd_title}' ({cmd_command}) with a suspicious name.",
                                file_path=str(file_path),
                                remediation="Review this command's implementation carefully.",
                                cwe_id="CWE-78",
                                raw_data={"extension": extension_name, "command": cmd_command, "title": cmd_title},
                            )

        # Check for suspicious scripts
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for script_name, script_cmd in scripts.items():
                if isinstance(script_cmd, str):
                    for pattern, (desc, severity, cwe) in [
                        (r"curl.*\|.*sh", ("Piped remote script execution in scripts", Severity.CRITICAL, "CWE-78")),
                        (r"wget.*\|.*sh", ("Piped remote script execution in scripts", Severity.CRITICAL, "CWE-78")),
                        (r"rm\s+-rf", ("Destructive deletion in scripts", Severity.HIGH, "CWE-78")),
                        (r"chmod\s+777", ("Overly permissive permissions in scripts", Severity.HIGH, "CWE-732")),
                    ]:
                        if re.search(pattern, script_cmd):
                            self.add_finding(
                                severity=severity,
                                title=f"Dangerous script '{script_name}' in extension '{display_name}'",
                                description=f"Script '{script_name}' contains: {desc}",
                                file_path=str(file_path),
                                remediation=f"Review and fix the '{script_name}' script.",
                                cwe_id=cwe,
                                raw_data={"extension": extension_name, "script": script_name, "command": script_cmd},
                            )

        # Check for AI-specific features (MCP, copilot, etc.)
        all_text = json.dumps(data).lower()
        ai_keywords = ["mcp", "copilot", "ai", "llm", "gpt", "claude", "gemini", "openai"]
        has_ai = any(kw in all_text for kw in ai_keywords)
        if has_ai:
            self.add_finding(
                severity=Severity.INFO,
                title=f"AI-powered extension detected: '{display_name}'",
                description=f"Extension '{display_name}' appears to integrate AI features. AI extensions may send code/data to external servers.",
                file_path=str(file_path),
                remediation="Review the extension's privacy policy and data handling practices. Check what data is sent to external AI services.",
                cwe_id="CWE-200",
                raw_data={"extension": extension_name},
            )

    def scan(self) -> ScanResult:
        """Execute the editor extension security scan."""
        import time
        start = time.time()

        files = self._walk_files()
        self.files_scanned = len(files)

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except (IOError, OSError):
                continue

            if not self._is_extension(content, file_path):
                continue

            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                continue

            if isinstance(data, dict):
                self._scan_extension(data, file_path)

        end = time.time()
        return ScanResult(
            scanner_id=self.scanner_id,
            scanner_name=self.scanner_name,
            findings=self.findings,
            files_scanned=self.files_scanned,
            scan_duration_ms=(end - start) * 1000,
        )
