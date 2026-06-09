"""
JSON Configuration Security Scanner
JSON配置文件安全扫描器

Scans JSON configuration files for:
- Hardcoded credentials
- Insecure default settings
- Overly permissive configurations
- Debug mode in production configs
"""

import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from ..core.engine import BaseScanner, ScanResult, Severity


class JSONConfigScanner(BaseScanner):
    """Scans JSON configuration files for security misconfigurations."""

    scanner_id = "json-config"
    scanner_name = "JSON Configuration Security Scanner"
    description = "Scans JSON config files for hardcoded credentials, insecure defaults, and misconfigurations"
    target_patterns = ["*.json"]

    # Insecure configuration patterns
    INSECURE_PATTERNS: List[Tuple[str, str, str, Severity, str]] = [
        (r'"debug"\s*:\s*true', "debug", "Debug mode enabled", Severity.MEDIUM, "CWE-489"),
        (r'"ssl"\s*:\s*false', "ssl", "SSL/TLS disabled", Severity.HIGH, "CWE-319"),
        (r'"verify"\s*:\s*false', "verify", "Certificate verification disabled", Severity.HIGH, "CWE-295"),
        (r'"secure"\s*:\s*false', "secure", "Secure flag disabled", Severity.MEDIUM, "CWE-311"),
        (r'"auth"\s*:\s*false', "auth", "Authentication disabled", Severity.CRITICAL, "CWE-306"),
        (r'"authentication"\s*:\s*false', "authentication", "Authentication disabled", Severity.CRITICAL, "CWE-306"),
        (r'"cors"\s*:\s*true', "cors", "CORS enabled without restrictions", Severity.MEDIUM, "CWE-346"),
        (r'"allowOrigin"\s*:\s*"\*"', "allowOrigin", "CORS allows all origins", Severity.HIGH, "CWE-346"),
        (r'"allowedOrigins"\s*:\s*\["\*"\]', "allowedOrigins", "CORS allows all origins", Severity.HIGH, "CWE-346"),
        (r'"trustProxy"\s*:\s*true', "trustProxy", "Trust proxy enabled (potential SSRF risk)", Severity.MEDIUM, "CWE-918"),
        (r'"eval"\s*:\s*true', "eval", "Eval mode enabled", Severity.HIGH, "CWE-95"),
        (r'"unsafe"\s*:\s*true', "unsafe", "Unsafe mode enabled", Severity.HIGH, "CWE-94"),
        (r'"strictMode"\s*:\s*false', "strictMode", "Strict mode disabled", Severity.LOW, "CWE-94"),
        (r'"noAuth"\s*:\s*true', "noAuth", "No authentication required", Severity.CRITICAL, "CWE-306"),
        (r'"anonymous"\s*:\s*true', "anonymous", "Anonymous access enabled", Severity.HIGH, "CWE-306"),
        (r'"logging"\s*:\s*true', "logging", "Logging enabled (may leak sensitive data)", Severity.INFO, "CWE-532"),
        (r'"logLevel"\s*:\s*"(debug|trace)"', "logLevel", "Debug/trace logging level (may leak sensitive data)", Severity.INFO, "CWE-532"),
    ]

    # Files to skip (already handled by other scanners)
    SKIP_FILES = {
        "package-lock.json", "package.json",  # Handled by dependency scanner
        "node_modules", ".git",
    }

    def should_scan_file(self, file_path: Path) -> bool:
        """Override to exclude specific files."""
        if file_path.name in self.SKIP_FILES:
            return False
        if any(part in file_path.parts for part in {"node_modules", ".git", "__pycache__", ".venv", "venv"}):
            return False
        return super().should_scan_file(file_path)

    def _scan_json_config(self, content: str, file_path: Path):
        """Scan a JSON configuration file."""
        # Check for insecure patterns in raw content
        for pattern, key, description, severity, cwe in self.INSECURE_PATTERNS:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                self.add_finding(
                    severity=severity,
                    title=f"Insecure config: {description}",
                    description=f"Configuration file contains '{key}' set to an insecure value at line {line_num}. {description}.",
                    file_path=str(file_path),
                    line_number=line_num,
                    remediation=f"Review the '{key}' setting and ensure it is configured securely for production use.",
                    cwe_id=cwe,
                    raw_data={"key": key, "file": file_path.name},
                )

        # Parse and check for nested credential patterns
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        if not isinstance(data, dict):
            return

        self._check_nested_config(data, file_path, "")

    def _check_nested_config(self, data: Dict[str, Any], file_path: Path, prefix: str):
        """Recursively check nested configuration for security issues."""
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key

            # Check for credential-like keys with non-placeholder values
            if isinstance(value, str) and value:
                key_lower = key.lower()
                credential_indicators = [
                    "password", "passwd", "pwd", "secret", "token",
                    "api_key", "apikey", "access_key", "private_key",
                    "credential", "auth_token", "session_key",
                ]
                for indicator in credential_indicators:
                    if indicator in key_lower:
                        # Check if value looks like a real credential
                        if not any(p in value.lower() for p in [
                            "${", "$(", "env:", "your_", "placeholder",
                            "xxx", "example", "<", ">", "change_me",
                            "todo", "fixme", "localhost",
                        ]):
                            if len(value) > 8 and not value.startswith("#"):
                                self.add_finding(
                                    severity=Severity.HIGH,
                                    title=f"Possible hardcoded credential: '{full_key}'",
                                    description=f"Configuration key '{full_key}' contains a value that appears to be a real credential.",
                                    file_path=str(file_path),
                                    remediation=f"Move the '{full_key}' value to environment variables or a secrets manager.",
                                    cwe_id="CWE-798",
                                    raw_data={"key": full_key},
                                )
                        break

            # Recurse into nested objects
            if isinstance(value, dict):
                self._check_nested_config(value, file_path, full_key)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        self._check_nested_config(item, file_path, f"{full_key}[{i}]")

    def scan(self) -> ScanResult:
        """Execute the JSON configuration security scan."""
        import time
        start = time.time()

        files = self._walk_files()
        self.files_scanned = len(files)

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except (IOError, OSError):
                continue

            self._scan_json_config(content, file_path)

        end = time.time()
        return ScanResult(
            scanner_id=self.scanner_id,
            scanner_name=self.scanner_name,
            findings=self.findings,
            files_scanned=self.files_scanned,
            scan_duration_ms=(end - start) * 1000,
        )
