"""
Secret Leak Scanner
密钥泄露扫描器

Scans all files for accidentally committed secrets, credentials, and sensitive data:
- API keys and tokens
- Database credentials
- Private keys and certificates
- Cloud provider credentials
- Generic secret patterns
"""

import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from ..core.engine import BaseScanner, ScanResult, Severity


class SecretLeakScanner(BaseScanner):
    """Scans files for accidentally committed secrets and credentials."""

    scanner_id = "secret-leak"
    scanner_name = "Secret Leak Scanner"
    description = "Scans all files for accidentally committed API keys, tokens, credentials, and private keys"
    target_patterns = ["*"]  # Scan all files

    # Regex patterns for secret detection (pattern, description, severity, CWE)
    SECRET_PATTERNS: List[Tuple[str, str, Severity, str]] = [
        # Generic API keys
        (r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "Generic API key", Severity.HIGH, "CWE-798"),
        (r"(?i)(?:secret[_-]?key|secretkey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "Secret key", Severity.HIGH, "CWE-798"),
        (r"(?i)(?:access[_-]?key|accesskey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "Access key", Severity.HIGH, "CWE-798"),

        # GitHub tokens
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token", Severity.CRITICAL, "CWE-798"),
        (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Access Token", Severity.CRITICAL, "CWE-798"),
        (r"ghu_[a-zA-Z0-9]{36}", "GitHub User-to-Server Token", Severity.CRITICAL, "CWE-798"),
        (r"ghs_[a-zA-Z0-9]{36}", "GitHub Server-to-Server Token", Severity.CRITICAL, "CWE-798"),
        (r"ghr_[a-zA-Z0-9]{36}", "GitHub Refresh Token", Severity.CRITICAL, "CWE-798"),

        # AWS credentials
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity.CRITICAL, "CWE-798"),
        (r"(?i)aws[_\-.]secret[_\-.]?access[_\-.]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}", "AWS Secret Access Key", Severity.CRITICAL, "CWE-798"),

        # Google Cloud
        (r'"type":\s*"service_account"', "Google Cloud Service Account Key", Severity.CRITICAL, "CWE-798"),

        # NPM tokens
        (r"npm_[a-zA-Z0-9]{36}", "NPM Access Token", Severity.CRITICAL, "CWE-798"),

        # PyPI tokens
        (r"pypi-[a-zA-Z0-9]{36}", "PyPI API Token", Severity.CRITICAL, "CWE-798"),

        # Slack tokens
        (r"xox[baprs]-[a-zA-Z0-9-]{10,}", "Slack Token", Severity.HIGH, "CWE-798"),

        # Private keys
        (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key", Severity.CRITICAL, "CWE-798"),
        (r"-----BEGIN CERTIFICATE-----", "Certificate", Severity.MEDIUM, "CWE-798"),

        # Database URLs
        (r"(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^\s'\"<>]+:[^\s'\"<>]+@", "Database Connection String with Password", Severity.CRITICAL, "CWE-327"),

        # JWT tokens
        (r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "JSON Web Token (JWT)", Severity.HIGH, "CWE-798"),

        # Generic high-entropy strings that look like secrets
        (r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}", "Password in code/config", Severity.HIGH, "CWE-798"),

        # Stripe keys
        (r"(?:sk|pk)_(?:test|live)_[a-zA-Z0-9]{24,}", "Stripe API Key", Severity.CRITICAL, "CWE-798"),

        # SendGrid
        (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "SendGrid API Key", Severity.CRITICAL, "CWE-798"),

        # Twilio
        (r"SK[0-9a-fA-F]{32}", "Twilio API Key", Severity.HIGH, "CWE-798"),

        # Azure
        (r"[a-zA-Z0-9]{36}\.windows\.net", "Azure Connection String", Severity.HIGH, "CWE-798"),

        # OpenAI
        (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key", Severity.CRITICAL, "CWE-798"),

        # Anthropic
        (r"sk-ant-[a-zA-Z0-9-]{95}", "Anthropic API Key", Severity.CRITICAL, "CWE-798"),

        # Generic Bearer tokens
        (r"(?i)Bearer\s+[a-zA-Z0-9._\-]{20,}", "Bearer Token", Severity.MEDIUM, "CWE-798"),

        # Webhook secrets
        (r"(?i)whsec_[a-zA-Z0-9]{32,}", "Webhook Secret", Severity.HIGH, "CWE-798"),
    ]

    # Files to skip (binary files, images, etc.)
    SKIP_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2",
        ".pyc", ".pyo", ".class", ".o", ".so", ".dll", ".dylib", ".exe",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",
        ".db", ".sqlite", ".sqlite3", ".mdb",
    }

    # Maximum file size to scan (1MB)
    MAX_FILE_SIZE = 1024 * 1024

    def should_scan_file(self, file_path: Path) -> bool:
        """Override to exclude binary files and large files."""
        if file_path.suffix.lower() in self.SKIP_EXTENSIONS:
            return False
        try:
            if file_path.stat().st_size > self.MAX_FILE_SIZE:
                return False
        except OSError:
            return False
        # Skip lock files and minified files
        if file_path.name.endswith(".lock") or ".min." in file_path.name:
            return False
        return True

    def _scan_content(self, content: str, file_path: Path):
        """Scan file content for secret patterns."""
        for pattern, description, severity, cwe in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                # Mask the actual secret value in the output
                matched_text = match.group(0)
                masked = matched_text[:8] + "..." + matched_text[-4:] if len(matched_text) > 16 else "***"

                self.add_finding(
                    severity=severity,
                    title=f"{description} detected",
                    description=f"Potential {description.lower()} found at line {line_num}: '{masked}'",
                    file_path=str(file_path),
                    line_number=line_num,
                    remediation="Remove the secret from the source code. Use environment variables, secrets managers, or encrypted config files instead. If this secret has been committed, rotate it immediately.",
                    cwe_id=cwe,
                    raw_data={"description": description, "masked_value": masked, "line": line_content.strip()},
                )

    def scan(self) -> ScanResult:
        """Execute the secret leak scan."""
        import time
        start = time.time()

        files = self._walk_files()
        self.files_scanned = len(files)

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except (IOError, OSError):
                continue

            self._scan_content(content, file_path)

        end = time.time()
        return ScanResult(
            scanner_id=self.scanner_id,
            scanner_name=self.scanner_name,
            findings=self.findings,
            files_scanned=self.files_scanned,
            scan_duration_ms=(end - start) * 1000,
        )
