"""
MCP Server Configuration Security Scanner
MCP服务器配置安全扫描器

Scans MCP server configuration files for security risks including:
- Unsafe command execution patterns
- Excessive filesystem permissions
- Network exposure risks
- Missing sandbox configurations
- Suspicious environment variable usage
"""

import json
import re
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from ..core.engine import BaseScanner, ScanResult, Severity


class MCPServerScanner(BaseScanner):
    """Scans MCP server configuration files for security vulnerabilities."""

    scanner_id = "mcp-server"
    scanner_name = "MCP Server Configuration Scanner"
    description = "Scans MCP server configs for unsafe commands, excessive permissions, and security risks"
    target_patterns = [
        "*.json",
        "mcp*.json",
        "claude_desktop_config.json",
        "cline_mcp_settings.json",
        ".mcp.json",
        "mcp.json",
        "mcp-config.json",
        "mcp_settings.json",
    ]

    # Known dangerous commands that should never be in MCP configs
    DANGEROUS_COMMANDS = {
        "rm -rf": ("Destructive file deletion command", Severity.CRITICAL, "CWE-78"),
        "mkfs": ("Filesystem formatting command", Severity.CRITICAL, "CWE-78"),
        "dd if=": ("Direct disk write command", Severity.CRITICAL, "CWE-78"),
        ":(){ :|:& };:": ("Fork bomb pattern", Severity.CRITICAL, "CWE-400"),
        "chmod 777": ("Overly permissive file permissions", Severity.HIGH, "CWE-732"),
        "curl | sh": ("Piped remote script execution", Severity.CRITICAL, "CWE-78"),
        "curl | bash": ("Piped remote script execution", Severity.CRITICAL, "CWE-78"),
        "wget | sh": ("Piped remote script execution", Severity.CRITICAL, "CWE-78"),
        "wget | bash": ("Piped remote script execution", Severity.CRITICAL, "CWE-78"),
        "eval ": ("Dynamic code evaluation", Severity.HIGH, "CWE-95"),
        "exec(": ("Shell exec function", Severity.HIGH, "CWE-78"),
        "system(": ("System call function", Severity.HIGH, "CWE-78"),
        "subprocess.call": ("Subprocess call without safety checks", Severity.MEDIUM, "CWE-78"),
        "os.system": ("OS system call", Severity.HIGH, "CWE-78"),
        "pickle.loads": ("Unsafe deserialization", Severity.CRITICAL, "CWE-502"),
        "yaml.load": ("Unsafe YAML parsing (use safe_load)", Severity.HIGH, "CWE-502"),
    }

    # Risky environment variables that shouldn't be exposed
    RISKY_ENV_VARS = {
        "AWS_SECRET_ACCESS_KEY": ("AWS secret key exposure", Severity.CRITICAL, "CWE-798"),
        "AWS_ACCESS_KEY_ID": ("AWS access key exposure", Severity.HIGH, "CWE-798"),
        "DATABASE_URL": ("Database connection string exposure", Severity.HIGH, "CWE-327"),
        "PRIVATE_KEY": ("Private key exposure", Severity.CRITICAL, "CWE-798"),
        "API_KEY": ("Generic API key exposure", Severity.HIGH, "CWE-798"),
        "SECRET_KEY": ("Secret key exposure", Severity.HIGH, "CWE-798"),
        "TOKEN": ("Token exposure", Severity.MEDIUM, "CWE-798"),
        "PASSWORD": ("Password exposure", Severity.CRITICAL, "CWE-798"),
        "GITHUB_TOKEN": ("GitHub token exposure", Severity.HIGH, "CWE-798"),
        "NPM_TOKEN": ("NPM token exposure", Severity.HIGH, "CWE-798"),
        "PYPI_API_TOKEN": ("PyPI token exposure", Severity.HIGH, "CWE-798"),
    }

    # Risky network patterns
    RISKY_NETWORK_PATTERNS = [
        (r"https?://localhost:\d+", ("Localhost network access without restriction", Severity.MEDIUM, "CWE-400")),
        (r"https?://127\.0\.0\.1:\d+", ("Loopback network access", Severity.MEDIUM, "CWE-400")),
        (r"https?://0\.0\.0\.0:\d+", ("All-interfaces network binding", Severity.HIGH, "CWE-400")),
        (r"ssh://.*@", ("SSH connection in config", Severity.MEDIUM, "CWE-319")),
        (r"ftp://", ("Insecure FTP protocol", Severity.HIGH, "CWE-319")),
        (r"http://(?!localhost|127\.0\.0\.1)", ("Unencrypted HTTP connection", Severity.MEDIUM, "CWE-319")),
    ]

    # MCP-specific configuration keys that need security review
    SENSITIVE_MCP_KEYS = [
        ("command", "Server startup command"),
        ("args", "Server arguments"),
        ("env", "Environment variables"),
        ("cwd", "Working directory"),
    ]

    def _is_mcp_config(self, content: str, file_path: Path) -> bool:
        """Check if a JSON file contains MCP configuration."""
        try:
            data = json.loads(content)
            # Check for common MCP config structures
            if isinstance(data, dict):
                # Top-level mcpServers key
                if "mcpServers" in data:
                    return True
                # Check for server entries with command/args/env
                for key, value in data.items():
                    if isinstance(value, dict) and "command" in value:
                        return True
                    if isinstance(value, dict) and "url" in value and "mcp" in str(value).lower():
                        return True
                # Cursor/Windsurf style config
                if any(k in data for k in ["mcp", "servers", "tools"]):
                    return True
            return False
        except (json.JSONDecodeError, TypeError):
            return False

    def _scan_mcp_server_entry(
        self, server_name: str, config: Dict[str, Any], file_path: Path, root_key: str
    ):
        """Scan a single MCP server configuration entry."""
        # Check command for dangerous patterns
        command = config.get("command", "")
        if command:
            cmd_str = str(command)
            for pattern, (desc, severity, cwe) in self.DANGEROUS_COMMANDS.items():
                if pattern in cmd_str:
                    self.add_finding(
                        severity=severity,
                        title=f"Dangerous command in MCP server '{server_name}'",
                        description=f"The server command contains a dangerous pattern: '{pattern}'. {desc}",
                        file_path=str(file_path),
                        remediation=f"Remove or replace the dangerous command pattern '{pattern}' with a safer alternative.",
                        cwe_id=cwe,
                        raw_data={"server_name": server_name, "command": cmd_str, "pattern": pattern},
                    )

            # Check if command uses npx/pipx without version pinning
            if cmd_str.startswith("npx ") and "@" not in cmd_str:
                self.add_finding(
                    severity=Severity.MEDIUM,
                    title=f"Unpinned npx command in MCP server '{server_name}'",
                    description=f"The npx command '{cmd_str}' does not specify a version, which could lead to supply chain attacks through package hijacking.",
                    file_path=str(file_path),
                    remediation="Pin the package version explicitly, e.g., 'npx package@1.2.3'",
                    cwe_id="CWE-1357",
                    raw_data={"server_name": server_name, "command": cmd_str},
                )

            if cmd_str.startswith("pipx run ") and "@" not in cmd_str:
                self.add_finding(
                    severity=Severity.MEDIUM,
                    title=f"Unpinned pipx command in MCP server '{server_name}'",
                    description=f"The pipx command '{cmd_str}' does not specify a version.",
                    file_path=str(file_path),
                    remediation="Pin the package version explicitly, e.g., 'pipx run package==1.2.3'",
                    cwe_id="CWE-1357",
                    raw_data={"server_name": server_name, "command": cmd_str},
                )

        # Check arguments for dangerous patterns
        args = config.get("args", [])
        if isinstance(args, list):
            args_str = " ".join(str(a) for a in args)
            for pattern, (desc, severity, cwe) in self.DANGEROUS_COMMANDS.items():
                if pattern in args_str:
                    self.add_finding(
                        severity=severity,
                        title=f"Dangerous argument in MCP server '{server_name}'",
                        description=f"Server arguments contain dangerous pattern: '{pattern}'. {desc}",
                        file_path=str(file_path),
                        remediation=f"Remove or replace the dangerous argument pattern '{pattern}'.",
                        cwe_id=cwe,
                        raw_data={"server_name": server_name, "args": args},
                    )

        # Check environment variables
        env = config.get("env", {})
        if isinstance(env, dict):
            for var_name, var_value in env.items():
                var_name_upper = var_name.upper()
                for pattern, (desc, severity, cwe) in self.RISKY_ENV_VARS.items():
                    if pattern in var_name_upper:
                        # Check if value looks like a real secret (not a placeholder)
                        value_str = str(var_value)
                        if value_str and not any(
                            p in value_str.lower()
                            for p in ["${", "$(", "your_", "placeholder", "xxx", "example", "<", ">"]
                        ):
                            self.add_finding(
                                severity=severity,
                                title=f"Sensitive env var '{var_name}' in MCP server '{server_name}'",
                                description=f"Environment variable '{var_name}' may contain a real secret value. {desc}",
                                file_path=str(file_path),
                                remediation=f"Use environment variable injection instead of hardcoding '{var_name}'. Set it in your shell profile or use a secrets manager.",
                                cwe_id=cwe,
                                raw_data={"server_name": server_name, "var_name": var_name},
                            )
                        else:
                            self.add_finding(
                                severity=Severity.INFO,
                                title=f"Env var '{var_name}' reference in MCP server '{server_name}'",
                                description=f"Environment variable '{var_name}' is referenced. Ensure it is set securely at runtime, not committed to version control.",
                                file_path=str(file_path),
                                remediation=f"Use a secrets manager or secure env injection for '{var_name}'.",
                                cwe_id=cwe,
                                raw_data={"server_name": server_name, "var_name": var_name},
                            )
                        break

                # Check for inline secrets in env values
                value_str = str(var_value)
                for secret_pattern, (desc, severity, cwe) in [
                    (r"(?:sk|pk|key|token|secret)[-_][a-zA-Z0-9]{20,}", ("Inline secret detected in env value", Severity.CRITICAL, "CWE-798")),
                    (r"ghp_[a-zA-Z0-9]{36}", ("GitHub PAT detected in env value", Severity.CRITICAL, "CWE-798")),
                    (r"gho_[a-zA-Z0-9]{36}", ("GitHub OAuth token detected", Severity.CRITICAL, "CWE-798")),
                    (r"ghs_[a-zA-Z0-9]{36}", ("GitHub App token detected", Severity.CRITICAL, "CWE-798")),
                    (r"npm_[a-zA-Z0-9]{36}", ("NPM token detected", Severity.CRITICAL, "CWE-798")),
                    (r"pypi-[a-zA-Z0-9]{36}", ("PyPI token detected", Severity.CRITICAL, "CWE-798")),
                ]:
                    if re.search(secret_pattern, value_str, re.IGNORECASE):
                        self.add_finding(
                            severity=severity,
                            title=f"Hardcoded secret in env var '{var_name}' for MCP server '{server_name}'",
                            description=f"{desc}. This is a critical security risk — secrets should never be hardcoded in configuration files.",
                            file_path=str(file_path),
                            remediation="Immediately rotate this credential and move it to a secure secrets manager.",
                            cwe_id=cwe,
                            raw_data={"server_name": server_name, "var_name": var_name},
                        )

        # Check for URL-based MCP servers (SSE/Streamable HTTP)
        url = config.get("url", "")
        if url:
            for pattern, (desc, severity, cwe) in self.RISKY_NETWORK_PATTERNS:
                if re.search(pattern, str(url)):
                    self.add_finding(
                        severity=severity,
                        title=f"Risky URL in MCP server '{server_name}'",
                        description=f"MCP server URL '{url}' uses a risky pattern. {desc}",
                        file_path=str(file_path),
                        remediation="Use HTTPS with proper authentication and verify the server identity.",
                        cwe_id=cwe,
                        raw_data={"server_name": server_name, "url": url},
                    )

            if "http://" in str(url) and "localhost" not in str(url) and "127.0.0.1" not in str(url):
                self.add_finding(
                    severity=Severity.HIGH,
                    title=f"Insecure HTTP URL in MCP server '{server_name}'",
                    description=f"MCP server uses unencrypted HTTP: '{url}'. Data may be intercepted in transit.",
                    file_path=str(file_path),
                    remediation="Switch to HTTPS to encrypt all MCP communication.",
                    cwe_id="CWE-319",
                    raw_data={"server_name": server_name, "url": url},
                )

        # Check working directory
        cwd = config.get("cwd", "")
        if cwd:
            cwd_str = str(cwd)
            if cwd_str == "/" or cwd_str == "/root" or cwd_str == "/home":
                self.add_finding(
                    severity=Severity.HIGH,
                    title=f"Overly broad working directory in MCP server '{server_name}'",
                    description=f"Working directory '{cwd_str}' is too broad, giving the MCP server access to the entire filesystem.",
                    file_path=str(file_path),
                    remediation="Restrict the working directory to a specific project folder.",
                    cwe_id="CWE-732",
                    raw_data={"server_name": server_name, "cwd": cwd_str},
                )

        # Check for missing sandbox/disabled safety features
        if "disabled" in config and config["disabled"] is False:
            # This is fine, just informational
            pass

        # Check for alwaysAllow patterns (auto-approving tools)
        always_allow = config.get("alwaysAllow", [])
        if isinstance(always_allow, list) and len(always_allow) > 10:
            self.add_finding(
                severity=Severity.MEDIUM,
                title=f"Excessive auto-approved tools in MCP server '{server_name}'",
                description=f"{len(always_allow)} tools are auto-approved without user confirmation. This reduces the security boundary between the AI agent and the system.",
                file_path=str(file_path),
                remediation="Review and minimize the auto-approved tools list. Only auto-approve read-only, safe operations.",
                cwe_id="CWE-284",
                raw_data={"server_name": server_name, "always_allow_count": len(always_allow)},
            )

    def scan(self) -> ScanResult:
        """Execute the MCP server configuration scan."""
        import time
        start = time.time()

        files = self._walk_files()
        self.files_scanned = len(files)

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except (IOError, OSError):
                continue

            if not self._is_mcp_config(content, file_path):
                continue

            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                self.add_finding(
                    severity=Severity.LOW,
                    title=f"Invalid JSON in potential MCP config: {file_path.name}",
                    description=f"File '{file_path}' appears to be an MCP configuration but contains invalid JSON.",
                    file_path=str(file_path),
                    remediation="Fix the JSON syntax errors in the configuration file.",
                )
                continue

            if not isinstance(data, dict):
                continue

            # Scan top-level mcpServers
            mcp_servers = data.get("mcpServers", {})
            if isinstance(mcp_servers, dict):
                for server_name, server_config in mcp_servers.items():
                    if isinstance(server_config, dict):
                        self._scan_mcp_server_entry(server_name, server_config, file_path, "mcpServers")

            # Scan direct server entries
            for key, value in data.items():
                if key == "mcpServers":
                    continue
                if isinstance(value, dict) and "command" in value:
                    self._scan_mcp_server_entry(key, value, file_path, "direct")
                # Nested structures (Cursor style)
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        if isinstance(sub_value, dict) and "command" in sub_value:
                            self._scan_mcp_server_entry(sub_key, sub_value, file_path, f"{key}.{sub_key}")

        end = time.time()
        return ScanResult(
            scanner_id=self.scanner_id,
            scanner_name=self.scanner_name,
            findings=self.findings,
            files_scanned=self.files_scanned,
            scan_duration_ms=(end - start) * 1000,
        )
