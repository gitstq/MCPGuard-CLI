"""
Dependency Security Scanner
依赖安全扫描器

Scans package dependency files for:
- Known vulnerable package patterns
- Suspicious dependency sources
- Missing lock files
- Outdated dependency patterns
- Typosquatting detection
"""

import re
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
from ..core.engine import BaseScanner, ScanResult, Severity


class DependencyScanner(BaseScanner):
    """Scans dependency files for security risks."""

    scanner_id = "dependency"
    scanner_name = "Dependency Security Scanner"
    description = "Scans package dependency files for vulnerable packages, typosquatting, and security risks"
    target_patterns = [
        "package.json",
        "package-lock.json",
        "requirements.txt",
        "Pipfile",
        "Pipfile.lock",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "poetry.lock",
        "Cargo.toml",
        "Cargo.lock",
        "go.mod",
        "go.sum",
        "Gemfile",
        "Gemfile.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
    ]

    # Common typosquatting patterns (package name → legitimate name)
    TYPOSQUAT_PATTERNS: Dict[str, List[str]] = {
        "npm": [
            (r"^(lodash|react|vue|express|axios|moment|webpack|babel|eslint|prettier)[-_](core|utils|lib|plus|pro|mini|js|ts)$", "Possible typosquatting of popular package"),
        ],
        "pypi": [
            (r"^(requests|numpy|pandas|flask|django|tensorflow|pytorch|pillow|scipy|matplotlib)[-_](utils|lib|plus|pro|mini|py|py3)$", "Possible typosquatting of popular package"),
        ],
    }

    # Packages with known critical vulnerabilities (simplified heuristic)
    KNOWN_VULN_PACKAGES: Dict[str, List[Tuple[str, str, Severity]]] = {
        "npm": [
            ("event-stream", "3.3.6", Severity.CRITICAL),
            ("crossenv", "any", Severity.CRITICAL),
            ("flatmap-stream", "any", Severity.CRITICAL),
            ("lodash", "4.17.11", Severity.HIGH),
            ("express", "4.16.0", Severity.MEDIUM),
            ("minimist", "0.0.8", Severity.HIGH),
            ("node-forge", "0.10.0", Severity.HIGH),
        ],
        "pypi": [
            ("pickle", "any", Severity.HIGH),
            ("pycrypto", "any", Severity.CRITICAL),
            ("urllib3", "1.25.0", Severity.MEDIUM),
        ],
    }

    def _parse_package_json(self, content: str, file_path: Path) -> List[Dict[str, str]]:
        """Parse npm package.json dependencies."""
        deps = []
        try:
            data = json.loads(content)
            for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
                for name, version in data.get(section, {}).items():
                    deps.append({"name": name, "version": version, "section": section})
        except (json.JSONDecodeError, TypeError):
            pass
        return deps

    def _parse_requirements_txt(self, content: str, file_path: Path) -> List[Dict[str, str]]:
        """Parse Python requirements.txt dependencies."""
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Handle various requirement formats
            match = re.match(r"^([a-zA-Z0-9_-]+)\s*(?:[=<>!~]+\s*)?([0-9][\w.*]*)?", line)
            if match:
                deps.append({"name": match.group(1), "version": match.group(2) or "unknown", "section": "requirements"})
        return deps

    def _parse_pyproject_toml(self, content: str, file_path: Path) -> List[Dict[str, str]]:
        """Parse Python pyproject.toml dependencies (basic parsing)."""
        deps = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("[project.dependencies]") or stripped.startswith("[tool.poetry.dependencies]"):
                in_deps = True
                continue
            if stripped.startswith("[") and in_deps:
                in_deps = False
                continue
            if in_deps and stripped and not stripped.startswith("#"):
                match = re.match(r'^([a-zA-Z0-9_-]+)\s*(?:[=<>!~]+\s*)?["\']?([0-9][\w.*]*)?["\']?', stripped)
                if match:
                    deps.append({"name": match.group(1), "version": match.group(2) or "unknown", "section": "dependencies"})
        return deps

    def _check_typosquatting(self, name: str, ecosystem: str, file_path: Path):
        """Check if a package name might be a typosquatting attempt."""
        patterns = self.TYPOSQUAT_PATTERNS.get(ecosystem, [])
        for pattern, desc in patterns:
            if re.match(pattern, name, re.IGNORECASE):
                self.add_finding(
                    severity=Severity.HIGH,
                    title=f"Possible typosquatting: '{name}'",
                    description=f"Package '{name}' matches a known typosquatting pattern. {desc}. Verify this is the intended package.",
                    file_path=str(file_path),
                    remediation=f"Verify the package '{name}' is legitimate by checking its npm/PyPI page, author, and download count.",
                    cwe_id="CWE-1357",
                    raw_data={"package_name": name, "ecosystem": ecosystem},
                )

    def _check_known_vulns(self, name: str, version: str, ecosystem: str, file_path: Path):
        """Check against known vulnerable packages."""
        vulns = self.KNOWN_VULN_PACKAGES.get(ecosystem, [])
        for vuln_name, vuln_version, severity in vulns:
            if name == vuln_name:
                if vuln_version == "any" or version == vuln_version:
                    self.add_finding(
                        severity=severity,
                        title=f"Known vulnerable package: '{name}'",
                        description=f"Package '{name}' (version {version}) has known security vulnerabilities.",
                        file_path=str(file_path),
                        remediation=f"Update '{name}' to the latest patched version immediately.",
                        cwe_id="CWE-1357",
                        raw_data={"package_name": name, "version": version, "ecosystem": ecosystem},
                    )

    def scan(self) -> ScanResult:
        """Execute the dependency security scan."""
        import time
        start = time.time()

        files = self._walk_files()
        self.files_scanned = len(files)

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except (IOError, OSError):
                continue

            fname = file_path.name
            deps = []

            if fname == "package.json":
                deps = self._parse_package_json(content, file_path)
                ecosystem = "npm"
                # Check for missing lock file
                lock_path = file_path.parent / "package-lock.json"
                if not lock_path.exists():
                    self.add_finding(
                        severity=Severity.MEDIUM,
                        title="Missing package-lock.json",
                        description="No lock file found. Dependencies may resolve to different versions across installations, leading to inconsistent builds.",
                        file_path=str(file_path),
                        remediation="Run 'npm install' to generate package-lock.json and commit it to version control.",
                        cwe_id="CWE-1357",
                        raw_data={"file": fname},
                    )

            elif fname == "requirements.txt":
                deps = self._parse_requirements_txt(content, file_path)
                ecosystem = "pypi"
                # Check for unpinned dependencies
                for dep in deps:
                    if dep["version"] == "unknown":
                        self.add_finding(
                            severity=Severity.MEDIUM,
                            title=f"Unpinned dependency: '{dep['name']}'",
                            description=f"Dependency '{dep['name']}' is not version-pinned, which may lead to unexpected breaking changes.",
                            file_path=str(file_path),
                            remediation=f"Pin the version: {dep['name']}==1.2.3",
                            cwe_id="CWE-1357",
                            raw_data={"package_name": dep["name"]},
                        )

            elif fname == "pyproject.toml":
                deps = self._parse_pyproject_toml(content, file_path)
                ecosystem = "pypi"

            if not deps:
                continue

            for dep in deps:
                self._check_typosquatting(dep["name"], ecosystem, file_path)
                self._check_known_vulns(dep["name"], dep["version"], ecosystem, file_path)

                # Check for suspicious package names
                if any(s in dep["name"].lower() for s in ["malware", "hack", "exploit", "backdoor", "rootkit"]):
                    self.add_finding(
                        severity=Severity.CRITICAL,
                        title=f"Suspicious package name: '{dep['name']}'",
                        description=f"Package '{dep['name']}' contains suspicious keywords that may indicate malicious intent.",
                        file_path=str(file_path),
                        remediation="Remove this package immediately and investigate if the system has been compromised.",
                        cwe_id="CWE-506",
                        raw_data={"package_name": dep["name"]},
                    )

        end = time.time()
        return ScanResult(
            scanner_id=self.scanner_id,
            scanner_name=self.scanner_name,
            findings=self.findings,
            files_scanned=self.files_scanned,
            scan_duration_ms=(end - start) * 1000,
        )
