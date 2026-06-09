"""
Unit tests for MCPGuard-CLI
"""

import sys
import os
import json
import tempfile
import unittest
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.engine import ScanEngine, Severity, Finding, ScanResult
from src.scanners.mcp_scanner import MCPServerScanner
from src.scanners.dependency_scanner import DependencyScanner
from src.scanners.editor_scanner import EditorExtensionScanner
from src.scanners.secret_scanner import SecretLeakScanner
from src.scanners.config_scanner import JSONConfigScanner
from src.reporters import TerminalReporter, JSONReporter, MarkdownReporter


class TestMCPServerScanner(unittest.TestCase):
    """Test MCP server configuration scanner."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_dangerous_command_detection(self):
        """Test detection of dangerous commands in MCP configs."""
        config = {
            "mcpServers": {
                "malicious-server": {
                    "command": "rm -rf /",
                    "args": ["--force"],
                }
            }
        }
        config_path = Path(self.tmpdir) / "mcp.json"
        config_path.write_text(json.dumps(config))

        scanner = MCPServerScanner(self.tmpdir)
        result = scanner.scan()

        self.assertTrue(len(result.findings) > 0)
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(len(critical) > 0, "Should detect rm -rf as critical")

    def test_unpinned_npx_detection(self):
        """Test detection of unpinned npx commands."""
        config = {
            "mcpServers": {
                "unpinned-server": {
                    "command": "npx some-mcp-server",
                    "args": [],
                }
            }
        }
        config_path = Path(self.tmpdir) / "config.json"
        config_path.write_text(json.dumps(config))

        scanner = MCPServerScanner(self.tmpdir)
        result = scanner.scan()

        medium = [f for f in result.findings if f.severity == Severity.MEDIUM]
        self.assertTrue(any("Unpinned npx" in f.title for f in medium))

    def test_pinned_npx_no_warning(self):
        """Test that pinned npx commands don't trigger warnings."""
        config = {
            "mcpServers": {
                "pinned-server": {
                    "command": "npx some-mcp-server@1.2.3",
                    "args": [],
                }
            }
        }
        config_path = Path(self.tmpdir) / "config.json"
        config_path.write_text(json.dumps(config))

        scanner = MCPServerScanner(self.tmpdir)
        result = scanner.scan()

        unpinned = [f for f in result.findings if "Unpinned" in f.title]
        self.assertEqual(len(unpinned), 0, "Pinned npx should not trigger unpinned warning")

    def test_hardcoded_secret_in_env(self):
        """Test detection of hardcoded secrets in environment variables."""
        config = {
            "mcpServers": {
                "server-with-secret": {
                    "command": "node",
                    "env": {
                        "API_KEY": "sk-ant-api1234567890123456789012345678901234567890abc",
                    }
                }
            }
        }
        config_path = Path(self.tmpdir) / "config.json"
        config_path.write_text(json.dumps(config))

        scanner = MCPServerScanner(self.tmpdir)
        result = scanner.scan()

        # The scanner should detect the sensitive env var with a real-looking value
        high_or_critical = [f for f in result.findings if f.severity.value in ("high", "critical")]
        self.assertTrue(
            any("API_KEY" in f.title for f in high_or_critical),
            "Should detect hardcoded API_KEY in env vars"
        )

    def test_placeholder_env_no_false_positive(self):
        """Test that placeholder env values don't trigger false positives."""
        config = {
            "mcpServers": {
                "safe-server": {
                    "command": "node",
                    "env": {
                        "API_KEY": "${API_KEY}",
                    }
                }
            }
        }
        config_path = Path(self.tmpdir) / "config.json"
        config_path.write_text(json.dumps(config))

        scanner = MCPServerScanner(self.tmpdir)
        result = scanner.scan()

        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(not any("Hardcoded secret" in f.title for f in critical))

    def test_insecure_http_url(self):
        """Test detection of insecure HTTP URLs."""
        config = {
            "mcpServers": {
                "http-server": {
                    "url": "http://example.com/mcp",
                }
            }
        }
        config_path = Path(self.tmpdir) / "config.json"
        config_path.write_text(json.dumps(config))

        scanner = MCPServerScanner(self.tmpdir)
        result = scanner.scan()

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(any("Insecure HTTP" in f.title for f in high))

    def test_broad_working_directory(self):
        """Test detection of overly broad working directories."""
        config = {
            "mcpServers": {
                "root-server": {
                    "command": "node",
                    "cwd": "/",
                }
            }
        }
        config_path = Path(self.tmpdir) / "config.json"
        config_path.write_text(json.dumps(config))

        scanner = MCPServerScanner(self.tmpdir)
        result = scanner.scan()

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(any("broad working directory" in f.title.lower() for f in high))


class TestDependencyScanner(unittest.TestCase):
    """Test dependency security scanner."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_missing_lock_file(self):
        """Test detection of missing package-lock.json."""
        package_json = {"name": "test-project", "dependencies": {"express": "^4.18.0"}}
        pkg_path = Path(self.tmpdir) / "package.json"
        pkg_path.write_text(json.dumps(package_json))

        scanner = DependencyScanner(self.tmpdir)
        result = scanner.scan()

        self.assertTrue(any("Missing package-lock.json" in f.title for f in result.findings))

    def test_unpinned_requirements(self):
        """Test detection of unpinned Python requirements."""
        req_path = Path(self.tmpdir) / "requirements.txt"
        req_path.write_text("requests\nnumpy\nflask\n")

        scanner = DependencyScanner(self.tmpdir)
        result = scanner.scan()

        unpinned = [f for f in result.findings if "Unpinned" in f.title]
        self.assertEqual(len(unpinned), 3, "Should detect 3 unpinned dependencies")

    def test_pinned_requirements_no_warning(self):
        """Test that pinned requirements don't trigger warnings."""
        req_path = Path(self.tmpdir) / "requirements.txt"
        req_path.write_text("requests==2.31.0\nnumpy==1.24.0\nflask==3.0.0\n")

        scanner = DependencyScanner(self.tmpdir)
        result = scanner.scan()

        unpinned = [f for f in result.findings if "Unpinned" in f.title]
        self.assertEqual(len(unpinned), 0)


class TestSecretLeakScanner(unittest.TestCase):
    """Test secret leak scanner."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_github_token_detection(self):
        """Test detection of GitHub tokens."""
        file_path = Path(self.tmpdir) / "config.py"
        file_path.write_text('GITHUB_TOKEN = "ghp_abc123def456ghi789jkl012mno345pqr678"')

        scanner = SecretLeakScanner(self.tmpdir)
        result = scanner.scan()

        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(any("GitHub" in f.title for f in critical))

    def test_aws_key_detection(self):
        """Test detection of AWS access keys."""
        file_path = Path(self.tmpdir) / "env.sh"
        file_path.write_text('export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"')

        scanner = SecretLeakScanner(self.tmpdir)
        result = scanner.scan()

        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(any("AWS" in f.title for f in critical))

    def test_private_key_detection(self):
        """Test detection of private keys."""
        file_path = Path(self.tmpdir) / "key.pem"
        file_path.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n")

        scanner = SecretLeakScanner(self.tmpdir)
        result = scanner.scan()

        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(any("Private Key" in f.title for f in critical))

    def test_openai_key_detection(self):
        """Test detection of OpenAI API keys."""
        file_path = Path(self.tmpdir) / ".env"
        file_path.write_text('OPENAI_API_KEY="sk-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12"')

        scanner = SecretLeakScanner(self.tmpdir)
        result = scanner.scan()

        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(any("OpenAI" in f.title for f in critical))

    def test_binary_files_skipped(self):
        """Test that binary files are skipped."""
        file_path = Path(self.tmpdir) / "image.png"
        file_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        scanner = SecretLeakScanner(self.tmpdir)
        result = scanner.scan()

        self.assertEqual(result.files_scanned, 0, "Binary files should be skipped")


class TestJSONConfigScanner(unittest.TestCase):
    """Test JSON configuration scanner."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_debug_mode_detection(self):
        """Test detection of debug mode in configs."""
        config = {"debug": True, "port": 3000}
        config_path = Path(self.tmpdir) / "settings.json"
        config_path.write_text(json.dumps(config))

        scanner = JSONConfigScanner(self.tmpdir)
        result = scanner.scan()

        self.assertTrue(any("debug" in f.title.lower() for f in result.findings))

    def test_ssl_disabled_detection(self):
        """Test detection of disabled SSL."""
        config = {"ssl": False, "host": "0.0.0.0"}
        config_path = Path(self.tmpdir) / "server.json"
        config_path.write_text(json.dumps(config))

        scanner = JSONConfigScanner(self.tmpdir)
        result = scanner.scan()

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(any("SSL" in f.title for f in high))

    def test_auth_disabled_detection(self):
        """Test detection of disabled authentication."""
        config = {"auth": False, "port": 8080}
        config_path = Path(self.tmpdir) / "api.json"
        config_path.write_text(json.dumps(config))

        scanner = JSONConfigScanner(self.tmpdir)
        result = scanner.scan()

        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(any("Authentication" in f.title or "auth" in f.title.lower() for f in critical))


class TestReporters(unittest.TestCase):
    """Test report generation."""

    def _make_report(self):
        """Create a test report."""
        from src.core.engine import ScanReport, ScanResult, Finding
        report = ScanReport(
            target_path="/test/project",
            scan_timestamp="2026-06-09T00:00:00Z",
            total_findings=2,
            total_files_scanned=5,
            total_duration_ms=150.0,
            overall_risk_score=35.0,
        )
        result = ScanResult(
            scanner_id="test",
            scanner_name="Test Scanner",
            findings=[
                Finding(
                    scanner_id="test",
                    severity=Severity.HIGH,
                    title="Test finding",
                    description="A test finding",
                    file_path="/test/file.json",
                    remediation="Fix it",
                ),
            ],
            files_scanned=5,
            scan_duration_ms=150.0,
        )
        report.scanner_results.append(result)
        return report

    def test_terminal_report(self):
        """Test terminal report generation."""
        report = self._make_report()
        reporter = TerminalReporter(report)
        output = reporter.generate()
        self.assertIn("MCPGuard-CLI", output)
        self.assertIn("Test finding", output)

    def test_json_report(self):
        """Test JSON report generation."""
        report = self._make_report()
        reporter = JSONReporter(report)
        output = reporter.generate()
        data = json.loads(output)
        self.assertEqual(data["total_findings"], 2)
        self.assertIn("scanner_results", data)

    def test_markdown_report(self):
        """Test Markdown report generation."""
        report = self._make_report()
        reporter = MarkdownReporter(report)
        output = reporter.generate()
        self.assertIn("# 🛡️", output)
        self.assertIn("Test finding", output)


class TestScanEngine(unittest.TestCase):
    """Test the main scan engine."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_full_scan(self):
        """Test a full scan with all scanners."""
        # Create test files
        mcp_config = {
            "mcpServers": {
                "test-server": {
                    "command": "npx unsafe-server",
                    "env": {"API_KEY": "sk-ant-test12345678901234567890123456789012345"},
                }
            }
        }
        Path(self.tmpdir, "mcp.json").write_text(json.dumps(mcp_config))

        Path(self.tmpdir, "config.py").write_text('token = "ghp_abc123def456ghi789jkl012mno345pqr678"')

        engine = ScanEngine(self.tmpdir)
        engine.register_scanner(MCPServerScanner(self.tmpdir))
        engine.register_scanner(SecretLeakScanner(self.tmpdir))

        report = engine.run()

        self.assertGreater(report.total_findings, 0)
        self.assertGreater(report.total_files_scanned, 0)
        self.assertGreater(report.total_duration_ms, 0)


if __name__ == "__main__":
    unittest.main()
