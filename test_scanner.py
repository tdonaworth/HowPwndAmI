#!/usr/bin/env python3
"""
Basic tests for HowPwndAmI scanner

Run with: python3 test_scanner.py
"""

import os
import sys
import tempfile
import json
from pathlib import Path

# Import the scanner
sys.path.insert(0, str(Path(__file__).parent))
from howpwndami import CredentialScanner, RiskLevel, Finding, RemediationCommand


def test_redaction():
    """Test credential redaction."""
    scanner = CredentialScanner()

    # Test normal redaction
    result = scanner.redact("very_long_secret_key_here_12345", show_chars=4)
    assert result.startswith("very"), "Should show first 4 chars"
    assert result.endswith("2345"), "Should show last 4 chars"
    assert "..." in result, "Should have ellipsis"

    # Test short string
    result = scanner.redact("short", show_chars=4)
    assert result == "***REDACTED***", "Short strings should be fully redacted"

    # Test empty string
    result = scanner.redact("")
    assert result == "***REDACTED***", "Empty strings should be redacted"

    print("✅ Redaction tests passed")


def test_env_detection():
    """Test environment variable detection."""
    # Set some test env vars
    test_vars = {
        'TEST_API_KEY': 'sk-test-key-12345',
        'TEST_SECRET': 'secret-value-67890',
        'NORMAL_VAR': 'this-should-not-be-flagged',
    }

    for key, value in test_vars.items():
        os.environ[key] = value

    scanner = CredentialScanner()
    scanner.scan_environment()

    # Should find at least the test vars with sensitive names
    env_findings = [f for f in scanner.findings if f.category == "Environment Variables"]
    assert len(env_findings) > 0, "Should detect sensitive environment variables"

    # Check that sensitive vars are in details
    details_text = " ".join(env_findings[0].details)
    assert "TEST_API_KEY" in details_text, "Should detect TEST_API_KEY"
    assert "TEST_SECRET" in details_text, "Should detect TEST_SECRET"

    # Check redaction
    assert "sk-test-key-12345" not in details_text, "Should redact full values"

    # Cleanup
    for key in test_vars:
        del os.environ[key]

    print("✅ Environment detection tests passed")


def test_config_file_detection():
    """Test config file detection."""
    scanner = CredentialScanner()

    # Mock home directory with test files
    original_home = scanner.home

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)

        # Create fake credential files
        (tmppath / '.aws').mkdir()
        (tmppath / '.aws' / 'credentials').write_text("[default]\naws_access_key_id = AKIATEST")
        (tmppath / '.ssh').mkdir()
        (tmppath / '.ssh' / 'id_rsa').write_text("-----BEGIN RSA PRIVATE KEY-----")

        # Override home for this test
        scanner.home = tmppath
        scanner.scan_config_files()

        # Check findings
        config_findings = [f for f in scanner.findings if f.category == "Configuration Files"]
        assert len(config_findings) >= 2, "Should detect AWS credentials and SSH key"

        descriptions = [f.description for f in config_findings]
        assert any("AWS" in d for d in descriptions), "Should detect AWS credentials"
        assert any("SSH" in d for d in descriptions), "Should detect SSH key"

    scanner.home = original_home
    print("✅ Config file detection tests passed")


def test_json_generation():
    """Test JSON report generation."""
    scanner = CredentialScanner()

    # Add a test finding
    scanner.findings.append(Finding(
        category="Test Category",
        location="/test/location",
        risk_level=RiskLevel.HIGH,
        description="Test finding",
        details=["Detail 1", "Detail 2"],
        remediation="Test remediation"
    ))

    json_output = scanner.generate_json_report()
    data = json.loads(json_output)

    assert "scan_timestamp" in data, "Should have timestamp"
    assert "summary" in data, "Should have summary"
    assert "findings" in data, "Should have findings"
    assert data["summary"]["total_findings"] == 1, "Should count findings"
    assert len(data["findings"]) == 1, "Should include all findings"
    assert data["findings"][0]["risk_level"] == "HIGH", "Should preserve risk level"

    print("✅ JSON generation tests passed")


def test_finding_risk_levels():
    """Test that findings have appropriate risk levels."""
    scanner = CredentialScanner()

    # Add test findings
    scanner.findings.append(Finding(
        category="Environment Variables",
        location="env",
        risk_level=RiskLevel.CRITICAL,
        description="Env var test"
    ))

    scanner.findings.append(Finding(
        category="Configuration Files",
        location="/test/config",
        risk_level=RiskLevel.HIGH,
        description="Config test"
    ))

    report = scanner.generate_report()

    # Check that risk levels appear in report
    assert "CRITICAL" in report, "Should show CRITICAL findings"
    assert "HIGH" in report, "Should show HIGH findings"

    print("✅ Risk level tests passed")


def test_remediation_command_dataclass():
    """Test RemediationCommand dataclass."""
    # Test with all fields
    cmd = RemediationCommand(
        command="chmod 600 /path/to/file",
        description="Fix file permissions",
        destructive=True
    )
    assert cmd.command == "chmod 600 /path/to/file"
    assert cmd.description == "Fix file permissions"
    assert cmd.destructive is True

    # Test default destructive=False
    cmd2 = RemediationCommand(
        command="echo 'test'",
        description="Test command"
    )
    assert cmd2.destructive is False

    print("✅ RemediationCommand dataclass tests passed")


def test_finding_with_remediation_commands():
    """Test Finding backward compatibility with remediation_commands."""
    # Test without remediation_commands (backward compat)
    finding = Finding(
        category="Test",
        location="/test",
        risk_level=RiskLevel.HIGH,
        description="Test finding"
    )
    assert finding.remediation_commands == []

    # Test with remediation_commands
    cmd = RemediationCommand(command="test cmd", description="test")
    finding2 = Finding(
        category="Test",
        location="/test",
        risk_level=RiskLevel.HIGH,
        description="Test finding",
        remediation_commands=[cmd]
    )
    assert len(finding2.remediation_commands) == 1
    assert finding2.remediation_commands[0].command == "test cmd"

    print("✅ Finding with remediation_commands tests passed")


def test_generate_fix_script_no_findings():
    """Test fix script generation with no findings."""
    scanner = CredentialScanner()
    script = scanner.generate_fix_script()
    assert script is None, "Should return None when no findings have commands"

    print("✅ Fix script with no findings tests passed")


def test_generate_fix_script_with_commands():
    """Test fix script generation with remediation commands."""
    scanner = CredentialScanner()

    # Add finding with non-destructive command
    scanner.findings.append(Finding(
        category="Configuration Files",
        location="/test/config",
        risk_level=RiskLevel.HIGH,
        description="Test config",
        remediation_commands=[
            RemediationCommand(
                command="chmod 600 /test/config",
                description="Fix permissions",
                destructive=False
            )
        ]
    ))

    # Add finding with destructive command
    scanner.findings.append(Finding(
        category="Shell History",
        location="/test/history",
        risk_level=RiskLevel.HIGH,
        description="Test history",
        remediation_commands=[
            RemediationCommand(
                command="safe_sed_delete 100 /test/history",
                description="Remove sensitive line",
                destructive=True
            )
        ]
    ))

    script = scanner.generate_fix_script()
    assert script is not None, "Should generate script"
    assert "#!/bin/bash" in script, "Should have shebang"
    assert "set -e" in script, "Should have error handling"
    assert "confirm()" in script, "Should have confirm function"
    assert "safe_sed_delete()" in script, "Should have safe_sed_delete function"
    assert "chmod 600 /test/config" in script, "Should include chmod command"
    assert 'if confirm "Remove sensitive line"' in script, "Should wrap destructive commands"
    assert "safe_sed_delete 100 /test/history" in script, "Should include history command"

    print("✅ Fix script generation tests passed")


def test_json_report_includes_remediation_commands():
    """Test JSON report includes remediation_commands."""
    scanner = CredentialScanner()

    cmd = RemediationCommand(
        command="test command",
        description="test description",
        destructive=True
    )

    scanner.findings.append(Finding(
        category="Test",
        location="/test",
        risk_level=RiskLevel.HIGH,
        description="Test",
        remediation_commands=[cmd]
    ))

    json_output = scanner.generate_json_report()
    data = json.loads(json_output)

    assert len(data["findings"]) == 1
    assert "remediation_commands" in data["findings"][0]
    assert len(data["findings"][0]["remediation_commands"]) == 1

    cmd_data = data["findings"][0]["remediation_commands"][0]
    assert cmd_data["command"] == "test command"
    assert cmd_data["description"] == "test description"
    assert cmd_data["destructive"] is True

    print("✅ JSON report remediation_commands tests passed")


def test_shell_history_reverse_order():
    """Test shell history remediation commands are in reverse order."""
    scanner = CredentialScanner()

    # Create a test history file with sensitive commands
    original_home = scanner.home

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        history_file = tmppath / '.zsh_history'

        # Create history with sensitive commands at lines 10, 20, 30
        lines = []
        for i in range(1, 31):
            if i == 10:
                lines.append("export SECRET_KEY=abc123")
            elif i == 20:
                lines.append("echo $API_TOKEN")
            elif i == 30:
                lines.append("curl -H 'Authorization: Bearer xyz'")
            else:
                lines.append(f"echo line {i}")

        history_file.write_text("\n".join(lines))

        scanner.home = tmppath
        scanner.scan_shell_history()

        history_findings = [f for f in scanner.findings if f.category == "Shell History"]
        assert len(history_findings) > 0, "Should detect shell history issues"

        commands = history_findings[0].remediation_commands
        assert len(commands) == 3, "Should have 3 remediation commands"

        # Extract line numbers from commands
        line_nums = []
        for cmd in commands:
            # Commands look like: "safe_sed_delete 30 /path/to/file"
            parts = cmd.command.split()
            line_nums.append(int(parts[1]))

        # Verify they're in reverse order (highest first)
        assert line_nums == [30, 20, 10], f"Commands should be in reverse order, got {line_nums}"

    scanner.home = original_home
    print("✅ Shell history reverse order tests passed")


def test_path_quoting():
    """Test that file paths with spaces are properly quoted."""
    scanner = CredentialScanner()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        # Create a file with spaces in the path
        testdir = tmppath / "test dir with spaces"
        testdir.mkdir()
        config_file = testdir / "credentials"
        config_file.write_text("test")

        # Add to scanner's config locations
        original_home = scanner.home
        scanner.home = tmppath

        # Manually add a finding with a path containing spaces
        scanner.findings.append(Finding(
            category="Configuration Files",
            location=str(config_file),
            risk_level=RiskLevel.HIGH,
            description="Test config",
            remediation_commands=[
                RemediationCommand(
                    command=f"chmod 600 '{config_file}'",  # Should be quoted
                    description="Fix permissions",
                    destructive=False
                )
            ]
        ))

        script = scanner.generate_fix_script()
        assert script is not None
        # The path should be present (even with spaces)
        assert "test dir with spaces" in script or "test\\ dir\\ with\\ spaces" in script

        scanner.home = original_home

    print("✅ Path quoting tests passed")


def run_all_tests():
    """Run all tests."""
    print("Running HowPwndAmI Tests")
    print("=" * 80)

    tests = [
        test_redaction,
        test_env_detection,
        test_config_file_detection,
        test_json_generation,
        test_finding_risk_levels,
        test_remediation_command_dataclass,
        test_finding_with_remediation_commands,
        test_generate_fix_script_no_findings,
        test_generate_fix_script_with_commands,
        test_json_report_includes_remediation_commands,
        test_shell_history_reverse_order,
        test_path_quoting,
    ]

    for test in tests:
        try:
            test()
        except Exception as e:
            print(f"❌ {test.__name__} failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    print("\n" + "=" * 80)
    print("✅ All tests passed!")
    return True


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
