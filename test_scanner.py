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
from howpwndami import CredentialScanner, RiskLevel, Finding


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
