#!/usr/bin/env python3
"""
Example: How to use HowPwndAmI programmatically

This shows how to integrate the scanner into your own tools or CI/CD pipelines.
"""

import json
import subprocess
import sys
from pathlib import Path


def run_scan_and_parse():
    """Run the scanner and parse JSON output."""
    result = subprocess.run(
        ['python3', 'howpwndami.py', '--json'],
        capture_output=True,
        text=True
    )

    # The scan output includes progress messages, so we need to find the JSON
    output_lines = result.stdout.split('\n')
    json_start = None
    for i, line in enumerate(output_lines):
        if line.strip().startswith('{'):
            json_start = i
            break

    if json_start is None:
        print("Error: Could not find JSON output")
        sys.exit(1)

    json_output = '\n'.join(output_lines[json_start:])
    return json.loads(json_output)


def check_security_policy(scan_data):
    """
    Example: Enforce a security policy based on scan results.

    Returns True if policy passes, False otherwise.
    """
    summary = scan_data['summary']

    # Policy: No CRITICAL findings allowed
    if summary['by_risk_level'].get('CRITICAL', 0) > 0:
        print("❌ POLICY VIOLATION: CRITICAL findings detected!")
        return False

    # Policy: No more than 2 HIGH findings allowed
    if summary['by_risk_level'].get('HIGH', 0) > 2:
        print("❌ POLICY VIOLATION: Too many HIGH findings!")
        return False

    print("✅ Security policy passed!")
    return True


def get_findings_by_category(scan_data, category):
    """Get all findings for a specific category."""
    return [
        f for f in scan_data['findings']
        if f['category'] == category
    ]


def check_aws_credentials_permissions():
    """Example: Check if AWS credentials have correct permissions."""
    scan_data = run_scan_and_parse()

    config_findings = get_findings_by_category(scan_data, 'Configuration Files')

    for finding in config_findings:
        if 'AWS Credentials' in finding['description']:
            # Check if permissions are mentioned in details
            for detail in finding['details']:
                if 'Permissions:' in detail:
                    perms = detail.split('Permissions:')[1].strip()
                    if perms != '600':
                        print(f"⚠️  AWS credentials have insecure permissions: {perms}")
                        print(f"   Fix with: chmod 600 ~/.aws/credentials")
                        return False

    print("✅ AWS credentials are properly secured")
    return True


def generate_remediation_report():
    """Generate a focused remediation action list."""
    scan_data = run_scan_and_parse()

    print("\n" + "=" * 80)
    print("REMEDIATION ACTION LIST")
    print("=" * 80)

    # Group by risk level
    critical_findings = [f for f in scan_data['findings'] if f['risk_level'] == 'CRITICAL']
    high_findings = [f for f in scan_data['findings'] if f['risk_level'] == 'HIGH']

    if critical_findings:
        print("\n🚨 CRITICAL - Act Immediately:")
        for i, finding in enumerate(critical_findings, 1):
            print(f"\n{i}. {finding['description']}")
            print(f"   Location: {finding['location']}")
            if finding['remediation']:
                print(f"   Action: {finding['remediation']}")

    if high_findings:
        print("\n⚠️  HIGH - Address Soon:")
        for i, finding in enumerate(high_findings, 1):
            print(f"\n{i}. {finding['description']}")
            print(f"   Location: {finding['location']}")
            if finding['remediation']:
                print(f"   Action: {finding['remediation']}")


def check_for_env_var_leakage():
    """Specifically check for environment variable exposure."""
    scan_data = run_scan_and_parse()

    env_findings = get_findings_by_category(scan_data, 'Environment Variables')

    if not env_findings:
        print("✅ No sensitive environment variables detected")
        return True

    print("⚠️  Sensitive environment variables detected:")
    for finding in env_findings:
        for detail in finding['details']:
            var_name = detail.split('=')[0].strip()
            print(f"   • {var_name}")

    print("\nRecommendation: Move these to a credential manager or use scoped access.")
    return False


def main():
    """Main example runner."""
    print("HowPwndAmI Integration Examples")
    print("=" * 80)

    examples = {
        '1': ('Run full scan and parse', run_scan_and_parse),
        '2': ('Check security policy compliance', lambda: check_security_policy(run_scan_and_parse())),
        '3': ('Check AWS credentials permissions', check_aws_credentials_permissions),
        '4': ('Generate remediation report', generate_remediation_report),
        '5': ('Check for environment variable leakage', check_for_env_var_leakage),
    }

    if len(sys.argv) > 1:
        choice = sys.argv[1]
    else:
        print("\nAvailable examples:")
        for key, (desc, _) in examples.items():
            print(f"  {key}. {desc}")
        print("\nUsage: ./example_integration.py <number>")
        print("   or: python3 example_integration.py <number>")
        return

    if choice in examples:
        desc, func = examples[choice]
        print(f"\nRunning: {desc}\n")
        result = func()
        if result is not None and not isinstance(result, bool):
            print(json.dumps(result, indent=2))
    else:
        print(f"Invalid choice: {choice}")


if __name__ == '__main__':
    main()
