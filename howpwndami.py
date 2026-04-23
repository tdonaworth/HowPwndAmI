#!/usr/bin/env python3
"""
HowPwndAmI - Local Credential Exposure Assessment Tool

Performs reconnaissance on your local system to identify potentially exposed
credentials, tokens, and API keys that could be compromised in a supply chain attack.
"""

import os
import json
import re
import glob
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field
from enum import Enum


class Colors:
    """ANSI color codes for terminal output."""
    DARK_RED = '\033[38;5;88m'      # Dark red for CRITICAL
    RED = '\033[91m'                 # Red for HIGH
    ORANGE = '\033[38;5;208m'        # Orange for MEDIUM
    YELLOW = '\033[93m'              # Yellow for LOW
    GREEN = '\033[92m'               # Green for safe/info
    LIGHT_BLUE = '\033[94m'          # Light blue for INFO
    RESET = '\033[0m'                # Reset to default
    BOLD = '\033[1m'


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def get_color(self) -> str:
        """Get the ANSI color code for this risk level."""
        color_map = {
            RiskLevel.CRITICAL: Colors.DARK_RED,
            RiskLevel.HIGH: Colors.RED,
            RiskLevel.MEDIUM: Colors.ORANGE,
            RiskLevel.LOW: Colors.YELLOW,
            RiskLevel.INFO: Colors.LIGHT_BLUE,
        }
        return color_map.get(self, Colors.RESET)


@dataclass
class Finding:
    category: str
    location: str
    risk_level: RiskLevel
    description: str
    details: List[str] = field(default_factory=list)
    remediation: str = ""


class CredentialScanner:
    """Scans system for exposed credentials and sensitive information."""

    # Common environment variable patterns that contain sensitive data
    SENSITIVE_ENV_PATTERNS = [
        r'.*KEY.*',
        r'.*SECRET.*',
        r'.*TOKEN.*',
        r'.*PASSWORD.*',
        r'.*PASSWD.*',
        r'.*API.*',
        r'.*AUTH.*',
        r'.*CREDENTIAL.*',
        r'.*ACCESS.*',
        r'.*PRIVATE.*',
        r'.*CERT.*',
    ]

    # Specific environment variables known to contain credentials
    KNOWN_SENSITIVE_VARS = {
        'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
        'GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_PAT',
        'GOOGLE_APPLICATION_CREDENTIALS',
        'AZURE_CLIENT_SECRET', 'AZURE_CLIENT_ID',
        'DOCKER_HUB_TOKEN', 'DOCKER_PASSWORD',
        'NPM_TOKEN', 'PYPI_TOKEN',
        'SLACK_TOKEN', 'SLACK_WEBHOOK',
        'DATABASE_URL', 'DB_PASSWORD',
        'ANTHROPIC_API_KEY', 'OPENAI_API_KEY',
        'STRIPE_SECRET_KEY', 'STRIPE_API_KEY',
        'TWILIO_AUTH_TOKEN', 'SENDGRID_API_KEY',
    }

    # Config file locations to check (relative to home directory)
    CONFIG_LOCATIONS = {
        '.aws/credentials': 'AWS Credentials',
        '.aws/config': 'AWS Config',
        '.config/gcloud/credentials.db': 'Google Cloud Credentials',
        '.config/gcloud/application_default_credentials.json': 'GCP Application Credentials',
        '.azure/accessTokens.json': 'Azure Access Tokens',
        '.azure/azureProfile.json': 'Azure Profile',
        '.docker/config.json': 'Docker Registry Credentials',
        '.kube/config': 'Kubernetes Config',
        '.netrc': 'Network Credentials (.netrc)',
        '.git-credentials': 'Git Credentials Store',
        '.gitconfig': 'Git Configuration',
        '.ssh/id_rsa': 'SSH Private Key (RSA)',
        '.ssh/id_ed25519': 'SSH Private Key (Ed25519)',
        '.ssh/id_ecdsa': 'SSH Private Key (ECDSA)',
        '.ssh/config': 'SSH Configuration',
        '.npmrc': 'NPM Registry Config',
        '.pypirc': 'PyPI Config',
        '.gem/credentials': 'Ruby Gems Credentials',
        '.boto': 'Boto (AWS SDK) Config',
        '.s3cfg': 'S3 Configuration',
        '.config/hub': 'GitHub Hub Config',
        '.github-token': 'GitHub Token',
        '.terraform.d/credentials.tfrc.json': 'Terraform Cloud Credentials',
        '.config/gh/hosts.yml': 'GitHub CLI Credentials',
    }

    # Shell history files
    SHELL_HISTORY_FILES = [
        '.bash_history', '.zsh_history', '.fish_history',
        '.python_history', '.node_repl_history', '.mysql_history',
    ]

    def __init__(self):
        self.findings: List[Finding] = []
        self.home = Path.home()

    def redact(self, value: str, show_chars: int = 4) -> str:
        """Redact sensitive value, showing only first/last few characters."""
        if not value or len(value) <= show_chars * 2:
            return "***REDACTED***"
        return f"{value[:show_chars]}...{value[-show_chars:]}"

    def scan_environment(self) -> None:
        """Scan environment variables for sensitive credentials."""
        sensitive_vars = set()

        # Check known sensitive variables
        for var in self.KNOWN_SENSITIVE_VARS:
            if var in os.environ:
                sensitive_vars.add(var)

        # Check pattern-matched variables
        for var in os.environ:
            for pattern in self.SENSITIVE_ENV_PATTERNS:
                if re.match(pattern, var, re.IGNORECASE):
                    sensitive_vars.add(var)
                    break

        if sensitive_vars:
            details = []
            for var in sorted(sensitive_vars):
                value = os.environ[var]
                redacted = self.redact(value)
                details.append(f"{var} = {redacted}")

            self.findings.append(Finding(
                category="Environment Variables",
                location="Current process environment",
                risk_level=RiskLevel.CRITICAL,
                description=f"Found {len(sensitive_vars)} sensitive environment variable(s)",
                details=details,
                remediation="These credentials are loaded in memory and accessible to any process running as your user. Consider using credential managers or scoped/temporary credentials."
            ))

    def scan_config_files(self) -> None:
        """Scan common configuration file locations."""
        for rel_path, description in self.CONFIG_LOCATIONS.items():
            full_path = self.home / rel_path
            if full_path.exists():
                stat = full_path.stat()
                size = stat.st_size

                # Check permissions
                perms = oct(stat.st_mode)[-3:]
                risk = RiskLevel.HIGH if perms != '600' else RiskLevel.MEDIUM

                details = [
                    f"Path: {full_path}",
                    f"Size: {size} bytes",
                    f"Permissions: {perms}",
                ]

                # Try to extract additional details for specific file types
                extra_details = self._extract_file_details(full_path, description)
                if extra_details:
                    details.extend(extra_details)

                self.findings.append(Finding(
                    category="Configuration Files",
                    location=str(full_path),
                    risk_level=risk,
                    description=f"{description} file found",
                    details=details,
                    remediation=f"Ensure file has restrictive permissions (600 recommended). Current: {perms}"
                ))

    def _extract_file_details(self, path: Path, description: str) -> List[str]:
        """Extract safe details from specific config files."""
        details = []
        try:
            if path.name == 'credentials' and '.aws' in str(path):
                # AWS credentials file
                content = path.read_text()
                profiles = re.findall(r'\[(.*?)\]', content)
                if profiles:
                    details.append(f"AWS Profiles: {', '.join(profiles)}")

            elif path.name == 'config.json' and '.docker' in str(path):
                # Docker config
                content = json.loads(path.read_text())
                if 'auths' in content:
                    registries = list(content['auths'].keys())
                    details.append(f"Authenticated registries: {', '.join(registries)}")

            elif path.name == 'config' and '.kube' in str(path):
                # Kubernetes config
                import yaml
                try:
                    content = yaml.safe_load(path.read_text())
                    if 'contexts' in content:
                        contexts = [c['name'] for c in content['contexts']]
                        details.append(f"K8s contexts: {', '.join(contexts[:5])}")
                except:
                    details.append("K8s config present (YAML parse skipped)")

            elif path.suffix == '.json' and 'gcloud' in str(path):
                # GCP credentials
                content = json.loads(path.read_text())
                if 'client_email' in content:
                    details.append(f"Service account: {content['client_email']}")
        except Exception:
            # Don't fail the whole scan if one file can't be read
            pass

        return details

    def scan_shell_history(self) -> None:
        """Scan shell history for accidentally exposed credentials."""
        found_patterns = []

        for history_file in self.SHELL_HISTORY_FILES:
            full_path = self.home / history_file
            if not full_path.exists():
                continue

            try:
                content = full_path.read_text(errors='ignore')
                lines = content.split('\n')

                # Look for common credential patterns in history
                risky_patterns = [
                    (r'export.*(?:KEY|SECRET|TOKEN|PASSWORD).*=', 'Credential export'),
                    (r'echo.*(?:KEY|SECRET|TOKEN)', 'Credential echo'),
                    (r'curl.*(?:-H|--header).*(?:Authorization|Bearer)', 'API call with auth header'),
                    (r'git.*https://.*@', 'Git command with embedded credentials'),
                    (r'(?:aws|gcloud|az).*(?:--key|--secret|--password)', 'Cloud CLI with inline credentials'),
                ]

                matches = []
                for line_num, line in enumerate(lines[-1000:], 1):  # Check last 1000 commands
                    for pattern, desc in risky_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            matches.append(f"Line ~{len(lines)-1000+line_num}: {desc}")
                            break

                if matches:
                    found_patterns.append((str(full_path), matches))

            except Exception:
                continue

        if found_patterns:
            for path, matches in found_patterns:
                self.findings.append(Finding(
                    category="Shell History",
                    location=path,
                    risk_level=RiskLevel.HIGH,
                    description=f"Found {len(matches)} potentially sensitive command(s) in history",
                    details=matches[:10],  # Limit to first 10
                    remediation="Consider clearing shell history or using 'history -d <line_number>' to remove sensitive command lines or 'history -c' to clear the entire history. Avoid putting credentials in command-line arguments."
                ))

    def scan_current_directory(self) -> None:
        """Scan current working directory for credential files."""
        cwd = Path.cwd()

        # Common credential file patterns
        patterns = [
            '.env', '.env.*',
            '*.pem', '*.key', '*.p12', '*.pfx',
            'secrets.*', 'credentials.*',
            '*.credentials', '*.secret',
            'service-account*.json',
        ]

        found_files = []
        for pattern in patterns:
            matches = glob.glob(str(cwd / pattern))
            matches.extend(glob.glob(str(cwd / '**' / pattern), recursive=True))
            found_files.extend(matches)

        found_files = list(set(found_files))  # Deduplicate

        if found_files:
            self.findings.append(Finding(
                category="Current Directory",
                location=str(cwd),
                risk_level=RiskLevel.HIGH,
                description=f"Found {len(found_files)} potential credential file(s) in working directory",
                details=[str(Path(f).relative_to(cwd)) for f in found_files[:20]],
                remediation="Add these files to .gitignore and avoid committing them. Consider using environment variables or secret management tools instead."
            ))

    def scan_browser_tokens(self) -> None:
        """Check for browser session storage that might contain tokens."""
        # This is a simplified check - full browser credential extraction would be more complex
        locations = []

        # Common browser session storage locations (macOS/Linux)
        browser_paths = [
            '.config/google-chrome/Default/Local Storage',
            '.config/google-chrome/Default/Session Storage',
            'Library/Application Support/Google/Chrome/Default/Local Storage',
            '.mozilla/firefox/*/storage',
            'Library/Application Support/Firefox/Profiles/*/storage',
        ]

        for rel_path in browser_paths:
            if '*' in rel_path:
                matches = glob.glob(str(self.home / rel_path))
                for match in matches:
                    if os.path.exists(match):
                        locations.append(match)
            else:
                full_path = self.home / rel_path
                if full_path.exists():
                    locations.append(str(full_path))

        if locations:
            self.findings.append(Finding(
                category="Browser Storage",
                location="Various browser profile directories",
                risk_level=RiskLevel.MEDIUM,
                description=f"Found {len(locations)} browser storage location(s) that may contain session tokens",
                details=locations[:5],
                remediation="Browser storage may contain authentication tokens for web applications. Log out of sensitive services when not in use."
            ))

    def generate_json_report(self) -> str:
        """Generate a JSON report of all findings."""
        report_data = {
            "scan_timestamp": __import__('datetime').datetime.now().isoformat(),
            "summary": {
                "total_findings": len(self.findings),
                "by_risk_level": {}
            },
            "findings": []
        }

        # Count by risk level
        for finding in self.findings:
            risk = finding.risk_level.value
            report_data["summary"]["by_risk_level"][risk] = \
                report_data["summary"]["by_risk_level"].get(risk, 0) + 1

        # Add findings
        for finding in self.findings:
            report_data["findings"].append({
                "category": finding.category,
                "location": finding.location,
                "risk_level": finding.risk_level.value,
                "description": finding.description,
                "details": finding.details,
                "remediation": finding.remediation
            })

        return json.dumps(report_data, indent=2)

    def generate_report(self) -> str:
        """Generate a formatted report of all findings."""
        report = []
        report.append("=" * 80)
        report.append("HOW PWND AM I? - Credential Exposure Assessment Report")
        report.append("=" * 80)
        report.append("")

        if not self.findings:
            report.append("✓ No significant credential exposure detected!")
            report.append("")
            return "\n".join(report)

        # Summary
        risk_counts = {}
        for finding in self.findings:
            risk_counts[finding.risk_level] = risk_counts.get(finding.risk_level, 0) + 1

        report.append("SUMMARY")
        report.append("-" * 80)
        total_findings = len(self.findings)
        report.append(f"Total Findings: {total_findings}")
        for risk_level in RiskLevel:
            count = risk_counts.get(risk_level, 0)
            if count > 0:
                report.append(f"  {risk_level.value}: {count}")
        report.append("")

        # Group findings by category
        by_category = {}
        for finding in self.findings:
            if finding.category not in by_category:
                by_category[finding.category] = []
            by_category[finding.category].append(finding)

        # Sort by risk level
        risk_order = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 3,
            RiskLevel.INFO: 4,
        }

        for category, findings in sorted(by_category.items()):
            report.append(f"\n{category.upper()}")
            report.append("=" * 80)

            for finding in sorted(findings, key=lambda f: risk_order[f.risk_level]):
                color = finding.risk_level.get_color()
                report.append(f"\n{color}{Colors.BOLD}[{finding.risk_level.value}]{Colors.RESET} {finding.description}")
                report.append(f"Location: {finding.location}")

                if finding.details:
                    report.append("Details:")
                    for detail in finding.details:
                        report.append(f"  • {detail}")

                if finding.remediation:
                    report.append(f"Remediation: {finding.remediation}")

                report.append("")

        # Recommendations
        report.append("\n" + "=" * 80)
        report.append("RECOMMENDATIONS")
        report.append("=" * 80)
        report.append("""
            1. Use credential managers (1Password, SecretsManager, system keychain) instead of files
            2. Implement short-lived, rotatable credentials where possible
            3. Use environment-specific credentials (dev/staging/prod)
            4. Enable MFA on all critical accounts
            5. Regularly audit and rotate credentials
            6. Use secret scanning tools in CI/CD pipelines
            7. Implement least-privilege access principles
            8. Monitor for unusual access patterns
            9. Keep sensitive config files with 600 permissions (user read/write only)
            10. Never commit credentials to version control
        """)
        report.append("\n" + "=" * 80)
        report.append("⚠️  This tool provides a snapshot of your current exposure.")
        report.append("For comprehensive security, combine with:")
        report.append("  • Regular security audits")
        report.append("  • Credential rotation policies")
        report.append("  • Network monitoring")
        report.append("  • Endpoint detection and response (EDR) tools")
        report.append("=" * 80)

        return "\n".join(report)

    def run_scan(self) -> None:
        """Execute all scanning modules."""
        print(f"{Colors.GREEN}Starting credential exposure scan...{Colors.RESET}")
        print()

        print(f"{Colors.YELLOW}→ Scanning environment variables...{Colors.RESET}")
        self.scan_environment()

        print(f"{Colors.YELLOW}→ Scanning configuration files...{Colors.RESET}")
        self.scan_config_files()

        print(f"{Colors.YELLOW}→ Scanning shell history...{Colors.RESET}")
        self.scan_shell_history()

        print(f"{Colors.YELLOW}→ Scanning current directory...{Colors.RESET}")
        self.scan_current_directory()

        print(f"{Colors.YELLOW}→ Checking browser storage...{Colors.RESET}")
        self.scan_browser_tokens()

        print()
        print(f"{Colors.GREEN}Scan complete!{Colors.RESET}")
        print()


def main():
    """Main entry point."""
    import sys

    # Parse arguments
    json_output = '--json' in sys.argv
    save_output = '--save' in sys.argv

    if not json_output:
        print(
            f"{Colors.YELLOW}\n"
            "╔═══════════════════════════════════════════════════════════════════╗\n"
            "║                         HOW PWND AM I?                            ║\n"
            "║                                                                   ║\n"
            "║           Local Credential Exposure Assessment Tool               ║\n"
            "║                                                                   ║\n"
            "║  This tool scans your system for exposed credentials that         ║\n"
            "║  could be compromised in a supply chain attack.                   ║\n"
            f"╚═══════════════════════════════════════════════════════════════════╝\n{Colors.RESET}"
        )

    scanner = CredentialScanner()
    scanner.run_scan()

    # Generate appropriate format
    if json_output:
        report = scanner.generate_json_report()
    else:
        report = scanner.generate_report()

    print(report)

    # Optionally save to file
    if save_output:
        if json_output:
            output_file = 'howpwndami_report.json'
        else:
            output_file = 'howpwndami_report.txt'

        with open(output_file, 'w') as f:
            f.write(report)
        print(f"\nReport saved to: {output_file}")


if __name__ == '__main__':
    main()
