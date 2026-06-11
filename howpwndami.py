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
import shlex
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
class RemediationCommand:
    command: str          # Shell command to run
    description: str      # Human-readable comment for the script
    destructive: bool = False  # If True, script prompts before executing


@dataclass
class Finding:
    category: str
    location: str
    risk_level: RiskLevel
    description: str
    details: List[str] = field(default_factory=list)
    remediation: str = ""
    remediation_commands: List[RemediationCommand] = field(default_factory=list)


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

    # Environment variable patterns to exclude (typically non-sensitive service endpoints)
    NON_SENSITIVE_PATTERNS = [
        r'.*_URL$',       # Endpoints/URLs (e.g., GITHUB_API_URL, DATABASE_URL is an exception)
        r'.*_URI$',       # URIs
        r'.*_ENDPOINT$',  # Service endpoints
        r'.*_HOST$',      # Host addresses
        r'.*_DOMAIN$',    # Domain names
        r'.*_ADDRESS$',   # Network addresses
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
            # Skip if matches non-sensitive pattern (unless in KNOWN_SENSITIVE_VARS)
            if var not in self.KNOWN_SENSITIVE_VARS:
                is_non_sensitive = any(
                    re.match(pattern, var, re.IGNORECASE)
                    for pattern in self.NON_SENSITIVE_PATTERNS
                )
                if is_non_sensitive:
                    continue

            for pattern in self.SENSITIVE_ENV_PATTERNS:
                if re.match(pattern, var, re.IGNORECASE):
                    sensitive_vars.add(var)
                    break

        if sensitive_vars:
            details = []
            remediation_commands = []
            for var in sorted(sensitive_vars):
                value = os.environ[var]
                redacted = self.redact(value)
                details.append(f"{var} = {redacted}")
                remediation_commands.append(RemediationCommand(
                    command=f"unset {var}",
                    description=f"Remove {var} from current shell session (does not affect .bashrc/.zshrc)",
                    destructive=False
                ))

            self.findings.append(Finding(
                category="Environment Variables",
                location="Current process environment",
                risk_level=RiskLevel.CRITICAL,
                description=f"Found {len(sensitive_vars)} sensitive environment variable(s)",
                details=details,
                remediation="These credentials are loaded in memory and accessible to any process running as your user. Consider using credential managers or scoped/temporary credentials.",
                remediation_commands=remediation_commands
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

                # Generate remediation command if permissions need fixing
                remediation_commands = []
                if perms != '600':
                    remediation_commands.append(RemediationCommand(
                        command=f"chmod 600 {shlex.quote(str(full_path))}",
                        description=f"Restrict {description} to owner read/write only (currently {perms})",
                        destructive=False
                    ))
                # Adjust the remediation based on risk level
                if risk == RiskLevel.HIGH:
                    _remediation = f"File has permissions {perms}, which may allow other users to read it. Set permissions to 600 (user read/write only) to reduce risk."
                elif risk == RiskLevel.MEDIUM:
                    _remediation = f"File has permissions {perms}. Although the permissions are correct, ensure that the file is not accessible by other users and consider using a credential manager for better security."
                

                self.findings.append(Finding(
                    category="Configuration Files",
                    location=str(full_path),
                    risk_level=risk,
                    description=f"{description} file found",
                    details=details,
                    remediation=f"Ensure file has restrictive permissions (600 recommended). Current: {perms}",
                    remediation_commands=remediation_commands
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

                # Collect structured match data with exact line numbers
                match_data = []  # List of (file_line_number, description)
                start_index = max(0, len(lines) - 1000)
                for file_line_num, line in enumerate(lines[start_index:], start=start_index + 1):
                    for pattern, desc in risky_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            match_data.append((file_line_num, desc))
                            break

                if match_data:
                    details = [f"Line ~{num}: {desc}" for num, desc in match_data[:10]]

                    # Build remediation commands: delete lines in REVERSE order to avoid line number shifts
                    remediation_commands = []
                    for file_line_num, desc in sorted(match_data, key=lambda x: x[0], reverse=True):
                        remediation_commands.append(RemediationCommand(
                            command=f"safe_sed_delete {file_line_num} {shlex.quote(str(full_path))}",
                            description=f"Remove line {file_line_num} ({desc}) from history file",
                            destructive=True
                        ))

                    found_patterns.append((str(full_path), details, remediation_commands))

            except Exception:
                continue

        if found_patterns:
            for path, matches, remediation_commands in found_patterns:
                self.findings.append(Finding(
                    category="Shell History",
                    location=path,
                    risk_level=RiskLevel.HIGH,
                    description=f"Found {len(matches)} potentially sensitive command(s) in history",
                    details=matches,
                    remediation="Consider clearing shell history or using 'history -d <line_number>' to remove sensitive command lines or 'history -c' to clear the entire history. Avoid putting credentials in command-line arguments.",
                    remediation_commands=remediation_commands
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
            # Check existing .gitignore entries
            gitignore_path = cwd / '.gitignore'
            existing_ignores = set()
            if gitignore_path.exists():
                try:
                    existing_ignores = set(gitignore_path.read_text().splitlines())
                except Exception:
                    pass

            # Generate remediation commands for files not already in .gitignore
            remediation_commands = []
            for f in found_files[:20]:
                rel_path = str(Path(f).relative_to(cwd))
                if rel_path not in existing_ignores:
                    remediation_commands.append(RemediationCommand(
                        command=f"echo {shlex.quote(rel_path)} >> {shlex.quote(str(gitignore_path))}",
                        description=f"Add {rel_path} to .gitignore to prevent accidental commits",
                        destructive=False
                    ))

            self.findings.append(Finding(
                category="Current Directory",
                location=str(cwd),
                risk_level=RiskLevel.HIGH,
                description=f"Found {len(found_files)} potential credential file(s) in working directory",
                details=[str(Path(f).relative_to(cwd)) for f in found_files[:20]],
                remediation="Add these files to .gitignore and avoid committing them. Consider using environment variables or secret management tools instead.",
                remediation_commands=remediation_commands
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
                "remediation": finding.remediation,
                "remediation_commands": [
                    {
                        "command": cmd.command,
                        "description": cmd.description,
                        "destructive": cmd.destructive
                    }
                    for cmd in finding.remediation_commands
                ]
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

    def generate_fix_script(self) -> Optional[str]:
        """Generate a shell script with remediation commands from findings."""
        # Collect all commands
        all_commands = []  # List of (category, RemediationCommand)

        for finding in self.findings:
            for cmd in finding.remediation_commands:
                all_commands.append((finding.category, cmd))

        if not all_commands:
            return None  # Nothing actionable

        timestamp = __import__('datetime').datetime.now().isoformat()

        lines = []
        lines.append("#!/bin/bash")
        lines.append("# ============================================================================")
        lines.append("# HowPwndAmI - Auto-generated Remediation Script")
        lines.append(f"# Generated: {timestamp}")
        lines.append("# ============================================================================")
        lines.append("#")
        lines.append("# This script contains remediation commands based on a credential exposure scan.")
        lines.append("# Review each section before running. Commands marked [DESTRUCTIVE] will prompt")
        lines.append("# for confirmation before executing.")
        lines.append("#")
        lines.append("# Usage: bash fix_credentials.sh")
        lines.append("# ============================================================================")
        lines.append("")
        lines.append("set -e")
        lines.append("")
        lines.append("# --- Helper Functions ---")
        lines.append("")
        lines.append("confirm() {")
        lines.append('    read -p "[DESTRUCTIVE] $1 (y/N) " response')
        lines.append('    case "$response" in')
        lines.append('        [yY][eE][sS]|[yY]) return 0 ;;')
        lines.append('        *) echo "  Skipped."; return 1 ;;')
        lines.append('    esac')
        lines.append("}")
        lines.append("")
        lines.append("# Portable in-place sed for line deletion")
        lines.append("safe_sed_delete() {")
        lines.append('    if sed --version 2>/dev/null | grep -q GNU; then')
        lines.append('        sed -i "${1}d" "$2"')
        lines.append("    else")
        lines.append('        sed -i '"''"' "${1}d" "$2"')
        lines.append("    fi")
        lines.append("}")
        lines.append("")
        lines.append('echo "========================================"')
        lines.append('echo "HowPwndAmI Remediation Script"')
        lines.append('echo "========================================"')
        lines.append('echo ""')
        lines.append("")

        # Group by category, maintaining a defined order
        category_order = [
            "Configuration Files",
            "Shell History",
            "Current Directory",
            "Environment Variables",
        ]

        by_category = {}
        for cat, cmd in all_commands:
            by_category.setdefault(cat, []).append(cmd)

        for category in category_order:
            if category not in by_category:
                continue
            commands = by_category[category]

            lines.append(f"# === {category} ===")
            lines.append(f'echo "--- {category} ---"')

            if category == "Environment Variables":
                lines.append('echo "NOTE: unset only affects the current shell session."')
                lines.append('echo "To permanently remove, edit your shell profile (.bashrc, .zshrc, etc.)"')

            lines.append('echo ""')
            lines.append("")

            for cmd in commands:
                lines.append(f"# {cmd.description}")
                if cmd.destructive:
                    lines.append(f'if confirm "{cmd.description}"; then')
                    lines.append(f"    {cmd.command}")
                    lines.append("fi")
                else:
                    lines.append(cmd.command)
                lines.append("")

            lines.append("")

        lines.append('echo ""')
        lines.append('echo "========================================"')
        lines.append('echo "Remediation complete. Re-run howpwndami.py to verify."')
        lines.append('echo "========================================"')

        return "\n".join(lines)

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
    fix_script = '--fix-script' in sys.argv

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

    # Optionally generate fix script
    if fix_script:
        script_content = scanner.generate_fix_script()
        if script_content is None:
            print(f"\n{Colors.YELLOW}No actionable remediation commands found.{Colors.RESET}")
        else:
            output_file = 'fix_credentials.sh'
            with open(output_file, 'w') as f:
                f.write(script_content)
            os.chmod(output_file, 0o700)  # Make executable
            print(f"\n{Colors.GREEN}Remediation script generated: {output_file}{Colors.RESET}")
            print(f"Review the script, then run: bash {output_file}")


if __name__ == '__main__':
    main()
