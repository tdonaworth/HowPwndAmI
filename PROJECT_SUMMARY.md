# HowPwndAmI - Project Summary

## Overview
**HowPwndAmI** is a defensive security tool that helps users understand their local credential exposure risk in the event of a supply chain attack (like Shai-hulud). It performs reconnaissance on the local system to identify sensitive credentials, API keys, and tokens that could be compromised.

## Key Features

### 🔍 Comprehensive Scanning
- **Environment Variables**: Detects sensitive tokens, API keys, secrets loaded in memory
- **Configuration Files**: Scans 25+ common credential locations (AWS, GCP, Azure, SSH, Docker, etc.)
- **Shell History**: Identifies accidentally exposed credentials in command history
- **Browser Storage**: Checks for session tokens in browser local storage
- **Current Directory**: Finds credential files in working directory

### 🛡️ Security-First Design
- **Redaction**: All sensitive values are redacted (shows only first/last 4 chars)
- **Read-only**: Never modifies files or environment
- **Local execution**: No data leaves your machine
- **Zero dependencies**: Uses only Python stdlib for portability

### 📊 Multiple Output Formats
- **Human-readable text**: Formatted terminal output with risk levels
- **JSON**: Structured data for automation and integration
- **Save to file**: Both text and JSON formats

### 🎯 Risk-Based Assessment
- **CRITICAL**: Credentials in memory (environment variables)
- **HIGH**: Credentials with broad permissions or in shell history
- **MEDIUM**: Properly secured credential files
- **LOW/INFO**: Informational findings

## Project Structure

```
HowPwndAmI/
├── howpwndami.py              # Main scanner tool
├── example_integration.py      # Integration examples
├── test_scanner.py            # Test suite
├── README.md                  # Project documentation
├── USAGE.md                   # Usage guide
├── CONTRIBUTING.md            # Contribution guidelines
├── PROJECT_SUMMARY.md         # This file
├── .gitignore                 # Git ignore rules
└── .github/
    └── workflows/
        └── security-scan.yml  # GitHub Actions workflow
```

## Technical Details

### Language & Requirements
- **Python 3.7+**
- **No external dependencies** (stdlib only)
- **Cross-platform** (macOS, Linux, Windows*)

*Windows support may vary for some file paths

### Architecture
- **Modular scanner design**: Each scan type (env, files, history) is independent
- **Dataclass-based findings**: Type-safe finding representation
- **Enum-based risk levels**: Clear risk categorization
- **Multiple output generators**: Text and JSON report generation

### Security Scanning Coverage

#### Environment Variables (14+ patterns)
- Cloud providers: AWS, GCP, Azure
- Source control: GitHub, GitLab
- APIs: OpenAI, Anthropic, Stripe, Twilio, SendGrid
- Infrastructure: Docker, Kubernetes
- Databases: PostgreSQL, MySQL, MongoDB
- Package managers: NPM, PyPI

#### Configuration Files (25+ locations)
- Cloud: `.aws/`, `.config/gcloud/`, `.azure/`
- SSH: `.ssh/id_*`, `.ssh/config`
- Containers: `.docker/config.json`, `.kube/config`
- Package managers: `.npmrc`, `.pypirc`, `.gem/credentials`
- Source control: `.git-credentials`, `.gitconfig`
- Network: `.netrc`, `.boto`, `.s3cfg`

#### Shell History
- Bash, Zsh, Fish
- Python REPL, Node REPL, MySQL client
- Pattern detection for credential exposure

## Use Cases

### 1. Personal Security Audit
Run on your development machine to understand your credential exposure:
```bash
./howpwndami.py
```

### 2. CI/CD Integration
Enforce security policies in your pipeline:
```yaml
- run: ./howpwndami.py --json
- run: jq '.summary.by_risk_level.CRITICAL' report.json
```

### 3. Security Training
Demonstrate credential exposure risks to developers and teams.

### 4. Compliance Audits
Document credential management practices for compliance requirements.

### 5. Incident Response
Quickly assess what credentials might be compromised after detecting malicious activity.

## Integration Options

### Command Line
```bash
./howpwndami.py                    # Interactive scan
./howpwndami.py --save             # Save text report
./howpwndami.py --json             # JSON output
./howpwndami.py --json --save      # Save JSON report
```

### Python Programmatic
```python
from howpwndami import CredentialScanner
scanner = CredentialScanner()
scanner.run_scan()
report = scanner.generate_json_report()
```

### Shell Scripting
```bash
# Check for critical findings
if jq -e '.summary.by_risk_level.CRITICAL > 0' report.json; then
    echo "Critical findings!"
    exit 1
fi
```

### CI/CD Workflows
- GitHub Actions (see `.github/workflows/security-scan.yml`)
- GitLab CI
- Jenkins
- CircleCI
- Any CI system with Python support

## Roadmap / Future Enhancements

### Potential Features
- [ ] Support for more credential locations (IDE configs, etc.)
- [ ] Historical tracking (compare scans over time)
- [ ] Credential validation (check if credentials are still active)
- [ ] Integration with secret management tools (1Password, HashiCorp Vault)
- [ ] Browser extension scanning (deeper browser credential analysis)
- [ ] Network activity monitoring
- [ ] Windows-specific credential store support
- [ ] macOS Keychain analysis
- [ ] Threat modeling based on findings
- [ ] Remediation automation (auto-fix permissions, etc.)

### Community Contributions Welcome
- Additional credential location patterns
- Cloud provider support
- Platform-specific enhancements
- Integration examples
- Documentation improvements

## Known Limitations

1. **Point-in-time scan**: Provides snapshot, not continuous monitoring
2. **Local only**: Does not check remote systems or cloud storage
3. **Pattern-based**: May miss credentials in non-standard locations
4. **No validation**: Does not verify if credentials are active/valid
5. **Limited browser analysis**: Basic browser storage detection only
6. **No encrypted volume access**: Cannot scan encrypted containers

## Security Considerations

### What This Tool Does
- ✅ Identifies credential exposure **locally**
- ✅ Helps understand **attack surface**
- ✅ Provides **remediation guidance**
- ✅ Enables **security awareness**

### What This Tool Does NOT Do
- ❌ Access remote systems
- ❌ Validate or use credentials
- ❌ Send data externally
- ❌ Replace comprehensive security audits
- ❌ Guarantee complete coverage

### Responsible Use
This tool is for **authorized defensive security purposes only**:
- ✅ Personal security audits
- ✅ Organizational security assessments
- ✅ Security training
- ✅ Compliance verification
- ❌ Unauthorized access attempts
- ❌ Malicious reconnaissance

## Testing

Run the test suite:
```bash
python3 test_scanner.py
```

Tests cover:
- Credential redaction
- Environment variable detection
- Config file discovery
- JSON report generation
- Risk level classification

## License
MIT License - Free for personal and commercial defensive security use.

## Support & Contribution
- **Issues**: Report bugs or request features via GitHub Issues
- **Pull Requests**: Contributions welcome (see CONTRIBUTING.md)
- **Questions**: Open a discussion or issue

## Acknowledgments
Inspired by real-world supply chain attacks and the need for better visibility into local credential exposure.

---

**Built with defensive security in mind. Stay safe!** 🛡️
