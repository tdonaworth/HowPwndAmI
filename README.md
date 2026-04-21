# HowPwndAmI 🔒

A defensive security tool that assesses your local system for credential exposure vulnerabilities, helping you understand what could be compromised in a supply chain attack (like the Shai-hulud vulnerability).

**⚡ New user?** Start with the [Quick Start Guide](QUICKSTART.md) (60 seconds to your first scan!)

## What It Does

This tool performs a reconnaissance scan on your local system to identify:

- 🔑 **Environment Variables**: Sensitive tokens, API keys, and secrets loaded in memory
- 📁 **Configuration Files**: Cloud provider credentials, SSH keys, Docker configs, etc.
- 📜 **Shell History**: Accidentally exposed credentials in command history
- 💾 **Browser Storage**: Session tokens in browser local storage
- 📂 **Current Directory**: Credential files in your working directory

All sensitive data is **redacted** in the output to prevent accidental exposure.

## Quick Start

```bash
# Make the script executable
chmod +x howpwndami.py

# Run the scan
./howpwndami.py

# Save report to file (text format)
./howpwndami.py --save

# JSON output for automation/integration
./howpwndami.py --json

# JSON output saved to file
./howpwndami.py --json --save
```

See [USAGE.md](USAGE.md) for advanced usage, CI/CD integration, and programmatic examples.

## Why This Matters

Supply chain attacks can compromise development tools and gain access to:
- Your AWS/GCP/Azure credentials
- GitHub tokens and SSH keys
- Database connection strings
- API keys in environment variables
- Docker registry credentials
- Kubernetes cluster access

This tool shows you **what's at risk** so you can take action.

## What It Checks

### Environment Variables
- AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
- Cloud provider tokens (GCP, Azure)
- API keys (GitHub, OpenAI, Anthropic, Stripe, etc.)
- Database URLs and passwords
- Any variable matching patterns like *KEY*, *SECRET*, *TOKEN*

### Configuration Files
- `~/.aws/credentials` - AWS credentials
- `~/.ssh/id_*` - SSH private keys
- `~/.docker/config.json` - Docker registry auth
- `~/.kube/config` - Kubernetes cluster access
- `~/.netrc` - Network authentication
- `~/.npmrc`, `~/.pypirc` - Package registry credentials
- And 20+ more common locations

### Shell History
Scans for commands that may have exposed credentials:
- `export SECRET_KEY=...`
- `curl -H "Authorization: Bearer ..."`
- Git URLs with embedded passwords
- Cloud CLI commands with inline credentials

### Current Directory
Looks for common credential file patterns:
- `.env` and `.env.*` files
- `*.pem`, `*.key` files
- `secrets.*`, `credentials.*` files
- Service account JSON files

## Understanding the Output

### Risk Levels

- **CRITICAL**: Credentials actively loaded in memory (environment variables)
- **HIGH**: Credentials in files with broad permissions or command history
- **MEDIUM**: Properly secured credential files (restrictive permissions)
- **LOW**: Informational findings
- **INFO**: General security observations

### Sample Output

```
[CRITICAL] Found 3 sensitive environment variable(s)
Location: Current process environment
Details:
  • AWS_ACCESS_KEY_ID = AKIA...X7KQ
  • AWS_SECRET_ACCESS_KEY = wJal...R7/M
  • GITHUB_TOKEN = ghp_...jK8P
Remediation: These credentials are loaded in memory and accessible
to any process running as your user.

[HIGH] AWS Credentials file found
Location: /Users/you/.aws/credentials
Size: 428 bytes
Permissions: 644
AWS Profiles: default, production, staging
Remediation: Ensure file has restrictive permissions (600 recommended).
Current: 644
```

## Remediation Strategies

### Immediate Actions
1. **Rotate any exposed credentials** - Especially those with overly broad permissions
2. **Fix file permissions**: `chmod 600 ~/.ssh/id_rsa ~/.aws/credentials`
3. **Clear shell history**: `history -c` (or selectively remove lines)
4. **Remove .env files from git**: Add to `.gitignore`

### Long-term Best Practices
1. **Use credential managers** - 1Password, LastPass, macOS Keychain
2. **Implement short-lived credentials** - AWS STS, temporary tokens
3. **Enable MFA** - On all critical services
4. **Use secret scanning** - GitHub secret scanning, pre-commit hooks
5. **Rotate regularly** - Automated credential rotation policies
6. **Principle of least privilege** - Minimal scoped permissions

## Limitations

This tool provides a **point-in-time snapshot** of your local exposure. It does not:
- Monitor network traffic for credential leakage
- Check credentials against breach databases
- Validate if credentials are still active
- Scan encrypted volumes or secure enclaves
- Replace comprehensive security auditing

## Requirements

- Python 3.7+
- No external dependencies (uses only stdlib)
- Works on macOS, Linux, and Windows (with some platform-specific differences)

## Privacy & Security

- **Runs entirely locally** - No data leaves your machine
- **Redacts sensitive values** - Only shows first/last 4 characters
- **Read-only operations** - Never modifies files or environment
- **Open source** - Review the code yourself

## Contributing

Found a common credential location we're missing? Submit a PR!

Common additions:
- Cloud provider credential paths
- IDE/editor credential stores
- Database client credential files
- CI/CD tool configurations

## License

MIT License - Use freely for personal or commercial defensive security purposes.

## Disclaimer

This tool is intended for **defensive security** and **authorized security testing** only. Use it to:
- ✅ Audit your own systems
- ✅ Security awareness training
- ✅ Compliance assessments
- ✅ DevSecOps workflows

Do not use for unauthorized access or malicious purposes.

---

**Stay safe out there!** 🛡️
