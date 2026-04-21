# Quick Start Guide

Get up and running with HowPwndAmI in 60 seconds.

## Step 1: Run Your First Scan

```bash
# Make executable (first time only)
chmod +x howpwndami.py

# Run the scan
./howpwndami.py
```

That's it! You'll see a report showing any exposed credentials on your system.

## Step 2: Understand Your Results

The report shows findings grouped by category with risk levels:

- 🚨 **CRITICAL** - Credentials in memory (act immediately)
- ⚠️ **HIGH** - Insecure file permissions or command history
- 🔶 **MEDIUM** - Properly secured credential files
- 🔵 **LOW/INFO** - General observations

### Example Output
```
[CRITICAL] Found 3 sensitive environment variable(s)
Location: Current process environment
Details:
  • AWS_ACCESS_KEY_ID = AKIA...X7KQ
  • GITHUB_TOKEN = ghp_...jK8P
```

**All sensitive values are automatically redacted** - only showing first/last 4 characters.

## Step 3: Take Action

### For CRITICAL Findings (Environment Variables)
```bash
# Move credentials from environment to a credential manager:
# - 1Password CLI
# - AWS SSO
# - Temporary session tokens
# - .env files (for development only, never commit!)
```

### For HIGH Findings (File Permissions)
```bash
# Fix AWS credentials permissions
chmod 600 ~/.aws/credentials

# Fix SSH key permissions
chmod 600 ~/.ssh/id_*
chmod 644 ~/.ssh/config
```

### For Shell History
```bash
# Clear specific entries
history -d <line_number>

# Or clear all history
history -c

# Prevent credential commands from being saved
export HISTIGNORE="*KEY*:*SECRET*:*TOKEN*:*PASSWORD*"
```

## Common Next Steps

### Save a Report
```bash
./howpwndami.py --save
# Creates: howpwndami_report.txt
```

### Get JSON Output (for scripts/CI)
```bash
./howpwndami.py --json
```

### Check Specific Risk Level
```bash
# Check if you have any CRITICAL findings
./howpwndami.py --json | jq '.summary.by_risk_level.CRITICAL'
```

### Run Integration Examples
```bash
chmod +x example_integration.py

# See what integration examples are available
./example_integration.py

# Run a specific example
./example_integration.py 4  # Remediation report
```

### Run Tests
```bash
python3 test_scanner.py
```

## Typical Workflow

1. **Run initial scan** to understand your baseline
2. **Fix CRITICAL findings** (environment variables)
3. **Fix HIGH findings** (file permissions, shell history)
4. **Document** remaining MEDIUM findings as acceptable risk
5. **Re-scan** to verify fixes
6. **Set up recurring scans** (daily/weekly)

## Setting Up Regular Scans

### macOS/Linux - Daily Scan
```bash
# Add to crontab (edit with: crontab -e)
0 9 * * * cd /path/to/HowPwndAmI && ./howpwndami.py --save
```

### Shell Alias
```bash
# Add to ~/.bashrc or ~/.zshrc
alias seccheck="cd ~/Projects/HowPwndAmI && ./howpwndami.py"

# Then run anytime with:
seccheck
```

### Pre-commit Hook
```bash
# .git/hooks/pre-commit
#!/bin/bash
cd /path/to/HowPwndAmI
./howpwndami.py --json > /tmp/scan.json
CRITICAL=$(jq '.summary.by_risk_level.CRITICAL // 0' /tmp/scan.json)

if [ $CRITICAL -gt 0 ]; then
    echo "⚠️  Warning: CRITICAL credential findings detected"
    echo "Run: ~/Projects/HowPwndAmI/howpwndami.py"
fi
```

## What to Look For

### ✅ Good Signs
- Credential files have 600 permissions
- No credentials in environment variables
- No credentials in shell history
- Minimal or no HIGH/CRITICAL findings

### ⚠️ Warning Signs
- Multiple CRITICAL findings
- Credentials with 644 or 755 permissions
- Credentials in shell history
- .env files in project directories

### 🚨 Red Flags
- Production credentials in environment
- API keys with broad permissions
- Long-lived access tokens
- Credentials in git history

## Tips

1. **Run before and after making changes** to see the difference
2. **Save reports with dates** for comparison: `--save` creates timestamped files
3. **Focus on CRITICAL first**, then HIGH, then MEDIUM
4. **Use credential managers** - 1Password, AWS SSO, Azure AD
5. **Enable MFA** on all accounts that support it
6. **Rotate credentials** after fixing exposure

## Getting Help

- **Full documentation**: See [README.md](README.md)
- **Usage examples**: See [USAGE.md](USAGE.md)
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md)
- **Report issues**: Open a GitHub issue

## One-Liner Summary

```bash
# Scan → Review → Fix → Verify
./howpwndami.py && chmod 600 ~/.aws/credentials ~/.ssh/id_* && ./howpwndami.py
```

---

**You're all set!** Run regular scans to keep your credentials secure. 🛡️
