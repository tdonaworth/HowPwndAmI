# Usage Guide

## Basic Usage

### Interactive Scan
Run a full scan and view results in your terminal:
```bash
./howpwndami.py
```

### Save Report to File
```bash
./howpwndami.py --save
# Creates: howpwndami_report.txt
```

### JSON Output (for automation)
```bash
./howpwndami.py --json
```

### JSON Output + Save
```bash
./howpwndami.py --json --save
# Creates: howpwndami_report.json
```

## Integration Examples

### 1. CI/CD Pipeline Check
```bash
#!/bin/bash
# pre-commit hook or CI script

./howpwndami.py --json --save

# Parse JSON and fail if CRITICAL findings exist
if jq '.summary.by_risk_level.CRITICAL' howpwndami_report.json | grep -q '[1-9]'; then
    echo "CRITICAL security findings detected!"
    exit 1
fi
```

### 2. Slack Notification on New Findings
```bash
#!/bin/bash

./howpwndami.py --json > current_scan.json

# Compare with previous scan
if [ -f previous_scan.json ]; then
    new_critical=$(comm -13 \
        <(jq -r '.findings[] | select(.risk_level=="CRITICAL") | .location' previous_scan.json | sort) \
        <(jq -r '.findings[] | select(.risk_level=="CRITICAL") | .location' current_scan.json | sort))
    
    if [ ! -z "$new_critical" ]; then
        curl -X POST $SLACK_WEBHOOK -d "{\"text\":\"🚨 New critical credential exposure: $new_critical\"}"
    fi
fi

mv current_scan.json previous_scan.json
```

### 3. Python Integration
```python
import subprocess
import json

# Run scan
result = subprocess.run(
    ['python3', 'howpwndami.py', '--json'],
    capture_output=True,
    text=True
)

# Parse output (skip progress lines)
lines = result.stdout.split('\n')
json_start = next(i for i, line in enumerate(lines) if line.strip().startswith('{'))
scan_data = json.loads('\n'.join(lines[json_start:]))

# Check findings
critical_count = scan_data['summary']['by_risk_level'].get('CRITICAL', 0)
if critical_count > 0:
    print(f"⚠️  {critical_count} critical findings!")
```

### 4. Daily Security Report (cron)
```bash
# Add to crontab: run daily at 9 AM
0 9 * * * cd /path/to/HowPwndAmI && ./howpwndami.py --save && mail -s "Daily Security Scan" you@example.com < howpwndami_report.txt
```

### 5. Pre-deploy Check
```bash
#!/bin/bash
# Check before deploying to production

./howpwndami.py --json > scan.json

high_count=$(jq '.summary.by_risk_level.HIGH // 0' scan.json)
critical_count=$(jq '.summary.by_risk_level.CRITICAL // 0' scan.json)

if [ $critical_count -gt 0 ] || [ $high_count -gt 3 ]; then
    echo "❌ Deployment blocked: Too many security findings"
    echo "Critical: $critical_count, High: $high_count"
    exit 1
fi

echo "✅ Security check passed"
```

## Advanced Usage

### Filter by Risk Level
```bash
# Show only CRITICAL findings
./howpwndami.py --json | jq '.findings[] | select(.risk_level=="CRITICAL")'
```

### Count Findings by Category
```bash
./howpwndami.py --json | jq -r '.findings[].category' | sort | uniq -c
```

### Extract Environment Variable Names
```bash
./howpwndami.py --json | \
  jq -r '.findings[] | select(.category=="Environment Variables") | .details[]' | \
  cut -d'=' -f1
```

### Check Specific File Permissions
```bash
./howpwndami.py --json | \
  jq -r '.findings[] | select(.location | contains(".aws/credentials")) | .details[] | select(contains("Permissions"))'
```

## Programmatic Usage

See [example_integration.py](example_integration.py) for Python examples:

```bash
# Run examples
./example_integration.py 1  # Full scan and parse
./example_integration.py 2  # Check security policy
./example_integration.py 3  # Check AWS credentials
./example_integration.py 4  # Generate remediation report
./example_integration.py 5  # Check environment variables
```

## JSON Schema

The JSON output follows this structure:

```json
{
  "scan_timestamp": "2026-04-21T15:00:00.000000",
  "summary": {
    "total_findings": 10,
    "by_risk_level": {
      "CRITICAL": 1,
      "HIGH": 5,
      "MEDIUM": 4
    }
  },
  "findings": [
    {
      "category": "Environment Variables",
      "location": "Current process environment",
      "risk_level": "CRITICAL",
      "description": "Found 14 sensitive environment variable(s)",
      "details": ["VAR_NAME = redacted..."],
      "remediation": "Recommendation text here"
    }
  ]
}
```

## Exit Codes

- `0`: Scan completed successfully
- Non-zero: Error during scan

Note: The tool does NOT exit with non-zero on findings. Use JSON parsing to enforce policies.

## Tips

### Regular Scanning
```bash
# Create an alias
echo 'alias seccheck="cd ~/Projects/HowPwndAmI && ./howpwndami.py"' >> ~/.bashrc

# Run anytime
seccheck
```

### Compare Scans
```bash
# Take snapshots
./howpwndami.py --json --save
mv howpwndami_report.json scan_$(date +%Y%m%d).json

# Compare
diff scan_20260420.json scan_20260421.json
```

### Continuous Monitoring
```bash
# Watch for changes (macOS/Linux with watch or entr)
echo howpwndami.py | entr -c ./howpwndami.py
```

### Custom Filtering
Create custom scripts to filter findings:

```bash
#!/bin/bash
# show-aws.sh - Show only AWS-related findings

./howpwndami.py --json | \
  jq '.findings[] | select(.description | contains("AWS"))' | \
  jq -s '.'
```

## Troubleshooting

### "Permission denied"
```bash
chmod +x howpwndami.py
```

### Python version issues
```bash
# Check version (requires 3.7+)
python3 --version

# Use specific version
python3.9 howpwndami.py
```

### JSON parsing errors
The tool outputs progress messages before JSON. Parse carefully:
```python
# Skip lines until first '{'
json_start = next(i for i, line in enumerate(lines) if line.strip().startswith('{'))
```
