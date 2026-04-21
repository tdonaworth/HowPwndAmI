# Contributing to HowPwndAmI

Thanks for helping make this tool better! Here's how to contribute.

## Adding New Credential Locations

The most common contribution is adding support for new credential file locations. Here's how:

### 1. Add to CONFIG_LOCATIONS

In `howpwndami.py`, find the `CONFIG_LOCATIONS` dictionary and add your entry:

```python
CONFIG_LOCATIONS = {
    # ... existing entries ...
    '.config/newtool/credentials.json': 'New Tool Credentials',
}
```

### 2. (Optional) Add Custom Extraction Logic

If you want to extract specific details from the file, add a handler in `_extract_file_details()`:

```python
def _extract_file_details(self, path: Path, description: str) -> List[str]:
    details = []
    try:
        # ... existing handlers ...
        
        elif path.name == 'credentials.json' and 'newtool' in str(path):
            content = json.loads(path.read_text())
            if 'accounts' in content:
                accounts = [a['email'] for a in content['accounts']]
                details.append(f"Accounts: {', '.join(accounts)}")
    except Exception:
        pass
    return details
```

## Adding New Environment Variable Patterns

Add to `KNOWN_SENSITIVE_VARS` for specific variable names:

```python
KNOWN_SENSITIVE_VARS = {
    # ... existing entries ...
    'NEWTOOL_API_KEY',
    'NEWTOOL_SECRET',
}
```

Or add a pattern to `SENSITIVE_ENV_PATTERNS` for pattern matching:

```python
SENSITIVE_ENV_PATTERNS = [
    # ... existing patterns ...
    r'.*NEWTOOL.*',
]
```

## Testing Your Changes

1. Ensure Python 3.7+ is installed
2. Create test credential files (with dummy data) in your home directory
3. Run the scanner: `./howpwndami.py`
4. Verify your new locations are detected

## Code Style

- Use type hints where practical
- Keep functions focused and single-purpose
- Add docstrings for new public methods
- Follow PEP 8 conventions

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b add-newtool-support`
3. Make your changes
4. Test thoroughly
5. Commit with clear message: `git commit -m "Add support for NewTool credentials"`
6. Push to your fork: `git push origin add-newtool-support`
7. Open a Pull Request

## Common Credential Locations Needed

Here are some tools/services we'd love support for:

- [ ] Heroku CLI credentials
- [ ] DigitalOcean CLI config
- [ ] Jenkins credentials
- [ ] CircleCI local config
- [ ] GitLab CLI credentials
- [ ] Bitbucket credentials
- [ ] JetBrains IDE credentials
- [ ] VS Code extension tokens
- [ ] Postman credentials
- [ ] MongoDB Compass connections
- [ ] PostgreSQL password file (.pgpass)
- [ ] MySQL config files
- [ ] Redis credentials
- [ ] Elasticsearch credentials

## Questions?

Open an issue for discussion before starting major changes.

## License

By contributing, you agree your contributions will be licensed under the MIT License.
