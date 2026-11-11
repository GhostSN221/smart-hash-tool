# Contributing

Thanks for helping improve the credential hygiene scanner.

## Development setup

```bash
git clone https://github.com/GhostSN221/smart-hash-tool
cd smart-hash-tool
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

## Before opening a pull request

```bash
ruff check smart_hash_cracker.py api.py credential_scanner.py tests bench
pytest -q
```

Add tests for every new detector, hash format or scanner behavior. For security
fixes, include a regression test that fails before the fix.

## Pull requests

- Keep changes focused; split unrelated work.
- Describe the problem, the change, and how you verified it.
- Update README, docs, or examples when behavior changes.
- Sign off your commits with the Developer Certificate of Origin:

```bash
git commit -s -m "feat: add ..."
```

By contributing, you agree that your contribution is licensed under Apache 2.0.

## Adding a detector

- Add a unit test with a fake, non-real credential.
- Keep the pattern specific enough to avoid obvious false positives.
- Redact secret values in findings; never print full credentials.
- Document the new rule in README or docs.

## Security and ethics

This project is for authorized audits, labs, CTFs and defensive research.
Contributions that make the tool easier to use against systems without
authorization will be rejected. See [SECURITY.md](SECURITY.md).

## Good first issues

Look for the `good first issue` label. Documentation, false-positive reduction,
SARIF improvements and additional detectors are all valuable.
