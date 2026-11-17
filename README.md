# security-gap-audit

A defensive toolkit for identifying security gaps in projects, accounts, and workflows you own or are authorized to review.

## Contents
- `scanner/audit.py`: scans a directory for common gaps (hardcoded secrets, committed `.env` files, missing `.gitignore`, risky patterns, unpinned dependencies).
- `docs/checklist.md`: manual review checklist (accounts, mobile money/wallets, devices, apps, code).
- `docs/finding-template.md`: template for writing up each gap.
- `reports/`: store audit outputs here.

## Usage
```bash
python3 scanner/audit.py /path/to/project
python3 scanner/audit.py /path/to/project --json reports/result.json
python3 -m unittest discover tests
```
Exit code is 1 if any HIGH finding exists, so it can run in CI.

## Scope
Only scan systems you own or have written permission to test.
