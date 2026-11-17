#!/usr/bin/env python3
"""Lightweight defensive scanner for common security gaps."""
import argparse, json, os, re, sys

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "reports"}
MAX_SIZE = 1_000_000

PATTERNS = [
    ("HIGH", "AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("HIGH", "Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("HIGH", "Hardcoded secret", re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]")),
    ("MEDIUM", "Disabled TLS verification", re.compile(r"verify\s*=\s*False")),
    ("MEDIUM", "Use of eval/exec", re.compile(r"\b(eval|exec)\s*\(")),
    ("MEDIUM", "shell=True subprocess", re.compile(r"shell\s*=\s*True")),
    ("LOW", "Insecure http URL", re.compile(r"http://(?!localhost|127\.0\.0\.1)")),
]

def scan(root):
    findings = []
    def add(sev, title, path, line=None):
        findings.append({"severity": sev, "title": title, "file": os.path.relpath(path, root), "line": line})

    if not os.path.exists(os.path.join(root, ".gitignore")):
        add("MEDIUM", "Missing .gitignore", root)

    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            path = os.path.join(dirpath, name)
            if name == ".env" or name.endswith((".pem", ".key")):
                add("HIGH", "Sensitive file present", path)
            if name == "requirements.txt":
                with open(path, errors="ignore") as f:
                    for i, l in enumerate(f, 1):
                        l = l.strip()
                        if l and not l.startswith("#") and "==" not in l:
                            add("LOW", "Unpinned dependency", path, i)
            try:
                if os.path.getsize(path) > MAX_SIZE:
                    continue
                with open(path, errors="ignore") as f:
                    for i, line in enumerate(f, 1):
                        for sev, title, rx in PATTERNS:
                            if rx.search(line):
                                add(sev, title, path, i)
            except OSError:
                pass
    return findings

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path")
    ap.add_argument("--json", help="write findings to this file")
    a = ap.parse_args()
    results = scan(os.path.abspath(a.path))
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for r in sorted(results, key=lambda r: order[r["severity"]]):
        loc = f'{r["file"]}:{r["line"]}' if r["line"] else r["file"]
        print(f'[{r["severity"]}] {r["title"]} ({loc})')
    print(f"\n{len(results)} finding(s)")
    if a.json:
        with open(a.json, "w") as f:
            json.dump(results, f, indent=2)
    sys.exit(1 if any(r["severity"] == "HIGH" for r in results) else 0)

if __name__ == "__main__":
    main()
