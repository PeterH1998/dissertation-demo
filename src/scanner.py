#!/usr/bin/env python3
import re
import os
import json
import yaml
import argparse
from pathlib import Path

# 1. Define our PII regex patterns (and severity)
PATTERNS = {
    'email': (
        re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}'),
        'medium'
    ),
    'phone': (
        re.compile(r'\b(?:\+?\d{1,3}[-.\s]?)?(?:\(\d{2,4}\)|\d{2,4})[-.\s]?\d{3}[-.\s]?\d{2,4}\b'),
        'high'
    ),
    'ssn': (
        re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'high'
    ),
}

def load_allowlist(path):
    with open(path, 'r') as f:
        data = yaml.safe_load(f) or {}
    return set(item['pattern'] for item in data.get('allowlist', []))

def is_allowed(value, allowlist_patterns):
    return any(re.fullmatch(pat, value) for pat in allowlist_patterns)

def scan_file(path: Path, allowlist_patterns):
    text = path.read_text(errors='ignore')
    results = []
    for name, (regex, severity) in PATTERNS.items():
        for match in regex.finditer(text):
            val = match.group(0)
            if not is_allowed(val, allowlist_patterns):
                line_no = text.count('\n', 0, match.start()) + 1
                results.append({
                    'file': str(path),
                    'type': name,
                    'match': val,
                    'line': line_no,
                    'severity': severity
                })
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Scan repo for PII (email, phone, SSN) with allowlist support."
    )
    parser.add_argument(
        '--allowlist', '-a', required=True,
        help="YAML file of regex patterns to ignore"
    )
    parser.add_argument(
        '--output', '-o', required=True,
        help="Path to write JSON results"
    )
    args = parser.parse_args()

    allowlist = load_allowlist(args.allowlist)
    all_results = []

    # 2. Walk the repo tree
    for root, _, files in os.walk('.'):
        for fname in files:
            if fname.endswith(('.py', '.js', '.ts', '.jsx', '.tsx', '.html', '.env')):
                path = Path(root) / fname
                all_results.extend(scan_file(path, allowlist))

    # 3. Write out JSON
    with open(args.output, 'w') as f:
        json.dump({'results': all_results}, f, indent=2)

    # 4. Exit code: non-zero if any high-severity findings
    high_count = sum(1 for r in all_results if r['severity'] == 'high')
    if high_count:
        print(f"Found {high_count} high-severity PII leaks.")
        exit(1)

if __name__ == '__main__':
    main()
