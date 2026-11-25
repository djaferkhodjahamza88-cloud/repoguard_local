import argparse
import json
import os
import re
from pathlib import Path

PATTERNS = {
    'private-key': re.compile(r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----'),
    'github-token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b'),
    'aws-access-key': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'possible-secret': re.compile(r'''(?i)\b(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*["'][^"'\s]{12,}["']'''),
}
SKIP = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', 'dist', 'build'}


def scan(root: Path):
    findings = []
    def add(rule, path, severity, line=None):
        findings.append(dict(rule=rule, path=str(path), severity=severity, line=line))
    names = {p.name.lower() for p in root.iterdir()}
    for required in ('readme', 'license', '.gitignore'):
        if not any(n == required or n.startswith(required + '.') for n in names):
            add('missing-' + required, '.', 'warning')
    def onerror(error):
        add('unreadable-directory', '.', 'warning')
    for folder, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
        dirs[:] = sorted(d for d in dirs if d not in SKIP and not (Path(folder)/d).is_symlink())
        for name in sorted(files):
            p = Path(folder)/name
            rel = p.relative_to(root)
            if p.is_symlink() or not p.is_file():
                continue
            if (name == '.env' or (name.startswith('.env.') and name not in {'.env.example', '.env.sample', '.env.template'})) or name.lower().endswith(('.pem', '.p12', '.key')):
                add('sensitive-filename', rel, 'warning')
            try:
                if p.stat().st_size > 1024*1024:
                    add('large-file-skipped', rel, 'warning'); continue
                data = p.read_bytes()
                if b'\x00' in data: continue
                content = data.decode('utf-8')
            except UnicodeError:
                continue
            except OSError:
                add('unreadable-file', rel, 'warning'); continue
            for i, line in enumerate(content.splitlines(), 1):
                for rule, pattern in PATTERNS.items():
                    if pattern.search(line): add(rule, rel, 'error', i)
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__ or 'Check repository hygiene locally.')
    parser.add_argument('path', nargs='?', default='.')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--strict', action='store_true', help='Fail on warnings too')
    args = parser.parse_args(argv)
    root = Path(args.path).resolve()
    if not root.is_dir(): parser.error('path must be a directory')
    findings = scan(root)
    if args.json: print(json.dumps(findings, indent=2))
    else:
        for f in findings:
            print(f"{f['severity'].upper()} {f['path']}:{f['line'] or '-'} {f['rule']}")
        print(f'{len(findings)} finding(s)')
    return int(any(f['severity']=='error' or args.strict for f in findings))

if __name__ == '__main__':
    raise SystemExit(main())
