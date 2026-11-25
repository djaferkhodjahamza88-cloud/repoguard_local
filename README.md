# RepoGuard Local

A lightweight, dependency-free Python CLI for checking repository hygiene before publication, especially for AI-assisted projects. It runs locally and never prints matched secret values.

## Quick start

Requires Python 3.10+. From a checkout:

```sh
python -m repoguard.cli .
python -m repoguard.cli . --json
python -m repoguard.cli . --strict
```

Optional installation: `python -m pip install .`, then `repoguard .`.

## Checks

Potential GitHub tokens, AWS access-key IDs, private-key headers, simple quoted credentials, sensitive filenames, and missing README, LICENSE or .gitignore. Exit status 1 indicates an error (or any finding in strict mode); 2 indicates invalid CLI usage.

## Limitations

This is an early prototype, not a security audit or a replacement for established scanners such as Gitleaks. It does not scan Git history, honor .gitignore rules, inspect binary or non-UTF-8 files, or inspect files larger than 1 MiB. Findings may be false positives or false negatives. Revoke exposed credentials rather than merely deleting them. Review all files manually before publishing.

## Development

Run `python -m unittest discover -s tests`. Contributions and reproducible bug reports are welcome. Do not include real credentials in issues or test fixtures.

MIT licensed. No affiliation with GitHub or Anthropic.
