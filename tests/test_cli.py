import tempfile
import unittest
from pathlib import Path
from repoguard.cli import scan, main

class ScanTests(unittest.TestCase):
    def test_clean(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            for n in ('README.md','LICENSE','.gitignore'): (p/n).touch()
            self.assertEqual(scan(p), [])
            self.assertEqual(main([d]), 0)
    def test_token_and_env(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p/'.env').write_text('gh'+'p_'+'A'*36)
            rules = {f['rule'] for f in scan(p)}
            self.assertIn('github-token', rules)
            self.assertIn('sensitive-filename', rules)
            self.assertEqual(main([d]), 1)
    def test_skip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d); (p/'.git').mkdir(); (p/'.git'/'secret').write_text('gh'+'p_'+'A'*36)
            self.assertNotIn('github-token', {f['rule'] for f in scan(p)})
