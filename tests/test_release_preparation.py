"""Public distribution metadata and synthetic regression inputs."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import audit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packaging'))
import build_release


class ReleasePreparationTests(unittest.TestCase):
    def test_version_sync_preserves_the_detailed_guide_title(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            names = ('distribution_version.py','packaging/sync_version.py','README.md',
                     'README-ja.md','START-HERE-ja.md','ACTION-PRESENTATION-ja.md','START-HERE.html')
            for name in names:
                target = source/name
                target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(ROOT/name,target)
            (source/'distribution_version.py').write_text(
                "VERSION = '1.0.1'\nDISPLAY_VERSION = VERSION\nTAG = 'v' + VERSION\n",encoding='utf-8')
            result = subprocess.run([sys.executable,'-B',str(source/'packaging/sync_version.py')],
                                    capture_output=True,text=True,encoding='utf-8',timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual((source/'README-ja.md').read_text(encoding='utf-8').splitlines()[0],
                             '# eMudhra 開発環境診断 1.0.1 — 詳細ガイド')
            self.assertEqual((source/'README.md').read_text(encoding='utf-8').splitlines()[0],
                             '# eMudhra 開発環境診断 1.0.1')

    def test_distribution_reports_internal_semver_and_ships_its_version_source(self):
        self.assertEqual(audit.TOOL_VERSION, '1.0.1')
        self.assertEqual(build_release.VERSION, audit.TOOL_VERSION)
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp)
            build_release.stage_files(ROOT, stage, 'macos-arm64')
            self.assertTrue((stage / 'app/distribution_version.py').is_file())
            self.assertIn('1.0.1', (stage / 'docs/使い方.html').read_text(encoding='utf-8'))
            self.assertNotIn('2.7.9', (stage / 'docs/使い方.html').read_text(encoding='utf-8'))

    def test_regression_json_contains_explicitly_synthetic_records_only(self):
        for name, count in (('display-corrections-2.7.8.json', 45), ('safechain-2.7.6.json', 3)):
            data = json.loads((ROOT / 'tests/fixtures' / name).read_text(encoding='utf-8'))
            self.assertEqual(len(data), count)
            for item in data:
                row = item.get('record', item)
                self.assertEqual(row['metadata'].get('fixture_origin'), 'synthetic-v1')
            serialized = json.dumps(data, ensure_ascii=False)
            for fragment in ('/Users/', '/home/', '/var/folders/', '/opt/homebrew/', '/usr/local/Cellar/'):
                self.assertNotIn(fragment, serialized)


if __name__ == '__main__':
    unittest.main()
