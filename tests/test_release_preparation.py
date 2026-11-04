"""Public distribution metadata and synthetic regression inputs."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

import audit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packaging'))
import build_release


class ReleasePreparationTests(unittest.TestCase):
    def test_distribution_reports_internal_semver_and_ships_its_version_source(self):
        self.assertEqual(audit.TOOL_VERSION, '1.0.0')
        self.assertEqual(build_release.VERSION, audit.TOOL_VERSION)
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp)
            build_release.stage_files(ROOT, stage, 'macos-arm64')
            self.assertTrue((stage / 'app/distribution_version.py').is_file())
            self.assertIn('1.0', (stage / 'docs/使い方.html').read_text(encoding='utf-8'))
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
