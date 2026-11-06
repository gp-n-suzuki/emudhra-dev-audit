"""New collection reaches the current report through source and package entry points."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'packaging'))
import build_release


class ReportFlowTests(unittest.TestCase):
    def verify_flow(self, app, output):
        result = subprocess.run([sys.executable, '-B', str(ROOT/'packaging/report_flow_smoke.py'),
                                 '--app', str(app), '--out', str(output)],
                                cwd=output.parent, capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        proof = json.loads(result.stdout)
        self.assertTrue(proof['normal_cli'] and proof['offline_cli'] and proof['desktop_flow'])
        self.assertEqual(len(proof['reports']), 4)
        self.assertFalse(proof['live_scan'] or proof['network'] or proof['bundled_runtime_executed'])

    def test_source_new_collection_uses_current_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.verify_flow(ROOT, Path(tmp)/'reports')

    def test_each_distribution_contains_every_report_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            for platform in build_release.PLATFORMS:
                with self.subTest(platform=platform):
                    stage = Path(tmp)/platform
                    stage.mkdir()
                    build_release.stage_files(ROOT, stage, platform)
                    self.verify_flow(stage/'app', Path(tmp)/(platform+'-reports'))


if __name__ == '__main__':
    unittest.main()
