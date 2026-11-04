"""Offline reassessment must preserve its source and never collect new evidence."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


class SavedReassessmentTests(unittest.TestCase):
    def test_reassessment_never_resolves_live_installations_or_starts_collection(self):
        import app_inventory
        import installed_metadata
        import verdicts
        records=json.loads((ROOT/'tests/fixtures/safechain-2.7.6.json').read_text(encoding='utf-8'))
        with patch.object(Path,'resolve',side_effect=AssertionError('live path resolution')), \
             patch.object(app_inventory.Reader,'read',side_effect=AssertionError('installed file read')), \
             patch.object(installed_metadata,'python_environment',side_effect=AssertionError('new collection')), \
             patch('subprocess.Popen',side_effect=AssertionError('process launch')), \
             patch('socket.socket',side_effect=AssertionError('network')):
            result=verdicts.prepare(records)
        self.assertTrue(any(r['status']=='UPDATE' for r in result))

    def test_command_writes_new_reports_and_keeps_input_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)/'original.json'
            source.write_text(json.dumps(dict(tool_version='2.7.6', generated_at='fixture observation',
                records=json.loads((ROOT/'tests/fixtures/safechain-2.7.6.json').read_text()))))
            before = source.read_bytes()
            destination = Path(tmp)/'new'
            command = [sys.executable,'-B',str(ROOT/'reassess_report.py'),str(source),'--out',str(destination)]
            result = subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(source.read_bytes(),before)
            report = json.loads((destination/'report.json').read_text())
            self.assertEqual(report['summary']['tool_review_counts']['action'],1)
            self.assertFalse(report['source_observation']['new_network_requests'])
            manifest = json.loads((destination/'reassessment.json').read_text())
            self.assertTrue(manifest['original_unchanged'])
            self.assertTrue(manifest['communication_evidence_unchanged'])
            self.assertEqual(manifest['new_observations'],0)
            self.assertEqual(manifest['derived_product_assessments'],['Safe Chain / 公式配布版の照合'])
            output_before = (destination/'report.json').read_bytes()
            retry = subprocess.run(command,capture_output=True,text=True)
            self.assertNotEqual(retry.returncode,0)
            self.assertEqual((destination/'report.json').read_bytes(),output_before)
            same_directory = subprocess.run(command[:-1]+[tmp],capture_output=True,text=True)
            self.assertNotEqual(same_directory.returncode,0)
            self.assertEqual(source.read_bytes(),before)


if __name__ == '__main__': unittest.main()
