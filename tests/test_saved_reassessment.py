"""Offline reassessment must preserve its source and never collect new evidence."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
CLI_WITH_REDIRECTED_ENCODING = '''import runpy,sys
from pathlib import Path
sys.stdout.reconfigure(encoding=sys.argv[1],errors='strict')
sys.stderr.reconfigure(encoding=sys.argv[1],errors='strict')
sys.argv=sys.argv[2:]
sys.path.insert(0,str(Path(sys.argv[0]).parent))
runpy.run_path(sys.argv[0],run_name='__main__')
'''


class SavedReassessmentTests(unittest.TestCase):
    def test_cli_completes_with_legacy_and_utf8_redirected_streams(self):
        with tempfile.TemporaryDirectory(prefix='再判定 CLI 空白 ') as tmp:
            source = Path(tmp)/'original.json'
            source.write_text(json.dumps(dict(tool_version='2.7.6', generated_at='fixture observation',
                records=json.loads((ROOT/'tests/fixtures/safechain-2.7.6.json').read_text(encoding='utf-8')))),
                encoding='utf-8')
            before = source.read_bytes()
            for encoding in ('cp1252','ascii','utf-8'):
                with self.subTest(encoding=encoding):
                    destination = Path(tmp)/encoding
                    command = [sys.executable,'-E','-s','-B','-c',CLI_WITH_REDIRECTED_ENCODING,encoding,
                               str(ROOT/'reassess_report.py'),str(source),'--out',str(destination)]
                    result = subprocess.run(command,cwd=tmp,capture_output=True,text=True,encoding='utf-8',timeout=30)
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertEqual(result.stderr,'')
                    self.assertIn('結果:',result.stdout)
                    self.assertEqual(source.read_bytes(),before)
                    for name in ('report.html','report.json','summary.txt','ui.css','reassessment.json'):
                        self.assertTrue((destination/name).is_file(),name)
                    manifest = json.loads((destination/'reassessment.json').read_text(encoding='utf-8'))
                    self.assertTrue(manifest['original_unchanged'])
                    self.assertTrue(manifest['communication_evidence_unchanged'])
                    self.assertEqual(manifest['new_observations'],0)
                    self.assertEqual(manifest['source']['sha256'],hashlib.sha256(before).hexdigest())
                    for name,digest in manifest['outputs'].items():
                        self.assertEqual(hashlib.sha256((destination/name).read_bytes()).hexdigest(),digest)

    def test_cli_keeps_exit_two_and_existing_files_with_legacy_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)/'original.json'
            source.write_text('{"records":[]}',encoding='utf-8')
            before = source.read_bytes()
            destination = Path(tmp)/'existing'
            destination.mkdir()
            sentinel = destination/'keep.txt'
            sentinel.write_bytes(b'existing output')
            for encoding in ('cp1252','ascii'):
                with self.subTest(encoding=encoding):
                    command = [sys.executable,'-E','-s','-B','-c',CLI_WITH_REDIRECTED_ENCODING,encoding,
                               str(ROOT/'reassess_report.py'),str(source),'--out',str(destination)]
                    result = subprocess.run(command,cwd=tmp,capture_output=True,text=True,encoding='utf-8',timeout=30)
                    self.assertEqual(result.returncode,2)
                    self.assertIn('既存ファイルは上書きしません',result.stderr)
                    self.assertNotIn('Traceback',result.stderr)
                    self.assertEqual(source.read_bytes(),before)
                    self.assertEqual(list(destination.iterdir()),[sentinel])
                    self.assertEqual(sentinel.read_bytes(),b'existing output')

    def test_cli_supports_in_memory_unicode_streams(self):
        import reassess_report
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)/'original.json'
            source.write_text('{"records":[]}',encoding='utf-8')
            before = source.read_bytes()
            destination = Path(tmp)/'new'
            output,errors = io.StringIO(),io.StringIO()
            with patch.object(sys,'argv',['reassess_report.py',str(source),'--out',str(destination)]), \
                 contextlib.redirect_stdout(output),contextlib.redirect_stderr(errors):
                self.assertIsNone(reassess_report.main())
            self.assertIn('結果:',output.getvalue())
            self.assertEqual(errors.getvalue(),'')
            self.assertEqual(source.read_bytes(),before)
            self.assertTrue((destination/'ui.css').is_file())
            self.assertTrue((destination/'reassessment.json').is_file())

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
