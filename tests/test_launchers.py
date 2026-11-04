import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name=='nt','Bash launcher test; Windows is validated separately')
class LauncherTests(unittest.TestCase):
    def test_double_click_launcher_uses_its_own_directory_without_python_on_path(self):
        for exit_code in (0, 3):
            with self.subTest(exit_code=exit_code), tempfile.TemporaryDirectory(prefix='診断 日本語 & ') as tmp:
                root=Path(tmp)
                launcher=root/'診断を開始.command'
                shutil.copyfile(ROOT/'packaging/start-diagnosis.sh',launcher)
                binary=root/'app/runtime/bin/python3'; binary.parent.mkdir(parents=True)
                binary.write_text('#!/bin/sh\nexec "'+sys.executable+'" "$@"\n'); binary.chmod(0o755)
                (root/'app/desktop_entry.py').write_text('import sys;print("DESKTOP_ENTRY_OK");sys.exit('+str(exit_code)+')')
                result=subprocess.run(['/bin/bash',str(launcher)],cwd='/',stdin=subprocess.DEVNULL,
                                      env=dict(os.environ,PATH='/does-not-exist'),capture_output=True,text=True)
                self.assertEqual(result.returncode,exit_code,result.stderr)
                self.assertIn('DESKTOP_ENTRY_OK',result.stdout)

    def test_bundle_starts_without_python_on_path_and_preserves_arguments_and_exit(self):
        with tempfile.TemporaryDirectory(prefix='emudhra 日本語 ') as tmp:
            root=Path(tmp); shutil.copyfile(ROOT/'run-checks.sh',root/'run-checks.sh')
            binary=root/'runtime/bin/python3'; binary.parent.mkdir(parents=True)
            binary.write_text('#!/bin/sh\nexec "'+sys.executable+'" "$@"\n'); binary.chmod(0o755)
            (root/'audit.py').write_text('import sys,json;print(json.dumps(sys.argv[1:]));sys.exit(2)')
            result=subprocess.run(['/bin/bash',str(root/'run-checks.sh'),'--project','日本語 path','--out','report path'],
                                  env=dict(os.environ,PATH='/does-not-exist'),capture_output=True,text=True)
            self.assertEqual(result.returncode,2,result.stderr)
            self.assertEqual(json.loads(result.stdout),['--project','日本語 path','--out','report path'])

    def test_missing_packaged_runtime_never_falls_back_to_system_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); shutil.copyfile(ROOT/'run-checks.sh',root/'run-checks.sh')
            (root/'RUNTIME.json').write_text('{}')
            (root/'audit.py').write_text('raise RuntimeError("must not run")')
            result=subprocess.run(['/bin/bash',str(root/'run-checks.sh'),'--help'],capture_output=True,text=True)
            self.assertEqual(result.returncode,2)
            self.assertIn('bundled Python',result.stderr)


if __name__=='__main__': unittest.main()
