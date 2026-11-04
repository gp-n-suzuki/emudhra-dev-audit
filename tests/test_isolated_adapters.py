"""Exercise Python entry adapters without loading unrelated venv startup hooks."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class IsolatedAdapters(unittest.TestCase):
    def site(self,root):
        site=root/'lib/python3/site-packages'; site.mkdir(parents=True)
        marker=root/'pth-ran'
        (site/'unrelated.pth').write_text('import pathlib; pathlib.Path('+repr(str(marker))+').touch()\n')
        return site,marker

    def test_azure_module_is_loaded_from_the_selected_site_without_pth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); site,marker=self.site(root); cli=site/'azure/cli'; cli.mkdir(parents=True)
            (cli/'__init__.py').write_text('')
            (cli/'__main__.py').write_text('import sys; print(" ".join(sys.argv[1:]))\n')
            result=subprocess.run([sys.executable,'-I','-S','-B',str(ROOT/'probes/azure_entry.py'),str(site),str(root),
                                   'rest','--skip-authorization-header'],capture_output=True,text=True,timeout=8)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.strip(),'rest --skip-authorization-header')
            self.assertFalse(marker.exists())

    def test_poetry_transport_imports_only_the_selected_site_without_pth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); site,marker=self.site(root)
            for name in ('poetry','poetry/utils','poetry/config','requests'):
                folder=site/name; folder.mkdir(parents=True,exist_ok=True); (folder/'__init__.py').write_text('')
            (site/'poetry/config/config.py').write_text('class Config:\n def __init__(self,**kw): pass\n def merge(self,items): pass\n')
            (site/'poetry/utils/authenticator.py').write_text(
                'class Response:\n status_code=200\n def close(self): pass\n'
                'class Authenticator:\n def __init__(self,**kw): pass\n'
                ' def get(self,*args,**kw): return Response()\n def close(self): pass\n')
            result=subprocess.run([sys.executable,'-I','-S','-B',str(ROOT/'probes/poetry_probe.py'),str(site),str(root),
                                   'https://fixture.invalid/', '2'],capture_output=True,text=True,timeout=8)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout)['state'],'accepted')
            self.assertFalse(marker.exists())


if __name__=='__main__': unittest.main()
