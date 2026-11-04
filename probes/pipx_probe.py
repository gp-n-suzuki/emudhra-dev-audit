"""Use only the selected pipx shared pip, without loading managed app .pth files."""
import importlib.util
from pathlib import Path
import runpy
import sys


shared=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(shared))
spec=importlib.util.find_spec('pip')
if spec is None or spec.origin is None or shared not in Path(spec.origin).resolve().parents:
    print('EMUDHRA_JSON:{"state":"unknown","detail":"pipx shared pip unavailable"}')
else:
    sys.argv=[str(Path(__file__).with_name('python_probe.py')),'pip',sys.argv[2],sys.argv[3]]
    runpy.run_path(sys.argv[0],run_name='__main__')
