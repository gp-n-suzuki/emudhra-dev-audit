"""Start only the selected Azure venv's CLI without executing .pth files."""
from pathlib import Path
import runpy
import sys

site,prefix=sys.argv[1:3]
sys.path.insert(0,site)
sys.prefix=sys.exec_prefix=prefix
sys.argv=['az']+sys.argv[3:]
runpy.run_module('azure.cli',run_name='__main__')
