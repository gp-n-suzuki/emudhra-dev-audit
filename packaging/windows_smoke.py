"""Windows/Wine entry point: synthetic offline checks, no host scan."""
import sys
from offline_smoke import verify

if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf-8',errors='replace')
    verify(sys.argv[1])
