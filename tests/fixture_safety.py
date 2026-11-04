"""Do not run direct package-manager fixtures when Safe Chain may be active."""
import os
from pathlib import Path
import audit


def safe_chain_active():
    try:
        rows=audit.app_inventory.scan(audit.reference)
        paths={os.path.normcase(os.path.realpath(p)) for p in os.environ.get('PATH','').split(os.pathsep) if p}
        incomplete=False
        for row in rows:
            meta=row.get('metadata',{})
            incomplete |= bool(meta.get('application_scan') and meta.get('incomplete'))
            if meta.get('tool_id')!='safe-chain': continue
            security=meta.get('security_tool') or {}
            candidate=Path(meta.get('path') or '')
            shim=candidate.parent.parent/'shims' if candidate.parent.name.lower()=='bin' else None
            if security.get('shell_sources') or security.get('shell_links') or (shim and os.path.normcase(os.path.realpath(shim)) in paths):
                return True
        return incomplete
    except (OSError,ValueError,RuntimeError):
        return True
