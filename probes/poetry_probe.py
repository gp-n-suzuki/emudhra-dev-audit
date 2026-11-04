"""Use the selected Poetry environment's own unauthenticated HTTP transport."""
import importlib.util
import json
from pathlib import Path
import sys


def within_prefix(path):
    try:
        return Path(sys.prefix).resolve() in Path(path).resolve().parents
    except (OSError, ValueError, TypeError):
        return False


def main():
    try:
        site,prefix=sys.argv[1:3]
        sys.path.insert(0,site)
        sys.prefix=sys.exec_prefix=prefix
        spec=importlib.util.find_spec('poetry.utils.authenticator')
        if not spec or not spec.origin or not within_prefix(spec.origin):
            raise RuntimeError('Poetry transport is not located in the selected environment')
        import requests
        if not within_prefix(requests.__file__):
            raise RuntimeError('Poetry requests is not located in the selected environment')
        from poetry.config.config import Config
        from poetry.utils.authenticator import Authenticator
        config=Config(use_environment=False)
        config.merge({'keyring':{'enabled':False},'repositories':{},'certificates':{}})
        client=Authenticator(config=config,disable_cache=True)
        try:
            response=client.get(sys.argv[3],timeout=float(sys.argv[4]),
                                allow_redirects=False,raise_for_status=False,stream=True)
            code=response.status_code
            response.close()
        finally:
            client.close()
        result={'state':'accepted' if 200 <= code <= 599 and code != 407 else 'unknown',
                'detail':'HTTP '+str(code)}
    except Exception as exc:
        result={'state':'error','detail':type(exc).__name__+': '+str(exc)[:1000]}
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__': main()
