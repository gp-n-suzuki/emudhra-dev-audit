"""Read-only TLS sampling. Executed by each selected Python, with -B.
The pip adapter uses pip's actual session builder; unsupported versions fail closed.
No package install, HTTP redirects, request bodies or origin credentials.
"""
from __future__ import print_function
import sys, os, json, ssl

def emit(x):
    print('EMUDHRA_JSON:' + json.dumps(x, ensure_ascii=True))

def errchain(e):
    texts = []
    seen = set()
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        texts.append(type(e).__name__ + ': ' + str(e))
        e = getattr(e, 'reason', None) or getattr(e, '__cause__', None) or getattr(e, '__context__', None)
    return ' | '.join(texts)[:4000]

def error_result(e):
    result = {'state':'error', 'detail':errchain(e)}
    seen = set()
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        code = getattr(e, 'verify_code', None)
        if type(code) is int:
            result['verify_code'] = code
            break
        e = getattr(e, 'reason', None) or getattr(e, '__cause__', None) or getattr(e, '__context__', None)
    return result

def version(name):
    try:
        from importlib.metadata import version as get
        return get(name)
    except Exception:
        try:
            m = __import__(name)
            return getattr(m, '__version__', '?')
        except ImportError:
            return None

def main():
    mode, url, timeout = sys.argv[-3:]
    timeout = float(timeout)
    if mode == 'meta':
        meta = {'executable': sys.executable, 'version': sys.version.split()[0],
                'prefix': sys.prefix, 'base_prefix': getattr(sys, 'base_prefix', sys.prefix),
                'openssl': ssl.OPENSSL_VERSION, 'ca': ssl.get_default_verify_paths()._asdict(),
                'packages': dict((k, version(k)) for k in ('pip', 'certifi', 'requests', 'httpx'))}
        try:
            import ensurepip
            meta['ensurepip_bundled_pip'] = ensurepip.version()
        except Exception:
            pass
        try:
            import pip._vendor.certifi as c
            meta['pip_vendored_ca'] = c.where()
            meta['pip_vendored_certifi_version'] = getattr(c, '__version__', '?')
        except Exception:
            pass
        try:
            import certifi
            meta['certifi_ca'] = certifi.where()
        except Exception:
            pass
        emit({'state': 'meta', 'data': meta})
        return
    try:
        if mode in ('urllib', 'certifi'):
            import urllib.request, urllib.error
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            context = ssl.create_default_context()
            if mode == 'certifi':
                import certifi
                # This isolates this PEM bundle; it is NOT the entire requests/pip configuration.
                context = ssl.create_default_context(cafile=certifi.where())
            opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
            try:
                response = opener.open(urllib.request.Request(url, headers={'User-Agent':'emudhra-dev-audit/2'}), timeout=timeout)
                code = response.getcode()
                response.close()
            except urllib.error.HTTPError as e:
                # Any origin HTTP status proves HTTPS completed; 404 is not a TLS rejection.
                code = e.code
                e.close()
            emit({'state':'accepted', 'detail':'HTTP ' + str(code)})
        elif mode in ('requests', 'pip'):
            if mode == 'requests':
                import requests
                session = requests.Session()
            else:
                try:
                    from pip._internal.commands import create_command
                    command = create_command('index')
                    options, args = command.parse_args([])
                    options.retries = 0
                    options.timeout = timeout
                    options.no_input = True
                    # Do not present an existing TLS client identity to an external checker.
                    if getattr(options, 'client_cert', None):
                        emit({'state':'skipped', 'detail':'pip client-cert is configured; active test withheld'})
                        return
                    session = command._build_session(options)
                except Exception as e:
                    emit({'state':'unknown', 'detail':'pip internal API unavailable: ' + type(e).__name__})
                    return
            # Keep CA/proxy settings, but disable netrc, keyring and index credentials for this probe.
            session.auth = lambda request: request
            for k in list(session.headers):
                if k.lower() in ('authorization', 'cookie'):
                    del session.headers[k]
            with session:
                response = session.get(url, timeout=timeout, allow_redirects=False, stream=True)
                emit({'state':'accepted', 'detail':'HTTP ' + str(response.status_code)})
                response.close()
        elif mode == 'httpx':
            import httpx
            with httpx.Client(timeout=timeout, follow_redirects=False) as client:
                with client.stream('GET', url) as response:
                    emit({'state':'accepted', 'detail':'HTTP ' + str(response.status_code)})
        else:
            emit({'state':'unknown', 'detail':'unknown probe mode'})
    except ImportError as e:
        emit({'state':'skipped', 'detail':'module unavailable: ' + str(e)})
    except Exception as e:
        emit(error_result(e))

if __name__ == '__main__':
    main()
