"""Corroborate opaque PHP stream errors with a separately verified TLS connection.

Never claim the OpenSSL CLI is the PHP stream or that its cause is directly observed.
"""
import os
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit
import evidence

TRUST_CODES={2,18,19,20,21,23,27,28}


def matching_openssl(version, run):
    match=re.fullmatch(r'OpenSSL ([3-9])\.\d+\.\d+ .+',version or '')
    if not match: return None
    major=match[1]
    candidates=[shutil.which('openssl')]
    candidates += [str(Path(root)/('openssl@'+major)/'bin/openssl')
                   for root in ('/opt/homebrew/opt','/usr/local/opt')]
    for candidate in dict.fromkeys(candidates):
        if not candidate or not Path(candidate).is_file(): continue
        rc,out,_=run([candidate,'version'])
        if not rc and out.strip() in (version,version+' (Library: '+version+')'):
            return candidate
    return None


def ca_arguments(locations):
    # PHP uses the explicit ini paths if either is set; otherwise it loads defaults.
    if locations.get('ini_cafile') or locations.get('ini_capath'):
        cafile,capath=locations.get('ini_cafile'),locations.get('ini_capath')
    else:
        cafile=os.environ.get('SSL_CERT_FILE') or locations.get('default_cert_file')
        capath=os.environ.get('SSL_CERT_DIR') or locations.get('default_cert_dir')
    args=['-no-CAfile','-no-CApath','-no-CAstore']
    if cafile:
        if evidence.read_public_file(cafile) is None: return None
        args += ['-CAfile',cafile]
    if capath:
        for part in str(capath).split(os.pathsep):
            path=Path(part)
            if not evidence.public_path(path): return None
            if not path.is_dir(): return None
            # OpenSSL may load files through hashed aliases. Do not permit env targets.
            try:
                if any(not evidence.public_path(child)
                       for child in path.iterdir() if re.fullmatch(r'[0-9a-fA-F]{8}\.\d+',child.name)):
                    return None
            except OSError: return None
        args += ['-CApath',capath]
    return args if cafile or capath else None


def corroborate(data,url,timeout,run):
    if data.get('state')!='unknown' or 'certificate verify failed' not in data.get('detail','').lower(): return data
    if re.search(r'expir|not yet valid|did not match|hostname|subjectAltName',data['detail'],re.I): return data
    # Do not silently change a configured proxy route or custom OpenSSL setup.
    if any(os.environ.get(k) for k in ('HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy',
                                      'ALL_PROXY','all_proxy','OPENSSL_CONF','OPENSSL_MODULES')): return data
    args=ca_arguments(data.get('ca_locations',{}))
    if args is None: return data
    executable=matching_openssl(data.get('openssl_version'),run)
    if not executable: return data
    parsed=urlsplit(url)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password: return data
    host=parsed.hostname
    command=[executable,'s_client','-connect',host+':'+str(parsed.port or 443),
             '-servername',host,'-verify_hostname',host,'-verify_return_error','-brief']+args
    rc,out,err=run(command,timeout=timeout+2)
    codes=[int(n) for n in re.findall(r'verify error:num=(\d+):',out+'\n'+err)]
    if rc in (0,124,127) or not codes or any(c not in TRUST_CODES for c in codes): return data
    reason=next((line.strip() for line in (out+'\n'+err).splitlines() if 'verify error:num=' in line),'')
    return dict(state='inferred_rejection',detail='PHP実測: certificate verify failed。'
                '同じOpenSSL版・CA参照先の別接続で '+reason+'。信頼拒否の推定で、PHP内部の検証コードを取得した結果ではありません。',
                corroboration=dict(openssl=executable,version=data['openssl_version'],verify_codes=codes,
                                   ca_arguments=args,original_state=data['state'],original_detail=data['detail']))
