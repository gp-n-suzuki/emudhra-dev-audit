"""Bounded metadata from a launcher's own venv; never execute or import it."""
from itertools import islice
from pathlib import Path
import re

import evidence
import official_versions

PIP_SOURCE = 'https://pip.pypa.io/en/stable/news/#v26-2-2'


def python_environment(entry, reader):
    """Inventory only: installed dist-info does not establish runtime imports/CA."""
    entry = Path(entry)
    if entry.parent.name != 'bin': return None
    start_bytes = reader.remaining
    try:
        text = reader.read(entry,4096,whole=False).decode('utf-8')
        direct = re.match(r'\A#!(/[^\r\n]+/python(?:\d+(?:\.\d+)*)?)\s*\n',text)
        # distlib's fixed shell trampoline for interpreter paths with spaces.
        quoted = re.match(r'''\A#!/bin/sh\n''' + r"'''exec' ([\"'])(/[^\r\n]+/python(?:\d+(?:\.\d+)*)?)\1 \"\$0\" \"\$@\"\n' '''\n", text)
        interpreter = Path(direct[1] if direct else quoted[2]) if direct or quoted else None
        prefix = entry.parent.parent
        if interpreter is None or interpreter.parent.resolve() != entry.parent.resolve(): return None
        root = prefix.resolve()
        def inside(path):
            return evidence.public_path(path) and root in path.resolve().parents
        cfg = prefix/'pyvenv.cfg'
        if not inside(cfg): return None
        reader.read(cfg,65536)  # existence/readability only; never retain config values
        result = dict(prefix=str(prefix),interpreter=str(interpreter),launcher=str(entry),
                      binding='absolute-launcher-and-venv-layout',runtime_usage_verified=False,
                      scope='自身のvenvにあるインストール済みメタデータ。実際のimport先・実効CA・通信は未確認。',
                      packages=[],gaps=[])
        lib = prefix/'lib'
        if not inside(lib): return result
        for runtime in islice(lib.iterdir(),32):
            if not re.fullmatch(r'python3\.\d+',runtime.name): continue
            site = runtime/'site-packages'
            if not inside(site) or not site.is_dir(): continue
            candidates = list(islice(site.iterdir(),513))
            if len(candidates)>512: result['gaps'].append('site-packages探索件数の上限')
            for package in candidates[:512]:
                if start_bytes-reader.remaining >= 1024*1024:
                    result['gaps'].append('自己環境メタデータの読取量の上限'); break
                if not re.fullmatch(r'(?:pip|poetry|certifi|requests|truststore)-[A-Za-z0-9._+-]+\.dist-info',package.name): continue
                metadata = package/'METADATA'
                if not inside(metadata):
                    result['gaps'].append('環境外を指すメタデータは未検査'); continue
                try:
                    contents = reader.read(metadata,65536).decode('utf-8')
                    name = re.findall(r'^Name: (pip|poetry|certifi|requests|truststore)\s*$',contents,re.M)
                    version = re.findall(r'^Version: ([0-9][A-Za-z0-9._+-]{0,79})\s*$',contents,re.M)
                    if len(name)!=1 or len(version)!=1: continue
                    item = dict(name=name[0],version=version[0],path=str(metadata),runtime_usage_verified=False)
                    if name[0] in ('pip','certifi'):
                        status,detail,floor = official_versions.reference(name[0],version[0])
                        item.update(reference_status=status,reference_floor=floor,detail=detail,
                                    source=PIP_SOURCE if name[0]=='pip' else official_versions.COMPONENT_SOURCES['certifi'])
                    result['packages'].append(item)
                except (OSError,ValueError,UnicodeError):
                    result['gaps'].append('パッケージメタデータの読取上限・解析失敗')
        result['packages'].sort(key=lambda p:(p['name'],p['version'],p['path']))
        return result
    except (OSError,ValueError,UnicodeError,RuntimeError):
        return None
