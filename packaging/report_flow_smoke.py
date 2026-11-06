"""Validate real CLI/desktop report generation with synthetic collection only.

Run with an already installed Python, against either source or a staged app.
This never executes the bundled runtime, a scanner, or a browser.
"""
import argparse
import contextlib
import copy
import hashlib
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
from unittest import mock


def fixture():
    rows = []
    # Completed installation comes first deliberately: the UI must prioritize
    # the later outdated installation without merging their findings.
    for location, version, status in (('new', '26.2.2', 'INFERRED_OK'),
                                       ('old', '26.2.1', 'UPDATE')):
        for component in ('pip', 'ensurepip同梱pip（新規venv用）'):
            rows.append(dict(name='Python / '+component, status=status,
                assessment_method='version', detail='合成入力・実環境の観測ではありません。',
                action='', samples=[], metadata=dict(tool_id='python', tool_name='Python',
                    executable='/fixture/'+location+'/python', python_version='3.13.18',
                    version=version, reference_floor='26.2.2', fixture_origin='synthetic-v1')))
    return rows


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.editors = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        if tag == 'textarea':
            self.editors.append(dict(attrs))


def verify(app, output):
    app, output = Path(app).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(app))
    import audit
    import desktop_entry
    assert Path(audit.__file__).resolve().parent == app, 'Wrong audit module'
    assert Path(desktop_entry.__file__).resolve().parent == app, 'Wrong desktop module'
    original = fixture()
    calls, opened = [], []

    def collect(instance):
        assert instance.args.host_only and instance.args.project is None
        calls.append(instance.args.offline)
        instance.records.extend(copy.deepcopy(original))

    def record_open(path):
        assert path.is_file(), 'Report must exist before opening'
        opened.append(path)
        return True

    def check(directory):
        report = json.loads((directory/'report.json').read_text(encoding='utf-8'))
        assert report['tool_version'] == audit.TOOL_VERSION
        assert 'source_observation' not in report, 'This is a new synthetic collection'
        def observed(rows):
            return sorted((r['metadata']['executable'], r['name'], r['status'],
                           r['metadata']['version']) for r in rows)
        assert observed(report['records']) == observed(original)
        assert all(r['metadata']['fixture_origin'] == 'synthetic-v1' for r in report['records'])
        tool = report['presentation']['tools'][0]
        assert tool['overview']['counts']['installations'] == 2
        assert tool['overview']['counts']['affected_installations'] == 1
        assert tool['overview']['counts']['update_items'] == 2
        assert tool['overview']['rows'][0]['priority'] == 1
        assert tool['work']['tasks']
        page = (directory/'report.html').read_text(encoding='utf-8')
        assert '先に対応' in page and '更新対象' in page
        assert '26.2.1' in page and '26.2.2' in page
        assert len(Page(page).editors) == 2, 'Overall and individual editable prompts'
        assert all('readonly' not in a and 'disabled' not in a for a in Page(page).editors)
        assert (app/'report-ui.js').read_text(encoding='utf-8') in page
        assert (directory/'ui.css').read_bytes() == (app/'ui.css').read_bytes()
        assert (directory/'summary.txt').is_file()
        return dict(path=str(directory), records=len(report['records']),
                    installations=2, affected_installations=1, update_items=2)

    # Guards make unexpected subprocesses or network activity a test failure.
    with mock.patch.object(audit.Audit, 'execute', collect), \
         mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('No subprocesses during synthetic collection')), \
         mock.patch.object(socket.socket, 'connect', side_effect=AssertionError('No network')), \
         mock.patch.object(socket.socket, 'connect_ex', side_effect=AssertionError('No network')), \
         mock.patch.object(socket, 'getaddrinfo', side_effect=AssertionError('No DNS')), \
         mock.patch.object(desktop_entry, 'PACKAGE', output/'desktop'), \
         mock.patch.object(desktop_entry, 'open_report', side_effect=record_open), \
         contextlib.redirect_stdout(io.StringIO()):
        reports = []
        for mode, args in (('cli', []), ('offline', ['--offline'])):
            dest = output/mode
            assert audit.main(args+['--out', str(dest)]) == 1
            reports.append(check(dest))
        (output/'desktop').mkdir()
        for _ in range(2):
            assert desktop_entry.main() == 0
        assert len(set(opened)) == 2, 'Repeated launches must retain both results'
        reports.extend(check(path.parent) for path in opened)
    assert calls == [False, True, False, False]
    assert original == fixture(), 'Fixture input changed'
    result = dict(version=audit.TOOL_VERSION, app=str(app), interpreter=sys.executable,
                  normal_cli=True, offline_cli=True, desktop_flow=True,
                  repeated_outputs_preserved=True, reports=reports,
                  css_sha256=hashlib.sha256((app/'ui.css').read_bytes()).hexdigest(),
                  collection='synthetic', live_scan=False, network=False,
                  bundled_runtime_executed=False, native_launcher_executed=False,
                  browser_ui_verified=False)
    (output/'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    verify(args.app, args.out)
