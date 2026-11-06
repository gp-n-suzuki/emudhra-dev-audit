"""User-visible report contracts: counts, environments and evidence access."""
from html.parser import HTMLParser
import unittest

import audit
import reporting
import verdicts


def row(name, status, meta, method='inventory'):
    return dict(name=name, status=status, metadata=meta, assessment_method=method,
                detail='recorded evidence', action='', samples=[])


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.depth = self.max_depth = 0
        self.tools = []
        self.text = ''
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'details':
            self.depth += 1
            self.max_depth = max(self.max_depth, self.depth)
        if tag == 'article' and 'data-tool' in attrs:
            self.tools.append(attrs)
    def handle_endtag(self, tag):
        if tag == 'details': self.depth -= 1
    def handle_data(self, data): self.text += data


class ReportLayoutTests(unittest.TestCase):
    def test_each_tool_counts_once_but_mixed_installations_are_preserved(self):
        records = verdicts.prepare([
            row('Python / pip', 'UPDATE', dict(tool_name='Python', executable='/old/python', version='26.2.1', reference_floor='26.2.2'), 'version'),
            row('Python / pip', 'INFERRED_OK', dict(tool_name='Python', executable='/new/python', version='26.2.2'), 'version'),
            row('curl', 'REJECTED', dict(executable='/bin/curl'), 'measured'),
            row('unknown', 'UNKNOWN', {}, 'manual')])
        self.assertEqual(reporting.tool_counts(records), dict(action=1, review=0, complete=1, unverified=1, scope=0, info=0))
        page = Page(); page.feed(audit.render_report(records, 'fixture'))
        python = next(t for t in page.tools if t['data-tool'] == 'Python')
        self.assertEqual(python['data-states'], 'update')
        self.assertIn('investigate', python['data-actions'].split())
        self.assertIn('26.2.1', page.text)
        self.assertIn('26.2.2', page.text)

    def test_environment_names_and_evidence_need_at_most_three_disclosures(self):
        records = []
        for path, version in [('/Users/example/.local/share/uv/python/cpython-3.11.15/bin/python3', '3.11.15'),
                              ('/Applications/Xcode.app/Contents/Developer/usr/bin/python3', '3.9.6')]:
            meta = dict(tool_id='python', tool_name='Python', executable=path, prefix=path.rsplit('/bin/', 1)[0])
            records += [row('Python', 'INFO', dict(meta, version=version, packages={})),
                        row('Python / version', 'MANUAL', dict(meta, python_version=version), 'version'),
                        row('Python / network', 'SKIP', meta, 'unmeasured')]
        html = audit.render_report(records, 'fixture')
        page = Page(); page.feed(html)
        self.assertLessEqual(page.max_depth, 3)
        self.assertIn('uv / Python 3.11.15', page.text)
        self.assertIn('Xcode / Python 3.9.6', page.text)
        self.assertNotIn('導入 1', page.text)
        self.assertIn('設定・パス（JSON）', page.text)
        self.assertIn(records[0]['metadata']['executable'], page.text)

    def test_components_group_by_version_and_result_without_losing_files(self):
        checks = []
        for version, status, names in [('1.26.9', 'UPDATE', ['a', 'b']), ('1.27.3', 'INFERRED_OK', ['c', 'd', 'e'])]:
            checks += [dict(component='go', version=version, status=status, reference_floor='1.27.3',
                            detail='version evidence', method='version', path='/Applications/Docker.app/bin/'+name) for name in names]
        record = row('Docker', 'UPDATE', dict(tool_name='Docker', application=True, path='/Applications/Docker.app',
                     inspections=checks, uninspected=[]), 'version')
        table = reporting.application_details(record)
        self.assertEqual(table.count('<tbody>'), 1)
        self.assertEqual(table.count('<tr>'), 3)  # Header plus two distinct findings.
        self.assertIn('<td>2</td>', table)
        self.assertIn('<td>3</td>', table)
        html = audit.render_report([record], 'fixture')
        for check in checks: self.assertIn(check['path'], html)
        self.assertIn('対策バージョン未満', html)
        self.assertIn('対応バージョンを使用中', html)

    def test_distinct_results_for_the_same_component_version_do_not_merge(self):
        checks = [dict(component='go', version='1.27.3', status=status, detail='evidence', path='/bin/'+status)
                  for status in ('INFERRED_OK', 'MANUAL')]
        table = reporting.application_details(row('Example', 'MANUAL', dict(application=True, inspections=checks)))
        self.assertEqual(table.count('<tr>'), 3)

    def test_manager_and_jdk_names_use_recorded_metadata(self):
        records = [row('Python', 'INFO', dict(tool_id='python', tool_name='Python', version='3.15.0', packages={},
                       prefix='/opt/homebrew/opt/python@3.15/Frameworks/Python.framework/Versions/3.15', executable='/opt/homebrew/bin/python3')),
                   row('Java version', 'INFO', dict(tool_id='java', tool_name='Java', version='17.0.20.1',
                       java_home='/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home', executable='/usr/bin/java'))]
        page = Page(); page.feed(audit.render_report(records, 'fixture'))
        self.assertIn('Homebrew / Python 3.15.0', page.text)
        self.assertIn('zulu-17.jdk / Java 17.0.20.1', page.text)

    def test_duplicate_names_and_container_context_remain_distinguishable(self):
        records = [row('Example', 'UNKNOWN', dict(tool_id='example', tool_name='Example',
                       executable='/'+prefix+'/bin/example', execution_context=context))
                   for prefix, context in [('old', 'ホスト'), ('new', 'ホスト'), ('old', 'コンテナ api')]]
        tools = reporting.group_tools(verdicts.prepare(records))[0]
        names = reporting.installation_names(tools[0]['units'])
        self.assertEqual(len(set(names)), 3)
        self.assertTrue(any('コンテナ api' in name for name in names))

    def test_unstartable_installation_and_scoped_success_are_visible_in_headers(self):
        record = row('Example', 'UNKNOWN', dict(tool_id='example', tool_name='Example', executable='/old/example'))
        record['detail'] = 'Bad CPU type in executable'
        inventory = row('Example inventory', 'MANUAL', dict(tool_id='example', tool_name='Example', application=True,
                        path='/old/example', inspections=[], uninspected=[]))
        html = audit.render_report([inventory, record, row('curl', 'REJECTED', {}, 'measured')], 'fixture')
        self.assertIn('起動できない（CPU形式）', html.split('data-tool="Example"', 1)[1].split('検査データ</summary>')[0])
        self.assertIn('検査先の証明書を拒否できた', html)


if __name__ == '__main__': unittest.main()
