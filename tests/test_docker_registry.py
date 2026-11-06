"""Docker Desktop's internal hop is separate from external TLS exceptions."""
import copy
import json
import os
from types import SimpleNamespace
import unittest
from unittest import mock

import audit
import ai_prompts
import evidence
import reporting
import verdicts
from test_report_usability import Page


INTERNAL = 'hubproxy.docker.internal:5555'


def registry(names, connection=None):
    meta = dict(count=len(names), insecure_registries=names, redacted_registry_count=0)
    if connection is not None:
        meta['docker_connection'] = connection
    return dict(name='Docker / registryのTLS設定', status='ACTION',
                assessment_method='configuration', detail='Secure=falseという元観測。',
                action='旧案内', samples=[], metadata=meta)


def desktop():
    return dict(context='desktop-linux', endpoint_type='unix', bound=True,
                server_os='Docker Desktop', server_name='docker-desktop')


def user_confirmation(names=None):
    return dict(schema_version=1, source='user-provided', provided_at='2026-11-06',
                source_sha256='a'*64, record_sha256='b'*64,
                facts=dict(local_docker_desktop=True, context='desktop-linux', endpoint_type='unix',
                           insecure_registries=names if names is not None else [INTERNAL],
                           insecure_registry_cidrs=['127.0.0.0/8', '::1/128'],
                           user_added_insecure_registries=False, user_added_registry_mirrors=False))


class DockerRegistryTests(unittest.TestCase):
    def assessed(self, row):
        before = copy.deepcopy(row)
        result = verdicts.prepare([row])[0]
        self.assertEqual(row, before)
        self.assertEqual(result['metadata']['insecure_registries'], row['metadata']['insecure_registries'])
        self.assertEqual(result['metadata']['count'], row['metadata']['count'])
        self.assertEqual(verdicts.prepare([result]), [result])
        return result

    def test_desktop_internal_only_needs_no_registry_change(self):
        row = self.assessed(registry([INTERNAL], desktop()))
        self.assertEqual(row['status'], 'CHECKED')
        self.assertEqual(row['metadata']['registry_assessment']['internal'], [INTERNAL])
        self.assertEqual(row['metadata']['registry_original_result']['status'], 'ACTION')
        tool = reporting.action_model([row])['tools'][0]
        self.assertNotIn('configure', tool['actions'])
        self.assertTrue(any(t['classification']=='unneeded' for t in tool['work']['tasks']))

    def test_mixed_internal_and_external_keeps_external_action(self):
        row = self.assessed(registry([INTERNAL, 'registry.example:5000'], desktop()))
        self.assertEqual(row['status'], 'ACTION')
        self.assertEqual(row['metadata']['registry_assessment']['external'], ['registry.example:5000'])
        self.assertEqual(row['metadata']['registry_assessment']['internal'], [INTERNAL])
        self.assertIn('configure', reporting.action_model([row])['tools'][0]['actions'])

    def test_same_name_on_non_desktop_is_still_actionable(self):
        connection = dict(desktop(), server_os='Ubuntu 24.04', server_name='engine')
        self.assertEqual(self.assessed(registry([INTERNAL], connection))['status'], 'ACTION')
        self.assertEqual(self.assessed(registry([INTERNAL], dict(connection,bound=False)))['status'], 'ACTION')

    def test_unknown_desktop_identity_is_pending_not_automatic_repair(self):
        row = self.assessed(registry([INTERNAL]))
        self.assertEqual(row['status'], 'MANUAL')
        self.assertIn('接続先', row['detail'])
        self.assertNotIn('configure', reporting.action_model([row])['tools'][0]['actions'])
        self.assertIn('接続先情報', reporting.action_model([row])['tools'][0]['overview']['concern']['title'])

    def test_historical_count_without_registry_names_is_not_assumed_external(self):
        row = registry([INTERNAL])
        row['metadata'] = dict(count=1)
        result = verdicts.prepare([row])[0]
        self.assertEqual(result['status'], 'MANUAL')
        self.assertTrue(result['metadata']['registry_assessment']['incomplete'])

    def test_pending_registry_shows_optional_concrete_instructions(self):
        page = Page(audit.render_report([registry([INTERNAL])], 'synthetic')).root
        pending = next(page.find('details', 'pending-work'))
        self.assertNotIn('open', pending.attrs)
        self.assertIn('判定保留', pending.text)
        self.assertIn('docker context inspect', pending.text)
        self.assertIn('docker info --format', pending.text)
        self.assertFalse(list(page.find(cls='work-task')))

    def test_name_or_context_alone_and_remote_endpoint_cannot_grant_exception(self):
        for connection in (dict(context='desktop-linux'),
                           dict(desktop(), endpoint_type='remote'),
                           dict(desktop(), bound=False),
                           dict(desktop(), server_os='')):
            with self.subTest(connection=connection):
                self.assertEqual(self.assessed(registry([INTERNAL], connection))['status'], 'MANUAL')

    def test_external_setting_remains_actionable_without_connection_identity(self):
        self.assertEqual(self.assessed(registry(['registry.example:5000']))['status'], 'ACTION')

    def test_similar_hostname_or_another_port_does_not_grant_exception(self):
        for name in ('hubproxy.docker.internal:5000', 'hubproxy.docker.internal.evil:5555'):
            self.assertEqual(self.assessed(registry([name], desktop()))['status'], 'ACTION')

    def test_redacted_external_entries_and_cidr_are_not_hidden(self):
        row = registry([INTERNAL], desktop())
        row['metadata'].update(count=2, redacted_registry_count=1)
        self.assertEqual(self.assessed(row)['status'], 'ACTION')

    def test_inconsistent_raw_observation_does_not_establish_internal_completion(self):
        row = registry([INTERNAL], desktop())
        row['metadata']['registry_secure_observations'] = {INTERNAL:True}
        result = self.assessed(row)
        self.assertEqual(result['status'], 'MANUAL')
        self.assertFalse(result['metadata']['registry_assessment']['internal'])
        row = registry([INTERNAL], desktop())
        row['metadata']['insecure_registry_cidrs'] = ['127.0.0.0/8', '::1/128', '10.0.0.0/8']
        self.assertEqual(self.assessed(row)['status'], 'ACTION')

    def test_internal_exception_does_not_hide_other_problems(self):
        for method, status in (('measured','ACTION'), ('configuration','ACTION'), ('version','UPDATE')):
            other = dict(name='Docker / 別の問題', status=status, assessment_method=method,
                         detail='別の問題を記録。', action='対応', samples=[],
                         metadata=dict(tool_id='docker', tool_name='Docker', executable='/fixture/docker',
                                       version='1.0', reference_floor='2.0'))
            prepared = verdicts.prepare([registry([INTERNAL], desktop()), other])
            self.assertEqual(next(r for r in prepared if r['name']==other['name'])['status'], status)
            tool = reporting.action_model(prepared)['tools'][0]
            self.assertTrue(set(tool['actions']) & {'configure','connection_problem','update','action_required'})

    def test_collector_binds_registry_and_server_identity_to_the_same_context(self):
        info = dict(OperatingSystem='Docker Desktop', Name='docker-desktop', RegistryConfig=dict(
            IndexConfigs={INTERNAL:dict(Secure=False), 'docker.io':dict(Secure=True)},
            InsecureRegistryCIDRs=['127.0.0.0/8','::1/128']))
        context = dict(Name='desktop-linux', Endpoints=dict(docker=dict(Host='unix:///fixture/.docker/run/docker.sock')))
        def call(command, **kwargs):
            if 'version' in command: return 0, '{}', ''
            if 'context' in command and 'inspect' in command: return 0, json.dumps(context), ''
            self.assertEqual(command[:3], ['/docker','--context','desktop-linux'])
            self.assertIn('info', command)
            return 0, json.dumps(info), ''
        host = SimpleNamespace(find=lambda _: '/docker', call=mock.Mock(side_effect=call))
        with mock.patch.dict(os.environ, {}, clear=True):
            checks = evidence.docker_evidence(SimpleNamespace(host=host,args=SimpleNamespace(offline=False)), [])
        check = next(c for c in checks if c['check']=='registryのTLS設定')
        row = verdicts.observation(dict(name='Docker Engine / Desktop / BuildKit / registry'),check,'Docker')
        self.assertEqual(self.assessed(row)['status'], 'CHECKED')
        self.assertEqual(check['registry_secure_observations'][INTERNAL], False)
        self.assertEqual(check['registry_secure_observations']['docker.io'], True)

    def test_environment_override_cannot_borrow_a_local_context_identity(self):
        for environment in ({'DOCKER_HOST':'tcp://remote.example:2375'},
                            {'DOCKER_HOST':'unix:///fixture/docker.sock','DOCKER_CONTEXT':'desktop-linux'}):
            context = dict(Name='desktop-linux', Endpoints=dict(docker=dict(Host='unix:///fixture/desktop.sock')))
            info = dict(OperatingSystem='Docker Desktop', Name='docker-desktop', RegistryConfig=dict(
                IndexConfigs={INTERNAL:dict(Secure=False)}))
            host = SimpleNamespace(find=lambda _: '/docker', call=mock.Mock(side_effect=[
                (0,'{}',''), (0,json.dumps(context),''), (0,json.dumps(info),'')]))
            with mock.patch.dict(os.environ, environment, clear=True):
                checks = evidence.docker_evidence(SimpleNamespace(host=host,args=SimpleNamespace(offline=False)), [])
            command = host.call.call_args_list[-1].args[0]
            self.assertEqual(command[:2], ['/docker','info'])
            check = next(c for c in checks if c['check']=='registryのTLS設定')
            row = verdicts.observation(dict(name='Docker Engine / Desktop / BuildKit / registry'),check,'Docker')
            self.assertEqual(row['status'], 'MANUAL')

    def test_user_confirmation_is_separate_from_automatic_observations(self):
        original = registry([INTERNAL])
        row = copy.deepcopy(original)
        row['metadata']['registry_user_confirmation'] = user_confirmation()
        result = self.assessed(row)
        self.assertEqual(result['status'], 'CHECKED')
        self.assertNotIn('docker_connection', result['metadata'])
        self.assertNotIn('insecure_registry_cidrs', result['metadata'])
        self.assertEqual(result['metadata']['registry_assessment']['basis'], 'user-confirmed-desktop-and-local-endpoint')
        self.assertIn('ユーザー提供', result['detail'])
        model = reporting.action_model([result])
        task = next(t for t in model['tools'][0]['work']['tasks'] if t['classification']=='unneeded')
        self.assertIn('ユーザー提供', task['fact'])
        prompt = ai_prompts.make(model, [result], 'synthetic', '2026-11-06')
        self.assertIn('ユーザー提供', prompt)
        self.assertIn('自動観測とは別', prompt)
        self.assertNotIn('同じEngineのDesktop情報とローカル接続を根拠に', prompt)
        self.assertEqual(verdicts.prepare([original])[0]['status'], 'MANUAL')

    def test_user_confirmation_does_not_hide_external_or_conflicting_evidence(self):
        cases = [
            (registry([INTERNAL, 'registry.example:5000']), user_confirmation([INTERNAL, 'registry.example:5000']), 'ACTION'),
            (registry([INTERNAL], dict(desktop(),server_os='Ubuntu')), user_confirmation(), 'ACTION'),
            (registry([INTERNAL], dict(desktop(),endpoint_type='remote-or-unknown')), user_confirmation(), 'MANUAL'),
            (registry([INTERNAL]), dict(user_confirmation(), facts={}), 'MANUAL'),
            (registry([INTERNAL]), user_confirmation(['another.example:5000']), 'MANUAL'),
        ]
        for row, confirmation, expected in cases:
            with self.subTest(row=row, confirmation=confirmation):
                row['metadata']['registry_user_confirmation'] = confirmation
                self.assertEqual(self.assessed(row)['status'], expected)
        row = registry([INTERNAL])
        confirmation = user_confirmation()
        confirmation['facts']['insecure_registry_cidrs'].append('10.0.0.0/8')
        row['metadata']['registry_user_confirmation'] = confirmation
        self.assertEqual(self.assessed(row)['status'], 'ACTION')
        row = registry([INTERNAL], desktop())
        confirmation = user_confirmation()
        confirmation['facts']['local_docker_desktop'] = False
        row['metadata']['registry_user_confirmation'] = confirmation
        result = self.assessed(row)
        self.assertEqual(result['status'], 'MANUAL')
        self.assertEqual(result['metadata']['registry_assessment']['user_confirmation_state'], 'conflict')

    def test_user_confirmation_cannot_override_other_records(self):
        row = registry([INTERNAL])
        row['metadata']['registry_user_confirmation'] = user_confirmation()
        for method, status in (('measured','ACTION'), ('configuration','ACTION'), ('version','UPDATE')):
            other = dict(name='Docker / 別の問題', status=status, assessment_method=method,
                         detail='別の問題', action='対応', samples=[], metadata=dict(tool_id='docker',version='1',reference_floor='2'))
            baseline = verdicts.prepare([other])[0]
            records = verdicts.prepare([row, other])
            self.assertEqual(next(r for r in records if r['name']==other['name']), baseline)
            self.assertNotEqual(reporting.action_model(records)['tools'][0]['primary_action'], 'complete')


if __name__ == '__main__': unittest.main()
