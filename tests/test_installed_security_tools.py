"""Evidence belongs to each installed scanner or Safe Chain, not the host runtime."""
import json
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import app_inventory
import audit


def varint(value):
    result = []
    while value > 127:
        result.append((value & 127) | 128); value >>= 7
    return bytes(result + [value])


def go_binary(path, version, modules):
    info = b'\xff Go buildinf:\x08\x02' + b'\0'*16
    info += varint(len(version)) + version.encode()
    raw = b'\x00'*16 + modules.encode() + b'\x00'*16
    info += varint(len(raw)) + raw
    header = bytearray(128)
    header[:16] = b'\x7fELF\x02\x01\x01' + b'\0'*9
    struct.pack_into('<HHIQQQIHHHHHH', header, 16, 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', header, 64, 1, 6, 128, 4096, 4096, len(info), len(info), 16)
    path.write_bytes(bytes(header) + info); path.chmod(0o755)


class SecurityToolEvidence(unittest.TestCase):
    def test_safe_chain_capture_keeps_the_native_binary_digest_with_its_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'safe-chain'
            content=b'\xcf\xfa\xed\xfe'+b'0'*64+b'{"name":"@aikidosec/safe-chain","version":"1.5.27"}'
            binary.write_bytes(content); binary.chmod(0o755)
            with mock.patch.object(Path,'home',return_value=root):
                rows=app_inventory.scan(audit.reference,path_dirs=[root],install_dirs=[])
            row=next(r for r in rows if r['metadata'].get('tool_id')=='safe-chain' and r['metadata'].get('application'))
            self.assertEqual(row['metadata']['security_tool'].get('binary_sha256'),hashlib.sha256(content).hexdigest())
            self.assertEqual(row['metadata']['security_tool']['version'],'1.5.27')

    def test_osv_scanner_build_info_is_its_own_go_and_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'osv-scanner'
            go_binary(path, 'go1.27.2', 'path\tgithub.com/google/osv-scanner/v2/cmd/osv-scanner\n'
                      'mod\tgithub.com/google/osv-scanner/v2\tv2.3.4\th1:ignored\n'
                      'dep\tgolang.org/x/crypto\tv0.50.0\th1:ignored\n')
            rows = app_inventory.scan(audit.reference, path_dirs=[path.parent], install_dirs=[])
            row = next(r for r in rows if r['metadata'].get('tool_id') == 'osv-scanner' and r['metadata'].get('application'))
            self.assertEqual(row['review_state'], 'review')
            details = row['metadata']['security_tool']
            self.assertEqual(details['go_versions'], ['1.27.2'])
            self.assertEqual(details['version'], 'v2.3.4')
            self.assertIn({'module': 'golang.org/x/crypto', 'version': 'v0.50.0'}, details['tls_dependencies'])
            self.assertIn('通信', row['detail'])

    def test_osv_unknown_build_information_is_not_claimed_to_have_been_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'osv-scanner'
            path.write_bytes(b'not a Go binary'); path.chmod(0o755)
            rows = app_inventory.scan(audit.reference, path_dirs=[path.parent], install_dirs=[])
            row = next(r for r in rows if r['metadata'].get('tool_id') == 'osv-scanner' and r['metadata'].get('application'))
            self.assertEqual(row['metadata']['security_tool']['go_versions'], [])
            self.assertIn('取得できません', row['detail'])

    def test_osv_homebrew_version_is_separate_from_its_embedded_go(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'Cellar/osv-scanner/2.7.0/bin/osv-scanner'
            path.parent.mkdir(parents=True)
            go_binary(path, 'go1.27.2', 'mod\tgithub.com/google/osv-scanner/v2\t(devel)\t\n')
            rows = app_inventory.scan(audit.reference, path_dirs=[path.parent], install_dirs=[])
            row = next(r for r in rows if r['metadata'].get('tool_id') == 'osv-scanner' and r['metadata'].get('application'))
            info = row['metadata']['security_tool']
            self.assertEqual(info['version'], '2.7.0')
            self.assertEqual(info['go_versions'], ['1.27.2'])
            self.assertIn('Homebrew', info['version_source'])

    def test_safe_chain_native_version_is_read_without_starting_the_binary(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'safe-chain'; path.write_bytes(b'\xcf\xfa\xed\xfe' + b'0'*64 +
                b'{"name":"@aikidosec/safe-chain","version":"1.5.23"}'); path.chmod(0o755)
            rows = app_inventory.scan(audit.reference, path_dirs=[path.parent], install_dirs=[])
            row = next(r for r in rows if r['metadata'].get('tool_id') == 'safe-chain' and r['metadata'].get('application'))
            instance = audit.Audit(SimpleNamespace(project=None))
            instance.records = [row]
            try:
                with mock.patch.object(instance.host, 'call', return_value=(0, 'Current safe-chain version: 1.5.23', '')) as call:
                    instance.safe_chain_version()
                self.assertEqual(row['metadata']['security_tool']['version'], '1.5.23')
                self.assertEqual(row['metadata']['security_tool']['version_source'], '本体内のパッケージ情報')
                call.assert_not_called()
            finally:
                instance.tmp.cleanup()

    def test_safe_chain_conflicting_embedded_versions_are_not_guessed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'safe-chain'
            path.write_bytes(b'\xcf\xfa\xed\xfe' + b'{"name":"@aikidosec/safe-chain","version":"1.2.3"}' +
                             b'{"name":"@aikidosec/safe-chain","version":"1.5.23"}')
            path.chmod(0o755)
            row = next(r for r in app_inventory.scan(audit.reference, path_dirs=[path.parent], install_dirs=[])
                       if r['metadata'].get('tool_id') == 'safe-chain' and r['metadata'].get('application'))
            self.assertEqual(row['metadata']['security_tool']['version'], '')

    def test_safe_chain_node_wrapper_reports_its_resolved_runtime_version(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); package=root/'node_modules/@aikidosec/safe-chain'
            (package/'bin').mkdir(parents=True)
            (package/'package.json').write_text(json.dumps({'name':'@aikidosec/safe-chain','version':'1.2.3'}))
            script=package/'bin/aikido-pip.js'; script.write_text('#!/usr/bin/env node\n'); script.chmod(0o755)
            link=root/'aikido-pip'; link.symlink_to(script)
            row=next(r for r in app_inventory.scan(audit.reference,path_dirs=[root],install_dirs=[])
                     if r['metadata'].get('tool_id')=='safe-chain' and r['metadata'].get('application'))
            instance=audit.Audit(SimpleNamespace(project=None)); instance.records=[row]
            try:
                with mock.patch.object(instance.host,'find',return_value='/runtime/node'), \
                     mock.patch.object(instance.host,'call',return_value=(0,'v24.22.1','')) as called:
                    instance.safe_chain_version()
                info=row['metadata']['security_tool']
                self.assertEqual(info['runtime_version'],'24.22.1')
                self.assertEqual(called.call_args.args[0], ['/runtime/node','--version'])
            finally: instance.tmp.cleanup()

    def test_safe_chain_shell_initialization_is_read_not_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            binary = home/'.safe-chain/bin/safe-chain'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'\xcf\xfa\xed\xfe' + b'0'*64); binary.chmod(0o755)
            cert = home/'.safe-chain/certs/ca-cert.pem'
            cert.parent.mkdir()
            cert.write_text('local CA fixture')
            script = home/'.safe-chain/scripts/init-posix.sh'
            script.parent.mkdir()
            script.write_text('TOOLS="npm pip uv"\n')
            (home/'.zshrc').write_text('source "$HOME/.safe-chain/scripts/init-posix.sh"\n')
            with mock.patch.object(Path,'home',return_value=home):
                rows=app_inventory.scan(audit.reference,path_dirs=[binary.parent],install_dirs=[])
            row=next(r for r in rows if r['metadata'].get('tool_id')=='safe-chain' and r['metadata'].get('application'))
            info=row['metadata']['security_tool']
            self.assertIn('.zshrc', info['shell_sources'])
            self.assertTrue(info['local_proxy_ca_present'])
            self.assertEqual(row['review_state'], 'unverified')
            self.assertTrue({'npm','pip','uv'} <= set(info['configured_wrappers']))
            self.assertIn('未確認', info['limitation'])

    def test_safe_chain_reads_package_and_shell_links_without_running_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root/'node_modules/@aikidosec/safe-chain'
            (package/'bin').mkdir(parents=True)
            (package/'package.json').write_text(json.dumps({'name': '@aikidosec/safe-chain', 'version': '1.2.3'}))
            script = package/'bin/aikido-npm.js'
            script.write_text('#!/usr/bin/env node\nthrow new Error("must not run")\n'); script.chmod(0o755)
            bin_dir = root/'bin'; bin_dir.mkdir()
            (bin_dir/'aikido-npm').symlink_to(script)
            (root/'.zshrc').write_text("alias npm='aikido-npm'\n")
            with mock.patch.object(Path, 'home', return_value=root):
                rows = app_inventory.scan(audit.reference, path_dirs=[bin_dir], install_dirs=[])
            row = next(r for r in rows if r['metadata'].get('tool_id') == 'safe-chain' and r['metadata'].get('application'))
            info = row['metadata']['security_tool']
            self.assertEqual(info['version'], '1.2.3')
            self.assertIn('npm', info['wrappers'])
            self.assertEqual(info['runtime'], 'node (PATH)')
            self.assertIn('npm', info['shell_links'])
            self.assertEqual(row['review_state'], 'unverified')
            self.assertIn('外部通信', row['detail'])
            page = audit.render_report([row], 'fixture')
            from test_report_guidance import ReportGuidanceTests
            visible = ReportGuidanceTests().expanded_result_text(page)
            self.assertIn('1.2.3', visible)
            self.assertIn('node (PATH)', page)
            self.assertIn('外部通信は未確認', page)
