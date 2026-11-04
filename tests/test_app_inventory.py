"""Installed application coverage, using isolated packages and executable fixtures."""
import contextlib
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit
import app_inventory


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    return path


def go_executable(path, version):
    # ELF64 with a writable PT_LOAD containing Go's inline build-info format.
    header = bytearray(128)
    header[:16] = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    struct.pack_into('<HHIQQQIHHHHHH', header, 16, 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    payload = b'\xff Go buildinf:' + b'\x08\x02' + b'\0' * 16
    value = version.encode()
    payload += bytes([len(value)]) + value + b'\0'
    struct.pack_into('<IIQQQQQQ', header, 64, 1, 6, 128, 4096, 4096, len(payload), len(payload), 16)
    write(path, bytes(header) + payload)
    path.chmod(0o755)
    return path


def apps(records):
    return [r for r in records if r['metadata'].get('application')]


class InstalledApplications(unittest.TestCase):
    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL fixture generator unavailable')
    def test_unrelated_certificate_never_counts_as_remediation(self):
        from integration_local_tls import create_certificates
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ca, cert, _ = create_certificates(root)
            for label, fixture in [('Internal', cert), ('PublicBundle', ca)]:
                app = root/label
                write(app/'cert.pem', fixture.read_bytes())
                row = apps(self.scan(extra_paths=[app]))[0]
                self.assertEqual(row['status'], 'MANUAL')
                self.assertEqual(row['review_state'], 'unverified')
                self.assertFalse(any(c['status'] == 'STATIC_OK' for c in row['metadata']['inspections']))
                page = audit.render_report([row], 'fixture')
                self.assertNotIn('証明書データは対応済み', page)

    def scan(self, **kwargs):
        return app_inventory.scan(audit.reference, path_dirs=kwargs.pop('path_dirs', []),
                                  install_dirs=kwargs.pop('install_dirs', []), **kwargs)

    def test_each_path_binary_is_checked_without_requiring_installed_go(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = go_executable(root/'one/osv-scanner.exe', 'go1.27.2')
            fixed = go_executable(root/'two/osv-scanner.exe', 'go1.27.3')
            rows = apps(self.scan(path_dirs=[old.parent, fixed.parent]))
            by_path = {r['metadata']['path']: r for r in rows}
            self.assertEqual(by_path[str(old.resolve())]['status'], 'UPDATE')
            self.assertEqual(by_path[str(fixed.resolve())]['status'], 'MANUAL')
            self.assertEqual(by_path[str(fixed.resolve())]['metadata']['inspections'][0]['status'], 'INFERRED_OK')
            self.assertEqual(by_path[str(old.resolve())]['metadata']['inspections'][0]['version'], '1.27.2')
            self.assertFalse(any(r['samples'] for r in rows))
            self.assertIn('実通信', by_path[str(fixed.resolve())]['scope'])

    def test_non_go_packages_and_unknown_apps_are_distinguished(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root/'PythonTool/lib/python3.13/site-packages/certifi-2026.9.1.dist-info/METADATA',
                  'Name: certifi\nVersion: 2026.9.1\n')
            write(root/'Editor.app/Contents/Frameworks/Electron Framework.framework/Resources/Info.plist',
                  plistlib.dumps({'CFBundleIdentifier': 'com.github.Electron.framework',
                                  'CFBundleVersion': '44.9.1'}))
            write(root/'Unknown/tool.exe', b'MZ unknown proprietary app')
            rows = apps(self.scan(extra_paths=[root/'PythonTool', root/'Editor.app', root/'Unknown']))
            by_name = {Path(r['metadata']['path']).name: r for r in rows}
            self.assertEqual(by_name['PythonTool']['status'], 'UPDATE')
            self.assertEqual(by_name['Editor.app']['status'], 'MANUAL')
            self.assertEqual(by_name['Editor.app']['metadata']['inspections'][0]['status'], 'INFERRED_OK')
            self.assertEqual(by_name['Unknown']['metadata']['coverage_state'], 'uninspected')
            self.assertEqual(by_name['Unknown']['status'], 'MANUAL')

    def test_discovery_is_read_only_and_skips_env_aliases_and_symlink_loops(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root/'executed'
            payload = ('@echo off\r\ntype nul > "'+str(marker)+'"\r\n' if os.name == 'nt'
                       else '#!/bin/sh\ntouch "'+str(marker)+'"\n')
            script = write(root/'bin/wget', payload)
            script.chmod(0o755)
            payload_file = write(root/'private-fixture', 'MUST_NOT_APPEAR')
            payload_file.chmod(0o755)
            secret = root/'.env.secret'
            for link, target, directory in ((root/'bin/alias.cmd', secret, False),
                                             (secret, payload_file, False),
                                             (root/'bin/loop', root/'bin', True),
                                             (root/'bin/wget.exe', script, False)):
                try:
                    link.symlink_to(target, target_is_directory=directory)
                except (OSError, NotImplementedError) as exc:
                    self.skipTest('Symbolic link creation is unavailable: '+str(exc))
                # Wine may report success without creating a link at all.
                if not link.is_symlink():
                    self.skipTest('The test environment did not create the requested symbolic link')
            rows = self.scan(path_dirs=[root/'bin'])
            self.assertEqual(len(apps(rows)), 1)
            self.assertFalse(marker.exists())
            self.assertNotIn('MUST_NOT_APPEAR', json.dumps(rows))
            self.assertEqual(len(apps(rows)[0]['metadata']['discovered_paths']), 2)

    def test_exploration_limit_is_not_reported_as_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('wget', 'curl', 'git'):
                go_executable(root/name, 'go1.27.3')
            rows = self.scan(path_dirs=[root], max_candidates=1)
            scope = next(r for r in rows if r['metadata'].get('application_scan'))
            self.assertEqual(scope['status'], 'UNKNOWN')
            self.assertTrue(scope['metadata']['incomplete'])
            self.assertEqual(len(apps(rows)), 1)

    def test_java_dotnet_and_rust_metadata_remain_scoped_to_the_app(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root/'Suite/jre/release', 'JAVA_VERSION="25.0.1"\nIMPLEMENTOR="Example"\n')
            write(root/'Suite/client.runtimeconfig.json', json.dumps({'runtimeOptions': {
                'includedFrameworks': [{'name': 'Microsoft.NETCore.App', 'version': '9.0.1'}]}}))
            write(root/'Suite/sbom.cdx.json', json.dumps({'bomFormat': 'CycloneDX', 'components': [
                {'purl': 'pkg:cargo/rustls-webpki@0.103.15'}, {'purl': 'pkg:cargo/webpki-roots@1.0.10'}]}))
            row = apps(self.scan(extra_paths=[root/'Suite']))[0]
            self.assertEqual(row['status'], 'UPDATE')
            self.assertEqual(row['metadata']['coverage_state'], 'partial')
            components = [c['component'] for c in row['metadata']['inspections']]
            self.assertIn('Java 25.0.1', components)
            java = next(c for c in row['metadata']['inspections'] if c['component'].startswith('Java '))
            self.assertEqual(java['version'], '25.0.1')
            self.assertEqual(java['vendor'], 'Example')
            self.assertIn('.NET 9.0.1', components)
            self.assertIn('rustls-webpki', components)
            self.assertIn('SBOM', ' '.join(row['metadata']['uninspected']))

    def test_version_strings_and_invalid_ca_files_do_not_create_positive_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = write(root/'Unknown/tool.exe', b'MZ unrelated go1.27.3')
            binary.chmod(0o755)
            write(root/'Unknown/cacert.pem', '-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n')
            row = apps(self.scan(extra_paths=[root/'Unknown']))[0]
            self.assertEqual(row['metadata']['coverage_state'], 'uninspected')
            self.assertEqual(row['status'], 'MANUAL')

    def test_cli_and_all_reports_show_checked_and_uninspected_applications(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            go_executable(root/'bin/osv-scanner.exe', 'go1.27.2')
            unknown = write(root/'bin/opaque.cmd', '@echo off\r\nexit /b 0\r\n')
            unknown.chmod(0o755)
            with mock.patch.object(app_inventory, 'default_locations', return_value=([root/'bin'], [])), \
                 mock.patch.object(app_inventory, 'managed_locations', return_value=([], [])), \
                 mock.patch.object(app_inventory, 'managed_metadata', return_value=([], [])), \
                 mock.patch.object(audit.Audit, 'config_inventory'), \
                 contextlib.redirect_stdout(io.StringIO()):
                code = audit.main(['--offline', '--only', 'apps', '--app', str(unknown), '--out', str(root/'report')])
            self.assertEqual(code, 2)
            data = json.loads((root/'report/report.json').read_text(encoding='utf-8'))
            self.assertEqual(data['summary']['application_counts']['static_checked'], 1)
            self.assertEqual(data['summary']['application_counts']['uninspected'], 1)
            for name in ('report.html', 'summary.txt'):
                text = (root/'report'/name).read_text(encoding='utf-8')
                self.assertIn('同梱Go', text)
                self.assertIn('実通信は未検査', text)
                self.assertIn('1.27.2', text)
            page = (root/'report/report.html').read_text(encoding='utf-8')
            self.assertIn('data-tool="OSV-Scanner"', page)
            self.assertIn('data-tool="opaque"', page)
            self.assertIn('data-result-group="investigate"', page)
            self.assertIn('data-result-group="not_found"', page)

    def test_app_is_in_default_scope_and_extra_paths_require_apps_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            seen = []
            def execute(instance):
                seen.append(instance.args.only.split(','))
            with mock.patch.object(audit.Audit, 'execute', execute), contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--offline', '--out', tmp])
            self.assertIn('apps', seen[0])
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                audit.main(['--only', 'go', '--app', tmp])

    def test_large_installed_tree_does_not_starve_path_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for i in range(20):
                write(root/'apps/Large'/str(i)/'ignored.txt', 'data')
            go_executable(root/'bin/osv-scanner.exe', 'go1.27.2')
            rows = apps(self.scan(path_dirs=[root/'bin'], install_dirs=[root/'apps'], extra_paths=[root/'apps/Large'], max_app_entries=5))
            scanner = next(r for r in rows if Path(r['metadata']['path']).name=='osv-scanner.exe')
            self.assertEqual(scanner['status'], 'UPDATE')
            large = next(r for r in rows if Path(r['metadata']['path']).name=='Large')
            self.assertIn('上限', ' '.join(large['metadata']['uninspected']))

    def test_read_budget_exhaustion_is_visible_in_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            go_executable(root/'osv-scanner.exe', 'go1.27.3')
            rows = self.scan(path_dirs=[root], max_bytes=32)
            self.assertEqual(rows[0]['status'], 'UNKNOWN')
            self.assertEqual(apps(rows)[0]['status'], 'MANUAL')

    def test_unknown_explicit_app_requires_review_but_unknown_path_tool_is_uninspected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=write(Path(tmp)/'opaque.cmd', '@echo off\r\nexit /b 0\r\n')
            path.chmod(0o755)
            found=apps(self.scan(path_dirs=[path.parent]))
            self.assertEqual(found,[])
            requested=apps(self.scan(extra_paths=[path]))[0]
            self.assertEqual(requested['review_state'],'unverified')

    def test_macho_named_buildinfo_section_in_readonly_segment(self):
        with tempfile.TemporaryDirectory() as tmp:
            # The scanner reads foreign formats too; .exe makes this a PATH candidate on Windows.
            path = Path(tmp)/'mac-tool.exe'
            data = bytearray(512)
            struct.pack_into('<IIIIIIII',data,0,0xfeedfacf,0x1000007,3,2,1,152,0,0)
            struct.pack_into('<II16sQQQQIIII',data,32,0x19,152,b'__DATA_CONST',4096,256,256,256,3,1,1,0)
            struct.pack_into('<16s16sQQIIIIIIII',data,104,b'__go_buildinfo',b'__DATA_CONST',4096,48,256,4,0,0,0,0,0,0)
            blob=b'\xff Go buildinf:\x08\x02'+b'\0'*16+b'\x08go1.25.4\0'
            data[256:256+len(blob)]=blob
            write(path,bytes(data)); path.chmod(0o755)
            row=apps(self.scan(extra_paths=[path]))[0]
            self.assertEqual(row['status'],'UPDATE')
            self.assertEqual(row['metadata']['inspections'][0]['version'],'1.25.4')

    def test_windows_pe_buildinfo_is_read_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'windows-tool.exe'
            data=bytearray(512); data[:2]=b'MZ'
            struct.pack_into('<I',data,60,64); data[64:68]=b'PE\0\0'
            struct.pack_into('<H',data,70,1)
            struct.pack_into('<II',data,104,128,256)
            struct.pack_into('<I',data,124,0xc0000040)
            blob=b'\xff Go buildinf:\x08\x02'+b'\0'*16+b'\x08go1.27.2\0'
            data[256:256+len(blob)]=blob
            write(path,bytes(data)); path.chmod(0o755)
            row=apps(self.scan(extra_paths=[path]))[0]
            self.assertEqual(row['status'],'UPDATE')

    def test_older_electron_is_update_candidate_but_unknown_future_branch_is_not_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name,version in [('Old.app','41.0.0'),('Future.app','46.0.0')]:
                write(root/name/'Contents/Frameworks/Electron Framework.framework/Resources/Info.plist',
                      plistlib.dumps({'CFBundleIdentifier':'com.github.Electron.framework',
                                      'CFBundleShortVersionString':version}))
            rows={Path(r['metadata']['path']).name:r for r in apps(self.scan(extra_paths=[root/'Old.app', root/'Future.app']))}
            self.assertEqual(rows['Old.app']['status'],'UPDATE')
            self.assertEqual(rows['Old.app']['review_state'],'review')
            self.assertEqual(rows['Future.app']['status'],'MANUAL')

    def test_library_documentation_is_not_detected_as_an_embedded_tls_library(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            write(root/'Docs/libcurl.3','manual page')
            write(root/'Docs/libcrypto.pc','package config')
            row=apps(self.scan(extra_paths=[root/'Docs']))[0]
            self.assertEqual(row['metadata']['inspections'],[])
            self.assertEqual(row['status'],'MANUAL')


if __name__ == '__main__':
    unittest.main()
