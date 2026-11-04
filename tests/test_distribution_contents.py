"""Every runtime and catalog needed by the shipped controller is included."""
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'packaging'))
import build_release


class DistributionContents(unittest.TestCase):
    def test_user_guide_links_to_the_shipped_os_cpu_execution_limits(self):
        for platform in build_release.PLATFORMS:
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as tmp:
                stage=Path(tmp)
                build_release.stage_files(ROOT,stage,platform)
                guide=(stage/'docs/使い方.html').read_text(encoding='utf-8')
                self.assertIn('href="VALIDATION-ja.md"',guide)
                self.assertEqual((stage/'docs/VALIDATION-ja.md').read_bytes(),
                                 (ROOT/'VALIDATION-ja.md').read_bytes())

    def test_runtime_modules_and_probes_are_staged(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp)
            build_release.stage_files(ROOT, stage, 'macos-arm64')
            for name in ('research_rules.py', 'references/official-research.json', 'version_inference.py', 'tool_catalog.py', 'app_inventory.py', 'package_checks.py', 'p2_coverage.py', 'p2_settings.py', 'safechain_probe.py', 'probes/safechain_preflight.py', 'probes/dotnet_http_probe.cs',
                         'probes/perl_probe.pl', 'probes/python_probe.py', 'probes/powershell_web_probe.ps1', 'probes/poetry_probe.py', 'probes/pipx_probe.py', 'probes/azure_entry.py',
                         'connection_evidence.py', 'probes/ruby_connection_observer.rb', 'presentation.py'):
                self.assertTrue((stage/'app'/name).is_file(), name)
            self.assertFalse((stage/'app/browser-check.html').exists())
            self.assertTrue((stage/'診断を開始.command').is_file())
            self.assertTrue((stage/'docs/P2-COVERAGE-ja.md').is_file())
            self.assertTrue((stage/'docs/ACTION-PRESENTATION-ja.md').is_file())
