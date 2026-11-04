import unittest
from unittest import mock
import fixture_safety


class FixtureSafety(unittest.TestCase):
    def test_safe_chain_shell_integration_disables_direct_manager_fixture_probes(self):
        row={'metadata':{'tool_id':'safe-chain','path':'/fixture/safe-chain',
                         'security_tool':{'shell_sources':['shell'],'configured_wrappers':['uv']}}}
        with mock.patch.object(fixture_safety.audit.app_inventory,'scan',return_value=[row]):
            self.assertTrue(fixture_safety.safe_chain_active())
        with mock.patch.object(fixture_safety.audit.app_inventory,'scan',return_value=[]):
            self.assertFalse(fixture_safety.safe_chain_active())

    def test_failed_discovery_is_conservatively_protected(self):
        with mock.patch.object(fixture_safety.audit.app_inventory,'scan',side_effect=OSError):
            self.assertTrue(fixture_safety.safe_chain_active())
