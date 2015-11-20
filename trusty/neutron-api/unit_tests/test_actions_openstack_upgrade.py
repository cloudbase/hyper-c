from mock import patch
import os

os.environ['JUJU_UNIT_NAME'] = 'neutron-api'

with patch('charmhelpers.core.hookenv.config') as config:
    config.return_value = 'ovs'
    with patch('neutron_api_utils.register_configs') as register_configs:
        import openstack_upgrade

from test_utils import (
    CharmTestCase
)

TO_PATCH = [
    'do_openstack_upgrade',
    'config_changed',
]


class TestNeutronAPIUpgradeActions(CharmTestCase):

    def setUp(self):
        super(TestNeutronAPIUpgradeActions, self).setUp(openstack_upgrade,
                                                        TO_PATCH)

    @patch('charmhelpers.contrib.openstack.utils.juju_log')
    @patch('charmhelpers.contrib.openstack.utils.config')
    @patch('charmhelpers.contrib.openstack.utils.action_set')
    @patch('charmhelpers.contrib.openstack.utils.git_install_requested')
    @patch('charmhelpers.contrib.openstack.utils.openstack_upgrade_available')
    def test_openstack_upgrade_true(self, upgrade_avail, git_requested,
                                    action_set, config, log):
        git_requested.return_value = False
        upgrade_avail.return_value = True
        config.return_value = True

        openstack_upgrade.openstack_upgrade()

        self.assertTrue(self.do_openstack_upgrade.called)
        self.assertTrue(self.config_changed.called)

    @patch('charmhelpers.contrib.openstack.utils.juju_log')
    @patch('charmhelpers.contrib.openstack.utils.config')
    @patch('charmhelpers.contrib.openstack.utils.action_set')
    @patch('charmhelpers.contrib.openstack.utils.git_install_requested')
    @patch('charmhelpers.contrib.openstack.utils.openstack_upgrade_available')
    def test_openstack_upgrade_false(self, upgrade_avail, git_requested,
                                     action_set, config, log):
        git_requested.return_value = False
        upgrade_avail.return_value = True
        config.return_value = False

        openstack_upgrade.openstack_upgrade()

        self.assertFalse(self.do_openstack_upgrade.called)
        self.assertFalse(self.config_changed.called)
