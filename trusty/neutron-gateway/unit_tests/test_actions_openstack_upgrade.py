from mock import patch
import os

from test_utils import (
    CharmTestCase
)

os.environ['JUJU_UNIT_NAME'] = 'neutron-gateway'

with patch('charmhelpers.core.hookenv.status_set'):
    with patch('neutron_utils.register_configs') as register_configs:
        import openstack_upgrade

TO_PATCH = [
    'do_openstack_upgrade',
    'config_changed',
]


class TestNeutronGWUpgradeActions(CharmTestCase):

    def setUp(self):
        super(TestNeutronGWUpgradeActions, self).setUp(openstack_upgrade,
                                                       TO_PATCH)

    @patch('charmhelpers.contrib.openstack.utils.config')
    @patch('charmhelpers.contrib.openstack.utils.action_set')
    @patch('charmhelpers.contrib.openstack.utils.git_install_requested')
    @patch('charmhelpers.contrib.openstack.utils.openstack_upgrade_available')
    def test_openstack_upgrade_true(self, upgrade_avail, git_requested,
                                    action_set, config):
        git_requested.return_value = False
        upgrade_avail.return_value = True
        config.return_value = True

        openstack_upgrade.openstack_upgrade()

        self.assertTrue(self.do_openstack_upgrade.called)
        self.assertTrue(self.config_changed.called)

    @patch('charmhelpers.contrib.openstack.utils.config')
    @patch('charmhelpers.contrib.openstack.utils.action_set')
    @patch('charmhelpers.contrib.openstack.utils.git_install_requested')
    @patch('charmhelpers.contrib.openstack.utils.openstack_upgrade_available')
    def test_openstack_upgrade_false(self, upgrade_avail, git_requested,
                                     action_set, config):
        git_requested.return_value = False
        upgrade_avail.return_value = True
        config.return_value = False

        openstack_upgrade.openstack_upgrade()

        self.assertFalse(self.do_openstack_upgrade.called)
        self.assertFalse(self.config_changed.called)
