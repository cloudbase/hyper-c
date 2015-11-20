from mock import patch
import os

os.environ['JUJU_UNIT_NAME'] = 'nova_compute'

with patch('charmhelpers.core.hookenv.config') as config:
    config.return_value = 'nova'
    import nova_compute_utils as utils  # noqa

with patch('nova_compute_utils.restart_map'):
    with patch('nova_compute_utils.register_configs'):
        import openstack_upgrade

from test_utils import (
    CharmTestCase
)

TO_PATCH = [
    'config_changed',
    'do_openstack_upgrade'
]


class TestNovaComputeUpgradeActions(CharmTestCase):

    def setUp(self):
        super(TestNovaComputeUpgradeActions, self).setUp(openstack_upgrade,
                                                         TO_PATCH)

    @patch('charmhelpers.contrib.openstack.utils.config')
    @patch('charmhelpers.contrib.openstack.utils.action_set')
    @patch('charmhelpers.contrib.openstack.utils.git_install_requested')
    @patch('charmhelpers.contrib.openstack.utils.openstack_upgrade_available')
    @patch('charmhelpers.contrib.openstack.utils.juju_log')
    def test_openstack_upgrade_true(self, log, upgrade_avail, git_requested,
                                    action_set, config):

        git_requested.return_value = False
        upgrade_avail.return_value = True
        config.return_value = True

        openstack_upgrade.openstack_upgrade()

        self.assertTrue(self.do_openstack_upgrade.called)
        self.assertTrue(self.config_changed.called)

    @patch('charmhelpers.contrib.openstack.utils.config')
    @patch('charmhelpers.contrib.openstack.utils.action_set')
    @patch('charmhelpers.contrib.openstack.utils.git_install_requested')  # noqa
    @patch('charmhelpers.contrib.openstack.utils.openstack_upgrade_available')  # noqa
    @patch('charmhelpers.contrib.openstack.utils.juju_log')
    def test_openstack_upgrade_false(self,  log, upgrade_avail, git_requested,
                                     action_set, config):

        git_requested.return_value = False
        upgrade_avail.return_value = True
        config.return_value = False

        openstack_upgrade.openstack_upgrade()

        self.assertFalse(self.do_openstack_upgrade.called)
        self.assertFalse(self.config_changed.called)
