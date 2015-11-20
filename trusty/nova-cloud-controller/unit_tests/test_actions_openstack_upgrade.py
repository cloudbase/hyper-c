from mock import patch, MagicMock
import os

os.environ['JUJU_UNIT_NAME'] = 'nova-cloud-controller'


with patch('charmhelpers.core.hookenv.config') as config:
    config.return_value = 'nova'
    import nova_cc_utils as utils  # noqa

_reg = utils.register_configs
_map = utils.restart_map

utils.register_configs = MagicMock()
utils.restart_map = MagicMock()

with patch('nova_cc_utils.guard_map') as gmap:
    with patch('charmhelpers.core.hookenv.config') as config:
        config.return_value = False
        gmap.return_value = {}
        import openstack_upgrade

utils.register_configs = _reg
utils.restart_map = _map

from test_utils import (
    CharmTestCase
)

TO_PATCH = [
    'do_openstack_upgrade',
    'relation_ids',
    'neutron_api_relation_joined',
    'config_changed',
]


class TestNovaCCUpgradeActions(CharmTestCase):

    def setUp(self):
        super(TestNovaCCUpgradeActions, self).setUp(openstack_upgrade,
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
        self.relation_ids.return_value = ['relid1']

        openstack_upgrade.openstack_upgrade()

        self.assertTrue(self.do_openstack_upgrade.called)
        self.assertTrue(
            self.neutron_api_relation_joined.called_with(rid='relid1',
                                                         remote_restart=True))
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
