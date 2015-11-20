from mock import MagicMock, patch
import yaml

from test_utils import CharmTestCase

with patch('charmhelpers.core.hookenv.config') as config:
    config.return_value = 'neutron'
    import neutron_ovs_utils as utils

_reg = utils.register_configs
_map = utils.restart_map

utils.register_configs = MagicMock()
utils.restart_map = MagicMock()

import neutron_ovs_hooks as hooks

utils.register_configs = _reg
utils.restart_map = _map

TO_PATCH = [
    'config',
    'CONFIGS',
    'get_shared_secret',
    'git_install',
    'log',
    'relation_ids',
    'relation_set',
    'configure_ovs',
    'use_dvr',
    'install_packages',
    'purge_packages',
    'enable_nova_metadata',
    'enable_local_dhcp',
]
NEUTRON_CONF_DIR = "/etc/neutron"

NEUTRON_CONF = '%s/neutron.conf' % NEUTRON_CONF_DIR


class NeutronOVSHooksTests(CharmTestCase):

    def setUp(self):
        super(NeutronOVSHooksTests, self).setUp(hooks, TO_PATCH)

        self.config.side_effect = self.test_config.get
        hooks.hooks._config_save = False

    def _call_hook(self, hookname):
        hooks.hooks.execute([
            'hooks/{}'.format(hookname)])

    @patch.object(hooks, 'git_install_requested')
    def test_install_hook(self, git_requested):
        git_requested.return_value = False
        self._call_hook('install')
        self.install_packages.assert_called_with()

    @patch.object(hooks, 'git_install_requested')
    def test_install_hook_git(self, git_requested):
        git_requested.return_value = True
        openstack_origin_git = {
            'repositories': [
                {'name': 'requirements',
                 'repository': 'git://git.openstack.org/openstack/requirements',  # noqa
                 'branch': 'stable/juno'},
                {'name': 'neutron',
                 'repository': 'git://git.openstack.org/openstack/neutron',
                 'branch': 'stable/juno'}
            ],
            'directory': '/mnt/openstack-git',
        }
        projects_yaml = yaml.dump(openstack_origin_git)
        self.test_config.set('openstack-origin-git', projects_yaml)
        self._call_hook('install')
        self.install_packages.assert_called_with()
        self.git_install.assert_called_with(projects_yaml)

    @patch.object(hooks, 'git_install_requested')
    def test_config_changed(self, git_requested):
        git_requested.return_value = False
        self.relation_ids.return_value = ['relid']
        _zmq_joined = self.patch('zeromq_configuration_relation_joined')
        self._call_hook('config-changed')
        self.assertTrue(self.CONFIGS.write_all.called)
        self.assertTrue(_zmq_joined.called_with('relid'))
        self.configure_ovs.assert_called_with()

    @patch.object(hooks, 'git_install_requested')
    @patch.object(hooks, 'config_value_changed')
    def test_config_changed_git(self, config_val_changed, git_requested):
        git_requested.return_value = True
        self.relation_ids.return_value = ['relid']
        _zmq_joined = self.patch('zeromq_configuration_relation_joined')
        openstack_origin_git = {
            'repositories': [
                {'name': 'requirements',
                 'repository':
                 'git://git.openstack.org/openstack/requirements',
                 'branch': 'stable/juno'},
                {'name': 'neutron',
                 'repository': 'git://git.openstack.org/openstack/neutron',
                 'branch': 'stable/juno'}
            ],
            'directory': '/mnt/openstack-git',
        }
        projects_yaml = yaml.dump(openstack_origin_git)
        self.test_config.set('openstack-origin-git', projects_yaml)
        self._call_hook('config-changed')
        self.git_install.assert_called_with(projects_yaml)
        self.assertTrue(self.CONFIGS.write_all.called)
        self.assertTrue(_zmq_joined.called_with('relid'))
        self.configure_ovs.assert_called_with()

    @patch.object(hooks, 'git_install_requested')
    def test_config_changed_dvr(self, git_requested):
        git_requested.return_value = False
        self._call_hook('config-changed')
        self.install_packages.assert_called_with()
        self.assertTrue(self.CONFIGS.write_all.called)
        self.configure_ovs.assert_called_with()

    @patch.object(hooks, 'neutron_plugin_joined')
    def test_neutron_plugin_api(self, _plugin_joined):
        self.relation_ids.return_value = ['rid']
        self._call_hook('neutron-plugin-api-relation-changed')
        self.configure_ovs.assert_called_with()
        self.assertTrue(self.CONFIGS.write_all.called)
        _plugin_joined.assert_called_with(relation_id='rid')
        self.install_packages.assert_called_with()

    @patch.object(hooks, 'neutron_plugin_joined')
    def test_neutron_plugin_api_nodvr(self, _plugin_joined):
        self.use_dvr.return_value = False
        self.relation_ids.return_value = ['rid']
        self._call_hook('neutron-plugin-api-relation-changed')
        self.configure_ovs.assert_called_with()
        self.assertTrue(self.CONFIGS.write_all.called)
        _plugin_joined.assert_called_with(relation_id='rid')
        self.purge_packages.assert_called_with(['neutron-l3-agent'])

    @patch.object(hooks, 'git_install_requested')
    def test_neutron_plugin_joined(self, git_requested):
        self.enable_nova_metadata.return_value = True
        self.enable_local_dhcp.return_value = True
        git_requested.return_value = False
        self.get_shared_secret.return_value = 'secret'
        self._call_hook('neutron-plugin-relation-joined')
        rel_data = {
            'metadata-shared-secret': 'secret',
        }
        self.relation_set.assert_called_with(
            relation_id=None,
            **rel_data
        )

    def test_amqp_joined(self):
        self._call_hook('amqp-relation-joined')
        self.relation_set.assert_called_with(
            username='neutron',
            vhost='openstack',
            relation_id=None
        )

    def test_amqp_changed(self):
        self.CONFIGS.complete_contexts.return_value = ['amqp']
        self._call_hook('amqp-relation-changed')
        self.assertTrue(self.CONFIGS.write.called_with(NEUTRON_CONF))

    def test_amqp_departed(self):
        self._call_hook('amqp-relation-departed')
        self.assertTrue(self.CONFIGS.write.called_with(NEUTRON_CONF))
