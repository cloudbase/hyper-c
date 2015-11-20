from mock import MagicMock, patch, call
import yaml
import charmhelpers.core.hookenv as hookenv
hookenv.config = MagicMock()
import neutron_utils as utils
_register_configs = utils.register_configs
_restart_map = utils.restart_map
utils.register_configs = MagicMock()
utils.restart_map = MagicMock()

with patch('charmhelpers.core.hookenv.status_set'):
    import neutron_hooks as hooks

utils.register_configs = _register_configs
utils.restart_map = _restart_map

from test_utils import CharmTestCase


TO_PATCH = [
    'config',
    'configure_installation_source',
    'valid_plugin',
    'apt_update',
    'apt_install',
    'apt_purge',
    'filter_installed_packages',
    'get_early_packages',
    'get_packages',
    'git_install',
    'log',
    'do_openstack_upgrade',
    'openstack_upgrade_available',
    'CONFIGS',
    'configure_ovs',
    'relation_set',
    'relation_ids',
    'unit_get',
    'relation_get',
    'install_ca_cert',
    'get_common_package',
    'execd_preinstall',
    'lsb_release',
    'stop_services',
    'b64decode',
    'is_relation_made',
    'create_sysctl',
    'update_nrpe_config',
    'update_legacy_ha_files',
    'install_legacy_ha_files',
    'cache_env_data',
    'get_hacluster_config',
    'remove_legacy_ha_files',
    'cleanup_ovs_netns',
    'stop_neutron_ha_monitor_daemon',
    'use_l3ha',
]


def passthrough(value):
    return value


class TestQuantumHooks(CharmTestCase):

    def setUp(self):
        super(TestQuantumHooks, self).setUp(hooks, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.test_config.set('openstack-origin', 'cloud:precise-havana')
        self.test_config.set('plugin', 'ovs')
        self.lsb_release.return_value = {'DISTRIB_CODENAME': 'precise'}
        self.b64decode.side_effect = passthrough
        hookenv.config.side_effect = self.test_config.get
        hooks.hooks._config_save = False

    def _call_hook(self, hookname):
        hooks.hooks.execute([
            'hooks/{}'.format(hookname)])

    def test_install_hook(self):
        self.valid_plugin.return_value = True
        _pkgs = ['foo', 'bar']
        self.filter_installed_packages.return_value = _pkgs
        self._call_hook('install')
        self.configure_installation_source.assert_called_with(
            'cloud:precise-havana'
        )
        self.apt_update.assert_called_with(fatal=True)
        self.apt_install.assert_has_calls([
            call(_pkgs, fatal=True),
            call(_pkgs, fatal=True),
        ])
        self.assertTrue(self.get_early_packages.called)
        self.assertTrue(self.get_packages.called)
        self.assertTrue(self.execd_preinstall.called)

    def test_install_hook_precise_nocloudarchive(self):
        self.test_config.set('openstack-origin', 'distro')
        self._call_hook('install')
        self.configure_installation_source.assert_called_with(
            'cloud:precise-folsom'
        )

    @patch('sys.exit')
    def test_install_hook_invalid_plugin(self, _exit):
        self.valid_plugin.return_value = False
        self._call_hook('install')
        self.assertTrue(self.log.called)
        _exit.assert_called_with(1)

    @patch.object(utils, 'git_install_requested')
    def test_install_hook_git(self, git_requested):
        git_requested.return_value = True
        self.valid_plugin.return_value = True
        _pkgs = ['foo', 'bar']
        self.filter_installed_packages.return_value = _pkgs
        repo = 'cloud:trusty-juno'
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
        self.test_config.set('openstack-origin', repo)
        self.test_config.set('openstack-origin-git', projects_yaml)
        self._call_hook('install')
        self.configure_installation_source.assert_called_with(
            'cloud:trusty-juno'
        )
        self.apt_update.assert_called_with(fatal=True)
        self.apt_install.assert_has_calls([
            call(_pkgs, fatal=True),
            call(_pkgs, fatal=True),
        ])
        self.assertTrue(self.get_early_packages.called)
        self.assertTrue(self.get_packages.called)
        self.git_install.assert_called_with(projects_yaml)
        self.assertTrue(self.execd_preinstall.called)

    @patch.object(hooks, 'git_install_requested')
    def test_config_changed(self, git_requested):
        def mock_relids(rel):
            return ['relid']
        git_requested.return_value = False
        self.test_config.set('sysctl', '{ kernel.max_pid: "1337"}')
        self.openstack_upgrade_available.return_value = True
        self.valid_plugin.return_value = True
        self.relation_ids.side_effect = mock_relids
        _db_joined = self.patch('db_joined')
        _pgsql_db_joined = self.patch('pgsql_db_joined')
        _amqp_joined = self.patch('amqp_joined')
        _amqp_nova_joined = self.patch('amqp_nova_joined')
        _zmq_joined = self.patch('zeromq_configuration_relation_joined')
        self._call_hook('config-changed')
        self.assertTrue(self.do_openstack_upgrade.called)
        self.assertTrue(self.configure_ovs.called)
        self.assertTrue(_db_joined.called)
        self.assertTrue(_pgsql_db_joined.called)
        self.assertTrue(_amqp_joined.called)
        self.assertTrue(_amqp_nova_joined.called)
        self.assertTrue(_zmq_joined.called)
        self.assertTrue(self.create_sysctl.called)

    @patch.object(hooks, 'git_install_requested')
    def test_config_changed_upgrade(self, git_requested):
        git_requested.return_value = False
        self.openstack_upgrade_available.return_value = True
        self.valid_plugin.return_value = True
        self._call_hook('config-changed')
        self.assertTrue(self.do_openstack_upgrade.called)
        self.assertTrue(self.configure_ovs.called)

    @patch.object(hooks, 'git_install_requested')
    def test_config_changed_n1kv(self, git_requested):
        git_requested.return_value = False
        self.openstack_upgrade_available.return_value = False
        self.valid_plugin.return_value = True
        self.filter_installed_packages.side_effect = lambda p: p
        self.test_config.set('plugin', 'n1kv')
        self._call_hook('config-changed')
        self.apt_install.assert_called_with('neutron-l3-agent')
        self.test_config.set('enable-l3-agent', False)
        self._call_hook('config-changed')
        self.apt_purge.assert_called_with('neutron-l3-agent')

    @patch('sys.exit')
    @patch.object(hooks, 'git_install_requested')
    def test_config_changed_invalid_plugin(self, git_requested, _exit):
        git_requested.return_value = False
        self.valid_plugin.return_value = False
        self._call_hook('config-changed')
        self.assertTrue(self.log.called)
        _exit.assert_called_with(1)

    @patch.object(hooks, 'git_install_requested')
    @patch.object(hooks, 'config_value_changed')
    def test_config_changed_git(self, config_val_changed, git_requested):
        def mock_relids(rel):
            return ['relid']
        git_requested.return_value = True
        self.test_config.set('sysctl', '{ kernel.max_pid: "1337"}')
        self.openstack_upgrade_available.return_value = True
        self.valid_plugin.return_value = True
        self.relation_ids.side_effect = mock_relids
        _db_joined = self.patch('db_joined')
        _pgsql_db_joined = self.patch('pgsql_db_joined')
        _amqp_joined = self.patch('amqp_joined')
        _amqp_nova_joined = self.patch('amqp_nova_joined')
        _zmq_joined = self.patch('zeromq_configuration_relation_joined')
        repo = 'cloud:trusty-juno'
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
        self.test_config.set('openstack-origin', repo)
        self.test_config.set('openstack-origin-git', projects_yaml)
        self._call_hook('config-changed')
        self.git_install.assert_called_with(projects_yaml)
        self.assertFalse(self.do_openstack_upgrade.called)
        self.assertTrue(self.configure_ovs.called)
        self.assertTrue(_db_joined.called)
        self.assertTrue(_pgsql_db_joined.called)
        self.assertTrue(_amqp_joined.called)
        self.assertTrue(_amqp_nova_joined.called)
        self.assertTrue(_zmq_joined.called)
        self.assertTrue(self.create_sysctl.called)

    def test_upgrade_charm(self):
        _install = self.patch('install')
        _config_changed = self.patch('config_changed')
        self._call_hook('upgrade-charm')
        self.assertTrue(_install.called)
        self.assertTrue(_config_changed.called)

    def test_db_joined(self):
        self.is_relation_made.return_value = False
        self.unit_get.return_value = 'myhostname'
        self._call_hook('shared-db-relation-joined')
        self.relation_set.assert_called_with(
            username='nova',
            database='nova',
            hostname='myhostname',
            relation_id=None
        )

    def test_db_joined_with_postgresql(self):
        self.is_relation_made.return_value = True

        with self.assertRaises(Exception) as context:
            hooks.db_joined()
        self.assertEqual(context.exception.message,
                         'Attempting to associate a mysql database when there '
                         'is already associated a postgresql one')

    def test_postgresql_db_joined(self):
        self.unit_get.return_value = 'myhostname'
        self.is_relation_made.return_value = False
        self._call_hook('pgsql-db-relation-joined')
        self.relation_set.assert_called_with(
            database='nova',
            relation_id=None
        )

    def test_postgresql_joined_with_db(self):
        self.is_relation_made.return_value = True

        with self.assertRaises(Exception) as context:
            hooks.pgsql_db_joined()
        self.assertEqual(context.exception.message,
                         'Attempting to associate a postgresql database when'
                         ' there is already associated a mysql one')

    def test_amqp_joined(self):
        self._call_hook('amqp-relation-joined')
        self.relation_set.assert_called_with(
            username='neutron',
            vhost='openstack',
            relation_id=None
        )

    def test_amqp_changed(self):
        self._call_hook('amqp-relation-changed')
        self.assertTrue(self.CONFIGS.write_all.called)

    def test_amqp_departed_no_rel(self):
        self.CONFIGS.complete_contexts.return_value = []
        self._call_hook('amqp-relation-departed')
        self.assertFalse(self.CONFIGS.write_all.called)

    def test_amqp_departed(self):
        self.CONFIGS.complete_contexts.return_value = ['amqp']
        self._call_hook('amqp-relation-departed')
        self.assertTrue(self.CONFIGS.write_all.called)

    def test_amqp_nova_joined(self):
        self._call_hook('amqp-nova-relation-joined')
        self.relation_set.assert_called_with(
            username='nova',
            vhost='openstack',
            relation_id=None
        )

    def test_amqp_nova_changed_no_rel(self):
        self.CONFIGS.complete_contexts.return_value = []
        self._call_hook('amqp-nova-relation-changed')
        self.assertFalse(self.CONFIGS.write_all.called)

    def test_amqp_nova_changed(self):
        self.CONFIGS.complete_contexts.return_value = ['amqp-nova']
        self._call_hook('amqp-nova-relation-changed')
        self.assertTrue(self.CONFIGS.write_all.called)

    def test_shared_db_changed(self):
        self._call_hook('shared-db-relation-changed')
        self.assertTrue(self.CONFIGS.write_all.called)

    def test_pgsql_db_changed(self):
        self._call_hook('pgsql-db-relation-changed')
        self.assertTrue(self.CONFIGS.write_all.called)

    def test_nm_changed(self):
        self.relation_get.return_value = "cert"
        self._call_hook('quantum-network-service-relation-changed')
        self.assertTrue(self.CONFIGS.write_all.called)
        self.install_ca_cert.assert_called_with('cert')

    def test_neutron_plugin_changed(self):
        self.use_l3ha.return_value = True
        self._call_hook('neutron-plugin-api-relation-changed')
        self.apt_install.assert_called_with(['keepalived', 'conntrack'],
                                            fatal=True)
        self.assertTrue(self.CONFIGS.write_all.called)

    def test_cluster_departed_nvp(self):
        self.test_config.set('plugin', 'nvp')
        self._call_hook('cluster-relation-departed')
        self.assertTrue(self.log.called)

    def test_stop(self):
        self._call_hook('stop')
        self.assertTrue(self.stop_services.called)

    def test_ha_relation_joined(self):
        self.test_config.set('ha-legacy-mode', True)
        self._call_hook('ha_relation_joined')
        self.assertTrue(self.cache_env_data.called)
        self.assertTrue(self.get_hacluster_config.called)
        self.assertTrue(self.install_legacy_ha_files.called)

    def test_ha_relation_departed(self):
        self.test_config.set('ha-legacy-mode', True)
        self._call_hook('ha-relation-departed')
        self.assertTrue(self.remove_legacy_ha_files.called)
        self.assertTrue(self.stop_neutron_ha_monitor_daemon.called)

    def test_quantum_network_service_relation_changed(self):
        self.test_config.set('ha-legacy-mode', True)
        self._call_hook('quantum-network-service-relation-changed')
        self.assertTrue(self.cache_env_data.called)
