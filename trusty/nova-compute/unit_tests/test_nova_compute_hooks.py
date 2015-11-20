from mock import (
    call,
    patch,
    MagicMock
)
import yaml

from test_utils import CharmTestCase

with patch("nova_compute_utils.restart_map"):
    with patch("nova_compute_utils.register_configs"):
        import nova_compute_hooks as hooks


TO_PATCH = [
    # charmhelpers.core.hookenv
    'Hooks',
    'config',
    'log',
    'is_relation_made',
    'relation_get',
    'relation_ids',
    'relation_set',
    'service_name',
    'unit_get',
    # charmhelpers.core.host
    'apt_install',
    'apt_update',
    'filter_installed_packages',
    'restart_on_change',
    'service_restart',
    # charmhelpers.contrib.openstack.utils
    'configure_installation_source',
    'openstack_upgrade_available',
    # nova_compute_utils
    # 'PACKAGES',
    'create_libvirt_secret',
    'restart_map',
    'determine_packages',
    'import_authorized_keys',
    'import_keystone_ca_cert',
    'initialize_ssh_keys',
    'migration_enabled',
    'do_openstack_upgrade',
    'network_manager',
    'manage_ovs',
    'public_ssh_key',
    'register_configs',
    'disable_shell',
    'enable_shell',
    'update_nrpe_config',
    'git_install',
    'git_install_requested',
    # misc_utils
    'ensure_ceph_keyring',
    'execd_preinstall',
    'assert_libvirt_imagebackend_allowed',
    'is_request_complete',
    'send_request_if_needed',
    # socket
    'gethostname',
    'create_sysctl',
    'install_hugepages',
]


class NovaComputeRelationsTests(CharmTestCase):

    def setUp(self):
        super(NovaComputeRelationsTests, self).setUp(hooks,
                                                     TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.filter_installed_packages.side_effect = \
            MagicMock(side_effect=lambda pkgs: pkgs)
        self.gethostname.return_value = 'testserver'

    def test_install_hook(self):
        repo = 'cloud:precise-grizzly'
        self.test_config.set('openstack-origin', repo)
        self.determine_packages.return_value = ['foo', 'bar']
        hooks.install()
        self.configure_installation_source.assert_called_with(repo)
        self.assertTrue(self.apt_update.called)
        self.apt_install.assert_called_with(['foo', 'bar'], fatal=True)
        self.assertTrue(self.execd_preinstall.called)

    def test_install_hook_git(self):
        self.git_install_requested.return_value = True
        self.determine_packages.return_value = ['foo', 'bar']
        repo = 'cloud:trusty-juno'
        openstack_origin_git = {
            'repositories': [
                {'name': 'requirements',
                 'repository': 'git://git.openstack.org/openstack/requirements',  # noqa
                 'branch': 'stable/juno'},
                {'name': 'nova',
                 'repository': 'git://git.openstack.org/openstack/nova',
                 'branch': 'stable/juno'}
            ],
            'directory': '/mnt/openstack-git',
        }
        projects_yaml = yaml.dump(openstack_origin_git)
        self.test_config.set('openstack-origin', repo)
        self.test_config.set('openstack-origin-git', projects_yaml)
        hooks.install()
        self.configure_installation_source.assert_called_with(repo)
        self.assertTrue(self.apt_update.called)
        self.apt_install.assert_called_with(['foo', 'bar'], fatal=True)
        self.git_install.assert_called_with(projects_yaml)
        self.assertTrue(self.execd_preinstall.called)

    def test_config_changed_with_upgrade(self):
        self.git_install_requested.return_value = False
        self.openstack_upgrade_available.return_value = True
        hooks.config_changed()
        self.assertTrue(self.do_openstack_upgrade.called)

    @patch.object(hooks, 'git_install_requested')
    def test_config_changed_with_openstack_upgrade_action(self, git_requested):
        git_requested.return_value = False
        self.openstack_upgrade_available.return_value = True
        self.test_config.set('action-managed-upgrade', True)

        hooks.config_changed()
        self.assertFalse(self.do_openstack_upgrade.called)

    @patch.object(hooks, 'compute_joined')
    def test_config_changed_with_migration(self, compute_joined):
        self.git_install_requested.return_value = False
        self.migration_enabled.return_value = True
        _zmq_joined = self.patch('zeromq_configuration_relation_joined')
        self.test_config.set('migration-auth-type', 'ssh')
        self.relation_ids.return_value = [
            'cloud-compute:0',
            'cloud-compute:1'
        ]
        hooks.config_changed()
        ex = [
            call('cloud-compute:0'),
            call('cloud-compute:1'),
        ]
        self.assertEquals(ex, compute_joined.call_args_list)
        self.assertTrue(self.initialize_ssh_keys.called)
        self.assertTrue(_zmq_joined.called)

    @patch.object(hooks, 'compute_joined')
    def test_config_changed_with_resize(self, compute_joined):
        self.git_install_requested.return_value = False
        self.test_config.set('enable-resize', True)
        _zmq_joined = self.patch('zeromq_configuration_relation_joined')
        self.relation_ids.return_value = [
            'cloud-compute:0',
            'cloud-compute:1'
        ]
        hooks.config_changed()
        ex = [
            call('cloud-compute:0'),
            call('cloud-compute:1'),
        ]
        self.assertEquals(ex, compute_joined.call_args_list)
        self.initialize_ssh_keys.assert_called_with(user='nova')
        self.enable_shell.assert_called_with(user='nova')
        self.assertTrue(_zmq_joined.called)

    @patch.object(hooks, 'compute_joined')
    def test_config_changed_without_resize(self, compute_joined):
        self.git_install_requested.return_value = False
        self.test_config.set('enable-resize', False)
        _zmq_joined = self.patch('zeromq_configuration_relation_joined')
        self.relation_ids.return_value = [
            'cloud-compute:0',
            'cloud-compute:1'
        ]
        hooks.config_changed()
        ex = [
            call('cloud-compute:0'),
            call('cloud-compute:1'),
        ]
        self.assertEquals(ex, compute_joined.call_args_list)
        self.disable_shell.assert_called_with(user='nova')
        self.assertTrue(_zmq_joined.called)

    @patch.object(hooks, 'compute_joined')
    def test_config_changed_no_upgrade_no_migration(self, compute_joined):
        self.git_install_requested.return_value = False
        self.openstack_upgrade_available.return_value = False
        self.migration_enabled.return_value = False
        hooks.config_changed()
        self.assertFalse(self.do_openstack_upgrade.called)
        self.assertFalse(compute_joined.called)

    @patch.object(hooks, 'compute_joined')
    def test_config_changed_with_sysctl(self, compute_joined):
        self.git_install_requested.return_value = False
        self.test_config.set('sysctl', '{ kernel.max_pid : "1337" }')
        hooks.config_changed()
        self.assertTrue(self.create_sysctl.called)

    @patch.object(hooks, 'config_value_changed')
    def test_config_changed_git(self, config_val_changed):
        self.git_install_requested.return_value = True
        repo = 'cloud:trusty-juno'
        openstack_origin_git = {
            'repositories': [
                {'name': 'requirements',
                 'repository':
                 'git://git.openstack.org/openstack/requirements',
                 'branch': 'stable/juno'},
                {'name': 'nova',
                 'repository': 'git://git.openstack.org/openstack/nova',
                 'branch': 'stable/juno'}
            ],
            'directory': '/mnt/openstack-git',
        }
        projects_yaml = yaml.dump(openstack_origin_git)
        self.test_config.set('openstack-origin', repo)
        self.test_config.set('openstack-origin-git', projects_yaml)
        hooks.config_changed()
        self.git_install.assert_called_with(projects_yaml)
        self.assertFalse(self.do_openstack_upgrade.called)

    @patch.object(hooks, 'compute_joined')
    def test_config_changed_no_nrpe(self, compute_joined):
        self.git_install_requested.return_value = False
        self.openstack_upgrade_available.return_value = False
        self.migration_enabled.return_value = False
        self.is_relation_made.return_value = False
        hooks.config_changed()
        self.assertFalse(self.update_nrpe_config.called)

    @patch.object(hooks, 'compute_joined')
    def test_config_changed_nrpe(self, compute_joined):
        self.git_install_requested.return_value = False
        self.openstack_upgrade_available.return_value = False
        self.migration_enabled.return_value = False
        self.is_relation_made.return_value = True
        hooks.config_changed()
        self.assertTrue(self.update_nrpe_config.called)

    def test_amqp_joined(self):
        hooks.amqp_joined()
        self.relation_set.assert_called_with(
            username='nova', vhost='openstack',
            relation_id=None)

    @patch.object(hooks, 'CONFIGS')
    def test_amqp_changed_missing_relation_data(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = []
        hooks.amqp_changed()
        self.log.assert_called_with(
            'amqp relation incomplete. Peer not ready?'
        )

    def _amqp_test(self, configs, quantum=False):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['amqp']
        configs.write = MagicMock()
        if quantum:
            self.network_manager.return_value = 'quantum'
        hooks.amqp_changed()

    @patch.object(hooks, 'CONFIGS')
    def test_amqp_changed_with_data_no_quantum(self, configs):
        self._amqp_test(configs, quantum=False)
        self.assertEquals([call('/etc/nova/nova.conf')],
                          configs.write.call_args_list)

    @patch.object(hooks, 'CONFIGS')
    def test_amqp_changed_with_data_and_quantum(self, configs):
        self.relation_ids.return_value = []
        self._amqp_test(configs, quantum=True)
        self.assertEquals([call('/etc/nova/nova.conf'),
                           call('/etc/quantum/quantum.conf')],
                          configs.write.call_args_list)

    @patch.object(hooks, 'CONFIGS')
    def test_amqp_changed_with_data_and_quantum_api(self, configs):
        self.manage_ovs.return_value = False
        self.relation_ids.return_value = ['neutron-plugin:0']
        self._amqp_test(configs, quantum=True)
        self.assertEquals([call('/etc/nova/nova.conf')],
                          configs.write.call_args_list)

    def test_db_joined(self):
        self.unit_get.return_value = 'nova.foohost.com'
        self.is_relation_made.return_value = False
        hooks.db_joined()
        self.relation_set.assert_called_with(relation_id=None,
                                             nova_database='nova',
                                             nova_username='nova',
                                             nova_hostname='nova.foohost.com')
        self.unit_get.assert_called_with('private-address')

    def test_postgresql_db_joined(self):
        self.unit_get.return_value = 'nova.foohost.com'
        self.is_relation_made.return_value = False
        hooks.pgsql_db_joined()
        self.relation_set.assert_called_with(database='nova'),

    def test_db_joined_with_postgresql(self):
        self.is_relation_made.return_value = True

        with self.assertRaises(Exception) as context:
            hooks.db_joined()
        self.assertEqual(context.exception.message,
                         'Attempting to associate a mysql database when there '
                         'is already associated a postgresql one')

    def test_postgresql_joined_with_db(self):
        self.is_relation_made.return_value = True

        with self.assertRaises(Exception) as context:
            hooks.pgsql_db_joined()
        self.assertEqual(context.exception.message,
                         'Attempting to associate a postgresql database when'
                         ' there is already associated a mysql one')

    @patch.object(hooks, 'CONFIGS')
    def test_db_changed_missing_relation_data(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = []
        hooks.db_changed()
        self.log.assert_called_with(
            'shared-db relation incomplete. Peer not ready?'
        )

    @patch.object(hooks, 'CONFIGS')
    def test_postgresql_db_changed_missing_relation_data(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = []
        hooks.postgresql_db_changed()
        self.log.assert_called_with(
            'pgsql-db relation incomplete. Peer not ready?'
        )

    def _shared_db_test(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['shared-db']
        configs.write = MagicMock()
        hooks.db_changed()

    def _postgresql_db_test(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['pgsql-db']
        configs.write = MagicMock()
        hooks.postgresql_db_changed()

    @patch.object(hooks, 'CONFIGS')
    def test_db_changed_with_data(self, configs):
        self._shared_db_test(configs)
        self.assertEquals([call('/etc/nova/nova.conf')],
                          configs.write.call_args_list)

    @patch.object(hooks, 'CONFIGS')
    def test_postgresql_db_changed_with_data(self, configs):
        self._postgresql_db_test(configs)
        self.assertEquals([call('/etc/nova/nova.conf')],
                          configs.write.call_args_list)

    @patch.object(hooks, 'CONFIGS')
    def test_image_service_missing_relation_data(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = []
        hooks.image_service_changed()
        self.log.assert_called_with(
            'image-service relation incomplete. Peer not ready?'
        )

    @patch.object(hooks, 'CONFIGS')
    def test_image_service_with_relation_data(self, configs):
        configs.complete_contexts = MagicMock()
        configs.write = MagicMock()
        configs.complete_contexts.return_value = ['image-service']
        hooks.image_service_changed()
        configs.write.assert_called_with('/etc/nova/nova.conf')

    def test_compute_joined_no_migration_no_resize(self):
        self.migration_enabled.return_value = False
        hooks.compute_joined()
        self.assertFalse(self.relation_set.called)

    def test_compute_joined_with_ssh_migration(self):
        self.migration_enabled.return_value = True
        self.test_config.set('migration-auth-type', 'ssh')
        self.public_ssh_key.return_value = 'foo'
        hooks.compute_joined()
        self.relation_set.assert_called_with(
            relation_id=None,
            ssh_public_key='foo',
            migration_auth_type='ssh',
            hostname='testserver',
        )
        hooks.compute_joined(rid='cloud-compute:2')
        self.relation_set.assert_called_with(
            relation_id='cloud-compute:2',
            ssh_public_key='foo',
            migration_auth_type='ssh',
            hostname='testserver',
        )

    def test_compute_joined_with_resize(self):
        self.migration_enabled.return_value = False
        self.test_config.set('enable-resize', True)
        self.public_ssh_key.return_value = 'bar'
        hooks.compute_joined()
        self.relation_set.assert_called_with(
            relation_id=None,
            nova_ssh_public_key='bar',
            hostname='testserver',
        )
        hooks.compute_joined(rid='cloud-compute:2')
        self.relation_set.assert_called_with(
            relation_id='cloud-compute:2',
            nova_ssh_public_key='bar',
            hostname='testserver',
        )

    def test_compute_changed(self):
        hooks.compute_changed()
        self.assertTrue(self.import_keystone_ca_cert.called)
        self.import_authorized_keys.assert_has_calls([
            call(),
            call(user='nova', prefix='nova'),
        ])

    def test_compute_changed_nonstandard_authorized_keys_path(self):
        self.migration_enabled.return_value = False
        self.test_config.set('enable-resize', True)
        hooks.compute_changed()
        self.import_authorized_keys.assert_called_with(
            user='nova',
            prefix='nova',
        )

    def test_ceph_joined(self):
        hooks.ceph_joined()
        self.apt_install.assert_called_with(['ceph-common'], fatal=True)
        self.service_restart.assert_called_with('libvirt-bin')

    @patch.object(hooks, 'CONFIGS')
    def test_ceph_changed_missing_relation_data(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = []
        hooks.ceph_changed()
        self.log.assert_called_with(
            'ceph relation incomplete. Peer not ready?'
        )

    @patch.object(hooks, 'CONFIGS')
    def test_ceph_changed_no_keyring(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['ceph']
        self.ensure_ceph_keyring.return_value = False
        hooks.ceph_changed()
        self.log.assert_called_with(
            'Could not create ceph keyring: peer not ready?'
        )

    @patch('nova_compute_context.service_name')
    @patch.object(hooks, 'CONFIGS')
    def test_ceph_changed_with_key_and_relation_data(self, configs,
                                                     service_name):
        self.test_config.set('libvirt-image-backend', 'rbd')
        self.is_request_complete.return_value = True
        self.assert_libvirt_imagebackend_allowed.return_value = True
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['ceph']
        configs.write = MagicMock()
        service_name.return_value = 'nova-compute'
        self.ensure_ceph_keyring.return_value = True
        hooks.ceph_changed()
        ex = [
            call('/var/lib/charm/nova-compute/ceph.conf'),
            call('/etc/ceph/secret.xml'),
            call('/etc/nova/nova.conf'),
        ]
        self.assertEquals(ex, configs.write.call_args_list)
        self.service_restart.assert_called_with('nova-compute')

    @patch.object(hooks, 'CONFIGS')
    def test_neutron_plugin_changed(self, configs):
        self.relation_get.return_value = {'metadata-shared-secret':
                                          'sharedsecret'}
        hooks.neutron_plugin_changed()
        self.assertTrue(self.apt_update.called)
        self.apt_install.assert_called_with('nova-api-metadata', fatal=True)
        configs.write.assert_called_with('/etc/nova/nova.conf')
