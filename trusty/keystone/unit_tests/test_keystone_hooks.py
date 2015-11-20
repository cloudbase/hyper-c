from mock import call, patch, MagicMock
import os
import json
import uuid
import yaml

from test_utils import CharmTestCase

os.environ['JUJU_UNIT_NAME'] = 'keystone'
with patch('charmhelpers.core.hookenv.config') as config:
    config.return_value = 'keystone'
    import keystone_utils as utils

_reg = utils.register_configs
_map = utils.restart_map

utils.register_configs = MagicMock()
utils.restart_map = MagicMock()

import keystone_hooks as hooks
from charmhelpers.contrib import unison

utils.register_configs = _reg
utils.restart_map = _map

TO_PATCH = [
    # charmhelpers.core.hookenv
    'Hooks',
    'config',
    'is_relation_made',
    'log',
    'local_unit',
    'filter_installed_packages',
    'relation_ids',
    'relation_set',
    'relation_get',
    'related_units',
    'unit_get',
    'peer_echo',
    # charmhelpers.core.host
    'apt_install',
    'apt_update',
    'restart_on_change',
    # charmhelpers.contrib.openstack.utils
    'configure_installation_source',
    # charmhelpers.contrib.openstack.ip
    'resolve_address',
    # charmhelpers.contrib.hahelpers.cluster_utils
    'is_elected_leader',
    'get_hacluster_config',
    # keystone_utils
    'restart_map',
    'register_configs',
    'do_openstack_upgrade',
    'openstack_upgrade_available',
    'save_script_rc',
    'migrate_database',
    'ensure_initial_admin',
    'add_service_to_keystone',
    'synchronize_ca_if_changed',
    'update_nrpe_config',
    'ensure_ssl_dirs',
    'is_db_initialised',
    'is_db_ready',
    # other
    'check_call',
    'execd_preinstall',
    'mkdir',
    'os',
    # ip
    'get_iface_for_address',
    'get_netmask_for_address',
    'get_address_in_network',
    'git_install',
]


class KeystoneRelationTests(CharmTestCase):

    def setUp(self):
        super(KeystoneRelationTests, self).setUp(hooks, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.ssh_user = 'juju_keystone'

    @patch.object(utils, 'git_install_requested')
    def test_install_hook(self, git_requested):
        git_requested.return_value = False
        repo = 'cloud:precise-grizzly'
        self.test_config.set('openstack-origin', repo)
        hooks.install()
        self.assertTrue(self.execd_preinstall.called)
        self.configure_installation_source.assert_called_with(repo)
        self.assertTrue(self.apt_update.called)
        self.apt_install.assert_called_with(
            ['apache2', 'haproxy', 'keystone', 'openssl', 'pwgen',
             'python-keystoneclient', 'python-mysqldb', 'python-psycopg2',
             'python-six', 'unison', 'uuid'], fatal=True)
        self.git_install.assert_called_with(None)

    @patch.object(utils, 'git_install_requested')
    def test_install_hook_git(self, git_requested):
        git_requested.return_value = True
        repo = 'cloud:trusty-juno'
        openstack_origin_git = {
            'repositories': [
                {'name': 'requirements',
                 'repository': 'git://git.openstack.org/openstack/requirements',  # noqa
                 'branch': 'stable/juno'},
                {'name': 'keystone',
                 'repository': 'git://git.openstack.org/openstack/keystone',
                 'branch': 'stable/juno'}
            ],
            'directory': '/mnt/openstack-git',
        }
        projects_yaml = yaml.dump(openstack_origin_git)
        self.test_config.set('openstack-origin', repo)
        self.test_config.set('openstack-origin-git', projects_yaml)
        hooks.install()
        self.assertTrue(self.execd_preinstall.called)
        self.configure_installation_source.assert_called_with(repo)
        self.assertTrue(self.apt_update.called)
        self.apt_install.assert_called_with(
            ['apache2', 'haproxy', 'libffi-dev', 'libmysqlclient-dev',
             'libssl-dev', 'libxml2-dev', 'libxslt1-dev', 'libyaml-dev',
             'openssl', 'pwgen', 'python-dev', 'python-keystoneclient',
             'python-mysqldb', 'python-pip', 'python-psycopg2',
             'python-setuptools', 'python-six', 'unison', 'uuid',
             'zlib1g-dev'], fatal=True)
        self.git_install.assert_called_with(projects_yaml)

    mod_ch_openstack_utils = 'charmhelpers.contrib.openstack.utils'

    @patch.object(hooks, 'config')
    @patch('%s.config' % (mod_ch_openstack_utils))
    @patch('%s.relation_set' % (mod_ch_openstack_utils))
    @patch('%s.relation_ids' % (mod_ch_openstack_utils))
    @patch('%s.get_ipv6_addr' % (mod_ch_openstack_utils))
    @patch('%s.sync_db_with_multi_ipv6_addresses' % (mod_ch_openstack_utils))
    def test_db_joined(self, mock_sync_db_with_multi, mock_get_ipv6_addr,
                       mock_relation_ids, mock_relation_set, mock_config,
                       mock_hooks_config):

        cfg_dict = {'prefer-ipv6': False,
                    'database': 'keystone',
                    'database-user': 'keystone',
                    'vip': None}

        class mock_cls_config():
            def __call__(self, key):
                return cfg_dict[key]

        cfg = mock_cls_config()
        mock_hooks_config.side_effect = cfg
        mock_config.side_effect = cfg

        self.is_relation_made.return_value = False
        self.unit_get.return_value = 'keystone.foohost.com'
        hooks.db_joined()
        self.relation_set.assert_called_with(database='keystone',
                                             username='keystone',
                                             hostname='keystone.foohost.com')
        self.unit_get.assert_called_with('private-address')

        cfg_dict['prefer-ipv6'] = True
        mock_hooks_config.side_effect = mock_cls_config()
        mock_relation_ids.return_value = ['shared-db']
        mock_get_ipv6_addr.return_value = ['keystone.foohost.com']
        self.is_relation_made.return_value = False
        hooks.db_joined()

        hosts = json.dumps(['keystone.foohost.com'])
        mock_relation_set.assert_called_with(relation_id='shared-db',
                                             database='keystone',
                                             username='keystone',
                                             hostname=hosts)

    def test_postgresql_db_joined(self):
        self.unit_get.return_value = 'keystone.foohost.com'
        self.is_relation_made.return_value = False
        hooks.pgsql_db_joined()
        self.relation_set.assert_called_with(database='keystone'),

    def test_db_joined_with_postgresql(self):
        self.is_relation_made.return_value = True

        with self.assertRaises(Exception) as context:
            hooks.db_joined()
        self.assertEqual(
            context.exception.message,
            'Attempting to associate a mysql database when there '
            'is already associated a postgresql one')

    def test_postgresql_joined_with_db(self):
        self.is_relation_made.return_value = True

        with self.assertRaises(Exception) as context:
            hooks.pgsql_db_joined()
        self.assertEqual(
            context.exception.message,
            'Attempting to associate a postgresql database when there '
            'is already associated a mysql one')

    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch.object(hooks, 'CONFIGS')
    def test_db_changed_missing_relation_data(self, configs,
                                              mock_ensure_ssl_cert_master,
                                              mock_log):
        mock_ensure_ssl_cert_master.return_value = False
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = []
        hooks.db_changed()
        self.log.assert_called_with(
            'shared-db relation incomplete. Peer not ready?'
        )

    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch.object(hooks, 'CONFIGS')
    def test_postgresql_db_changed_missing_relation_data(self, configs,
                                                         mock_ensure_leader,
                                                         mock_log):
        mock_ensure_leader.return_value = False
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = []
        hooks.pgsql_db_changed()
        self.log.assert_called_with(
            'pgsql-db relation incomplete. Peer not ready?'
        )

    def _shared_db_test(self, configs, unit_name):
        self.relation_get.return_value = 'keystone/0 keystone/3'
        self.local_unit.return_value = unit_name
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['shared-db']
        configs.write = MagicMock()
        hooks.db_changed()

    def _postgresql_db_test(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['pgsql-db']
        configs.write = MagicMock()
        hooks.pgsql_db_changed()

    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'identity_changed')
    def test_db_changed_allowed(self, identity_changed, configs,
                                mock_ensure_ssl_cert_master,
                                mock_log):
        self.is_db_initialised.return_value = True
        self.is_db_ready.return_value = True
        mock_ensure_ssl_cert_master.return_value = False
        self.relation_ids.return_value = ['identity-service:0']
        self.related_units.return_value = ['unit/0']

        self._shared_db_test(configs, 'keystone/3')
        self.assertEquals([call('/etc/keystone/keystone.conf')],
                          configs.write.call_args_list)
        self.migrate_database.assert_called_with()
        self.assertTrue(self.ensure_initial_admin.called)
        identity_changed.assert_called_with(
            relation_id='identity-service:0',
            remote_unit='unit/0')

    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'identity_changed')
    def test_db_changed_not_allowed(self, identity_changed, configs,
                                    mock_ensure_ssl_cert_master, mock_log):
        self.is_db_ready.return_value = False
        mock_ensure_ssl_cert_master.return_value = False
        self.relation_ids.return_value = ['identity-service:0']
        self.related_units.return_value = ['unit/0']

        self._shared_db_test(configs, 'keystone/2')
        self.assertEquals([call('/etc/keystone/keystone.conf')],
                          configs.write.call_args_list)
        self.assertFalse(self.migrate_database.called)
        self.assertFalse(self.ensure_initial_admin.called)
        self.assertFalse(identity_changed.called)

    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'identity_changed')
    def test_postgresql_db_changed(self, identity_changed, configs,
                                   mock_ensure_ssl_cert_master, mock_log):
        self.is_db_initialised.return_value = True
        self.is_db_ready.return_value = True
        mock_ensure_ssl_cert_master.return_value = False
        self.relation_ids.return_value = ['identity-service:0']
        self.related_units.return_value = ['unit/0']

        self._postgresql_db_test(configs)
        self.assertEquals([call('/etc/keystone/keystone.conf')],
                          configs.write.call_args_list)
        self.migrate_database.assert_called_with()
        self.assertTrue(self.ensure_initial_admin.called)
        identity_changed.assert_called_with(
            relation_id='identity-service:0',
            remote_unit='unit/0')

    @patch.object(hooks, 'git_install_requested')
    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch('keystone_utils.ensure_ssl_dirs')
    @patch.object(hooks, 'ensure_permissions')
    @patch.object(hooks, 'ensure_pki_dir_permissions')
    @patch.object(hooks, 'ensure_ssl_dir')
    @patch.object(hooks, 'is_pki_enabled')
    @patch.object(hooks, 'is_ssl_cert_master')
    @patch.object(hooks, 'send_ssl_sync_request')
    @patch.object(hooks, 'peer_units')
    @patch.object(hooks, 'admin_relation_changed')
    @patch.object(hooks, 'cluster_joined')
    @patch.object(unison, 'ensure_user')
    @patch.object(unison, 'get_homedir')
    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'identity_changed')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_no_upgrade_leader(self, configure_https,
                                              identity_changed,
                                              configs, get_homedir,
                                              ensure_user,
                                              cluster_joined,
                                              admin_relation_changed,
                                              mock_peer_units,
                                              mock_send_ssl_sync_request,
                                              mock_is_ssl_cert_master,
                                              mock_is_pki_enabled,
                                              mock_ensure_ssl_dir,
                                              mock_ensure_permissions,
                                              mock_ensure_pki_dir_permissions,
                                              mock_ensure_ssl_dirs,
                                              mock_ensure_ssl_cert_master,
                                              mock_log, git_requested):
        git_requested.return_value = False
        mock_is_pki_enabled.return_value = True
        mock_is_ssl_cert_master.return_value = True
        self.is_db_initialised.return_value = True
        self.is_db_ready.return_value = True
        self.openstack_upgrade_available.return_value = False
        self.is_elected_leader.return_value = True
        # avoid having to mock syncer
        mock_ensure_ssl_cert_master.return_value = False
        mock_peer_units.return_value = []
        self.relation_ids.return_value = ['identity-service:0']
        self.related_units.return_value = ['unit/0']

        hooks.config_changed()
        ensure_user.assert_called_with(user=self.ssh_user, group='keystone')
        get_homedir.assert_called_with(self.ssh_user)

        self.save_script_rc.assert_called_with()
        configure_https.assert_called_with()
        self.assertTrue(configs.write_all.called)

        self.assertTrue(self.ensure_initial_admin.called)
        self.log.assert_called_with(
            'Firing identity_changed hook for all related services.')
        identity_changed.assert_called_with(
            relation_id='identity-service:0',
            remote_unit='unit/0')
        admin_relation_changed.assert_called_with('identity-service:0')

    @patch.object(hooks, 'git_install_requested')
    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch('keystone_utils.ensure_ssl_dirs')
    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(hooks, 'ensure_permissions')
    @patch.object(hooks, 'ensure_pki_dir_permissions')
    @patch.object(hooks, 'ensure_ssl_dir')
    @patch.object(hooks, 'is_pki_enabled')
    @patch.object(hooks, 'peer_units')
    @patch.object(hooks, 'is_ssl_cert_master')
    @patch.object(hooks, 'cluster_joined')
    @patch.object(unison, 'ensure_user')
    @patch.object(unison, 'get_homedir')
    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'identity_changed')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_no_upgrade_not_leader(self, configure_https,
                                                  identity_changed,
                                                  configs, get_homedir,
                                                  ensure_user, cluster_joined,
                                                  mock_is_ssl_cert_master,
                                                  mock_peer_units,
                                                  mock_is_pki_enabled,
                                                  mock_ensure_ssl_dir,
                                                  mock_ensure_permissions,
                                                  mock_ensure_pki_permissions,
                                                  mock_update_all_id_rel_units,
                                                  ensure_ssl_dirs,
                                                  mock_ensure_ssl_cert_master,
                                                  mock_log, git_requested):
        git_requested.return_value = False
        mock_is_pki_enabled.return_value = True
        mock_is_ssl_cert_master.return_value = True
        mock_peer_units.return_value = []
        self.openstack_upgrade_available.return_value = False
        self.is_elected_leader.return_value = False
        mock_ensure_ssl_cert_master.return_value = False

        hooks.config_changed()
        ensure_user.assert_called_with(user=self.ssh_user, group='keystone')
        get_homedir.assert_called_with(self.ssh_user)

        self.save_script_rc.assert_called_with()
        configure_https.assert_called_with()
        self.assertTrue(configs.write_all.called)

        self.assertFalse(self.migrate_database.called)
        self.assertFalse(self.ensure_initial_admin.called)
        self.assertFalse(identity_changed.called)

    @patch.object(hooks, 'git_install_requested')
    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch('keystone_utils.ensure_ssl_dirs')
    @patch.object(hooks, 'ensure_permissions')
    @patch.object(hooks, 'ensure_pki_dir_permissions')
    @patch.object(hooks, 'ensure_ssl_dir')
    @patch.object(hooks, 'is_pki_enabled')
    @patch.object(hooks, 'is_ssl_cert_master')
    @patch.object(hooks, 'send_ssl_sync_request')
    @patch.object(hooks, 'peer_units')
    @patch.object(hooks, 'admin_relation_changed')
    @patch.object(hooks, 'cluster_joined')
    @patch.object(unison, 'ensure_user')
    @patch.object(unison, 'get_homedir')
    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'identity_changed')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_with_openstack_upgrade(self, configure_https,
                                                   identity_changed,
                                                   configs, get_homedir,
                                                   ensure_user, cluster_joined,
                                                   admin_relation_changed,
                                                   mock_peer_units,
                                                   mock_send_ssl_sync_request,
                                                   mock_is_ssl_cert_master,
                                                   mock_is_pki_enabled,
                                                   mock_ensure_ssl_dir,
                                                   mock_ensure_permissions,
                                                   mock_ensure_pki_permissions,
                                                   mock_ensure_ssl_dirs,
                                                   mock_ensure_ssl_cert_master,
                                                   mock_log, git_requested):
        git_requested.return_value = False
        mock_is_pki_enabled.return_value = True
        mock_is_ssl_cert_master.return_value = True
        self.is_db_ready.return_value = True
        self.is_db_initialised.return_value = True
        self.openstack_upgrade_available.return_value = True
        self.is_elected_leader.return_value = True
        # avoid having to mock syncer
        mock_ensure_ssl_cert_master.return_value = False
        mock_peer_units.return_value = []
        self.relation_ids.return_value = ['identity-service:0']
        self.related_units.return_value = ['unit/0']

        hooks.config_changed()
        ensure_user.assert_called_with(user=self.ssh_user, group='keystone')
        get_homedir.assert_called_with(self.ssh_user)

        self.assertTrue(self.do_openstack_upgrade.called)

        self.save_script_rc.assert_called_with()
        configure_https.assert_called_with()
        self.assertTrue(configs.write_all.called)

        self.assertTrue(self.ensure_initial_admin.called)
        self.log.assert_called_with(
            'Firing identity_changed hook for all related services.')
        identity_changed.assert_called_with(
            relation_id='identity-service:0',
            remote_unit='unit/0')
        admin_relation_changed.assert_called_with('identity-service:0')

    @patch.object(hooks, 'git_install_requested')
    @patch.object(hooks, 'config_value_changed')
    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch.object(hooks, 'ensure_ssl_dir')
    @patch.object(hooks, 'is_pki_enabled')
    @patch.object(hooks, 'send_ssl_sync_request')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'is_db_ready')
    @patch.object(hooks, 'peer_units')
    @patch.object(hooks, 'admin_relation_changed')
    @patch.object(hooks, 'cluster_joined')
    @patch.object(unison, 'ensure_user')
    @patch.object(unison, 'get_homedir')
    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'identity_changed')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_git_updated(self, configure_https,
                                        identity_changed,
                                        configs, get_homedir, ensure_user,
                                        cluster_joined, admin_relation_changed,
                                        mock_peer_units,
                                        mock_is_db_ready,
                                        mock_is_db_initialised,
                                        mock_send_ssl_sync_request,
                                        mock_is_pki_enabled,
                                        mock_ensure_ssl_dir,
                                        mock_ensure_ssl_cert_master,
                                        mock_log, config_val_changed,
                                        git_requested):
        git_requested.return_value = True
        mock_ensure_ssl_cert_master.return_value = False
        mock_is_pki_enabled.return_value = False
        self.openstack_upgrade_available.return_value = False
        self.is_elected_leader.return_value = True
        mock_peer_units.return_value = []
        self.relation_ids.return_value = ['identity-service:0']
        self.related_units.return_value = ['unit/0']

        repo = 'cloud:trusty-juno'
        openstack_origin_git = {
            'repositories': [
                {'name': 'requirements',
                 'repository': 'git://git.openstack.org/openstack/requirements',  # noqa
                 'branch': 'stable/juno'},
                {'name': 'keystone',
                 'repository': 'git://git.openstack.org/openstack/keystone',
                 'branch': 'stable/juno'}
            ],
            'directory': '/mnt/openstack-git',
        }
        projects_yaml = yaml.dump(openstack_origin_git)
        self.test_config.set('openstack-origin', repo)
        self.test_config.set('openstack-origin-git', projects_yaml)
        hooks.config_changed()
        self.git_install.assert_called_with(projects_yaml)
        self.assertFalse(self.openstack_upgrade_available.called)
        self.assertFalse(self.do_openstack_upgrade.called)

    @patch.object(hooks, 'git_install_requested')
    @patch.object(hooks, 'config_value_changed')
    @patch.object(hooks, 'ensure_ssl_dir')
    @patch.object(hooks, 'configure_https')
    @patch.object(hooks, 'is_pki_enabled')
    @patch.object(hooks, 'is_ssl_cert_master')
    @patch.object(hooks, 'peer_units')
    @patch.object(unison, 'get_homedir')
    @patch.object(unison, 'ensure_user')
    @patch('keystone_utils.ensure_ssl_cert_master')
    def test_config_changed_with_openstack_upgrade_action(self,
                                                          ensure_ssl_cert,
                                                          ensure_user,
                                                          get_home,
                                                          peer_units, is_ssl,
                                                          is_pki, config_https,
                                                          ensure_ssl_dir,
                                                          config_value_changed,
                                                          git_requested):
        ensure_ssl_cert.return_value = False
        is_pki.return_value = False
        peer_units.return_value = []

        git_requested.return_value = False
        self.openstack_upgrade_available.return_value = True
        self.test_config.set('action-managed-upgrade', True)

        hooks.config_changed()

        self.assertFalse(self.do_openstack_upgrade.called)

    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch.object(hooks, 'hashlib')
    @patch.object(hooks, 'send_notifications')
    def test_identity_changed_leader(self, mock_send_notifications,
                                     mock_hashlib, mock_ensure_ssl_cert_master,
                                     mock_log):
        self.is_db_initialised.return_value = True
        self.is_db_ready.return_value = True
        mock_ensure_ssl_cert_master.return_value = False
        hooks.identity_changed(
            relation_id='identity-service:0',
            remote_unit='unit/0')
        self.add_service_to_keystone.assert_called_with(
            'identity-service:0',
            'unit/0')

    @patch.object(hooks, 'local_unit')
    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    def test_identity_changed_no_leader(self, mock_ensure_ssl_cert_master,
                                        mock_log, mock_local_unit):
        mock_ensure_ssl_cert_master.return_value = False
        mock_local_unit.return_value = 'unit/0'
        self.is_elected_leader.return_value = False
        hooks.identity_changed(
            relation_id='identity-service:0',
            remote_unit='unit/0')
        self.assertFalse(self.add_service_to_keystone.called)
        self.log.assert_called_with(
            'Deferring identity_changed() to service leader.')

    @patch.object(hooks, 'local_unit')
    @patch.object(hooks, 'peer_units')
    @patch.object(unison, 'ssh_authorized_peers')
    def test_cluster_joined(self, ssh_authorized_peers, mock_peer_units,
                            mock_local_unit):
        mock_local_unit.return_value = 'unit/0'
        mock_peer_units.return_value = ['unit/0']
        hooks.cluster_joined()
        ssh_authorized_peers.assert_called_with(
            user=self.ssh_user, group='juju_keystone',
            peer_interface='cluster', ensure_local_user=True)

    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(hooks, 'get_ssl_sync_request_units')
    @patch.object(hooks, 'is_ssl_cert_master')
    @patch.object(hooks, 'peer_units')
    @patch('keystone_utils.relation_ids')
    @patch('keystone_utils.config')
    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch('keystone_utils.synchronize_ca')
    @patch.object(hooks, 'check_peer_actions')
    @patch.object(unison, 'ssh_authorized_peers')
    @patch.object(hooks, 'CONFIGS')
    def test_cluster_changed(self, configs, ssh_authorized_peers,
                             check_peer_actions, mock_synchronize_ca,
                             mock_ensure_ssl_cert_master,
                             mock_log, mock_config, mock_relation_ids,
                             mock_peer_units,
                             mock_is_ssl_cert_master,
                             mock_get_ssl_sync_request_units,
                             mock_update_all_identity_relation_units):

        relation_settings = {'foo_passwd': '123',
                             'identity-service:16_foo': 'bar'}

        mock_is_ssl_cert_master.return_value = False
        mock_peer_units.return_value = ['unit/0']
        mock_ensure_ssl_cert_master.return_value = False
        mock_relation_ids.return_value = []
        self.is_elected_leader.return_value = False

        def fake_rel_get(attribute=None, *args, **kwargs):
            if not attribute:
                return relation_settings

            return relation_settings.get(attribute)

        self.relation_get.side_effect = fake_rel_get

        mock_config.return_value = None

        hooks.cluster_changed()
        whitelist = ['_passwd', 'identity-service:', 'ssl-cert-master',
                     'db-initialised', 'ssl-cert-available-updates']
        self.peer_echo.assert_called_with(force=True, includes=whitelist)
        ssh_authorized_peers.assert_called_with(
            user=self.ssh_user, group='juju_keystone',
            peer_interface='cluster', ensure_local_user=True)
        self.assertFalse(mock_synchronize_ca.called)
        self.assertTrue(configs.write_all.called)

    def test_ha_joined(self):
        self.get_hacluster_config.return_value = {
            'vip': '10.10.10.10',
            'ha-bindiface': 'em0',
            'ha-mcastport': '8080'
        }
        self.get_iface_for_address.return_value = 'em1'
        self.get_netmask_for_address.return_value = '255.255.255.0'
        hooks.ha_joined()
        args = {
            'relation_id': None,
            'corosync_bindiface': 'em0',
            'corosync_mcastport': '8080',
            'init_services': {'res_ks_haproxy': 'haproxy'},
            'resources': {'res_ks_em1_vip': 'ocf:heartbeat:IPaddr2',
                          'res_ks_haproxy': 'lsb:haproxy'},
            'resource_params': {
                'res_ks_em1_vip': 'params ip="10.10.10.10"'
                                  ' cidr_netmask="255.255.255.0" nic="em1"',
                'res_ks_haproxy': 'op monitor interval="5s"'},
            'clones': {'cl_ks_haproxy': 'res_ks_haproxy'}
        }
        self.relation_set.assert_called_with(**args)

    def test_ha_joined_duplicate_vip_key(self):
        self.get_hacluster_config.return_value = {
            'vip': '10.10.10.10 10.10.10.11',
            'ha-bindiface': 'em0',
            'ha-mcastport': '8080'
        }
        self.get_iface_for_address.return_value = 'em1'
        self.get_netmask_for_address.return_value = '255.255.255.0'
        hooks.ha_joined()
        args = {
            'relation_id': None,
            'corosync_bindiface': 'em0',
            'corosync_mcastport': '8080',
            'init_services': {'res_ks_haproxy': 'haproxy'},
            'resources': {'res_ks_em1_vip': 'ocf:heartbeat:IPaddr2',
                          'res_ks_haproxy': 'lsb:haproxy'},
            'resource_params': {
                'res_ks_em1_vip': 'params ip="10.10.10.10"'
                                  ' cidr_netmask="255.255.255.0" nic="em1"',
                'res_ks_haproxy': 'op monitor interval="5s"'},
            'clones': {'cl_ks_haproxy': 'res_ks_haproxy'}
        }
        self.relation_set.assert_called_with(**args)

    def test_ha_joined_no_bound_ip(self):
        self.get_hacluster_config.return_value = {
            'vip': '10.10.10.10',
            'ha-bindiface': 'em0',
            'ha-mcastport': '8080'
        }
        self.test_config.set('vip_iface', 'eth120')
        self.test_config.set('vip_cidr', '21')
        self.get_iface_for_address.return_value = None
        self.get_netmask_for_address.return_value = None
        hooks.ha_joined()
        args = {
            'relation_id': None,
            'corosync_bindiface': 'em0',
            'corosync_mcastport': '8080',
            'init_services': {'res_ks_haproxy': 'haproxy'},
            'resources': {'res_ks_eth120_vip': 'ocf:heartbeat:IPaddr2',
                          'res_ks_haproxy': 'lsb:haproxy'},
            'resource_params': {
                'res_ks_eth120_vip': 'params ip="10.10.10.10"'
                                     ' cidr_netmask="21" nic="eth120"',
                'res_ks_haproxy': 'op monitor interval="5s"'},
            'clones': {'cl_ks_haproxy': 'res_ks_haproxy'}
        }
        self.relation_set.assert_called_with(**args)

    def test_ha_joined_with_ipv6(self):
        self.test_config.set('prefer-ipv6', True)
        self.get_hacluster_config.return_value = {
            'vip': '2001:db8:1::1',
            'ha-bindiface': 'em0',
            'ha-mcastport': '8080'
        }
        self.get_iface_for_address.return_value = 'em1'
        self.get_netmask_for_address.return_value = '64'
        hooks.ha_joined()
        args = {
            'relation_id': None,
            'corosync_bindiface': 'em0',
            'corosync_mcastport': '8080',
            'init_services': {'res_ks_haproxy': 'haproxy'},
            'resources': {'res_ks_em1_vip': 'ocf:heartbeat:IPv6addr',
                          'res_ks_haproxy': 'lsb:haproxy'},
            'resource_params': {
                'res_ks_em1_vip': 'params ipv6addr="2001:db8:1::1"'
                                  ' cidr_netmask="64" nic="em1"',
                'res_ks_haproxy': 'op monitor interval="5s"'},
            'clones': {'cl_ks_haproxy': 'res_ks_haproxy'}
        }
        self.relation_set.assert_called_with(**args)

    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch('keystone_utils.synchronize_ca')
    @patch.object(hooks, 'CONFIGS')
    def test_ha_relation_changed_not_clustered_not_leader(self, configs,
                                                          mock_synchronize_ca,
                                                          mock_is_master,
                                                          mock_log):
        mock_is_master.return_value = False
        self.relation_get.return_value = False
        self.is_elected_leader.return_value = False

        hooks.ha_changed()
        self.assertTrue(configs.write_all.called)
        self.assertFalse(mock_synchronize_ca.called)

    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch.object(hooks, 'identity_changed')
    @patch.object(hooks, 'CONFIGS')
    def test_ha_relation_changed_clustered_leader(self, configs,
                                                  identity_changed,
                                                  mock_ensure_ssl_cert_master,
                                                  mock_log):
        self.is_db_initialised.return_value = True
        self.is_db_ready.return_value = True
        mock_ensure_ssl_cert_master.return_value = False
        self.relation_get.return_value = True
        self.is_elected_leader.return_value = True
        self.relation_ids.return_value = ['identity-service:0']
        self.related_units.return_value = ['unit/0']

        hooks.ha_changed()
        self.assertTrue(configs.write_all.called)
        self.log.assert_called_with(
            'Firing identity_changed hook for all related services.')
        identity_changed.assert_called_with(
            relation_id='identity-service:0',
            remote_unit='unit/0')

    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch.object(hooks, 'CONFIGS')
    def test_configure_https_enable(self, configs, mock_ensure_ssl_cert_master,
                                    mock_log):
        mock_ensure_ssl_cert_master.return_value = False
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['https']
        configs.write = MagicMock()

        hooks.configure_https()
        self.assertTrue(configs.write_all.called)
        cmd = ['a2ensite', 'openstack_https_frontend']
        self.check_call.assert_called_with(cmd)

    @patch('keystone_utils.log')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch.object(hooks, 'CONFIGS')
    def test_configure_https_disable(self, configs,
                                     mock_ensure_ssl_cert_master,
                                     mock_log):
        mock_ensure_ssl_cert_master.return_value = False
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['']
        configs.write = MagicMock()

        hooks.configure_https()
        self.assertTrue(configs.write_all.called)
        cmd = ['a2dissite', 'openstack_https_frontend']
        self.check_call.assert_called_with(cmd)

    @patch.object(utils, 'git_install_requested')
    @patch.object(hooks, 'is_db_ready')
    @patch.object(hooks, 'is_db_initialised')
    @patch('keystone_utils.log')
    @patch('keystone_utils.relation_ids')
    @patch('keystone_utils.is_elected_leader')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch('keystone_utils.update_hash_from_path')
    @patch('keystone_utils.synchronize_ca')
    @patch.object(unison, 'ssh_authorized_peers')
    def test_upgrade_charm_leader(self, ssh_authorized_peers,
                                  mock_synchronize_ca,
                                  mock_update_hash_from_path,
                                  mock_ensure_ssl_cert_master,
                                  mock_is_elected_leader,
                                  mock_relation_ids,
                                  mock_log,
                                  mock_is_db_initialised,
                                  mock_is_db_ready,
                                  git_requested):
        mock_is_db_initialised.return_value = True
        mock_is_db_ready.return_value = True
        mock_is_elected_leader.return_value = False
        mock_relation_ids.return_value = []
        mock_ensure_ssl_cert_master.return_value = True
        # Ensure always returns diff
        mock_update_hash_from_path.side_effect = \
            lambda hash, *args, **kwargs: hash.update(str(uuid.uuid4()))

        self.is_elected_leader.return_value = True
        self.filter_installed_packages.return_value = []
        git_requested.return_value = False
        hooks.upgrade_charm()
        self.assertTrue(self.apt_install.called)
        ssh_authorized_peers.assert_called_with(
            user=self.ssh_user, group='juju_keystone',
            peer_interface='cluster', ensure_local_user=True)
        self.assertTrue(mock_synchronize_ca.called)
        self.log.assert_called_with(
            'Firing identity_changed hook for all related services.')
        self.assertTrue(self.ensure_initial_admin.called)

    @patch.object(utils, 'git_install_requested')
    @patch('keystone_utils.log')
    @patch('keystone_utils.relation_ids')
    @patch('keystone_utils.ensure_ssl_cert_master')
    @patch('keystone_utils.update_hash_from_path')
    @patch.object(unison, 'ssh_authorized_peers')
    def test_upgrade_charm_not_leader(self, ssh_authorized_peers,
                                      mock_update_hash_from_path,
                                      mock_ensure_ssl_cert_master,
                                      mock_relation_ids,
                                      mock_log, git_requested):
        mock_relation_ids.return_value = []
        mock_ensure_ssl_cert_master.return_value = False
        # Ensure always returns diff
        mock_update_hash_from_path.side_effect = \
            lambda hash, *args, **kwargs: hash.update(str(uuid.uuid4()))

        self.is_elected_leader.return_value = False
        self.filter_installed_packages.return_value = []
        git_requested.return_value = False
        hooks.upgrade_charm()
        self.assertTrue(self.apt_install.called)
        ssh_authorized_peers.assert_called_with(
            user=self.ssh_user, group='juju_keystone',
            peer_interface='cluster', ensure_local_user=True)
        self.assertFalse(self.log.called)
        self.assertFalse(self.ensure_initial_admin.called)
