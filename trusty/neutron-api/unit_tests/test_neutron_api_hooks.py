from mock import MagicMock, patch, call
import yaml
from test_utils import CharmTestCase


with patch('charmhelpers.core.hookenv.config') as config:
    config.return_value = 'neutron'
    import neutron_api_utils as utils

_reg = utils.register_configs
_map = utils.restart_map

utils.register_configs = MagicMock()
utils.restart_map = MagicMock()

import neutron_api_hooks as hooks
hooks.hooks._config_save = False

hooks.hooks._config_save = False

utils.register_configs = _reg
utils.restart_map = _map

TO_PATCH = [
    'api_port',
    'apt_update',
    'apt_install',
    'config',
    'CONFIGS',
    'check_call',
    'configure_installation_source',
    'determine_packages',
    'determine_ports',
    'do_openstack_upgrade',
    'dvr_router_present',
    'local_unit',
    'l3ha_router_present',
    'execd_preinstall',
    'filter_installed_packages',
    'get_dvr',
    'get_l3ha',
    'get_l2population',
    'get_overlay_network_type',
    'git_install',
    'is_elected_leader',
    'is_relation_made',
    'log',
    'migrate_neutron_database',
    'neutron_ready',
    'open_port',
    'openstack_upgrade_available',
    'os_release',
    'os_requires_version',
    'relation_get',
    'relation_ids',
    'relation_set',
    'service_restart',
    'unit_get',
    'get_iface_for_address',
    'get_netmask_for_address',
    'get_address_in_network',
    'update_nrpe_config',
    'service_reload',
    'IdentityServiceContext',
    'force_etcd_restart',
]
NEUTRON_CONF_DIR = "/etc/neutron"

NEUTRON_CONF = '%s/neutron.conf' % NEUTRON_CONF_DIR

from random import randrange


class DummyContext():

    def __init__(self, return_value):
        self.return_value = return_value

    def __call__(self):
        return self.return_value


class NeutronAPIHooksTests(CharmTestCase):

    def setUp(self):
        super(NeutronAPIHooksTests, self).setUp(hooks, TO_PATCH)

        self.config.side_effect = self.test_config.get
        self.relation_get.side_effect = self.test_relation.get
        self.test_config.set('openstack-origin', 'distro')
        self.test_config.set('neutron-plugin', 'ovs')

    def _fake_relids(self, rel_name):
        return [randrange(100) for _count in range(2)]

    def _call_hook(self, hookname):
        hooks.hooks.execute([
            'hooks/{}'.format(hookname)])

    @patch.object(utils, 'git_install_requested')
    def test_install_hook(self, git_requested):
        git_requested.return_value = False
        _pkgs = ['foo', 'bar']
        _ports = [80, 81, 82]
        _port_calls = [call(port) for port in _ports]
        self.determine_packages.return_value = _pkgs
        self.determine_ports.return_value = _ports
        self._call_hook('install')
        self.configure_installation_source.assert_called_with(
            'distro'
        )
        self.apt_update.assert_called_with()
        self.apt_install.assert_has_calls([
            call(_pkgs, fatal=True),
        ])
        self.open_port.assert_has_calls(_port_calls)
        self.assertTrue(self.execd_preinstall.called)

    @patch.object(utils, 'git_install_requested')
    def test_install_hook_git(self, git_requested):
        git_requested.return_value = True
        _pkgs = ['foo', 'bar']
        _ports = [80, 81, 82]
        _port_calls = [call(port) for port in _ports]
        self.determine_packages.return_value = _pkgs
        self.determine_ports.return_value = _ports
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
        self.assertTrue(self.execd_preinstall.called)
        self.configure_installation_source.assert_called_with(repo)
        self.apt_update.assert_called_with()
        self.apt_install.assert_has_calls([
            call(_pkgs, fatal=True),
        ])
        self.git_install.assert_called_with(projects_yaml)
        self.open_port.assert_has_calls(_port_calls)

    @patch.object(hooks, 'configure_https')
    @patch.object(hooks, 'git_install_requested')
    def test_config_changed(self, git_requested, conf_https):
        git_requested.return_value = False
        self.neutron_ready.return_value = True
        self.openstack_upgrade_available.return_value = True
        self.dvr_router_present.return_value = False
        self.l3ha_router_present.return_value = False
        self.relation_ids.side_effect = self._fake_relids
        _n_api_rel_joined = self.patch('neutron_api_relation_joined')
        _n_plugin_api_rel_joined =\
            self.patch('neutron_plugin_api_relation_joined')
        _amqp_rel_joined = self.patch('amqp_joined')
        _id_rel_joined = self.patch('identity_joined')
        _id_cluster_joined = self.patch('cluster_joined')
        _zmq_joined = self.patch('zeromq_configuration_relation_joined')
        self._call_hook('config-changed')
        self.assertTrue(_n_api_rel_joined.called)
        self.assertTrue(_n_plugin_api_rel_joined.called)
        self.assertTrue(_amqp_rel_joined.called)
        self.assertTrue(_id_rel_joined.called)
        self.assertTrue(_id_cluster_joined.called)
        self.assertTrue(_zmq_joined.called)
        self.assertTrue(self.CONFIGS.write_all.called)
        self.assertTrue(self.do_openstack_upgrade.called)
        self.assertTrue(self.apt_install.called)

    def test_config_changed_nodvr_disprouters(self):
        self.neutron_ready.return_value = True
        self.dvr_router_present.return_value = True
        self.get_dvr.return_value = False
        with self.assertRaises(Exception) as context:
            self._call_hook('config-changed')
        self.assertEqual(context.exception.message,
                         'Cannot disable dvr while dvr enabled routers exist.'
                         ' Please remove any distributed routers')

    def test_config_changed_nol3ha_harouters(self):
        self.neutron_ready.return_value = True
        self.dvr_router_present.return_value = False
        self.l3ha_router_present.return_value = True
        self.get_l3ha.return_value = False
        with self.assertRaises(Exception) as context:
            self._call_hook('config-changed')
        self.assertEqual(context.exception.message,
                         'Cannot disable Router HA while ha enabled routers'
                         ' exist. Please remove any ha routers')

    @patch.object(hooks, 'configure_https')
    @patch.object(hooks, 'git_install_requested')
    @patch.object(hooks, 'config_value_changed')
    def test_config_changed_git(self, config_val_changed, git_requested,
                                configure_https):
        git_requested.return_value = True
        self.neutron_ready.return_value = True
        self.dvr_router_present.return_value = False
        self.l3ha_router_present.return_value = False
        self.relation_ids.side_effect = self._fake_relids
        _n_api_rel_joined = self.patch('neutron_api_relation_joined')
        _n_plugin_api_rel_joined =\
            self.patch('neutron_plugin_api_relation_joined')
        _amqp_rel_joined = self.patch('amqp_joined')
        _id_rel_joined = self.patch('identity_joined')
        _id_cluster_joined = self.patch('cluster_joined')
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
        self.assertTrue(self.apt_install.called)
        self.assertTrue(configure_https.called)
        self.assertTrue(self.update_nrpe_config.called)
        self.assertTrue(self.CONFIGS.write_all.called)
        self.assertTrue(_n_api_rel_joined.called)
        self.assertTrue(_n_plugin_api_rel_joined.called)
        self.assertTrue(_amqp_rel_joined.called)
        self.assertTrue(_id_rel_joined.called)
        self.assertTrue(_zmq_joined.called)
        self.assertTrue(_id_cluster_joined.called)

    @patch.object(hooks, 'git_install_requested')
    def test_config_changed_with_openstack_upgrade_action(self, git_requested):
        git_requested.return_value = False
        self.openstack_upgrade_available.return_value = True
        self.test_config.set('action-managed-upgrade', True)

        self._call_hook('config-changed')

        self.assertFalse(self.do_openstack_upgrade.called)

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

    def test_db_joined(self):
        self.is_relation_made.return_value = False
        self.unit_get.return_value = 'myhostname'
        self._call_hook('shared-db-relation-joined')
        self.relation_set.assert_called_with(
            username='neutron',
            database='neutron',
            hostname='myhostname',
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
            database='neutron',
        )

    def test_postgresql_joined_with_db(self):
        self.is_relation_made.return_value = True

        with self.assertRaises(Exception) as context:
            hooks.pgsql_neutron_db_joined()
        self.assertEqual(context.exception.message,
                         'Attempting to associate a postgresql database when'
                         ' there is already associated a mysql one')

    @patch.object(hooks, 'conditional_neutron_migration')
    def test_shared_db_changed(self, cond_neutron_mig):
        self.CONFIGS.complete_contexts.return_value = ['shared-db']
        self._call_hook('shared-db-relation-changed')
        self.assertTrue(self.CONFIGS.write_all.called)
        cond_neutron_mig.assert_called_with()

    def test_shared_db_changed_partial_ctxt(self):
        self.CONFIGS.complete_contexts.return_value = []
        self._call_hook('shared-db-relation-changed')
        self.assertFalse(self.CONFIGS.write_all.called)

    @patch.object(hooks, 'conditional_neutron_migration')
    def test_pgsql_db_changed(self, cond_neutron_mig):
        self._call_hook('pgsql-db-relation-changed')
        self.assertTrue(self.CONFIGS.write.called)
        cond_neutron_mig.assert_called_with()

    def test_amqp_broken(self):
        self._call_hook('amqp-relation-broken')
        self.assertTrue(self.CONFIGS.write_all.called)

    @patch.object(hooks, 'canonical_url')
    def test_identity_joined(self, _canonical_url):
        _canonical_url.return_value = 'http://127.0.0.1'
        self.api_port.return_value = '9696'
        self.test_config.set('region', 'region1')
        _neutron_url = 'http://127.0.0.1:9696'
        _endpoints = {
            'quantum_service': 'quantum',
            'quantum_region': 'region1',
            'quantum_public_url': _neutron_url,
            'quantum_admin_url': _neutron_url,
            'quantum_internal_url': _neutron_url,
        }
        self._call_hook('identity-service-relation-joined')
        self.relation_set.assert_called_with(
            relation_id=None,
            relation_settings=_endpoints
        )

    @patch('charmhelpers.contrib.openstack.ip.service_name',
           lambda *args: 'neutron-api')
    @patch('charmhelpers.contrib.openstack.ip.unit_get')
    @patch('charmhelpers.contrib.openstack.ip.is_clustered')
    @patch('charmhelpers.contrib.openstack.ip.config')
    def test_identity_changed_public_name(self, _config, _is_clustered,
                                          _unit_get):
        _unit_get.return_value = '127.0.0.1'
        _is_clustered.return_value = False
        _config.side_effect = self.test_config.get
        self.api_port.return_value = '9696'
        self.test_config.set('region', 'region1')
        self.test_config.set('os-public-hostname',
                             'neutron-api.example.com')
        self._call_hook('identity-service-relation-joined')
        _neutron_url = 'http://127.0.0.1:9696'
        _endpoints = {
            'quantum_service': 'quantum',
            'quantum_region': 'region1',
            'quantum_public_url': 'http://neutron-api.example.com:9696',
            'quantum_admin_url': _neutron_url,
            'quantum_internal_url': _neutron_url,
        }
        self.relation_set.assert_called_with(
            relation_id=None,
            relation_settings=_endpoints
        )

    def test_identity_changed_partial_ctxt(self):
        self.CONFIGS.complete_contexts.return_value = []
        _api_rel_joined = self.patch('neutron_api_relation_joined')
        self.relation_ids.side_effect = self._fake_relids
        self._call_hook('identity-service-relation-changed')
        self.assertFalse(_api_rel_joined.called)

    @patch.object(hooks, 'configure_https')
    def test_identity_changed(self, conf_https):
        self.CONFIGS.complete_contexts.return_value = ['identity-service']
        _api_rel_joined = self.patch('neutron_api_relation_joined')
        self.relation_ids.side_effect = self._fake_relids
        self._call_hook('identity-service-relation-changed')
        self.assertTrue(self.CONFIGS.write.called_with(NEUTRON_CONF))
        self.assertTrue(_api_rel_joined.called)

    @patch.object(hooks, 'canonical_url')
    def test_neutron_api_relation_no_id_joined(self, _canonical_url):
        host = 'http://127.0.0.1'
        port = 1234
        _id_rel_joined = self.patch('identity_joined')
        self.relation_ids.side_effect = self._fake_relids
        _canonical_url.return_value = host
        self.api_port.return_value = port
        self.is_relation_made = False
        neutron_url = '%s:%s' % (host, port)
        _relation_data = {
            'neutron-plugin': 'ovs',
            'neutron-url': neutron_url,
            'neutron-security-groups': 'no',
        }
        self._call_hook('neutron-api-relation-joined')
        self.relation_set.assert_called_with(
            relation_id=None,
            **_relation_data
        )
        self.assertTrue(_id_rel_joined.called)
        self.test_config.set('neutron-security-groups', True)
        self._call_hook('neutron-api-relation-joined')
        _relation_data['neutron-security-groups'] = 'yes'
        self.relation_set.assert_called_with(
            relation_id=None,
            **_relation_data
        )

    @patch.object(hooks, 'canonical_url')
    def test_neutron_api_relation_joined(self, _canonical_url):
        host = 'http://127.0.0.1'
        port = 1234
        _canonical_url.return_value = host
        self.api_port.return_value = port
        self.is_relation_made = True
        neutron_url = '%s:%s' % (host, port)
        _relation_data = {
            'neutron-plugin': 'ovs',
            'neutron-url': neutron_url,
            'neutron-security-groups': 'no',
        }
        self._call_hook('neutron-api-relation-joined')
        self.relation_set.assert_called_with(
            relation_id=None,
            **_relation_data
        )

    def test_neutron_api_relation_changed(self):
        self.CONFIGS.complete_contexts.return_value = ['shared-db']
        self._call_hook('neutron-api-relation-changed')
        self.assertTrue(self.CONFIGS.write.called_with(NEUTRON_CONF))

    def test_neutron_api_relation_changed_incomplere_ctxt(self):
        self.CONFIGS.complete_contexts.return_value = []
        self._call_hook('neutron-api-relation-changed')
        self.assertTrue(self.CONFIGS.write.called_with(NEUTRON_CONF))

    def test_neutron_plugin_api_relation_joined_nol2(self):
        self.unit_get.return_value = '172.18.18.18'
        self.IdentityServiceContext.return_value = \
            DummyContext(return_value={})
        _relation_data = {
            'neutron-security-groups': False,
            'enable-dvr': False,
            'enable-l3ha': False,
            'addr': '172.18.18.18',
            'l2-population': False,
            'overlay-network-type': 'vxlan',
            'service_protocol': None,
            'auth_protocol': None,
            'service_tenant': None,
            'service_port': None,
            'region': 'RegionOne',
            'service_password': None,
            'auth_port': None,
            'auth_host': None,
            'service_username': None,
            'service_host': None
        }
        self.get_dvr.return_value = False
        self.get_l3ha.return_value = False
        self.get_l2population.return_value = False
        self.get_overlay_network_type.return_value = 'vxlan'
        self._call_hook('neutron-plugin-api-relation-joined')
        self.relation_set.assert_called_with(
            relation_id=None,
            **_relation_data
        )

    def test_neutron_plugin_api_relation_joined_dvr(self):
        self.unit_get.return_value = '172.18.18.18'
        self.IdentityServiceContext.return_value = \
            DummyContext(return_value={})
        _relation_data = {
            'neutron-security-groups': False,
            'enable-dvr': True,
            'enable-l3ha': False,
            'addr': '172.18.18.18',
            'l2-population': True,
            'overlay-network-type': 'vxlan',
            'service_protocol': None,
            'auth_protocol': None,
            'service_tenant': None,
            'service_port': None,
            'region': 'RegionOne',
            'service_password': None,
            'auth_port': None,
            'auth_host': None,
            'service_username': None,
            'service_host': None
        }
        self.get_dvr.return_value = True
        self.get_l3ha.return_value = False
        self.get_l2population.return_value = True
        self.get_overlay_network_type.return_value = 'vxlan'
        self._call_hook('neutron-plugin-api-relation-joined')
        self.relation_set.assert_called_with(
            relation_id=None,
            **_relation_data
        )

    def test_neutron_plugin_api_relation_joined_l3ha(self):
        self.unit_get.return_value = '172.18.18.18'
        self.IdentityServiceContext.return_value = \
            DummyContext(return_value={})
        _relation_data = {
            'neutron-security-groups': False,
            'enable-dvr': False,
            'enable-l3ha': True,
            'addr': '172.18.18.18',
            'l2-population': False,
            'overlay-network-type': 'vxlan',
            'service_protocol': None,
            'auth_protocol': None,
            'service_tenant': None,
            'service_port': None,
            'region': 'RegionOne',
            'service_password': None,
            'auth_port': None,
            'auth_host': None,
            'service_username': None,
            'service_host': None
        }
        self.get_dvr.return_value = False
        self.get_l3ha.return_value = True
        self.get_l2population.return_value = False
        self.get_overlay_network_type.return_value = 'vxlan'
        self._call_hook('neutron-plugin-api-relation-joined')
        self.relation_set.assert_called_with(
            relation_id=None,
            **_relation_data
        )

    def test_neutron_plugin_api_relation_joined_w_mtu(self):
        self.unit_get.return_value = '172.18.18.18'
        self.IdentityServiceContext.return_value = \
            DummyContext(return_value={})
        self.test_config.set('network-device-mtu', 1500)
        _relation_data = {
            'neutron-security-groups': False,
            'addr': '172.18.18.18',
            'l2-population': False,
            'overlay-network-type': 'vxlan',
            'network-device-mtu': 1500,
            'enable-l3ha': True,
            'enable-dvr': True,
            'service_protocol': None,
            'auth_protocol': None,
            'service_tenant': None,
            'service_port': None,
            'region': 'RegionOne',
            'service_password': None,
            'auth_port': None,
            'auth_host': None,
            'service_username': None,
            'service_host': None
        }
        self.get_dvr.return_value = True
        self.get_l3ha.return_value = True
        self.get_l2population.return_value = False
        self.get_overlay_network_type.return_value = 'vxlan'
        self._call_hook('neutron-plugin-api-relation-joined')
        self.relation_set.assert_called_with(
            relation_id=None,
            **_relation_data
        )

    def test_cluster_changed(self):
        self._call_hook('cluster-relation-changed')
        self.assertTrue(self.CONFIGS.write_all.called)

    @patch.object(hooks, 'get_hacluster_config')
    def test_ha_joined(self, _get_ha_config):
        _ha_config = {
            'vip': '10.0.0.1',
            'vip_cidr': '24',
            'vip_iface': 'eth0',
            'ha-bindiface': 'eth1',
            'ha-mcastport': '5405',
        }
        vip_params = 'params ip="%s" cidr_netmask="255.255.255.0" nic="%s"' % \
                     (_ha_config['vip'], _ha_config['vip_iface'])
        _get_ha_config.return_value = _ha_config
        self.get_iface_for_address.return_value = 'eth0'
        self.get_netmask_for_address.return_value = '255.255.255.0'
        _relation_data = {
            'init_services': {'res_neutron_haproxy': 'haproxy'},
            'corosync_bindiface': _ha_config['ha-bindiface'],
            'corosync_mcastport': _ha_config['ha-mcastport'],
            'resources': {
                'res_neutron_eth0_vip': 'ocf:heartbeat:IPaddr2',
                'res_neutron_haproxy': 'lsb:haproxy'
            },
            'resource_params': {
                'res_neutron_eth0_vip': vip_params,
                'res_neutron_haproxy': 'op monitor interval="5s"'
            },
            'clones': {'cl_nova_haproxy': 'res_neutron_haproxy'}
        }
        self._call_hook('ha-relation-joined')
        self.relation_set.assert_called_with(
            **_relation_data
        )

    @patch.object(hooks, 'get_hacluster_config')
    def test_ha_joined_no_bound_ip(self, _get_ha_config):
        _ha_config = {
            'vip': '10.0.0.1',
            'ha-bindiface': 'eth1',
            'ha-mcastport': '5405',
        }
        vip_params = 'params ip="10.0.0.1" cidr_netmask="21" nic="eth120"'
        _get_ha_config.return_value = _ha_config
        self.test_config.set('vip_iface', 'eth120')
        self.test_config.set('vip_cidr', '21')
        self.get_iface_for_address.return_value = None
        self.get_netmask_for_address.return_value = None
        _relation_data = {
            'init_services': {'res_neutron_haproxy': 'haproxy'},
            'corosync_bindiface': _ha_config['ha-bindiface'],
            'corosync_mcastport': _ha_config['ha-mcastport'],
            'resources': {
                'res_neutron_eth120_vip': 'ocf:heartbeat:IPaddr2',
                'res_neutron_haproxy': 'lsb:haproxy'
            },
            'resource_params': {
                'res_neutron_eth120_vip': vip_params,
                'res_neutron_haproxy': 'op monitor interval="5s"'
            },
            'clones': {'cl_nova_haproxy': 'res_neutron_haproxy'}
        }
        self._call_hook('ha-relation-joined')
        self.relation_set.assert_called_with(
            **_relation_data
        )

    @patch.object(hooks, 'get_hacluster_config')
    def test_ha_joined_with_ipv6(self, _get_ha_config):
        self.test_config.set('prefer-ipv6', 'True')
        _ha_config = {
            'vip': '2001:db8:1::1',
            'vip_cidr': '64',
            'vip_iface': 'eth0',
            'ha-bindiface': 'eth1',
            'ha-mcastport': '5405',
        }
        vip_params = 'params ipv6addr="%s" ' \
                     'cidr_netmask="ffff.ffff.ffff.ffff" ' \
                     'nic="%s"' % \
                     (_ha_config['vip'], _ha_config['vip_iface'])
        _get_ha_config.return_value = _ha_config
        self.get_iface_for_address.return_value = 'eth0'
        self.get_netmask_for_address.return_value = 'ffff.ffff.ffff.ffff'
        _relation_data = {
            'init_services': {'res_neutron_haproxy': 'haproxy'},
            'corosync_bindiface': _ha_config['ha-bindiface'],
            'corosync_mcastport': _ha_config['ha-mcastport'],
            'resources': {
                'res_neutron_eth0_vip': 'ocf:heartbeat:IPv6addr',
                'res_neutron_haproxy': 'lsb:haproxy'
            },
            'resource_params': {
                'res_neutron_eth0_vip': vip_params,
                'res_neutron_haproxy': 'op monitor interval="5s"'
            },
            'clones': {'cl_nova_haproxy': 'res_neutron_haproxy'}
        }
        self._call_hook('ha-relation-joined')
        self.relation_set.assert_called_with(
            **_relation_data
        )

    def test_ha_changed(self):
        self.test_relation.set({
            'clustered': 'true',
        })
        self.relation_ids.side_effect = self._fake_relids
        _n_api_rel_joined = self.patch('neutron_api_relation_joined')
        _id_rel_joined = self.patch('identity_joined')
        self._call_hook('ha-relation-changed')
        self.assertTrue(_n_api_rel_joined.called)
        self.assertTrue(_id_rel_joined.called)

    def test_ha_changed_not_clustered(self):
        self.test_relation.set({
            'clustered': None,
        })
        self.relation_ids.side_effect = self._fake_relids
        _n_api_rel_joined = self.patch('neutron_api_relation_joined')
        _id_rel_joined = self.patch('identity_joined')
        self._call_hook('ha-relation-changed')
        self.assertFalse(_n_api_rel_joined.called)
        self.assertFalse(_id_rel_joined.called)

    def test_configure_https(self):
        self.CONFIGS.complete_contexts.return_value = ['https']
        self.relation_ids.side_effect = self._fake_relids
        _id_rel_joined = self.patch('identity_joined')
        hooks.configure_https()
        self.check_call.assert_called_with(['a2ensite',
                                            'openstack_https_frontend'])
        self.assertTrue(_id_rel_joined.called)

    def test_configure_https_nohttps(self):
        self.CONFIGS.complete_contexts.return_value = []
        self.relation_ids.side_effect = self._fake_relids
        _id_rel_joined = self.patch('identity_joined')
        hooks.configure_https()
        self.check_call.assert_called_with(['a2dissite',
                                            'openstack_https_frontend'])
        self.assertTrue(_id_rel_joined.called)

    def test_conditional_neutron_migration_icehouse(self):
        self.os_release.return_value = 'icehouse'
        hooks.conditional_neutron_migration()
        self.log.assert_called_with(
            'Not running neutron database migration as migrations are handled '
            'by the neutron-server process or nova-cloud-controller charm.'
        )

    def test_conditional_neutron_migration_ncc_rel_leader_juno(self):
        self.test_relation.set({
            'allowed_units': 'neutron-api/0 neutron-api/1 neutron-api/4',
        })
        self.local_unit.return_value = 'neutron-api/1'
        self.is_elected_leader.return_value = True
        self.os_release.return_value = 'juno'
        hooks.conditional_neutron_migration()
        self.log.assert_called_with(
            'Not running neutron database migration as migrations are handled'
            ' by the neutron-server process or nova-cloud-controller charm.'
        )

    def test_conditional_neutron_migration_ncc_rel_leader_kilo(self):
        self.test_relation.set({
            'allowed_units': 'neutron-api/0 neutron-api/1 neutron-api/4',
        })
        self.local_unit.return_value = 'neutron-api/1'
        self.is_elected_leader.return_value = True
        self.os_release.return_value = 'kilo'
        hooks.conditional_neutron_migration()
        self.migrate_neutron_database.assert_called_with()
        self.service_restart.assert_called_with('neutron-server')

    def test_conditional_neutron_migration_ncc_rel_notleader(self):
        self.is_elected_leader.return_value = False
        self.os_release.return_value = 'juno'
        hooks.conditional_neutron_migration()
        self.assertFalse(self.migrate_neutron_database.called)
        self.assertFalse(self.service_restart.called)
        self.log.assert_called_with(
            'Not running neutron database migration as migrations are handled '
            'by the neutron-server process or nova-cloud-controller charm.'
        )

    def test_etcd_peer_joined(self):
        self._call_hook('etcd-proxy-relation-joined')
        self.assertTrue(self.CONFIGS.register.called)
        self.CONFIGS.write.assert_called_with('/etc/init/etcd.conf')
