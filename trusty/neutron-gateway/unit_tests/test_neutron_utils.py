from mock import MagicMock, call, patch
import collections
import charmhelpers.contrib.openstack.templating as templating

templating.OSConfigRenderer = MagicMock()

import neutron_utils


try:
    import neutronclient
except ImportError:
    neutronclient = None

from test_utils import (
    CharmTestCase
)

import charmhelpers.core.hookenv as hookenv


TO_PATCH = [
    'config',
    'get_os_codename_install_source',
    'get_os_codename_package',
    'apt_update',
    'apt_upgrade',
    'apt_install',
    'configure_installation_source',
    'log',
    'add_bridge',
    'add_bridge_port',
    'networking_name',
    'headers_package',
    'full_restart',
    'service_running',
    'NetworkServiceContext',
    'ExternalPortContext',
    'unit_private_ip',
    'relations_of_type',
    'service_stop',
    'determine_dkms_package',
    'service_restart',
    'remap_plugin',
    'is_relation_made',
    'lsb_release',
    'mkdir',
    'copy2',
    'NeutronAPIContext',
]

openstack_origin_git = \
    """repositories:
         - {name: requirements,
            repository: 'git://git.openstack.org/openstack/requirements',
            branch: stable/juno}
         - {name: neutron,
            repository: 'git://git.openstack.org/openstack/neutron',
            branch: stable/juno}"""


class TestQuantumUtils(CharmTestCase):

    def assertDictEqual(self, d1, d2, msg=None):  # assertEqual uses for dicts
        for k, v1 in d1.iteritems():
            self.assertIn(k, d2, msg)
            v2 = d2[k]
            if(isinstance(v1, collections.Iterable) and
               not isinstance(v1, basestring)):
                self.assertItemsEqual(v1, v2, msg)
            else:
                self.assertEqual(v1, v2, msg)

    def setUp(self):
        super(TestQuantumUtils, self).setUp(neutron_utils, TO_PATCH)
        self.networking_name.return_value = 'neutron'
        self.headers_package.return_value = 'linux-headers-2.6.18'
        self._set_distrib_codename('trusty')

        def noop(value):
            return value
        self.remap_plugin.side_effect = noop

    def tearDown(self):
        # Reset cached cache
        hookenv.cache = {}

    def _set_distrib_codename(self, newcodename):
        self.lsb_release.return_value = {'DISTRIB_CODENAME': newcodename}

    def test_valid_plugin(self):
        self.config.return_value = 'ovs'
        self.assertTrue(neutron_utils.valid_plugin())
        self.config.return_value = 'nvp'
        self.assertTrue(neutron_utils.valid_plugin())
        self.config.return_value = 'nsx'
        self.assertTrue(neutron_utils.valid_plugin())

    def test_invalid_plugin(self):
        self.config.return_value = 'invalid'
        self.assertFalse(neutron_utils.valid_plugin())

    def test_get_early_packages_ovs(self):
        self.config.return_value = 'ovs'
        self.determine_dkms_package.return_value = [
            'openvswitch-datapath-dkms']
        self.assertEquals(
            neutron_utils.get_early_packages(),
            ['openvswitch-datapath-dkms', 'linux-headers-2.6.18'])

    def test_get_early_packages_nvp(self):
        self.config.return_value = 'nvp'
        self.assertEquals(
            neutron_utils.get_early_packages(),
            [])

    def test_get_early_packages_empty(self):
        self.config.return_value = 'noop'
        self.assertEquals(neutron_utils.get_early_packages(),
                          [])

    @patch.object(neutron_utils, 'git_install_requested')
    def test_get_packages_ovs(self, git_requested):
        git_requested.return_value = False
        self.config.return_value = 'ovs'
        self.get_os_codename_install_source.return_value = 'havana'
        self.assertNotEqual(neutron_utils.get_packages(), [])

    @patch.object(neutron_utils, 'git_install_requested')
    def test_get_packages_ovs_icehouse(self, git_requested):
        git_requested.return_value = False
        self.config.return_value = 'ovs'
        self.get_os_codename_install_source.return_value = 'icehouse'
        self.assertTrue('neutron-vpn-agent' in neutron_utils.get_packages())
        self.assertFalse('neutron-l3-agent' in neutron_utils.get_packages())

    @patch.object(neutron_utils, 'git_install_requested')
    def test_get_packages_ovs_juno_utopic(self, git_requested):
        git_requested.return_value = False
        self.config.return_value = 'ovs'
        self.get_os_codename_install_source.return_value = 'juno'
        self._set_distrib_codename('utopic')
        self.assertFalse('neutron-vpn-agent' in neutron_utils.get_packages())
        self.assertTrue('neutron-l3-agent' in neutron_utils.get_packages())

    @patch.object(neutron_utils, 'git_install_requested')
    def test_get_packages_ovs_juno_trusty(self, git_requested):
        git_requested.return_value = False
        self.config.return_value = 'ovs'
        self.get_os_codename_install_source.return_value = 'juno'
        self.assertTrue('neutron-vpn-agent' in neutron_utils.get_packages())
        self.assertFalse('neutron-l3-agent' in neutron_utils.get_packages())

    @patch.object(neutron_utils, 'git_install_requested')
    def test_get_packages_ovs_kilo(self, git_requested):
        git_requested.return_value = False
        self.config.return_value = 'ovs'
        self.get_os_codename_install_source.return_value = 'kilo'
        self.assertTrue('python-neutron-fwaas' in neutron_utils.get_packages())

    @patch.object(neutron_utils, 'git_install_requested')
    def test_get_packages_ovs_liberty(self, git_requested):
        git_requested.return_value = False
        self.config.return_value = 'ovs'
        self.get_os_codename_install_source.return_value = 'liberty'
        packages = neutron_utils.get_packages()
        self.assertTrue('neutron-metering-agent' in packages)
        self.assertFalse('neutron-plugin-metering-agent' in packages)
        self.assertFalse('python-mysqldb' in packages)
        self.assertTrue('python-pymysql' in packages)

    @patch.object(neutron_utils, 'git_install_requested')
    def test_get_packages_l3ha(self, git_requested):
        git_requested.return_value = False
        self.config.return_value = 'ovs'
        self.get_os_codename_install_source.return_value = 'juno'
        self.assertTrue('keepalived' in neutron_utils.get_packages())

    @patch('charmhelpers.contrib.openstack.context.config')
    def test_configure_ovs_starts_service_if_required(self, mock_config):
        mock_config.side_effect = self.test_config.get
        self.config.return_value = 'ovs'
        self.service_running.return_value = False
        neutron_utils.configure_ovs()
        self.assertTrue(self.full_restart.called)

    def test_configure_ovs_doesnt_restart_service(self):
        self.service_running.return_value = True
        neutron_utils.configure_ovs()
        self.assertFalse(self.full_restart.called)

    @patch('charmhelpers.contrib.openstack.context.config')
    def test_configure_ovs_ovs_ext_port(self, mock_config):
        mock_config.side_effect = self.test_config.get
        self.config.side_effect = self.test_config.get
        self.test_config.set('plugin', 'ovs')
        self.test_config.set('ext-port', 'eth0')
        self.ExternalPortContext.return_value = \
            DummyExternalPortContext(return_value={'ext_port': 'eth0'})
        neutron_utils.configure_ovs()
        self.add_bridge.assert_has_calls([
            call('br-int'),
            call('br-ex'),
            call('br-data')
        ])
        self.add_bridge_port.assert_called_with('br-ex', 'eth0')

    @patch('charmhelpers.contrib.openstack.context.config')
    def test_configure_ovs_ovs_data_port(self, mock_config):
        mock_config.side_effect = self.test_config.get
        self.config.side_effect = self.test_config.get
        self.test_config.set('plugin', 'ovs')
        self.ExternalPortContext.return_value = \
            DummyExternalPortContext(return_value=None)
        # Test back-compatibility i.e. port but no bridge (so br-data is
        # assumed)
        self.test_config.set('data-port', 'eth0')
        neutron_utils.configure_ovs()
        self.add_bridge.assert_has_calls([
            call('br-int'),
            call('br-ex'),
            call('br-data')
        ])
        calls = [call('br-data', 'eth0', promisc=True)]
        self.add_bridge_port.assert_has_calls(calls)

        # Now test with bridge:port format and bogus bridge
        self.test_config.set('data-port', 'br-foo:eth0')
        self.add_bridge.reset_mock()
        self.add_bridge_port.reset_mock()
        neutron_utils.configure_ovs()
        self.add_bridge.assert_has_calls([
            call('br-int'),
            call('br-ex'),
            call('br-data')
        ])
        # Not called since we have a bogus bridge in data-ports
        self.assertFalse(self.add_bridge_port.called)

        # Now test with bridge:port format
        self.test_config.set('bridge-mappings', 'net1:br1')
        self.test_config.set('data-port', 'br1:eth0.100 br1:eth0.200')
        self.add_bridge.reset_mock()
        self.add_bridge_port.reset_mock()
        neutron_utils.configure_ovs()
        self.add_bridge.assert_has_calls([
            call('br-int'),
            call('br-ex'),
            call('br1')
        ])
        calls = [call('br1', 'eth0.100', promisc=True),
                 call('br1', 'eth0.200', promisc=True)]
        self.add_bridge_port.assert_has_calls(calls)

    @patch.object(neutron_utils, 'git_install_requested')
    def test_do_openstack_upgrade(self, git_requested):
        git_requested.return_value = False
        self.config.side_effect = self.test_config.get
        self.is_relation_made.return_value = False
        self.test_config.set('openstack-origin', 'cloud:precise-havana')
        self.test_config.set('plugin', 'ovs')
        self.get_os_codename_install_source.return_value = 'havana'
        configs = neutron_utils.register_configs()
        neutron_utils.do_openstack_upgrade(configs)
        self.assertTrue(self.log.called)
        self.apt_update.assert_called_with(fatal=True)
        dpkg_opts = [
            '--option', 'Dpkg::Options::=--force-confnew',
            '--option', 'Dpkg::Options::=--force-confdef',
        ]
        self.apt_upgrade.assert_called_with(
            options=dpkg_opts, fatal=True, dist=True
        )
        self.configure_installation_source.assert_called_with(
            'cloud:precise-havana'
        )

    def test_register_configs_ovs(self):
        self.config.return_value = 'ovs'
        self.is_relation_made.return_value = False
        configs = neutron_utils.register_configs()
        confs = [neutron_utils.NEUTRON_DHCP_AGENT_CONF,
                 neutron_utils.NEUTRON_METADATA_AGENT_CONF,
                 neutron_utils.NOVA_CONF,
                 neutron_utils.NEUTRON_CONF,
                 neutron_utils.NEUTRON_L3_AGENT_CONF,
                 neutron_utils.NEUTRON_OVS_PLUGIN_CONF,
                 neutron_utils.EXT_PORT_CONF]
        for conf in confs:
            configs.register.assert_any_call(
                conf,
                neutron_utils.CONFIG_FILES['neutron'][neutron_utils.OVS][conf]
                                          ['hook_contexts']
            )

    def test_register_configs_ovs_odl(self):
        self.config.side_effect = self.test_config.get
        self.test_config.set('plugin', 'ovs-odl')
        self.is_relation_made.return_value = False
        self.get_os_codename_install_source.return_value = 'icehouse'
        configs = neutron_utils.register_configs()
        confs = [neutron_utils.NEUTRON_DHCP_AGENT_CONF,
                 neutron_utils.NEUTRON_METADATA_AGENT_CONF,
                 neutron_utils.NOVA_CONF,
                 neutron_utils.NEUTRON_CONF,
                 neutron_utils.NEUTRON_L3_AGENT_CONF,
                 neutron_utils.EXT_PORT_CONF]
        for conf in confs:
            configs.register.assert_any_call(
                conf,
                neutron_utils.CONFIG_FILES['neutron']
                                          [neutron_utils.OVS_ODL][conf]
                                          ['hook_contexts']
            )

    def test_register_configs_amqp_nova(self):
        self.config.return_value = 'ovs'
        self.is_relation_made.return_value = True
        configs = neutron_utils.register_configs()
        confs = [neutron_utils.NEUTRON_DHCP_AGENT_CONF,
                 neutron_utils.NEUTRON_METADATA_AGENT_CONF,
                 neutron_utils.NOVA_CONF,
                 neutron_utils.NEUTRON_CONF,
                 neutron_utils.NEUTRON_L3_AGENT_CONF,
                 neutron_utils.NEUTRON_OVS_PLUGIN_CONF,
                 neutron_utils.EXT_PORT_CONF]
        for conf in confs:
            configs.register.assert_any_call(
                conf,
                neutron_utils.CONFIG_FILES['neutron'][neutron_utils.OVS][conf]
                                          ['hook_contexts']
            )

    def test_restart_map_ovs(self):
        self.config.return_value = 'ovs'
        self.get_os_codename_install_source.return_value = 'havana'
        ex_map = {
            neutron_utils.NEUTRON_CONF: ['neutron-l3-agent',
                                         'neutron-dhcp-agent',
                                         'neutron-metadata-agent',
                                         'neutron-plugin-openvswitch-agent',
                                         'neutron-plugin-metering-agent',
                                         'neutron-metering-agent',
                                         'neutron-lbaas-agent',
                                         'neutron-plugin-vpn-agent',
                                         'neutron-vpn-agent'],
            neutron_utils.NEUTRON_DNSMASQ_CONF: ['neutron-dhcp-agent'],
            neutron_utils.NEUTRON_LBAAS_AGENT_CONF:
            ['neutron-lbaas-agent'],
            neutron_utils.NEUTRON_OVS_PLUGIN_CONF:
            ['neutron-plugin-openvswitch-agent'],
            neutron_utils.NEUTRON_METADATA_AGENT_CONF:
            ['neutron-metadata-agent'],
            neutron_utils.NEUTRON_VPNAAS_AGENT_CONF: [
                'neutron-plugin-vpn-agent',
                'neutron-vpn-agent'],
            neutron_utils.NEUTRON_L3_AGENT_CONF: ['neutron-l3-agent',
                                                  'neutron-vpn-agent'],
            neutron_utils.NEUTRON_DHCP_AGENT_CONF: ['neutron-dhcp-agent'],
            neutron_utils.NEUTRON_FWAAS_CONF: ['neutron-l3-agent',
                                               'neutron-vpn-agent'],
            neutron_utils.NEUTRON_METERING_AGENT_CONF:
            ['neutron-metering-agent', 'neutron-plugin-metering-agent'],
            neutron_utils.NOVA_CONF: ['nova-api-metadata'],
            neutron_utils.EXT_PORT_CONF: ['ext-port'],
            neutron_utils.PHY_NIC_MTU_CONF: ['os-charm-phy-nic-mtu'],
        }

        self.assertDictEqual(neutron_utils.restart_map(), ex_map)

    def test_restart_map_ovs_odl(self):
        self.config.return_value = 'ovs-odl'
        self.get_os_codename_install_source.return_value = 'icehouse'
        ex_map = {
            neutron_utils.NEUTRON_CONF: ['neutron-l3-agent',
                                         'neutron-dhcp-agent',
                                         'neutron-metadata-agent',
                                         'neutron-plugin-metering-agent',
                                         'neutron-metering-agent',
                                         'neutron-lbaas-agent',
                                         'neutron-plugin-vpn-agent',
                                         'neutron-vpn-agent'],
            neutron_utils.NEUTRON_DNSMASQ_CONF: ['neutron-dhcp-agent'],
            neutron_utils.NEUTRON_LBAAS_AGENT_CONF:
            ['neutron-lbaas-agent'],
            neutron_utils.NEUTRON_METADATA_AGENT_CONF:
            ['neutron-metadata-agent'],
            neutron_utils.NEUTRON_VPNAAS_AGENT_CONF: [
                'neutron-plugin-vpn-agent',
                'neutron-vpn-agent'],
            neutron_utils.NEUTRON_L3_AGENT_CONF: ['neutron-l3-agent',
                                                  'neutron-vpn-agent'],
            neutron_utils.NEUTRON_DHCP_AGENT_CONF: ['neutron-dhcp-agent'],
            neutron_utils.NEUTRON_FWAAS_CONF: ['neutron-l3-agent',
                                               'neutron-vpn-agent'],
            neutron_utils.NEUTRON_METERING_AGENT_CONF:
            ['neutron-metering-agent', 'neutron-plugin-metering-agent'],
            neutron_utils.NOVA_CONF: ['nova-api-metadata'],
            neutron_utils.EXT_PORT_CONF: ['ext-port'],
            neutron_utils.PHY_NIC_MTU_CONF: ['os-charm-phy-nic-mtu'],
        }

        self.assertDictEqual(neutron_utils.restart_map(), ex_map)

    def test_register_configs_nvp(self):
        self.config.return_value = 'nvp'
        self.is_relation_made.return_value = False
        configs = neutron_utils.register_configs()
        confs = [neutron_utils.NEUTRON_DHCP_AGENT_CONF,
                 neutron_utils.NEUTRON_METADATA_AGENT_CONF,
                 neutron_utils.NOVA_CONF,
                 neutron_utils.NEUTRON_CONF]
        for conf in confs:
            configs.register.assert_any_call(
                conf,
                neutron_utils.CONFIG_FILES['neutron'][neutron_utils.NVP][conf]
                                          ['hook_contexts']
            )

    def test_register_configs_nsx(self):
        self.config.return_value = 'nsx'
        configs = neutron_utils.register_configs()
        confs = [neutron_utils.NEUTRON_DHCP_AGENT_CONF,
                 neutron_utils.NEUTRON_METADATA_AGENT_CONF,
                 neutron_utils.NOVA_CONF,
                 neutron_utils.NEUTRON_CONF]
        for conf in confs:
            configs.register.assert_any_call(
                conf,
                neutron_utils.CONFIG_FILES['neutron'][neutron_utils.NSX][conf]
                                          ['hook_contexts']
            )

    def test_stop_services_nvp(self):
        self.config.return_value = 'nvp'
        neutron_utils.stop_services()
        calls = [
            call('neutron-dhcp-agent'),
            call('nova-api-metadata'),
            call('neutron-metadata-agent')
        ]
        self.service_stop.assert_has_calls(
            calls,
            any_order=True,
        )

    def test_stop_services_ovs(self):
        self.config.return_value = 'ovs'
        neutron_utils.stop_services()
        calls = [call('neutron-dhcp-agent'),
                 call('neutron-plugin-openvswitch-agent'),
                 call('nova-api-metadata'),
                 call('neutron-l3-agent'),
                 call('neutron-metadata-agent')]
        self.service_stop.assert_has_calls(
            calls,
            any_order=True,
        )

    def test_restart_map_nvp(self):
        self.config.return_value = 'nvp'
        ex_map = {
            neutron_utils.NEUTRON_DHCP_AGENT_CONF: ['neutron-dhcp-agent'],
            neutron_utils.NEUTRON_DNSMASQ_CONF: ['neutron-dhcp-agent'],
            neutron_utils.NOVA_CONF: ['nova-api-metadata'],
            neutron_utils.NEUTRON_CONF: ['neutron-dhcp-agent',
                                         'neutron-metadata-agent'],
            neutron_utils.NEUTRON_METADATA_AGENT_CONF:
            ['neutron-metadata-agent'],
        }
        self.assertEquals(neutron_utils.restart_map(), ex_map)

    def test_register_configs_pre_install(self):
        self.config.return_value = 'ovs'
        self.is_relation_made.return_value = False
        self.networking_name.return_value = 'quantum'
        configs = neutron_utils.register_configs()
        confs = [neutron_utils.QUANTUM_DHCP_AGENT_CONF,
                 neutron_utils.QUANTUM_METADATA_AGENT_CONF,
                 neutron_utils.NOVA_CONF,
                 neutron_utils.QUANTUM_CONF,
                 neutron_utils.QUANTUM_L3_AGENT_CONF,
                 neutron_utils.QUANTUM_OVS_PLUGIN_CONF,
                 neutron_utils.EXT_PORT_CONF]
        print configs.register.mock_calls
        for conf in confs:
            configs.register.assert_any_call(
                conf,
                neutron_utils.CONFIG_FILES['quantum'][neutron_utils.OVS][conf]
                                          ['hook_contexts']
            )

    def test_get_common_package_quantum(self):
        self.get_os_codename_package.return_value = 'folsom'
        self.assertEquals(neutron_utils.get_common_package(), 'quantum-common')

    def test_get_common_package_neutron(self):
        self.get_os_codename_package.return_value = None
        self.assertEquals(neutron_utils.get_common_package(), 'neutron-common')

    def test_copy_file_without_update(self):
        src = 'dummy_source_dir/dummy_file'
        dst = 'dummy_des_dir'
        neutron_utils.copy_file(src, dst)
        self.assertTrue(self.mkdir.called)
        self.assertTrue(self.copy2.called)

    @patch('neutron_utils.os.path.isfile')
    def test_copy_file_with_update(self, _isfile):
        src = 'dummy_source_dir/dummy_file'
        dst = 'dummy_des_dir'
        _isfile.return_value = False
        neutron_utils.copy_file(src, dst, force=True)
        self.assertTrue(self.mkdir.called)
        self.assertTrue(self.copy2.called)

    @patch('neutron_utils.os.remove')
    @patch('neutron_utils.os.path.isfile')
    def test_remove_file_exists(self, _isfile, _remove):
        path = 'dummy_des_dir/dummy_file'
        _isfile.return_value = True
        neutron_utils.remove_file(path)
        self.assertTrue(_remove.called)
        self.assertFalse(self.log.called)

    @patch('neutron_utils.os.remove')
    @patch('neutron_utils.os.path.isfile')
    def test_remove_file_non_exists(self, _isfile, _remove):
        path = 'dummy_des_dir/dummy_file'
        _isfile.return_value = False
        neutron_utils.remove_file(path)
        self.assertFalse(_remove.called)
        self.assertTrue(self.log.called)


network_context = {
    'service_username': 'foo',
    'service_password': 'bar',
    'service_tenant': 'baz',
    'region': 'foo-bar',
    'keystone_host': 'keystone',
    'auth_port': 5000,
    'auth_protocol': 'https'
}


class DummyNetworkServiceContext():

    def __init__(self, return_value):
        self.return_value = return_value

    def __call__(self):
        return self.return_value


class DummyExternalPortContext():

    def __init__(self, return_value):
        self.return_value = return_value

    def __call__(self):
        return self.return_value

agents_all_alive = {
    'DHCP Agent': {
        'agents': [
            {'alive': True,
             'host': 'cluster1-machine1.internal',
             'id': '3e3550f2-38cc-11e3-9617-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster1-machine2.internal',
             'id': '53d6eefc-38cc-11e3-b3c8-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster2-machine1.internal',
             'id': '92b8b6bc-38ce-11e3-8537-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster2-machine3.internal',
             'id': 'ebdcc950-51c8-11e3-a804-1c6f65b044df'},
        ]
    },
    'L3 Agent': {
        'agents': [
            {'alive': True,
             'host': 'cluster1-machine1.internal',
             'id': '7128198e-38ce-11e3-ba78-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster1-machine2.internal',
             'id': '72453824-38ce-11e3-938e-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster2-machine1.internal',
             'id': '84a04126-38ce-11e3-9449-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster2-machine3.internal',
             'id': '00f4268a-51c9-11e3-9177-1c6f65b044df'},
        ]
    }
}

agents_some_dead_cl1 = {
    'DHCP Agent': {
        'agents': [
            {'alive': False,
             'host': 'cluster1-machine1.internal',
             'id': '3e3550f2-38cc-11e3-9617-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster2-machine1.internal',
             'id': '53d6eefc-38cc-11e3-b3c8-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster2-machine2.internal',
             'id': '92b8b6bc-38ce-11e3-8537-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster2-machine3.internal',
             'id': 'ebdcc950-51c8-11e3-a804-1c6f65b044df'},
        ]
    },
    'L3 Agent': {
        'agents': [
            {'alive': False,
             'host': 'cluster1-machine1.internal',
             'id': '7128198e-38ce-11e3-ba78-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster2-machine1.internal',
             'id': '72453824-38ce-11e3-938e-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster2-machine2.internal',
             'id': '84a04126-38ce-11e3-9449-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster2-machine3.internal',
             'id': '00f4268a-51c9-11e3-9177-1c6f65b044df'},
        ]
    }
}

agents_some_dead_cl2 = {
    'DHCP Agent': {
        'agents': [
            {'alive': True,
             'host': 'cluster1-machine1.internal',
             'id': '3e3550f2-38cc-11e3-9617-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster2-machine1.internal',
             'id': '53d6eefc-38cc-11e3-b3c8-3c970e8b1cf7'},
            {'alive': False,
             'host': 'cluster2-machine2.internal',
             'id': '92b8b6bc-38ce-11e3-8537-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster2-machine3.internal',
             'id': 'ebdcc950-51c8-11e3-a804-1c6f65b044df'},
        ]
    },
    'L3 Agent': {
        'agents': [
            {'alive': True,
             'host': 'cluster1-machine1.internal',
             'id': '7128198e-38ce-11e3-ba78-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster2-machine1.internal',
             'id': '72453824-38ce-11e3-938e-3c970e8b1cf7'},
            {'alive': False,
             'host': 'cluster2-machine2.internal',
             'id': '84a04126-38ce-11e3-9449-3c970e8b1cf7'},
            {'alive': True,
             'host': 'cluster2-machine3.internal',
             'id': '00f4268a-51c9-11e3-9177-1c6f65b044df'},
        ]
    }
}

dhcp_agent_networks = {
    'networks': [
        {'id': 'foo'},
        {'id': 'bar'}
    ]
}

l3_agent_routers = {
    'routers': [
        {'id': 'baz'},
        {'id': 'bong'}
    ]
}

cluster1 = ['cluster1-machine1.internal']
cluster2 = ['cluster2-machine1.internal', 'cluster2-machine2.internal'
            'cluster2-machine3.internal']


class TestQuantumAgentReallocation(CharmTestCase):

    def setUp(self):
        if not neutronclient:
            raise self.skipTest('Skipping, no neutronclient installed')
        super(TestQuantumAgentReallocation, self).setUp(neutron_utils,
                                                        TO_PATCH)

    def tearDown(self):
        # Reset cached cache
        hookenv.cache = {}

    def test_no_network_context(self):
        self.NetworkServiceContext.return_value = \
            DummyNetworkServiceContext(return_value=None)
        neutron_utils.reassign_agent_resources()
        self.assertTrue(self.log.called)

    @patch('neutronclient.v2_0.client.Client')
    def test_no_down_agents(self, _client):
        self.NetworkServiceContext.return_value = \
            DummyNetworkServiceContext(return_value=network_context)
        dummy_client = MagicMock()
        dummy_client.list_agents.side_effect = agents_all_alive.itervalues()
        _client.return_value = dummy_client
        neutron_utils.reassign_agent_resources()
        dummy_client.add_router_to_l3_agent.assert_not_called()
        dummy_client.remove_router_from_l3_agent.assert_not_called()
        dummy_client.add_network_to_dhcp_agent.assert_not_called()
        dummy_client.remove_network_from_dhcp_agent.assert_not_called()

    @patch('neutronclient.v2_0.client.Client')
    def test_agents_down_relocation_required(self, _client):
        self.NetworkServiceContext.return_value = \
            DummyNetworkServiceContext(return_value=network_context)
        dummy_client = MagicMock()
        dummy_client.list_agents.side_effect = \
            agents_some_dead_cl2.itervalues()
        dummy_client.list_networks_on_dhcp_agent.return_value = \
            dhcp_agent_networks
        dummy_client.list_routers_on_l3_agent.return_value = \
            l3_agent_routers
        _client.return_value = dummy_client
        self.unit_private_ip.return_value = 'cluster2-machine1.internal'
        self.relations_of_type.return_value = \
            [{'private-address': 'cluster2-machine3.internal'}]
        neutron_utils.reassign_agent_resources()

        # Ensure routers removed from dead l3 agent
        dummy_client.remove_router_from_l3_agent.assert_has_calls(
            [call(l3_agent='84a04126-38ce-11e3-9449-3c970e8b1cf7',
                  router_id='bong'),
             call(l3_agent='84a04126-38ce-11e3-9449-3c970e8b1cf7',
                  router_id='baz')], any_order=True)
        # and re-assigned across the remaining two live agents
        dummy_client.add_router_to_l3_agent.assert_has_calls(
            [call(l3_agent='00f4268a-51c9-11e3-9177-1c6f65b044df',
                  body={'router_id': 'baz'}),
             call(l3_agent='72453824-38ce-11e3-938e-3c970e8b1cf7',
                  body={'router_id': 'bong'})], any_order=True)
        # Ensure networks removed from dead dhcp agent
        dummy_client.remove_network_from_dhcp_agent.assert_has_calls(
            [call(dhcp_agent='92b8b6bc-38ce-11e3-8537-3c970e8b1cf7',
                  network_id='foo'),
             call(dhcp_agent='92b8b6bc-38ce-11e3-8537-3c970e8b1cf7',
                  network_id='bar')], any_order=True)
        # and re-assigned across the remaining two live agents
        dummy_client.add_network_to_dhcp_agent.assert_has_calls(
            [call(dhcp_agent='53d6eefc-38cc-11e3-b3c8-3c970e8b1cf7',
                  body={'network_id': 'foo'}),
             call(dhcp_agent='ebdcc950-51c8-11e3-a804-1c6f65b044df',
                  body={'network_id': 'bar'})], any_order=True)

    @patch('neutronclient.v2_0.client.Client')
    def test_agents_down_relocation_impossible(self, _client):
        self.NetworkServiceContext.return_value = \
            DummyNetworkServiceContext(return_value=network_context)
        dummy_client = MagicMock()
        dummy_client.list_agents.side_effect = \
            agents_some_dead_cl1.itervalues()
        dummy_client.list_networks_on_dhcp_agent.return_value = \
            dhcp_agent_networks
        dummy_client.list_routers_on_l3_agent.return_value = \
            l3_agent_routers
        _client.return_value = dummy_client
        self.unit_private_ip.return_value = 'cluster1-machine1.internal'
        self.relations_of_type.return_value = []
        neutron_utils.reassign_agent_resources()
        self.assertTrue(self.log.called)
        assert not dummy_client.remove_router_from_l3_agent.called
        assert not dummy_client.remove_network_from_dhcp_agent.called

    @patch.object(neutron_utils, 'git_install_requested')
    @patch.object(neutron_utils, 'git_clone_and_install')
    @patch.object(neutron_utils, 'git_post_install')
    @patch.object(neutron_utils, 'git_pre_install')
    def test_git_install(self, git_pre, git_post, git_clone_and_install,
                         git_requested):
        projects_yaml = openstack_origin_git
        git_requested.return_value = True
        neutron_utils.git_install(projects_yaml)
        self.assertTrue(git_pre.called)
        git_clone_and_install.assert_called_with(openstack_origin_git,
                                                 core_project='neutron')
        self.assertTrue(git_post.called)

    @patch.object(neutron_utils, 'mkdir')
    @patch.object(neutron_utils, 'write_file')
    @patch.object(neutron_utils, 'add_user_to_group')
    @patch.object(neutron_utils, 'add_group')
    @patch.object(neutron_utils, 'adduser')
    def test_git_pre_install(self, adduser, add_group, add_user_to_group,
                             write_file, mkdir):
        neutron_utils.git_pre_install()
        adduser.assert_called_with('neutron', shell='/bin/bash',
                                   system_user=True)
        add_group.assert_called_with('neutron', system_group=True)
        add_user_to_group.assert_called_with('neutron', 'neutron')
        expected = [
            call('/etc/neutron', owner='neutron',
                 group='neutron', perms=0755, force=False),
            call('/etc/neutron/rootwrap.d', owner='neutron',
                 group='neutron', perms=0755, force=False),
            call('/etc/neutron/plugins', owner='neutron',
                 group='neutron', perms=0755, force=False),
            call('/etc/nova', owner='neutron',
                 group='neutron', perms=0755, force=False),
            call('/var/lib/neutron', owner='neutron',
                 group='neutron', perms=0755, force=False),
            call('/var/lib/neutron/lock', owner='neutron',
                 group='neutron', perms=0755, force=False),
            call('/var/log/neutron', owner='neutron',
                 group='neutron', perms=0755, force=False),
        ]
        self.assertEquals(mkdir.call_args_list, expected)
        expected = [
            call('/var/log/neutron/bigswitch-agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/dhcp-agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/l3-agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/lbaas-agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/ibm-agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/linuxbridge-agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/metadata-agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/metering_agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/mlnx-agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/nec-agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/nvsd-agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/openflow-agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/openvswitch-agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/ovs-cleanup.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/ryu-agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/server.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/sriov-agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
            call('/var/log/neutron/vpn_agent.log', '', owner='neutron',
                 group='neutron', perms=0644),
        ]
        self.assertEquals(write_file.call_args_list, expected)

    @patch('os.remove')
    @patch.object(neutron_utils, 'git_src_dir')
    @patch.object(neutron_utils, 'render')
    @patch('os.path.join')
    @patch('os.path.exists')
    @patch('os.symlink')
    @patch('shutil.rmtree')
    @patch('shutil.copyfile')
    @patch('shutil.copytree')
    def test_git_post_install(self, copytree, copyfile, rmtree, symlink,
                              exists, join, render, git_src_dir, remove):
        projects_yaml = openstack_origin_git
        join.return_value = 'joined-string'
        neutron_utils.git_post_install(projects_yaml)
        expected = [
            call('joined-string', '/etc/neutron'),
            call('joined-string', '/etc/neutron/plugins'),
            call('joined-string', '/etc/neutron/rootwrap.d'),
        ]
        copytree.assert_has_calls(expected)
        expected = [
            call('/usr/local/bin/neutron-rootwrap',
                 '/usr/bin/neutron-rootwrap'),
        ]
        symlink.assert_has_calls(expected)
        service_name = 'quantum-gateway'
        user_name = 'neutron'
        neutron_api_context = {
            'service_description': 'Neutron API server',
            'charm_name': 'neutron-api',
            'process_name': 'neutron-server',
            'executable_name': 'joined-string',
        }
        neutron_dhcp_agent_context = {
            'service_description': 'Neutron DHCP Agent',
            'service_name': service_name,
            'process_name': 'neutron-dhcp-agent',
            'executable_name': 'joined-string',
            'config_files': ['/etc/neutron/neutron.conf',
                             '/etc/neutron/dhcp_agent.ini'],
            'log_file': '/var/log/neutron/dhcp-agent.log',
        }
        neutron_l3_agent_context = {
            'service_description': 'Neutron L3 Agent',
            'service_name': service_name,
            'process_name': 'neutron-l3-agent',
            'executable_name': 'joined-string',
            'config_files': ['/etc/neutron/neutron.conf',
                             '/etc/neutron/l3_agent.ini',
                             '/etc/neutron/fwaas_driver.ini'],
            'log_file': '/var/log/neutron/l3-agent.log',
        }
        neutron_lbaas_agent_context = {
            'service_description': 'Neutron LBaaS Agent',
            'service_name': service_name,
            'user_name': user_name,
            'start_dir': '/var/lib/neutron',
            'process_name': 'neutron-lbaas-agent',
            'executable_name': 'joined-string',
            'config_files': ['/etc/neutron/neutron.conf',
                             '/etc/neutron/lbaas_agent.ini'],
            'log_file': '/var/log/neutron/lbaas-agent.log',
        }
        neutron_metadata_agent_context = {
            'service_description': 'Neutron Metadata Agent',
            'service_name': service_name,
            'user_name': user_name,
            'start_dir': '/var/lib/neutron',
            'process_name': 'neutron-metadata-agent',
            'executable_name': 'joined-string',
            'config_files': ['/etc/neutron/neutron.conf',
                             '/etc/neutron/metadata_agent.ini'],
            'log_file': '/var/log/neutron/metadata-agent.log',
        }
        neutron_metering_agent_context = {
            'service_description': 'Neutron Metering Agent',
            'service_name': service_name,
            'user_name': user_name,
            'start_dir': '/var/lib/neutron',
            'process_name': 'neutron-metering-agent',
            'executable_name': 'joined-string',
            'config_files': ['/etc/neutron/neutron.conf',
                             '/etc/neutron/metering_agent.ini'],
            'log_file': '/var/log/neutron/metering-agent.log',
        }
        neutron_ovs_cleanup_context = {
            'service_description': 'Neutron OVS cleanup',
            'service_name': service_name,
            'user_name': user_name,
            'start_dir': '/var/lib/neutron',
            'process_name': 'neutron-ovs-cleanup',
            'executable_name': 'joined-string',
            'config_file': '/etc/neutron/neutron.conf',
            'log_file': '/var/log/neutron/ovs-cleanup.log',
        }
        neutron_plugin_bigswitch_context = {
            'service_description': 'Neutron BigSwitch Plugin Agent',
            'service_name': service_name,
            'user_name': user_name,
            'start_dir': '/var/lib/neutron',
            'process_name': 'neutron-restproxy-agent',
            'executable_name': 'joined-string',
            'config_files': ['/etc/neutron/neutron.conf',
                             '/etc/neutron/plugins/bigswitch/restproxy.ini'],
            'log_file': '/var/log/neutron/bigswitch-agent.log',
        }
        neutron_plugin_ibm_context = {
            'service_description': 'Neutron IBM SDN Plugin Agent',
            'service_name': service_name,
            'user_name': user_name,
            'start_dir': '/var/lib/neutron',
            'process_name': 'neutron-ibm-agent',
            'executable_name': 'joined-string',
            'config_files':
            ['/etc/neutron/neutron.conf',
             '/etc/neutron/plugins/ibm/sdnve_neutron_plugin.ini'],
            'log_file': '/var/log/neutron/ibm-agent.log',
        }
        neutron_plugin_linuxbridge_context = {
            'service_description': 'Neutron Linux Bridge Plugin Agent',
            'service_name': service_name,
            'user_name': user_name,
            'start_dir': '/var/lib/neutron',
            'process_name': 'neutron-linuxbridge-agent',
            'executable_name': 'joined-string',
            'config_files': ['/etc/neutron/neutron.conf',
                             '/etc/neutron/plugins/ml2/ml2_conf.ini'],
            'log_file': '/var/log/neutron/linuxbridge-agent.log',
        }
        neutron_plugin_mlnx_context = {
            'service_description': 'Neutron MLNX Plugin Agent',
            'service_name': service_name,
            'user_name': user_name,
            'start_dir': '/var/lib/neutron',
            'process_name': 'neutron-mlnx-agent',
            'executable_name': 'joined-string',
            'config_files': ['/etc/neutron/neutron.conf',
                             '/etc/neutron/plugins/mlnx/mlnx_conf.ini'],
            'log_file': '/var/log/neutron/mlnx-agent.log',
        }
        neutron_plugin_nec_context = {
            'service_description': 'Neutron NEC Plugin Agent',
            'service_name': service_name,
            'start_dir': '/var/lib/neutron',
            'process_name': 'neutron-nec-agent',
            'executable_name': 'joined-string',
            'config_files': ['/etc/neutron/neutron.conf',
                             '/etc/neutron/plugins/nec/nec.ini'],
            'log_file': '/var/log/neutron/nec-agent.log',
        }
        neutron_plugin_oneconvergence_context = {
            'service_description': 'Neutron One Convergence Plugin Agent',
            'service_name': service_name,
            'user_name': user_name,
            'start_dir': '/var/lib/neutron',
            'process_name': 'neutron-nvsd-agent',
            'executable_name': 'joined-string',
            'config_files': ['/etc/neutron/neutron.conf',
                             '/etc/neutron/plugins/oneconvergence/'
                             'nvsdplugin.ini'],
            'log_file': '/var/log/neutron/nvsd-agent.log',
        }
        neutron_plugin_openflow_context = {
            'service_description': 'Neutron OpenFlow Plugin Agent',
            'service_name': service_name,
            'user_name': user_name,
            'start_dir': '/var/lib/neutron',
            'process_name': 'neutron-ofagent-agent',
            'executable_name': 'joined-string',
            'config_files': ['/etc/neutron/neutron.conf',
                             '/etc/neutron/plugins/ml2/ml2_conf_ofa.ini'],
            'log_file': '/var/log/neutron/openflow-agent.log',
        }
        neutron_plugin_openvswitch_context = {
            'service_description': 'Neutron OpenvSwitch Plugin Agent',
            'service_name': service_name,
            'user_name': user_name,
            'start_dir': '/var/lib/neutron',
            'process_name': 'neutron-openvswitch-agent',
            'executable_name': 'joined-string',
            'config_files': ['/etc/neutron/neutron.conf',
                             '/etc/neutron/plugins/ml2/ml2_conf.ini'],
            'log_file': '/var/log/neutron/openvswitch-agent.log',
        }
        neutron_plugin_ryu_context = {
            'service_description': 'Neutron RYU Plugin Agent',
            'service_name': service_name,
            'user_name': user_name,
            'start_dir': '/var/lib/neutron',
            'process_name': 'neutron-ryu-agent',
            'executable_name': 'joined-string',
            'config_files': ['/etc/neutron/neutron.conf',
                             '/etc/neutron/plugins/ryu/ryu.ini'],
            'log_file': '/var/log/neutron/ryu-agent.log',
        }
        neutron_plugin_sriov_context = {
            'service_description': 'Neutron SRIOV SDN Plugin Agent',
            'service_name': service_name,
            'user_name': user_name,
            'start_dir': '/var/lib/neutron',
            'process_name': 'neutron-sriov-nic-agent',
            'executable_name': 'joined-string',
            'config_files': ['/etc/neutron/neutron.conf',
                             '/etc/neutron/plugins/ml2/ml2_conf_sriov'],
            'log_file': '/var/log/neutron/sriov-agent.log',
        }
        neutron_api_context = {
            'service_description': 'Neutron API server',
            'service_name': service_name,
            'process_name': 'neutron-server',
            'executable_name': 'joined-string',
        }
        neutron_vpn_agent_context = {
            'service_description': 'Neutron VPN Agent',
            'service_name': service_name,
            'process_name': 'neutron-vpn-agent',
            'executable_name': 'joined-string',
            'config_files': ['/etc/neutron/neutron.conf',
                             '/etc/neutron/vpn_agent.ini',
                             '/etc/neutron/l3_agent.ini',
                             '/etc/neutron/fwaas_driver.ini'],
            'log_file': '/var/log/neutron/vpn_agent.log',
        }
        expected = [
            call('git/neutron_sudoers',
                 '/etc/sudoers.d/neutron_sudoers',
                 {}, perms=0o440),
            call('git/cron.d/neutron-dhcp-agent-netns-cleanup',
                 '/etc/cron.d/neutron-dhcp-agent-netns-cleanup',
                 {}, perms=0o755),
            call('git/cron.d/neutron-l3-agent-netns-cleanup',
                 '/etc/cron.d/neutron-l3-agent-netns-cleanup',
                 {}, perms=0o755),
            call('git/cron.d/neutron-lbaas-agent-netns-cleanup',
                 '/etc/cron.d/neutron-lbaas-agent-netns-cleanup',
                 {}, perms=0o755),
            call('git/upstart/neutron-agent.upstart',
                 '/etc/init/neutron-dhcp-agent.conf',
                 neutron_dhcp_agent_context, perms=0o644),
            call('git/upstart/neutron-agent.upstart',
                 '/etc/init/neutron-l3-agent.conf',
                 neutron_l3_agent_context, perms=0o644),
            call('git.upstart',
                 '/etc/init/neutron-lbaas-agent.conf',
                 neutron_lbaas_agent_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart',
                 '/etc/init/neutron-metadata-agent.conf',
                 neutron_metadata_agent_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart',
                 '/etc/init/neutron-metering-agent.conf',
                 neutron_metering_agent_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart',
                 '/etc/init/neutron-ovs-cleanup.conf',
                 neutron_ovs_cleanup_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart',
                 '/etc/init/neutron-plugin-bigswitch-agent.conf',
                 neutron_plugin_bigswitch_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart',
                 '/etc/init/neutron-plugin-ibm-agent.conf',
                 neutron_plugin_ibm_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart',
                 '/etc/init/neutron-plugin-linuxbridge-agent.conf',
                 neutron_plugin_linuxbridge_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart',
                 '/etc/init/neutron-plugin-mlnx-agent.conf',
                 neutron_plugin_mlnx_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart',
                 '/etc/init/neutron-plugin-nec-agent.conf',
                 neutron_plugin_nec_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart',
                 '/etc/init/neutron-plugin-oneconvergence-agent.conf',
                 neutron_plugin_oneconvergence_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart',
                 '/etc/init/neutron-plugin-openflow-agent.conf',
                 neutron_plugin_openflow_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart',
                 '/etc/init/neutron-plugin-openvswitch-agent.conf',
                 neutron_plugin_openvswitch_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart',
                 '/etc/init/neutron-plugin-ryu-agent.conf',
                 neutron_plugin_ryu_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart',
                 '/etc/init/neutron-plugin-sriov-agent.conf',
                 neutron_plugin_sriov_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git/upstart/neutron-server.upstart',
                 '/etc/init/neutron-server.conf',
                 neutron_api_context, perms=0o644),
            call('git/upstart/neutron-agent.upstart',
                 '/etc/init/neutron-vpn-agent.conf',
                 neutron_vpn_agent_context, perms=0o644),
        ]
        self.assertEquals(render.call_args_list, expected)
