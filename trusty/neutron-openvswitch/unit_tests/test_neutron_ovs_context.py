
from test_utils import CharmTestCase
from test_utils import patch_open
from mock import patch
import neutron_ovs_context as context
import charmhelpers

TO_PATCH = [
    'resolve_address',
    'config',
    'unit_get',
    'get_host_ip',
]


def fake_context(settings):
    def outer():
        def inner():
            return settings
        return inner
    return outer


class OVSPluginContextTest(CharmTestCase):

    def setUp(self):
        super(OVSPluginContextTest, self).setUp(context, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.test_config.set('debug', True)
        self.test_config.set('verbose', True)
        self.test_config.set('use-syslog', True)

    def tearDown(self):
        super(OVSPluginContextTest, self).tearDown()

    @patch('charmhelpers.contrib.openstack.context.config')
    @patch('charmhelpers.contrib.openstack.context.NeutronPortContext.'
           'resolve_ports')
    def test_data_port_name(self, mock_resolve_ports, config):
        self.test_config.set('data-port', 'br-data:em1')
        config.side_effect = self.test_config.get
        mock_resolve_ports.side_effect = lambda ports: ports
        self.assertEquals(
            charmhelpers.contrib.openstack.context.DataPortContext()(),
            {'em1': 'br-data'}
        )

    @patch('charmhelpers.contrib.openstack.context.is_phy_iface',
           lambda port: True)
    @patch('charmhelpers.contrib.openstack.context.config')
    @patch('charmhelpers.contrib.openstack.context.get_nic_hwaddr')
    @patch('charmhelpers.contrib.openstack.context.list_nics')
    def test_data_port_mac(self, list_nics, get_nic_hwaddr, config):
        machine_machs = {
            'em1': 'aa:aa:aa:aa:aa:aa',
            'eth0': 'bb:bb:bb:bb:bb:bb',
        }
        absent_mac = "cc:cc:cc:cc:cc:cc"
        config_macs = ("br-d1:%s br-d2:%s" %
                       (absent_mac, machine_machs['em1']))
        self.test_config.set('data-port', config_macs)
        config.side_effect = self.test_config.get
        list_nics.return_value = machine_machs.keys()
        get_nic_hwaddr.side_effect = lambda nic: machine_machs[nic]
        self.assertEquals(
            charmhelpers.contrib.openstack.context.DataPortContext()(),
            {'em1': 'br-d2'}
        )

    @patch.object(charmhelpers.contrib.openstack.context, 'config',
                  lambda *args: None)
    @patch.object(charmhelpers.contrib.openstack.context, 'relation_get')
    @patch.object(charmhelpers.contrib.openstack.context, 'relation_ids')
    @patch.object(charmhelpers.contrib.openstack.context, 'related_units')
    @patch.object(charmhelpers.contrib.openstack.context, 'config')
    @patch.object(charmhelpers.contrib.openstack.context, 'unit_get')
    @patch.object(charmhelpers.contrib.openstack.context, 'is_clustered')
    @patch.object(charmhelpers.contrib.openstack.context, 'https')
    @patch.object(context.OVSPluginContext, '_save_flag_file')
    @patch.object(context.OVSPluginContext, '_ensure_packages')
    @patch.object(charmhelpers.contrib.openstack.context,
                  'neutron_plugin_attribute')
    @patch.object(charmhelpers.contrib.openstack.context, 'unit_private_ip')
    def test_neutroncc_context_api_rel(self, _unit_priv_ip, _npa, _ens_pkgs,
                                       _save_ff, _https, _is_clus, _unit_get,
                                       _config, _runits, _rids, _rget):
        def mock_npa(plugin, section, manager):
            if section == "driver":
                return "neutron.randomdriver"
            if section == "config":
                return "neutron.randomconfig"

        config = {'vlan-ranges': "physnet1:1000:1500 physnet2:2000:2500",
                  'use-syslog': True,
                  'verbose': True,
                  'debug': True,
                  'bridge-mappings': "physnet1:br-data physnet2:br-data",
                  'flat-network-providers': 'physnet3 physnet4'}

        def mock_config(key=None):
            if key:
                return config.get(key)

            return config

        self.maxDiff = None
        self.config.side_effect = mock_config
        _npa.side_effect = mock_npa
        _unit_get.return_value = '127.0.0.13'
        _unit_priv_ip.return_value = '127.0.0.14'
        _is_clus.return_value = False
        _runits.return_value = ['unit1']
        _rids.return_value = ['rid2']
        rdata = {
            'neutron-security-groups': 'True',
            'l2-population': 'True',
            'network-device-mtu': 1500,
            'overlay-network-type': 'gre',
            'enable-dvr': 'True',
        }
        _rget.side_effect = lambda *args, **kwargs: rdata
        self.get_host_ip.return_value = '127.0.0.15'
        napi_ctxt = context.OVSPluginContext()
        expect = {
            'neutron_security_groups': True,
            'distributed_routing': True,
            'verbose': True,
            'local_ip': '127.0.0.15',
            'network_device_mtu': 1500,
            'veth_mtu': 1500,
            'config': 'neutron.randomconfig',
            'use_syslog': True,
            'network_manager': 'neutron',
            'debug': True,
            'core_plugin': 'neutron.randomdriver',
            'neutron_plugin': 'ovs',
            'neutron_url': 'https://127.0.0.13:9696',
            'l2_population': True,
            'overlay_network_type': 'gre',
            'network_providers': 'physnet3,physnet4',
            'bridge_mappings': 'physnet1:br-data,physnet2:br-data',
            'vlan_ranges': 'physnet1:1000:1500,physnet2:2000:2500',
        }
        self.assertEquals(expect, napi_ctxt())

    @patch.object(charmhelpers.contrib.openstack.context, 'relation_get')
    @patch.object(charmhelpers.contrib.openstack.context, 'relation_ids')
    @patch.object(charmhelpers.contrib.openstack.context, 'related_units')
    @patch.object(charmhelpers.contrib.openstack.context, 'config')
    @patch.object(charmhelpers.contrib.openstack.context, 'unit_get')
    @patch.object(charmhelpers.contrib.openstack.context, 'is_clustered')
    @patch.object(charmhelpers.contrib.openstack.context, 'https')
    @patch.object(context.OVSPluginContext, '_save_flag_file')
    @patch.object(context.OVSPluginContext, '_ensure_packages')
    @patch.object(charmhelpers.contrib.openstack.context,
                  'neutron_plugin_attribute')
    @patch.object(charmhelpers.contrib.openstack.context, 'unit_private_ip')
    def test_neutroncc_context_api_rel_disable_security(self,
                                                        _unit_priv_ip, _npa,
                                                        _ens_pkgs, _save_ff,
                                                        _https, _is_clus,
                                                        _unit_get,
                                                        _config, _runits,
                                                        _rids, _rget):
        def mock_npa(plugin, section, manager):
            if section == "driver":
                return "neutron.randomdriver"
            if section == "config":
                return "neutron.randomconfig"

        _npa.side_effect = mock_npa
        _config.return_value = 'ovs'
        _unit_get.return_value = '127.0.0.13'
        _unit_priv_ip.return_value = '127.0.0.14'
        _is_clus.return_value = False
        self.test_config.set('disable-security-groups', True)
        _runits.return_value = ['unit1']
        _rids.return_value = ['rid2']
        rdata = {
            'neutron-security-groups': 'True',
            'l2-population': 'True',
            'network-device-mtu': 1500,
            'overlay-network-type': 'gre',
        }
        _rget.side_effect = lambda *args, **kwargs: rdata
        self.get_host_ip.return_value = '127.0.0.15'
        napi_ctxt = context.OVSPluginContext()
        expect = {
            'distributed_routing': False,
            'neutron_alchemy_flags': {},
            'neutron_security_groups': False,
            'verbose': True,
            'local_ip': '127.0.0.15',
            'veth_mtu': 1500,
            'network_device_mtu': 1500,
            'config': 'neutron.randomconfig',
            'use_syslog': True,
            'network_manager': 'neutron',
            'debug': True,
            'core_plugin': 'neutron.randomdriver',
            'neutron_plugin': 'ovs',
            'neutron_url': 'https://127.0.0.13:9696',
            'l2_population': True,
            'overlay_network_type': 'gre',
            'bridge_mappings': 'physnet1:br-data',
            'vlan_ranges': 'physnet1:1000:2000',
        }
        self.assertEquals(expect, napi_ctxt())


class L3AgentContextTest(CharmTestCase):

    def setUp(self):
        super(L3AgentContextTest, self).setUp(context, TO_PATCH)
        self.config.side_effect = self.test_config.get

    def tearDown(self):
        super(L3AgentContextTest, self).tearDown()

    @patch.object(charmhelpers.contrib.openstack.context, 'relation_get')
    @patch.object(charmhelpers.contrib.openstack.context, 'relation_ids')
    @patch.object(charmhelpers.contrib.openstack.context, 'related_units')
    def test_dvr_enabled(self, _runits, _rids, _rget):
        _runits.return_value = ['unit1']
        _rids.return_value = ['rid2']
        rdata = {
            'neutron-security-groups': 'True',
            'enable-dvr': 'True',
            'l2-population': 'True',
            'overlay-network-type': 'vxlan',
            'network-device-mtu': 1500,
        }
        _rget.side_effect = lambda *args, **kwargs: rdata
        self.assertEquals(context.L3AgentContext()(), {'agent_mode': 'dvr'})

    @patch.object(charmhelpers.contrib.openstack.context, 'relation_get')
    @patch.object(charmhelpers.contrib.openstack.context, 'relation_ids')
    @patch.object(charmhelpers.contrib.openstack.context, 'related_units')
    def test_dvr_disabled(self, _runits, _rids, _rget):
        _runits.return_value = ['unit1']
        _rids.return_value = ['rid2']
        rdata = {
            'neutron-security-groups': 'True',
            'enable-dvr': 'False',
            'l2-population': 'True',
            'overlay-network-type': 'vxlan',
            'network-device-mtu': 1500,
        }
        _rget.side_effect = lambda *args, **kwargs: rdata
        self.assertEquals(context.L3AgentContext()(), {'agent_mode': 'legacy'})


class SharedSecretContext(CharmTestCase):

    def setUp(self):
        super(SharedSecretContext, self).setUp(context,
                                               TO_PATCH)
        self.config.side_effect = self.test_config.get

    @patch('os.path')
    @patch('uuid.uuid4')
    def test_secret_created_stored(self, _uuid4, _path):
        _path.exists.return_value = False
        _uuid4.return_value = 'secret_thing'
        with patch_open() as (_open, _file):
            self.assertEquals(context.get_shared_secret(),
                              'secret_thing')
            _open.assert_called_with(
                context.SHARED_SECRET.format('quantum'), 'w')
            _file.write.assert_called_with('secret_thing')

    @patch('os.path')
    def test_secret_retrieved(self, _path):
        _path.exists.return_value = True
        with patch_open() as (_open, _file):
            _file.read.return_value = 'secret_thing\n'
            self.assertEquals(context.get_shared_secret(),
                              'secret_thing')
            _open.assert_called_with(
                context.SHARED_SECRET.format('quantum'), 'r')

    @patch.object(context, 'NeutronAPIContext')
    @patch.object(context, 'get_shared_secret')
    def test_shared_secretcontext_dvr(self, _shared_secret,
                                      _NeutronAPIContext):
        _NeutronAPIContext.side_effect = fake_context({'enable_dvr': True})
        _shared_secret.return_value = 'secret_thing'
        self.resolve_address.return_value = '10.0.0.10'
        self.assertEquals(context.SharedSecretContext()(),
                          {'shared_secret': 'secret_thing',
                           'local_ip': '10.0.0.10'})

    @patch.object(context, 'NeutronAPIContext')
    @patch.object(context, 'get_shared_secret')
    def test_shared_secretcontext_nodvr(self, _shared_secret,
                                        _NeutronAPIContext):
        _NeutronAPIContext.side_effect = fake_context({'enable_dvr': False})
        _shared_secret.return_value = 'secret_thing'
        self.resolve_address.return_value = '10.0.0.10'
        self.assertEquals(context.SharedSecretContext()(), {})
