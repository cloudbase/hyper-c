from mock import (
    Mock,
    MagicMock,
    patch
)
import neutron_contexts
import sys
from contextlib import contextmanager

from test_utils import (
    CharmTestCase
)

TO_PATCH = [
    'apt_install',
    'config',
    'eligible_leader',
    'get_os_codename_install_source',
    'unit_get',
]


@contextmanager
def patch_open():
    '''Patch open() to allow mocking both open() itself and the file that is
    yielded.

    Yields the mock for "open" and "file", respectively.'''
    mock_open = MagicMock(spec=open)
    mock_file = MagicMock(spec=file)

    @contextmanager
    def stub_open(*args, **kwargs):
        mock_open(*args, **kwargs)
        yield mock_file

    with patch('__builtin__.open', stub_open):
        yield mock_open, mock_file


class DummyNeutronAPIContext():

    def __init__(self, return_value):
        self.return_value = return_value

    def __call__(self):
        return self.return_value


class TestL3AgentContext(CharmTestCase):

    def setUp(self):
        super(TestL3AgentContext, self).setUp(neutron_contexts,
                                              TO_PATCH)
        self.config.side_effect = self.test_config.get

    @patch('neutron_contexts.NeutronAPIContext')
    def test_no_ext_netid(self,  _NeutronAPIContext):
        _NeutronAPIContext.return_value = \
            DummyNeutronAPIContext(return_value={'enable_dvr': False})
        self.test_config.set('run-internal-router', 'none')
        self.test_config.set('external-network-id', '')
        self.eligible_leader.return_value = False
        self.assertEquals(neutron_contexts.L3AgentContext()(),
                          {'agent_mode': 'legacy',
                           'handle_internal_only_router': False,
                           'plugin': 'ovs'})

    @patch('neutron_contexts.NeutronAPIContext')
    def test_hior_leader(self, _NeutronAPIContext):
        _NeutronAPIContext.return_value = \
            DummyNeutronAPIContext(return_value={'enable_dvr': False})
        self.test_config.set('run-internal-router', 'leader')
        self.test_config.set('external-network-id', 'netid')
        self.eligible_leader.return_value = True
        self.assertEquals(neutron_contexts.L3AgentContext()(),
                          {'agent_mode': 'legacy',
                           'handle_internal_only_router': True,
                           'ext_net_id': 'netid',
                           'plugin': 'ovs'})

    @patch('neutron_contexts.NeutronAPIContext')
    def test_hior_all(self, _NeutronAPIContext):
        _NeutronAPIContext.return_value = \
            DummyNeutronAPIContext(return_value={'enable_dvr': False})
        self.test_config.set('run-internal-router', 'all')
        self.test_config.set('external-network-id', 'netid')
        self.eligible_leader.return_value = True
        self.assertEquals(neutron_contexts.L3AgentContext()(),
                          {'agent_mode': 'legacy',
                           'handle_internal_only_router': True,
                           'ext_net_id': 'netid',
                           'plugin': 'ovs'})

    @patch('neutron_contexts.NeutronAPIContext')
    def test_dvr(self, _NeutronAPIContext):
        _NeutronAPIContext.return_value = \
            DummyNeutronAPIContext(return_value={'enable_dvr': True})
        self.assertEquals(neutron_contexts.L3AgentContext()()['agent_mode'],
                          'dvr_snat')


class TestNeutronGatewayContext(CharmTestCase):

    def setUp(self):
        super(TestNeutronGatewayContext, self).setUp(neutron_contexts,
                                                     TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.maxDiff = None

    @patch('charmhelpers.contrib.openstack.context.relation_get')
    @patch('charmhelpers.contrib.openstack.context.related_units')
    @patch('charmhelpers.contrib.openstack.context.relation_ids')
    @patch.object(neutron_contexts, 'get_shared_secret')
    @patch.object(neutron_contexts, 'get_host_ip')
    def test_all(self, _host_ip, _secret, _rids, _runits, _rget):
        rdata = {'l2-population': 'True',
                 'enable-dvr': 'True',
                 'overlay-network-type': 'gre',
                 'enable-l3ha': 'True',
                 'network-device-mtu': 9000}
        self.test_config.set('plugin', 'ovs')
        self.test_config.set('debug', False)
        self.test_config.set('verbose', True)
        self.test_config.set('instance-mtu', 1420)
        self.test_config.set('vlan-ranges',
                             'physnet1:1000:2000 physnet2:2001:3000')
        self.test_config.set('flat-network-providers', 'physnet3 physnet4')
        # Provided by neutron-api relation
        _rids.return_value = ['neutron-plugin-api:0']
        _runits.return_value = ['neutron-api/0']
        _rget.side_effect = lambda *args, **kwargs: rdata
        self.get_os_codename_install_source.return_value = 'folsom'
        _host_ip.return_value = '10.5.0.1'
        _secret.return_value = 'testsecret'
        ctxt = neutron_contexts.NeutronGatewayContext()()
        self.assertEquals(ctxt, {
            'shared_secret': 'testsecret',
            'enable_dvr': True,
            'enable_l3ha': True,
            'local_ip': '10.5.0.1',
            'instance_mtu': 1420,
            'core_plugin': "quantum.plugins.openvswitch.ovs_quantum_plugin."
                           "OVSQuantumPluginV2",
            'plugin': 'ovs',
            'debug': False,
            'verbose': True,
            'l2_population': True,
            'overlay_network_type': 'gre',
            'bridge_mappings': 'physnet1:br-data',
            'network_providers': 'physnet3,physnet4',
            'vlan_ranges': 'physnet1:1000:2000,physnet2:2001:3000',
            'network_device_mtu': 9000,
            'veth_mtu': 9000,
        })


class TestSharedSecret(CharmTestCase):

    def setUp(self):
        super(TestSharedSecret, self).setUp(neutron_contexts,
                                            TO_PATCH)
        self.config.side_effect = self.test_config.get

    @patch('os.path')
    @patch('uuid.uuid4')
    def test_secret_created_stored(self, _uuid4, _path):
        _path.exists.return_value = False
        _uuid4.return_value = 'secret_thing'
        with patch_open() as (_open, _file):
            self.assertEquals(neutron_contexts.get_shared_secret(),
                              'secret_thing')
            _open.assert_called_with(
                neutron_contexts.SHARED_SECRET.format('quantum'), 'w')
            _file.write.assert_called_with('secret_thing')

    @patch('os.path')
    def test_secret_retrieved(self, _path):
        _path.exists.return_value = True
        with patch_open() as (_open, _file):
            _file.read.return_value = 'secret_thing\n'
            self.assertEquals(neutron_contexts.get_shared_secret(),
                              'secret_thing')
            _open.assert_called_with(
                neutron_contexts.SHARED_SECRET.format('quantum'), 'r')


class TestHostIP(CharmTestCase):

    def setUp(self):
        super(TestHostIP, self).setUp(neutron_contexts,
                                      TO_PATCH)
        self.config.side_effect = self.test_config.get
        # Save and inject
        self.mods = {'dns': None, 'dns.resolver': None}
        for mod in self.mods:
            if mod not in sys.modules:
                sys.modules[mod] = Mock()
            else:
                del self.mods[mod]

    def tearDown(self):
        super(TestHostIP, self).tearDown()
        # Cleanup
        for mod in self.mods.keys():
            del sys.modules[mod]

    def test_get_host_ip_already_ip(self):
        self.assertEquals(neutron_contexts.get_host_ip('10.5.0.1'),
                          '10.5.0.1')

    def test_get_host_ip_noarg(self):
        self.unit_get.return_value = "10.5.0.1"
        self.assertEquals(neutron_contexts.get_host_ip(),
                          '10.5.0.1')

    @patch('dns.resolver.query')
    def test_get_host_ip_hostname_unresolvable(self, _query):
        class NXDOMAIN(Exception):
            pass
        _query.side_effect = NXDOMAIN()
        self.assertRaises(NXDOMAIN, neutron_contexts.get_host_ip,
                          'missing.example.com')

    @patch('dns.resolver.query')
    def test_get_host_ip_hostname_resolvable(self, _query):
        data = MagicMock()
        data.address = '10.5.0.1'
        _query.return_value = [data]
        self.assertEquals(neutron_contexts.get_host_ip('myhost.example.com'),
                          '10.5.0.1')
        _query.assert_called_with('myhost.example.com', 'A')


class TestMisc(CharmTestCase):

    def setUp(self):
        super(TestMisc,
              self).setUp(neutron_contexts,
                          TO_PATCH)

    def test_lt_havana(self):
        self.get_os_codename_install_source.return_value = 'folsom'
        self.assertEquals(neutron_contexts.networking_name(), 'quantum')

    def test_ge_havana(self):
        self.get_os_codename_install_source.return_value = 'havana'
        self.assertEquals(neutron_contexts.networking_name(), 'neutron')

    def test_remap_plugin(self):
        self.get_os_codename_install_source.return_value = 'havana'
        self.assertEquals(neutron_contexts.remap_plugin('nvp'), 'nvp')
        self.assertEquals(neutron_contexts.remap_plugin('nsx'), 'nvp')

    def test_remap_plugin_icehouse(self):
        self.get_os_codename_install_source.return_value = 'icehouse'
        self.assertEquals(neutron_contexts.remap_plugin('nvp'), 'nsx')
        self.assertEquals(neutron_contexts.remap_plugin('nsx'), 'nsx')

    def test_remap_plugin_noop(self):
        self.get_os_codename_install_source.return_value = 'icehouse'
        self.assertEquals(neutron_contexts.remap_plugin('ovs'), 'ovs')

    def test_core_plugin(self):
        self.get_os_codename_install_source.return_value = 'havana'
        self.config.return_value = 'ovs'
        self.assertEquals(neutron_contexts.core_plugin(),
                          neutron_contexts.NEUTRON_OVS_PLUGIN)

    def test_core_plugin_ml2(self):
        self.get_os_codename_install_source.return_value = 'icehouse'
        self.config.return_value = 'ovs'
        self.assertEquals(neutron_contexts.core_plugin(),
                          neutron_contexts.NEUTRON_ML2_PLUGIN)
