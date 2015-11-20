import json
from test_utils import CharmTestCase
from mock import patch
import neutron_api_context as context
import charmhelpers
TO_PATCH = [
    'config',
    'determine_api_port',
    'determine_apache_port',
    'log',
    'os_release',
    'relation_get',
    'relation_ids',
    'related_units',
]


class GeneralTests(CharmTestCase):
    def setUp(self):
        super(GeneralTests, self).setUp(context, TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get
        self.config.side_effect = self.test_config.get

    def test_l2population(self):
        self.test_config.set('l2-population', True)
        self.test_config.set('neutron-plugin', 'ovs')
        self.assertEquals(context.get_l2population(), True)

    def test_l2population_nonovs(self):
        self.test_config.set('l2-population', True)
        self.test_config.set('neutron-plugin', 'nsx')
        self.assertEquals(context.get_l2population(), False)

    def test_get_overlay_network_type(self):
        self.test_config.set('overlay-network-type', 'gre')
        self.assertEquals(context.get_overlay_network_type(), 'gre')

    def test_get_overlay_network_type_multi(self):
        self.test_config.set('overlay-network-type', 'gre vxlan')
        self.assertEquals(context.get_overlay_network_type(), 'gre,vxlan')

    def test_get_overlay_network_type_unsupported(self):
        self.test_config.set('overlay-network-type', 'tokenring')
        with self.assertRaises(ValueError) as _exceptctxt:
            context.get_overlay_network_type()
        self.assertEqual(_exceptctxt.exception.message,
                         'Unsupported overlay-network-type tokenring')

    def test_get_l3ha(self):
        self.test_config.set('enable-l3ha', True)
        self.test_config.set('overlay-network-type', 'gre')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', False)
        self.os_release.return_value = 'juno'
        self.assertEquals(context.get_l3ha(), True)

    def test_get_l3ha_prejuno(self):
        self.test_config.set('enable-l3ha', True)
        self.test_config.set('overlay-network-type', 'gre')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', False)
        self.os_release.return_value = 'icehouse'
        self.assertEquals(context.get_l3ha(), False)

    def test_get_l3ha_l2pop(self):
        self.test_config.set('enable-l3ha', True)
        self.test_config.set('overlay-network-type', 'gre')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', True)
        self.os_release.return_value = 'juno'
        self.assertEquals(context.get_l3ha(), False)

    def test_get_dvr(self):
        self.test_config.set('enable-dvr', True)
        self.test_config.set('enable-l3ha', False)
        self.test_config.set('overlay-network-type', 'vxlan')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', True)
        self.os_release.return_value = 'juno'
        self.assertEquals(context.get_dvr(), True)

    def test_get_dvr_explicit_off(self):
        self.test_config.set('enable-dvr', False)
        self.test_config.set('enable-l3ha', False)
        self.test_config.set('overlay-network-type', 'vxlan')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', True)
        self.os_release.return_value = 'juno'
        self.assertEquals(context.get_dvr(), False)

    def test_get_dvr_prejuno(self):
        self.test_config.set('enable-dvr', True)
        self.test_config.set('enable-l3ha', False)
        self.test_config.set('overlay-network-type', 'vxlan')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', True)
        self.os_release.return_value = 'icehouse'
        self.assertEquals(context.get_dvr(), False)

    def test_get_dvr_gre(self):
        self.test_config.set('enable-dvr', True)
        self.test_config.set('enable-l3ha', False)
        self.test_config.set('overlay-network-type', 'gre')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', True)
        self.os_release.return_value = 'juno'
        self.assertEquals(context.get_dvr(), False)

    def test_get_dvr_gre_kilo(self):
        self.test_config.set('enable-dvr', True)
        self.test_config.set('enable-l3ha', False)
        self.test_config.set('overlay-network-type', 'gre')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', True)
        self.os_release.return_value = 'kilo'
        self.assertEquals(context.get_dvr(), True)

    def test_get_dvr_vxlan_kilo(self):
        self.test_config.set('enable-dvr', True)
        self.test_config.set('enable-l3ha', False)
        self.test_config.set('overlay-network-type', 'vxlan')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', True)
        self.os_release.return_value = 'kilo'
        self.assertEquals(context.get_dvr(), True)

    def test_get_dvr_l3ha_on(self):
        self.test_config.set('enable-dvr', True)
        self.test_config.set('enable-l3ha', True)
        self.test_config.set('overlay-network-type', 'vxlan')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', False)
        self.os_release.return_value = 'juno'
        self.assertEquals(context.get_dvr(), False)

    def test_get_dvr_l2pop(self):
        self.test_config.set('enable-dvr', True)
        self.test_config.set('enable-l3ha', False)
        self.test_config.set('overlay-network-type', 'vxlan')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', False)
        self.os_release.return_value = 'juno'
        self.assertEquals(context.get_dvr(), False)


class IdentityServiceContext(CharmTestCase):

    def setUp(self):
        super(IdentityServiceContext, self).setUp(context, TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get
        self.config.side_effect = self.test_config.get
        self.test_config.set('region', 'region457')
        self.test_config.set('prefer-ipv6', False)

    @patch.object(charmhelpers.contrib.openstack.context, 'format_ipv6_addr')
    @patch.object(charmhelpers.contrib.openstack.context, 'context_complete')
    @patch.object(charmhelpers.contrib.openstack.context, 'relation_get')
    @patch.object(charmhelpers.contrib.openstack.context, 'related_units')
    @patch.object(charmhelpers.contrib.openstack.context, 'relation_ids')
    @patch.object(charmhelpers.contrib.openstack.context, 'log')
    def test_ids_ctxt(self, _log, _rids, _runits, _rget, _ctxt_comp,
                      format_ipv6_addr):
        _rids.return_value = 'rid1'
        _runits.return_value = 'runit'
        _ctxt_comp.return_value = True
        id_data = {
            'service_port': 9876,
            'service_host': '127.0.0.4',
            'auth_host': '127.0.0.5',
            'auth_port': 5432,
            'service_tenant': 'ten',
            'service_username': 'admin',
            'service_password': 'adminpass',
        }
        _rget.return_value = id_data
        ids_ctxt = context.IdentityServiceContext()
        self.assertEquals(ids_ctxt()['region'], 'region457')

    @patch.object(charmhelpers.contrib.openstack.context, 'relation_ids')
    @patch.object(charmhelpers.contrib.openstack.context, 'log')
    def test_ids_ctxt_no_rels(self, _log, _rids):
        _rids.return_value = []
        ids_ctxt = context.IdentityServiceContext()
        self.assertEquals(ids_ctxt(), None)


class HAProxyContextTest(CharmTestCase):

    def setUp(self):
        super(HAProxyContextTest, self).setUp(context, TO_PATCH)
        self.determine_api_port.return_value = 9686
        self.determine_apache_port.return_value = 9686
        self.api_port = 9696

    def tearDown(self):
        super(HAProxyContextTest, self).tearDown()

    @patch.object(charmhelpers.contrib.openstack.context, 'relation_ids')
    @patch.object(charmhelpers.contrib.openstack.context, 'log')
    def test_context_No_peers(self, _log, _rids):
        _rids.return_value = []
        hap_ctxt = context.HAProxyContext()
        with patch('__builtin__.__import__'):
            self.assertTrue('units' not in hap_ctxt())

    @patch.object(
        charmhelpers.contrib.openstack.context, 'get_netmask_for_address')
    @patch.object(
        charmhelpers.contrib.openstack.context, 'get_address_in_network')
    @patch.object(charmhelpers.contrib.openstack.context, 'config')
    @patch.object(charmhelpers.contrib.openstack.context, 'local_unit')
    @patch.object(charmhelpers.contrib.openstack.context, 'unit_get')
    @patch.object(charmhelpers.contrib.openstack.context, 'relation_get')
    @patch.object(charmhelpers.contrib.openstack.context, 'related_units')
    @patch.object(charmhelpers.contrib.openstack.context, 'relation_ids')
    @patch.object(charmhelpers.contrib.openstack.context, 'log')
    @patch('__builtin__.__import__')
    @patch('__builtin__.open')
    def test_context_peers(self, _open, _import, _log, _rids, _runits, _rget,
                           _uget, _lunit, _config,  _get_address_in_network,
                           _get_netmask_for_address):
        unit_addresses = {
            'neutron-api-0': '10.10.10.10',
            'neutron-api-1': '10.10.10.11',
        }
        _rids.return_value = ['rid1']
        _runits.return_value = ['neutron-api/0']
        _rget.return_value = unit_addresses['neutron-api-0']
        _lunit.return_value = "neutron-api/1"
        _uget.return_value = unit_addresses['neutron-api-1']
        _config.return_value = None
        _get_address_in_network.return_value = None
        _get_netmask_for_address.return_value = '255.255.255.0'
        service_ports = {'neutron-server': [9696, 9686]}
        self.maxDiff = None
        ctxt_data = {
            'local_host': '127.0.0.1',
            'haproxy_host': '0.0.0.0',
            'local_host': '127.0.0.1',
            'stat_port': ':8888',
            'frontends': {
                '10.10.10.11': {
                    'network': '10.10.10.11/255.255.255.0',
                    'backends': unit_addresses,
                }
            },
            'default_backend': '10.10.10.11',
            'service_ports': service_ports,
            'neutron_bind_port': 9686,
        }
        _import().api_port.return_value = 9696
        hap_ctxt = context.HAProxyContext()
        self.assertEquals(hap_ctxt(), ctxt_data)
        _open.assert_called_with('/etc/default/haproxy', 'w')


class NeutronCCContextTest(CharmTestCase):

    def setUp(self):
        super(NeutronCCContextTest, self).setUp(context, TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get
        self.config.side_effect = self.test_config.get
        self.api_port = 9696
        self.determine_api_port.return_value = self.api_port
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('neutron-security-groups', True)
        self.test_config.set('debug', True)
        self.test_config.set('verbose', True)
        self.test_config.set('neutron-external-network', 'bob')
        self.test_config.set('nsx-username', 'bob')
        self.test_config.set('nsx-password', 'hardpass')
        self.test_config.set('nsx-tz-uuid', 'tzuuid')
        self.test_config.set('nsx-l3-uuid', 'l3uuid')
        self.test_config.set('nsx-controllers', 'ctrl1 ctrl2')
        self.test_config.set('plumgrid-username', 'plumgrid')
        self.test_config.set('plumgrid-password', 'plumgrid')
        self.test_config.set('plumgrid-virtual-ip', '192.168.100.250')

    def tearDown(self):
        super(NeutronCCContextTest, self).tearDown()

    @patch.object(context.NeutronCCContext, 'network_manager')
    @patch.object(context.NeutronCCContext, 'plugin')
    @patch('__builtin__.__import__')
    def test_neutroncc_context_no_setting(self, _import, plugin, nm):
        plugin.return_value = None
        ctxt_data = {
            'debug': True,
            'enable_dvr': False,
            'l3_ha': False,
            'external_network': 'bob',
            'neutron_bind_port': self.api_port,
            'verbose': True,
            'l2_population': True,
            'overlay_network_type': 'gre',
            'quota_floatingip': 50,
            'quota_health_monitors': -1,
            'quota_member': -1,
            'quota_network': 10,
            'quota_pool': 10,
            'quota_port': 50,
            'quota_router': 10,
            'quota_security_group': 10,
            'quota_security_group_rule': 100,
            'quota_subnet': 10,
            'quota_vip': 10,
            'vlan_ranges': 'physnet1:1000:2000',
        }
        napi_ctxt = context.NeutronCCContext()
        with patch.object(napi_ctxt, '_ensure_packages'):
            self.assertEquals(ctxt_data, napi_ctxt())

    @patch.object(context.NeutronCCContext, 'network_manager')
    @patch.object(context.NeutronCCContext, 'plugin')
    @patch('__builtin__.__import__')
    def test_neutroncc_context_vxlan(self, _import, plugin, nm):
        plugin.return_value = None
        self.test_config.set('flat-network-providers', 'physnet2 physnet3')
        self.test_config.set('overlay-network-type', 'vxlan')
        ctxt_data = {
            'debug': True,
            'enable_dvr': False,
            'l3_ha': False,
            'external_network': 'bob',
            'neutron_bind_port': self.api_port,
            'verbose': True,
            'l2_population': True,
            'overlay_network_type': 'vxlan',
            'quota_floatingip': 50,
            'quota_health_monitors': -1,
            'quota_member': -1,
            'quota_network': 10,
            'quota_pool': 10,
            'quota_port': 50,
            'quota_router': 10,
            'quota_security_group': 10,
            'quota_security_group_rule': 100,
            'quota_subnet': 10,
            'quota_vip': 10,
            'vlan_ranges': 'physnet1:1000:2000',
            'network_providers': 'physnet2,physnet3',
        }
        napi_ctxt = context.NeutronCCContext()
        with patch.object(napi_ctxt, '_ensure_packages'):
            self.assertEquals(ctxt_data, napi_ctxt())

    @patch.object(context.NeutronCCContext, 'network_manager')
    @patch.object(context.NeutronCCContext, 'plugin')
    @patch('__builtin__.__import__')
    def test_neutroncc_context_l3ha(self, _import, plugin, nm):
        plugin.return_value = None
        self.test_config.set('enable-l3ha', True)
        self.test_config.set('overlay-network-type', 'gre')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', False)
        self.os_release.return_value = 'juno'
        ctxt_data = {
            'debug': True,
            'enable_dvr': False,
            'l3_ha': True,
            'external_network': 'bob',
            'neutron_bind_port': self.api_port,
            'verbose': True,
            'l2_population': False,
            'overlay_network_type': 'gre',
            'max_l3_agents_per_router': 2,
            'min_l3_agents_per_router': 2,
            'quota_floatingip': 50,
            'quota_health_monitors': -1,
            'quota_member': -1,
            'quota_network': 10,
            'quota_pool': 10,
            'quota_port': 50,
            'quota_router': 10,
            'quota_security_group': 10,
            'quota_security_group_rule': 100,
            'quota_subnet': 10,
            'quota_vip': 10,
            'vlan_ranges': 'physnet1:1000:2000',
        }
        napi_ctxt = context.NeutronCCContext()
        with patch.object(napi_ctxt, '_ensure_packages'):
            self.assertEquals(ctxt_data, napi_ctxt())

    @patch.object(context.NeutronCCContext, 'network_manager')
    @patch.object(context.NeutronCCContext, 'plugin')
    @patch('__builtin__.__import__')
    def test_neutroncc_context_unsupported_overlay(self, _import, plugin, nm):
        plugin.return_value = None
        self.test_config.set('overlay-network-type', 'bobswitch')
        with self.assertRaises(Exception) as context:
            context.NeutronCCContext()

    @patch.object(context.NeutronCCContext, 'network_manager')
    @patch.object(context.NeutronCCContext, 'plugin')
    @patch('__builtin__.__import__')
    def test_neutroncc_context_api_rel(self, _import, plugin, nm):
        nova_url = 'http://127.0.0.10'
        plugin.return_value = None
        self.related_units.return_value = ['unit1']
        self.relation_ids.return_value = ['rid2']
        self.test_relation.set({'nova_url': nova_url,
                                'restart_trigger': 'bob'})
        napi_ctxt = context.NeutronCCContext()
        self.assertEquals(nova_url, napi_ctxt()['nova_url'])
        self.assertEquals('bob', napi_ctxt()['restart_trigger'])
        self.assertEquals(self.api_port, napi_ctxt()['neutron_bind_port'])

    def test_neutroncc_context_manager(self):
        napi_ctxt = context.NeutronCCContext()
        self.assertEquals(napi_ctxt.network_manager, 'neutron')
        self.assertEquals(napi_ctxt.plugin, 'ovs')
        self.assertEquals(napi_ctxt.neutron_security_groups, True)

    def test_neutroncc_context_manager_pkgs(self):
        napi_ctxt = context.NeutronCCContext()
        with patch.object(napi_ctxt, '_ensure_packages') as ep:
            napi_ctxt._ensure_packages()
            ep.assert_has_calls([])

    @patch.object(context.NeutronCCContext, 'network_manager')
    @patch.object(context.NeutronCCContext, 'plugin')
    @patch('__builtin__.__import__')
    def test_neutroncc_context_nsx(self, _import, plugin, nm):
        plugin.return_value = 'nsx'
        self.related_units.return_value = []
        self.test_config.set('neutron-plugin', 'nsx')
        napi_ctxt = context.NeutronCCContext()()
        expect = {
            'nsx_controllers': 'ctrl1,ctrl2',
            'nsx_controllers_list': ['ctrl1', 'ctrl2'],
            'nsx_l3_uuid': 'l3uuid',
            'nsx_password': 'hardpass',
            'nsx_tz_uuid': 'tzuuid',
            'nsx_username': 'bob',
        }
        for key in expect.iterkeys():
            self.assertEquals(napi_ctxt[key], expect[key])


class EtcdContextTest(CharmTestCase):

    def setUp(self):
        super(EtcdContextTest, self).setUp(context, TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get
        self.config.side_effect = self.test_config.get
        self.test_config.set('neutron-plugin', 'Calico')

    def tearDown(self):
        super(EtcdContextTest, self).tearDown()

    def test_etcd_no_related_units(self):
        self.related_units.return_value = []
        ctxt = context.EtcdContext()()
        expect = {'cluster': ''}

        self.assertEquals(expect, ctxt)

    def test_some_related_units(self):
        self.related_units.return_value = ['unit1']
        self.relation_ids.return_value = ['rid2', 'rid3']
        result = (
            'testname=http://172.18.18.18:8888,'
            'testname=http://172.18.18.18:8888'
        )
        self.test_relation.set({'cluster': result})

        ctxt = context.EtcdContext()()
        expect = {'cluster': result}

        self.assertEquals(expect, ctxt)

    def test_early_exit(self):
        self.test_config.set('neutron-plugin', 'notCalico')

        self.related_units.return_value = ['unit1']
        self.relation_ids.return_value = ['rid2', 'rid3']
        self.test_relation.set({'ip': '172.18.18.18',
                                'port': 8888,
                                'name': 'testname'})

        ctxt = context.EtcdContext()()
        expect = {'cluster': ''}

        self.assertEquals(expect, ctxt)


class NeutronApiSDNContextTest(CharmTestCase):

    def setUp(self):
        super(NeutronApiSDNContextTest, self).setUp(context, TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get

    def tearDown(self):
        super(NeutronApiSDNContextTest, self).tearDown()

    def test_init(self):
        napisdn_ctxt = context.NeutronApiSDNContext()
        self.assertEquals(
            napisdn_ctxt.interfaces,
            ['neutron-plugin-api-subordinate']
        )
        self.assertEquals(napisdn_ctxt.services, ['neutron-api'])
        self.assertEquals(
            napisdn_ctxt.config_file,
            '/etc/neutron/neutron.conf'
        )

    @patch.object(charmhelpers.contrib.openstack.context, 'log')
    @patch.object(charmhelpers.contrib.openstack.context, 'relation_get')
    @patch.object(charmhelpers.contrib.openstack.context, 'related_units')
    @patch.object(charmhelpers.contrib.openstack.context, 'relation_ids')
    def ctxt_check(self, rel_settings, expect, _rids, _runits, _rget, _log):
        self.test_relation.set(rel_settings)
        _runits.return_value = ['unit1']
        _rids.return_value = ['rid2']
        _rget.side_effect = self.test_relation.get
        self.relation_ids.return_value = ['rid2']
        self.related_units.return_value = ['unit1']
        napisdn_ctxt = context.NeutronApiSDNContext()()
        self.assertEquals(napisdn_ctxt, expect)

    def test_defaults(self):
        self.ctxt_check(
            {'neutron-plugin': 'ovs'},
            {
                'core_plugin': 'neutron.plugins.ml2.plugin.Ml2Plugin',
                'neutron_plugin_config': ('/etc/neutron/plugins/ml2/'
                                          'ml2_conf.ini'),
                'service_plugins': 'router,firewall,lbaas,vpnaas,metering',
                'restart_trigger': '',
                'quota_driver': '',
                'neutron_plugin': 'ovs',
                'sections': {},
            }
        )

    def test_overrides(self):
        self.ctxt_check(
            {
                'neutron-plugin': 'ovs',
                'core-plugin': 'neutron.plugins.ml2.plugin.MidoPlumODL',
                'neutron-plugin-config': '/etc/neutron/plugins/fl/flump.ini',
                'service-plugins': 'router,unicorn,rainbows',
                'restart-trigger': 'restartnow',
                'quota-driver': 'quotadriver',
            },
            {
                'core_plugin': 'neutron.plugins.ml2.plugin.MidoPlumODL',
                'neutron_plugin_config': '/etc/neutron/plugins/fl/flump.ini',
                'service_plugins': 'router,unicorn,rainbows',
                'restart_trigger': 'restartnow',
                'quota_driver': 'quotadriver',
                'neutron_plugin': 'ovs',
                'sections': {},
            }
        )

    def test_subordinateconfig(self):
        principle_config = {
            "neutron-api": {
                "/etc/neutron/neutron.conf": {
                    "sections": {
                        'DEFAULT': [
                            ('neutronboost', True)
                        ],
                    }
                }
            }
        }
        self.ctxt_check(
            {
                'neutron-plugin': 'ovs',
                'subordinate_configuration': json.dumps(principle_config),
            },
            {
                'core_plugin': 'neutron.plugins.ml2.plugin.Ml2Plugin',
                'neutron_plugin_config': ('/etc/neutron/plugins/ml2/'
                                          'ml2_conf.ini'),
                'service_plugins': 'router,firewall,lbaas,vpnaas,metering',
                'restart_trigger': '',
                'quota_driver': '',
                'neutron_plugin': 'ovs',
                'sections': {u'DEFAULT': [[u'neutronboost', True]]},
            }
        )

    def test_empty(self):
        self.ctxt_check(
            {},
            {'sections': {}},
        )


class NeutronApiSDNConfigFileContextTest(CharmTestCase):

    def setUp(self):
        super(NeutronApiSDNConfigFileContextTest, self).setUp(
            context, TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get

    def tearDown(self):
        super(NeutronApiSDNConfigFileContextTest, self).tearDown()

    def test_configset(self):
        self.test_relation.set({
            'neutron-plugin-config': '/etc/neutron/superplugin.ini'
        })
        self.relation_ids.return_value = ['rid2']
        self.related_units.return_value = ['unit1']
        napisdn_ctxt = context.NeutronApiSDNConfigFileContext()()
        self.assertEquals(napisdn_ctxt, {
            'config': '/etc/neutron/superplugin.ini'
        })

    def test_default(self):
        self.relation_ids.return_value = []
        napisdn_ctxt = context.NeutronApiSDNConfigFileContext()()
        self.assertEquals(napisdn_ctxt, {
            'config': '/etc/neutron/plugins/ml2/ml2_conf.ini'
        })
