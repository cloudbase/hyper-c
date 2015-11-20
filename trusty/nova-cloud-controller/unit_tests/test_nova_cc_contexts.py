from __future__ import print_function

import mock

#####
# NOTE(freyes): this is a workaround to patch config() function imported by
# nova_cc_utils before it gets a reference to the actual config() provided by
# hookenv module.
from charmhelpers.core import hookenv
_conf = hookenv.config
hookenv.config = mock.MagicMock()
import nova_cc_utils as _utils  # noqa
hookenv.config = _conf
#####

import nova_cc_context as context

from charmhelpers.contrib.openstack import utils

from test_utils import CharmTestCase

from charmhelpers.contrib.openstack import neutron

TO_PATCH = [
    'apt_install',
    'filter_installed_packages',
    'relation_ids',
    'relation_get',
    'related_units',
    'config',
    'log',
    'relations_for_id',
    'https',
    'is_relation_made',
]


def fake_log(msg, level=None):
    level = level or 'INFO'
    print('[juju test log (%s)] %s' % (level, msg))


class NovaComputeContextTests(CharmTestCase):
    def setUp(self):
        super(NovaComputeContextTests, self).setUp(context, TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get
        self.config.side_effect = self.test_config.get
        self.log.side_effect = fake_log

    @mock.patch.object(context, 'resolve_address',
                       lambda *args, **kwargs: None)
    @mock.patch.object(utils, 'os_release')
    @mock.patch('charmhelpers.contrib.network.ip.log')
    def test_instance_console_context_without_memcache(self, os_release, log_):
        self.relation_ids.return_value = 'cache:0'
        self.related_units.return_value = 'memcached/0'
        instance_console = context.InstanceConsoleContext()
        os_release.return_value = 'icehouse'
        self.assertEqual({'memcached_servers': ''},
                         instance_console())

    @mock.patch.object(context, 'resolve_address',
                       lambda *args, **kwargs: None)
    @mock.patch.object(utils, 'os_release')
    @mock.patch('charmhelpers.contrib.network.ip.log')
    def test_instance_console_context_with_memcache(self, os_release, log_):
        self.check_instance_console_context_with_memcache(os_release,
                                                          '127.0.1.1',
                                                          '127.0.1.1')

    @mock.patch.object(context, 'resolve_address',
                       lambda *args, **kwargs: None)
    @mock.patch.object(utils, 'os_release')
    @mock.patch('charmhelpers.contrib.network.ip.log')
    def test_instance_console_context_with_memcache_ipv6(self, os_release,
                                                         log_):
        self.check_instance_console_context_with_memcache(os_release, '::1',
                                                          '[::1]')

    def check_instance_console_context_with_memcache(self, os_release, ip,
                                                     formated_ip):
        memcached_servers = [{'private-address': formated_ip,
                              'port': '11211'}]
        self.relation_ids.return_value = ['cache:0']
        self.relations_for_id.return_value = memcached_servers
        self.related_units.return_value = 'memcached/0'
        instance_console = context.InstanceConsoleContext()
        os_release.return_value = 'icehouse'
        self.maxDiff = None
        self.assertEqual({'memcached_servers': "%s:11211" % (formated_ip, )},
                         instance_console())

    @mock.patch('charmhelpers.contrib.openstack.neutron.os_release')
    @mock.patch.object(context, 'use_local_neutron_api')
    @mock.patch('charmhelpers.contrib.openstack.ip.config')
    @mock.patch('charmhelpers.contrib.openstack.ip.is_clustered')
    def test_neutron_context_single_vip(self, mock_is_clustered, mock_config,
                                        mock_use_local_neutron_api,
                                        _os_release):
        mock_use_local_neutron_api.return_value = True
        self.https.return_value = False
        mock_is_clustered.return_value = True
        config = {'vip': '10.0.0.1',
                  'os-internal-network': '10.0.0.1/24',
                  'os-admin-network': '10.0.1.0/24',
                  'os-public-network': '10.0.2.0/24'}
        mock_config.side_effect = lambda key: config.get(key)

        mock_use_local_neutron_api.return_value = False
        ctxt = context.NeutronCCContext()()
        self.assertEqual(ctxt['nova_url'], 'http://10.0.0.1:8774/v2')
        self.assertFalse('neutron_url' in ctxt)

        mock_use_local_neutron_api.return_value = True
        ctxt = context.NeutronCCContext()()
        self.assertEqual(ctxt['nova_url'], 'http://10.0.0.1:8774/v2')
        self.assertEqual(ctxt['neutron_url'], 'http://10.0.0.1:9696')

    @mock.patch('charmhelpers.contrib.openstack.neutron.os_release')
    @mock.patch.object(context, 'use_local_neutron_api')
    @mock.patch('charmhelpers.contrib.openstack.ip.config')
    @mock.patch('charmhelpers.contrib.openstack.ip.is_clustered')
    def test_neutron_context_multi_vip(self, mock_is_clustered, mock_config,
                                       mock_use_local_neutron_api,
                                       _os_release):
        self.https.return_value = False
        mock_is_clustered.return_value = True
        config = {'vip': '10.0.0.1 10.0.1.1 10.0.2.1',
                  'os-internal-network': '10.0.1.0/24',
                  'os-admin-network': '10.0.0.0/24',
                  'os-public-network': '10.0.2.0/24'}
        mock_config.side_effect = lambda key: config.get(key)

        mock_use_local_neutron_api.return_value = False
        ctxt = context.NeutronCCContext()()
        self.assertEqual(ctxt['nova_url'], 'http://10.0.1.1:8774/v2')
        self.assertFalse('neutron_url' in ctxt)

        mock_use_local_neutron_api.return_value = True
        ctxt = context.NeutronCCContext()()
        self.assertEqual(ctxt['nova_url'], 'http://10.0.1.1:8774/v2')
        self.assertEqual(ctxt['neutron_url'], 'http://10.0.1.1:9696')

    def test_use_local_neutron_api(self):
        self.relation_ids.return_value = []
        self.related_units.return_value = []
        self.assertTrue(context.use_local_neutron_api())
        self.relation_ids.return_value = ['rel:0']
        self.related_units.return_value = []
        self.assertTrue(context.use_local_neutron_api())
        self.related_units.return_value = ['unit/0']
        self.assertFalse(context.use_local_neutron_api())

    @mock.patch.object(neutron, 'network_manager')
    @mock.patch('charmhelpers.contrib.hahelpers.cluster.https')
    @mock.patch('charmhelpers.contrib.openstack.context.'
                'get_address_in_network')
    @mock.patch('charmhelpers.contrib.openstack.context.'
                'get_netmask_for_address')
    @mock.patch('charmhelpers.contrib.openstack.context.local_unit')
    @mock.patch('charmhelpers.contrib.openstack.context.get_ipv6_addr')
    @mock.patch('charmhelpers.contrib.openstack.context.relation_ids')
    def test_haproxy_context(self, mock_relation_ids, mock_get_ipv6_addr,
                             mock_local_unit, mock_get_netmask_for_address,
                             mock_get_address_in_network, mock_https,
                             mock_network_manager):
        mock_network_manager.return_value = 'neutron'
        mock_https.return_value = False
        self.is_relation_made.return_value = False
        ctxt = context.HAProxyContext()()
        self.assertEqual(ctxt['service_ports']['neutron-server'], [9696, 9686])

    @mock.patch.object(neutron, 'network_manager')
    @mock.patch('charmhelpers.contrib.hahelpers.cluster.https')
    @mock.patch('charmhelpers.contrib.openstack.context.'
                'get_address_in_network')
    @mock.patch('charmhelpers.contrib.openstack.context.'
                'get_netmask_for_address')
    @mock.patch('charmhelpers.contrib.openstack.context.local_unit')
    @mock.patch('charmhelpers.contrib.openstack.context.get_ipv6_addr')
    @mock.patch('charmhelpers.contrib.openstack.context.relation_ids')
    def test_haproxy_context_api_relation(self, mock_relation_ids,
                                          mock_get_ipv6_addr, mock_local_unit,
                                          mock_get_netmask_for_address,
                                          mock_get_address_in_network,
                                          mock_https, mock_network_manager):
        mock_network_manager.return_value = 'neutron'
        mock_https.return_value = False
        self.is_relation_made.return_value = True
        ctxt = context.HAProxyContext()()
        self.assertEqual(ctxt['service_ports'].get('neutron-server'), None)

    @mock.patch.object(context, 'config')
    def test_console_ssl_disabled(self, mock_config):
        config = {'console-ssl-cert': 'LS0tLS1CRUdJTiBDRV',
                  'console-ssl-key': 'LS0tLS1CRUdJTiBQUk'}
        mock_config.side_effect = lambda key: config.get(key)

        ctxt = context.ConsoleSSLContext()()
        self.assertEqual(ctxt, {})

        config = {'console-ssl-cert': None,
                  'console-ssl-key': None}
        mock_config.side_effect = lambda key: config.get(key)

        ctxt = context.ConsoleSSLContext()()
        self.assertEqual(ctxt, {})

        config = {'console-access-protocol': 'novnc',
                  'console-ssl-cert': None,
                  'console-ssl-key': None}
        mock_config.side_effect = lambda key: config.get(key)

        ctxt = context.ConsoleSSLContext()()
        self.assertEqual(ctxt, {})

    @mock.patch('__builtin__.open')
    @mock.patch('os.path.exists')
    @mock.patch.object(context, 'config')
    @mock.patch.object(context, 'unit_get')
    @mock.patch.object(context, 'is_clustered')
    @mock.patch.object(context, 'resolve_address')
    @mock.patch.object(context, 'b64decode')
    def test_noVNC_ssl_enabled(self, mock_b64decode,
                               mock_resolve_address,
                               mock_is_clustered, mock_unit_get,
                               mock_config, mock_exists, mock_open):
        config = {'console-ssl-cert': 'LS0tLS1CRUdJTiBDRV',
                  'console-ssl-key': 'LS0tLS1CRUdJTiBQUk',
                  'console-access-protocol': 'novnc'}
        mock_config.side_effect = lambda key: config.get(key)
        mock_exists.return_value = True
        mock_unit_get.return_value = '127.0.0.1'
        mock_is_clustered.return_value = True
        mock_resolve_address.return_value = '10.5.100.1'
        mock_b64decode.return_value = 'decode_success'

        mock_open.return_value.__enter__ = lambda s: s
        mock_open.return_value.__exit__ = mock.Mock()

        ctxt = context.ConsoleSSLContext()()
        self.assertTrue(ctxt['ssl_only'])
        self.assertEqual(ctxt['ssl_cert'], '/etc/nova/ssl/nova_cert.pem')
        self.assertEqual(ctxt['ssl_key'], '/etc/nova/ssl/nova_key.pem')
        self.assertEqual(ctxt['novncproxy_base_url'],
                         'https://10.5.100.1:6080/vnc_auto.html')

    @mock.patch('__builtin__.open')
    @mock.patch('os.path.exists')
    @mock.patch.object(context, 'config')
    @mock.patch.object(context, 'unit_get')
    @mock.patch.object(context, 'is_clustered')
    @mock.patch.object(context, 'resolve_address')
    @mock.patch.object(context, 'b64decode')
    def test_noVNC_ssl_enabled_no_cluster(self, mock_b64decode,
                                          mock_resolve_address,
                                          mock_is_clustered, mock_unit_get,
                                          mock_config, mock_exists, mock_open):
        config = {'console-ssl-cert': 'LS0tLS1CRUdJTiBDRV',
                  'console-ssl-key': 'LS0tLS1CRUdJTiBQUk',
                  'console-access-protocol': 'novnc'}
        mock_config.side_effect = lambda key: config.get(key)
        mock_exists.return_value = True
        mock_unit_get.return_value = '10.5.0.1'
        mock_is_clustered.return_value = False
        mock_b64decode.return_value = 'decode_success'

        mock_open.return_value.__enter__ = lambda s: s
        mock_open.return_value.__exit__ = mock.Mock()

        ctxt = context.ConsoleSSLContext()()
        self.assertTrue(ctxt['ssl_only'])
        self.assertEqual(ctxt['ssl_cert'], '/etc/nova/ssl/nova_cert.pem')
        self.assertEqual(ctxt['ssl_key'], '/etc/nova/ssl/nova_key.pem')
        self.assertEqual(ctxt['novncproxy_base_url'],
                         'https://10.5.0.1:6080/vnc_auto.html')

    @mock.patch('__builtin__.open')
    @mock.patch('os.path.exists')
    @mock.patch.object(context, 'config')
    @mock.patch.object(context, 'unit_get')
    @mock.patch.object(context, 'is_clustered')
    @mock.patch.object(context, 'resolve_address')
    @mock.patch.object(context, 'b64decode')
    def test_spice_html5_ssl_enabled(self, mock_b64decode,
                                     mock_resolve_address,
                                     mock_is_clustered, mock_unit_get,
                                     mock_config, mock_exists, mock_open):
        config = {'console-ssl-cert': 'LS0tLS1CRUdJTiBDRV',
                  'console-ssl-key': 'LS0tLS1CRUdJTiBQUk',
                  'console-access-protocol': 'spice'}
        mock_config.side_effect = lambda key: config.get(key)
        mock_exists.return_value = True
        mock_unit_get.return_value = '127.0.0.1'
        mock_is_clustered.return_value = True
        mock_resolve_address.return_value = '10.5.100.1'
        mock_b64decode.return_value = 'decode_success'

        mock_open.return_value.__enter__ = lambda s: s
        mock_open.return_value.__exit__ = mock.Mock()

        ctxt = context.ConsoleSSLContext()()
        self.assertTrue(ctxt['ssl_only'])
        self.assertEqual(ctxt['ssl_cert'], '/etc/nova/ssl/nova_cert.pem')
        self.assertEqual(ctxt['ssl_key'], '/etc/nova/ssl/nova_key.pem')
        self.assertEqual(ctxt['html5proxy_base_url'],
                         'https://10.5.100.1:6082/spice_auto.html')

    @mock.patch('__builtin__.open')
    @mock.patch('os.path.exists')
    @mock.patch.object(context, 'config')
    @mock.patch.object(context, 'unit_get')
    @mock.patch.object(context, 'is_clustered')
    @mock.patch.object(context, 'resolve_address')
    @mock.patch.object(context, 'b64decode')
    def test_spice_html5_ssl_enabled_no_cluster(self, mock_b64decode,
                                                mock_resolve_address,
                                                mock_is_clustered,
                                                mock_unit_get,
                                                mock_config, mock_exists,
                                                mock_open):
        config = {'console-ssl-cert': 'LS0tLS1CRUdJTiBDRV',
                  'console-ssl-key': 'LS0tLS1CRUdJTiBQUk',
                  'console-access-protocol': 'spice'}
        mock_config.side_effect = lambda key: config.get(key)
        mock_exists.return_value = True
        mock_unit_get.return_value = '10.5.0.1'
        mock_is_clustered.return_value = False
        mock_b64decode.return_value = 'decode_success'

        mock_open.return_value.__enter__ = lambda s: s
        mock_open.return_value.__exit__ = mock.Mock()

        ctxt = context.ConsoleSSLContext()()
        self.assertTrue(ctxt['ssl_only'])
        self.assertEqual(ctxt['ssl_cert'], '/etc/nova/ssl/nova_cert.pem')
        self.assertEqual(ctxt['ssl_key'], '/etc/nova/ssl/nova_key.pem')
        self.assertEqual(ctxt['html5proxy_base_url'],
                         'https://10.5.0.1:6082/spice_auto.html')

    @mock.patch('charmhelpers.core.hookenv.local_unit')
    def test_nova_config_context(self, local_unit):
        local_unit.return_value = 'nova-cloud-controller/0'
        ctxt = context.NovaConfigContext()()
        self.assertEqual(ctxt['scheduler_default_filters'],
                         self.config('scheduler-default-filters'))
        self.assertEqual(ctxt['cpu_allocation_ratio'],
                         self.config('cpu-allocation-ratio'))
        self.assertEqual(ctxt['ram_allocation_ratio'],
                         self.config('ram-allocation-ratio'))
