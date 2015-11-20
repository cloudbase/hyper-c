import platform

from mock import patch
from test_utils import CharmTestCase

from charmhelpers.contrib.openstack.context import OSContextError

import nova_compute_context as context

TO_PATCH = [
    'apt_install',
    'filter_installed_packages',
    'relation_ids',
    'relation_get',
    'related_units',
    'config',
    'log',
    'os_release',
    '_save_flag_file',
    'unit_get',
]

QUANTUM_CONTEXT = {
    'network_manager': 'quantum',
    'quantum_auth_strategy': 'keystone',
    'keystone_host': 'keystone_host',
    'auth_port': '5000',
    'auth_protocol': 'https',
    'quantum_url': 'http://quantum_url',
    'service_tenant_name': 'admin',
    'service_username': 'admin',
    'service_password': 'openstack',
    'quantum_security_groups': 'yes',
    'quantum_plugin': 'ovs',
    'auth_host': 'keystone_host',
}

# Context for an OVS plugin contains at least the following.  Other bits
# (driver names) are dependent on OS release.
BASE_QUANTUM_OVS_PLUGIN_CONTEXT = {
    'core_plugin': 'quantum.plugins.openvswitch.ovs_quantum_plugin.'
                   'OVSQuantumPluginV2',
    'enable_tunneling': True,
    'libvirt_use_virtio_for_bridges': True,
    'local_ip': '10.0.0.1',
    'nova_firewall_driver': 'nova.virt.firewall.NoopFirewallDriver',
    'ovs_firewall_driver': 'quantum.agent.linux.iptables_firewall.'
                           'OVSHybridIptablesFirewallDriver',
    'tenant_network_type': 'gre',
    'tunnel_id_ranges': '1:1000',
    'quantum_plugin': 'ovs',
    'quantum_security_groups': 'yes',
}


def fake_log(msg, level=None):
    level = level or 'INFO'
    print '[juju test log (%s)] %s' % (level, msg)


class NovaComputeContextTests(CharmTestCase):

    def setUp(self):
        super(NovaComputeContextTests, self).setUp(context, TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get
        self.config.side_effect = self.test_config.get
        self.log.side_effect = fake_log

    def test_cloud_compute_context_no_relation(self):
        self.relation_ids.return_value = []
        cloud_compute = context.CloudComputeContext()
        self.assertEquals({}, cloud_compute())

    @patch.object(context, '_network_manager')
    def test_cloud_compute_context_restart_trigger(self, nm):
        nm.return_value = None
        cloud_compute = context.CloudComputeContext()
        with patch.object(cloud_compute, 'restart_trigger') as rt:
            rt.return_value = 'footrigger'
            ctxt = cloud_compute()
        self.assertEquals(ctxt.get('restart_trigger'), 'footrigger')

        with patch.object(cloud_compute, 'restart_trigger') as rt:
            rt.return_value = None
            ctxt = cloud_compute()
        self.assertEquals(ctxt.get('restart_trigger'), None)

    @patch.object(context, '_network_manager')
    def test_cloud_compute_volume_context_cinder(self, netman):
        netman.return_value = None
        self.relation_ids.return_value = 'cloud-compute:0'
        self.related_units.return_value = 'nova-cloud-controller/0'
        cloud_compute = context.CloudComputeContext()
        self.test_relation.set({'volume_service': 'cinder'})
        self.assertEquals({'volume_service': 'cinder'}, cloud_compute())

    @patch.object(context, '_network_manager')
    def test_cloud_compute_volume_context_nova_vol(self, netman):
        netman.return_value = None
        self.relation_ids.return_value = 'cloud-compute:0'
        self.related_units.return_value = 'nova-cloud-controller/0'
        cloud_compute = context.CloudComputeContext()
        self.os_release.return_value = 'essex'
        self.test_relation.set({'volume_service': 'nova-volume'})
        self.assertEquals({'volume_service': 'nova-volume'}, cloud_compute())

    @patch.object(context, '_network_manager')
    def test_cloud_compute_volume_context_nova_vol_unsupported(self, netman):
        self.skipTest('TODO')
        netman.return_value = None
        self.relation_ids.return_value = 'cloud-compute:0'
        cloud_compute = context.CloudComputeContext()
        # n-vol doesn't exist in grizzly
        self.os_release.return_value = 'grizzly'
        self.test_relation.set({'volume_service': 'nova-volume'})
        self.assertRaises(OSContextError, cloud_compute)

    @patch.object(context, '_network_manager')
    def test_cloud_compute_flatdhcp_context(self, netman):
        netman.return_value = 'flatdhcpmanager'
        self.relation_ids.return_value = 'cloud-compute:0'
        self.related_units.return_value = 'nova-cloud-controller/0'
        self.test_relation.set({
            'network_manager': 'FlatDHCPManager',
            'ec2_host': 'novaapihost'})
        cloud_compute = context.CloudComputeContext()
        ex_ctxt = {
            'network_manager': 'flatdhcpmanager',
            'network_manager_config': {
                'ec2_dmz_host': 'novaapihost',
                'flat_interface': 'eth1'
            }
        }
        self.assertEquals(ex_ctxt, cloud_compute())

    @patch.object(context, '_neutron_plugin')
    @patch.object(context, '_neutron_url')
    @patch.object(context, '_network_manager')
    def test_cloud_compute_quantum_context(self, netman, url, plugin):
        self.relation_ids.return_value = 'cloud-compute:0'
        self.related_units.return_value = 'nova-cloud-controller/0'
        netman.return_value = 'quantum'
        plugin.return_value = 'ovs'
        url.return_value = 'http://nova-c-c:9696'
        self.test_relation.set(QUANTUM_CONTEXT)
        cloud_compute = context.CloudComputeContext()
        ex_ctxt = {
            'network_manager': 'quantum',
            'network_manager_config': {
                'auth_protocol': 'https',
                'service_protocol': 'http',
                'auth_port': '5000',
                'keystone_host': 'keystone_host',
                'quantum_admin_auth_url': 'https://keystone_host:5000/v2.0',
                'quantum_admin_password': 'openstack',
                'quantum_admin_tenant_name': 'admin',
                'quantum_admin_username': 'admin',
                'quantum_auth_strategy': 'keystone',
                'quantum_plugin': 'ovs',
                'quantum_security_groups': True,
                'quantum_url': 'http://nova-c-c:9696'
            }
        }
        self.assertEquals(ex_ctxt, cloud_compute())
        self._save_flag_file.assert_called_with(
            path='/etc/nova/nm.conf', data='quantum')

    @patch.object(context.NeutronComputeContext, 'network_manager')
    @patch.object(context.NeutronComputeContext, 'plugin')
    def test_quantum_plugin_context_no_setting(self, plugin, nm):
        plugin.return_value = None
        qplugin = context.NeutronComputeContext()
        with patch.object(qplugin, '_ensure_packages'):
            self.assertEquals({}, qplugin())

    @patch.object(context.uuid, 'uuid4')
    def test_libvirt_bin_context_no_migration(self, mock_uuid):
        self.test_config.set('enable-live-migration', False)
        mock_uuid.return_value = 'e46e530d-18ae-4a67-9ff0-e6e2ba7c60a7'
        libvirt = context.NovaComputeLibvirtContext()

        self.assertEqual(
            {'libvirtd_opts': '-d',
             'arch': platform.machine(),
             'listen_tls': 0,
             'host_uuid': 'e46e530d-18ae-4a67-9ff0-e6e2ba7c60a7'}, libvirt())

    @patch.object(context.uuid, 'uuid4')
    def test_libvirt_bin_context_migration_tcp_listen(self, mock_uuid):
        self.test_config.set('enable-live-migration', True)
        mock_uuid.return_value = 'e46e530d-18ae-4a67-9ff0-e6e2ba7c60a7'
        libvirt = context.NovaComputeLibvirtContext()

        self.assertEqual(
            {'libvirtd_opts': '-d -l',
             'arch': platform.machine(),
             'listen_tls': 0,
             'host_uuid': 'e46e530d-18ae-4a67-9ff0-e6e2ba7c60a7'}, libvirt())

    @patch.object(context.uuid, 'uuid4')
    def test_libvirt_disk_cachemodes(self, mock_uuid):
        self.test_config.set('disk-cachemodes', 'file=unsafe,block=none')
        mock_uuid.return_value = 'e46e530d-18ae-4a67-9ff0-e6e2ba7c60a7'
        libvirt = context.NovaComputeLibvirtContext()

        self.assertEqual(
            {'libvirtd_opts': '-d',
             'disk_cachemodes': 'file=unsafe,block=none',
             'arch': platform.machine(),
             'listen_tls': 0,
             'host_uuid': 'e46e530d-18ae-4a67-9ff0-e6e2ba7c60a7'}, libvirt())

    @patch.object(context.NeutronComputeContext, 'network_manager')
    @patch.object(context.NeutronComputeContext, 'plugin')
    def test_disable_security_groups_true(self, plugin, nm):
        plugin.return_value = "ovs"
        nm.return_value = "neutron"
        self.test_config.set('disable-neutron-security-groups', True)
        qplugin = context.NeutronComputeContext()
        with patch.object(qplugin, '_ensure_packages'):
            self.assertEquals({'disable_neutron_security_groups': True},
                              qplugin())
        self.test_config.set('disable-neutron-security-groups', False)
        qplugin = context.NeutronComputeContext()
        with patch.object(qplugin, '_ensure_packages'):
            self.assertEquals({}, qplugin())

    @patch('subprocess.call')
    def test_host_IP_context(self, _call):
        self.log = fake_log
        self.unit_get.return_value = '172.24.0.79'
        host_ip = context.HostIPContext()
        self.assertEquals({'host_ip': '172.24.0.79'}, host_ip())
        self.unit_get.assert_called_with('private-address')

    @patch.object(context, 'get_ipv6_addr')
    @patch('subprocess.call')
    def test_host_IP_context_ipv6(self, _call, mock_get_ipv6_addr):
        self.log = fake_log
        self.test_config.set('prefer-ipv6', True)
        mock_get_ipv6_addr.return_value = ['2001:db8:0:1::2']
        host_ip = context.HostIPContext()
        self.assertEquals({'host_ip': '2001:db8:0:1::2'}, host_ip())
        self.assertTrue(mock_get_ipv6_addr.called)

    def test_metadata_service_ctxt(self):
        self.relation_ids.return_value = 'neutron-plugin:0'
        self.related_units.return_value = 'neutron-openvswitch/0'
        self.test_relation.set({'metadata-shared-secret': 'shared_secret'})
        metadatactxt = context.MetadataServiceContext()
        self.assertEqual(metadatactxt(), {'metadata_shared_secret':
                                          'shared_secret'})
