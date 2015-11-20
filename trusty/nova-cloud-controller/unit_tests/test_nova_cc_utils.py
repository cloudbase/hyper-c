from collections import OrderedDict
from mock import patch, MagicMock, call
from copy import deepcopy
from test_utils import CharmTestCase, patch_open

from charmhelpers.core import hookenv

_conf = hookenv.config
hookenv.config = MagicMock()

import nova_cc_utils as utils

hookenv.config = _conf

TO_PATCH = [
    'apt_update',
    'apt_upgrade',
    'apt_install',
    'cmd_all_services',
    'config',
    'configure_installation_source',
    'disable_policy_rcd',
    'is_elected_leader',
    'enable_policy_rcd',
    'enable_services',
    'get_os_codename_install_source',
    'is_relation_made',
    'log',
    'ml2_migration',
    'network_manager',
    'neutron_db_manage',
    'neutron_plugin',
    'neutron_plugin_attribute',
    'os_release',
    'peer_store',
    'register_configs',
    'relation_ids',
    'remote_unit',
    '_save_script_rc',
    'service_start',
    'services',
    'service_running',
    'service_stop'
]

SCRIPTRC_ENV_VARS = {
    'OPENSTACK_PORT_MCASTPORT': 5404,
    'OPENSTACK_SERVICE_API_EC2': 'nova-api-ec2',
    'OPENSTACK_SERVICE_API_OS_COMPUTE': 'nova-api-os-compute',
    'OPENSTACK_SERVICE_CERT': 'nova-cert',
    'OPENSTACK_SERVICE_CONDUCTOR': 'nova-conductor',
    'OPENSTACK_SERVICE_OBJECTSTORE': 'nova-objectstore',
    'OPENSTACK_SERVICE_SCHEDULER': 'nova-scheduler',
}


AUTHORIZED_KEYS = """
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC27Us7lSjCpa7bumXAgc nova-compute-1
ssh-rsa BBBBB3NzaC1yc2EBBBBDBQBBBBBBBQC27Us7lSjCpa7bumXBgc nova-compute-2
ssh-rsa CCCCB3NzaC1yc2ECCCCDCQCBCCCBCQC27Us7lSjCpa7bumXCgc nova-compute-3
"""

BASE_ENDPOINTS = {
    'ec2_admin_url': 'http://foohost.com:8773/services/Cloud',
    'ec2_internal_url': 'http://foohost.com:8773/services/Cloud',
    'ec2_public_url': 'http://foohost.com:8773/services/Cloud',
    'ec2_region': 'RegionOne',
    'ec2_service': 'ec2',
    'nova_admin_url': 'http://foohost.com:8774/v1.1/$(tenant_id)s',
    'nova_internal_url': 'http://foohost.com:8774/v1.1/$(tenant_id)s',
    'nova_public_url': 'http://foohost.com:8774/v1.1/$(tenant_id)s',
    'nova_region': 'RegionOne',
    'nova_service': 'nova',
    's3_admin_url': 'http://foohost.com:3333',
    's3_internal_url': 'http://foohost.com:3333',
    's3_public_url': 'http://foohost.com:3333',
    's3_region': 'RegionOne',
    's3_service': 's3'
}

# Restart map should be constructed such that API services restart
# before frontends (haproxy/apaceh) to avoid port conflicts.
RESTART_MAP = OrderedDict([
    ('/etc/nova/nova.conf', [
        'nova-api-ec2', 'nova-api-os-compute', 'nova-objectstore',
        'nova-cert', 'nova-scheduler', 'nova-api-os-volume', 'nova-conductor'
    ]),
    ('/etc/nova/api-paste.ini', [
        'nova-api-ec2', 'nova-api-os-compute'
    ]),
    ('/etc/neutron/neutron.conf', ['neutron-server']),
    ('/etc/default/neutron-server', ['neutron-server']),
    ('/etc/haproxy/haproxy.cfg', ['haproxy']),
    ('/etc/apache2/sites-available/openstack_https_frontend', ['apache2']),
    ('/etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini',
        ['quantum-server'])
])


PLUGIN_ATTRIBUTES = {
    'ovs': {
        'config': '/etc/quantum/plugins/openvswitch/'
                  'ovs_quantum_plugin.ini',
        'driver': 'quantum.plugins.openvswitch.ovs_quantum_plugin.'
                  'OVSQuantumPluginV2',
        'contexts': ['FakeDBContext'],
        'services': ['quantum-plugin-openvswitch-agent'],
        'packages': ['quantum-plugin-openvswitch-agent',
                     'openvswitch-datapath-dkms'],
        'server_packages': ['quantum-server', 'quantum-plugin-openvswitch'],
        'server_services': ['quantum-server'],
    },
    'nvp': {
        'config': '/etc/quantum/plugins/nicira/nvp.ini',
        'driver': 'quantum.plugins.nicira.nicira_nvp_plugin.'
                  'QuantumPlugin.NvpPluginV2',
        'services': [],
        'packages': [],
        'server_packages': ['quantum-server', 'quantum-plugin-nicria'],
        'server_services': ['quantum-server'],
    }
}


DPKG_OPTS = [
    '--option', 'Dpkg::Options::=--force-confnew',
    '--option', 'Dpkg::Options::=--force-confdef',
]

openstack_origin_git = \
    """repositories:
         - {name: requirements,
            repository: 'git://git.openstack.org/openstack/requirements',
            branch: stable/juno}
         - {name: nova,
            repository: 'git://git.openstack.org/openstack/nova',
            branch: stable/juno}"""


def fake_plugin_attribute(plugin, attr, net_manager):
    if plugin in PLUGIN_ATTRIBUTES:
        try:
            return PLUGIN_ATTRIBUTES[plugin][attr]
        except KeyError:
            pass


class NovaCCUtilsTests(CharmTestCase):

    def setUp(self):
        super(NovaCCUtilsTests, self).setUp(utils, TO_PATCH)
        self.config.side_effect = self.test_config.get

    def _resource_map(self, network_manager=None, volume_manager=None):
        if network_manager:
            self.network_manager.return_value = network_manager
            self.test_config.set('network-manager', network_manager.title())
            self.neutron_plugin.return_value = 'ovs'
            self.neutron_plugin_attribute.side_effect = fake_plugin_attribute
        if volume_manager == 'nova-volume':
            self.relation_ids.return_value = 'nova-volume-service:0'
        with patch('charmhelpers.contrib.openstack.context.'
                   'SubordinateConfigContext'):
            _map = utils.resource_map()
            return _map

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    def test_resource_map_quantum(self, subcontext):
        self.is_relation_made.return_value = False
        self._resource_map(network_manager='quantum')
        _map = utils.resource_map()
        confs = [
            '/etc/quantum/quantum.conf',
            '/etc/quantum/api-paste.ini',
            '/etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini',
        ]
        [self.assertIn(q_conf, _map.keys()) for q_conf in confs]

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    def test_resource_map_neutron(self, subcontext):
        self.is_relation_made.return_value = False
        self._resource_map(network_manager='neutron')
        _map = utils.resource_map()
        confs = [
            '/etc/neutron/neutron.conf',
        ]
        [self.assertIn(q_conf, _map.keys()) for q_conf in confs]

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    def test_resource_map_neutron_api_rel(self, subcontext):
        self.is_relation_made.return_value = True
        self._resource_map(network_manager='neutron')
        _map = utils.resource_map()
        confs = [
            '/etc/neutron/neutron.conf',
        ]
        for q_conf in confs:
            self.assertEquals(_map[q_conf]['services'], [])

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    def test_resource_map_vmware(self, subcontext):
        fake_context = MagicMock()
        fake_context.return_value = {
            'sections': [],
            'services': ['nova-compute', 'nova-network'],

        }
        subcontext.return_value = fake_context
        _map = utils.resource_map()
        for s in ['nova-compute', 'nova-network']:
            self.assertIn(s, _map['/etc/nova/nova.conf']['services'])

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    def test_resource_map_neutron_no_agent_installed(self, subcontext):
        self._resource_map(network_manager='neutron')
        _map = utils.resource_map()
        services = []
        [services.extend(_map[c]['services'])for c in _map]
        for svc in services:
            self.assertNotIn('agent', svc)

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    def test_resource_map_nova_volume(self, subcontext):
        self.relation_ids.return_value = ['nova-volume-service:0']
        _map = utils.resource_map()
        self.assertIn('nova-api-os-volume',
                      _map['/etc/nova/nova.conf']['services'])

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    def test_resource_map_console_xvpvnc(self, subcontext):
        self.test_config.set('console-access-protocol', 'xvpvnc')
        self.relation_ids.return_value = []
        _map = utils.resource_map()
        console_services = ['nova-xvpvncproxy', 'nova-consoleauth']
        for service in console_services:
            self.assertIn(service, _map['/etc/nova/nova.conf']['services'])

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    def test_resource_map_console_novnc(self, subcontext):
        self.test_config.set('console-access-protocol', 'novnc')
        self.relation_ids.return_value = []
        _map = utils.resource_map()
        console_services = ['nova-novncproxy', 'nova-consoleauth']
        for service in console_services:
            self.assertIn(service, _map['/etc/nova/nova.conf']['services'])

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    def test_resource_map_console_vnc(self, subcontext):
        self.test_config.set('console-access-protocol', 'vnc')
        self.relation_ids.return_value = []
        _map = utils.resource_map()
        console_services = ['nova-novncproxy', 'nova-xvpvncproxy',
                            'nova-consoleauth']
        for service in console_services:
            self.assertIn(service, _map['/etc/nova/nova.conf']['services'])

    def test_console_attributes_none(self):
        self.test_config.set('console-access-protocol', None)
        _proto = utils.console_attributes('protocol')
        self.assertEquals(_proto, None)

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    def test_resource_map_console_spice(self, subcontext):
        self.test_config.set('console-access-protocol', 'spice')
        self.relation_ids.return_value = []
        _map = utils.resource_map()
        console_services = ['nova-spiceproxy', 'nova-consoleauth']
        for service in console_services:
            self.assertIn(service, _map['/etc/nova/nova.conf']['services'])

    @patch('os.path.exists')
    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    def test_restart_map_api_before_frontends(self, subcontext, _exists):
        self.is_relation_made.return_value = False
        _exists.return_value = False
        self._resource_map(network_manager='neutron')
        _map = utils.restart_map()
        self.assertTrue(isinstance(_map, OrderedDict))
        self.assertEquals(_map, RESTART_MAP)

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    @patch('os.path.exists')
    def test_restart_map_apache24(self, _exists, subcontext):
        _exists.return_Value = True
        self._resource_map(network_manager='neutron')
        _map = utils.restart_map()
        self.assertTrue('/etc/apache2/sites-available/'
                        'openstack_https_frontend.conf' in _map)
        self.assertTrue('/etc/apache2/sites-available/'
                        'openstack_https_frontend' not in _map)

    def test_console_attributes_spice(self):
        _proto = utils.console_attributes('protocol', proto='spice')
        self.assertEquals(_proto, 'spice')

    def test_console_attributes_vnc(self):
        self.test_config.set('console-access-protocol', 'vnc')
        _proto = utils.console_attributes('protocol')
        _servs = utils.console_attributes('services')
        _pkgs = utils.console_attributes('packages')
        _proxy_page = utils.console_attributes('proxy-page')
        vnc_pkgs = ['nova-novncproxy', 'nova-xvpvncproxy', 'nova-consoleauth']
        vnc_servs = ['nova-novncproxy', 'nova-xvpvncproxy', 'nova-consoleauth']
        self.assertEquals(_proto, 'vnc')
        self.assertEquals(_servs, vnc_servs)
        self.assertEquals(_pkgs, vnc_pkgs)
        self.assertEquals(_proxy_page, None)

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    @patch.object(utils, 'git_install_requested')
    def test_determine_packages_quantum(self, git_requested, subcontext):
        git_requested.return_value = False
        self._resource_map(network_manager='quantum')
        pkgs = utils.determine_packages()
        self.assertIn('quantum-server', pkgs)

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    @patch.object(utils, 'git_install_requested')
    def test_determine_packages_neutron(self, git_requested, subcontext):
        git_requested.return_value = False
        self.is_relation_made.return_value = False
        self._resource_map(network_manager='neutron')
        pkgs = utils.determine_packages()
        self.assertIn('neutron-server', pkgs)

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    @patch.object(utils, 'git_install_requested')
    def test_determine_packages_nova_volume(self, git_requested, subcontext):
        git_requested.return_value = False
        self.relation_ids.return_value = ['nova-volume-service:0']
        pkgs = utils.determine_packages()
        self.assertIn('nova-api-os-volume', pkgs)

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    @patch.object(utils, 'git_install_requested')
    def test_determine_packages_console(self, git_requested, subcontext):
        git_requested.return_value = False
        self.test_config.set('console-access-protocol', 'spice')
        self.relation_ids.return_value = []
        pkgs = utils.determine_packages()
        console_pkgs = ['nova-spiceproxy', 'nova-consoleauth']
        for console_pkg in console_pkgs:
            self.assertIn(console_pkg, pkgs)

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    @patch.object(utils, 'git_install_requested')
    def test_determine_packages_base(self, git_requested, subcontext):
        git_requested.return_value = False
        self.relation_ids.return_value = []
        self.os_release.return_value = 'folsom'
        pkgs = utils.determine_packages()
        ex = list(set(utils.BASE_PACKAGES + utils.BASE_SERVICES))
        self.assertEquals(ex, pkgs)

    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    @patch.object(utils, 'git_install_requested')
    def test_determine_packages_base_grizzly_beyond(self, git_requested,
                                                    subcontext):
        git_requested.return_value = False
        self.relation_ids.return_value = []
        self.os_release.return_value = 'grizzly'
        pkgs = utils.determine_packages()
        ex = list(set(utils.BASE_PACKAGES + utils.BASE_SERVICES))
        ex.append('nova-conductor')
        self.assertEquals(sorted(ex), sorted(pkgs))

    @patch.object(utils, 'restart_map')
    def test_determine_ports(self, restart_map):
        restart_map.return_value = {
            '/etc/nova/nova.conf': ['nova-api-os-compute', 'nova-api-ec2'],
            '/etc/nova/api-paste.ini': ['nova-api-os-compute', 'nova-api-ec2'],
            '/etc/quantum/quantum.conf': ['quantum-server'],
        }
        ports = utils.determine_ports()
        ex = [8773, 8774, 9696]
        self.assertEquals(ex, sorted(ports))

    def test_save_script_rc_base(self):
        self.relation_ids.return_value = []
        utils.save_script_rc()
        self._save_script_rc.called_with(**SCRIPTRC_ENV_VARS)

    def test_save_script_quantum(self):
        self.relation_ids.return_value = []
        self.test_config.set('network-manager', 'Quantum')
        utils.save_script_rc()
        _ex = deepcopy(SCRIPTRC_ENV_VARS)
        _ex['OPENSTACK_SERVICE_API_QUANTUM'] = 'quantum-server'
        self._save_script_rc.called_with(**_ex)

    def test_save_script_nova_volume(self):
        self.relation_ids.return_value = ['nvol:0']
        utils.save_script_rc()
        _ex = deepcopy(SCRIPTRC_ENV_VARS)
        _ex['OPENSTACK_SERVICE_API_OS_VOL'] = 'nova-api-os-volume'
        self._save_script_rc.called_with(**_ex)

    def test_determine_volume_service_essex(self):
        self.os_release.return_value = 'essex'
        self.assertEquals('nova-volume', utils.volume_service())

    def test_determine_volume_service_folsom_cinder(self):
        self.os_release.return_value = 'folsom'
        self.relation_ids.return_value = ['cinder:0']
        self.assertEquals('cinder', utils.volume_service())

    def test_determine_volume_service_folsom_nova_vol(self):
        self.os_release.return_value = 'folsom'
        self.relation_ids.return_value = []
        self.assertEquals('nova-volume', utils.volume_service())

    def test_determine_volume_service_grizzly_and_beyond(self):
        pass

    @patch.object(utils, 'remove_known_host')
    @patch.object(utils, 'ssh_known_host_key')
    @patch('subprocess.check_output')
    def test_add_known_host_exists(self, check_output, host_key, rm):
        check_output.return_value = '|1|= fookey'
        host_key.return_value = '|1|= fookey'
        with patch_open() as (_open, _file):
            utils.add_known_host('foohost')
            self.assertFalse(rm.called)
            self.assertFalse(_file.write.called)

    @patch.object(utils, 'known_hosts')
    @patch.object(utils, 'remove_known_host')
    @patch.object(utils, 'ssh_known_host_key')
    @patch('subprocess.check_output')
    def test_add_known_host_exists_outdated(
            self, check_output, host_key, rm, known_hosts):
        check_output.return_value = '|1|= fookey'
        host_key.return_value = '|1|= fookey_old'
        with patch_open() as (_open, _file):
            utils.add_known_host('foohost', None, None)
            rm.assert_called_with('foohost', None, None)

    @patch.object(utils, 'known_hosts')
    @patch.object(utils, 'remove_known_host')
    @patch.object(utils, 'ssh_known_host_key')
    @patch('subprocess.check_output')
    def test_add_known_host_exists_added(
            self, check_output, host_key, rm, known_hosts):
        check_output.return_value = '|1|= fookey'
        host_key.return_value = None
        with patch_open() as (_open, _file):
            _file.write = MagicMock()
            utils.add_known_host('foohost')
            self.assertFalse(rm.called)
            _file.write.assert_called_with('|1|= fookey\n')

    @patch('__builtin__.open')
    @patch('os.mkdir')
    @patch('os.path.isdir')
    def test_ssh_directory_for_unit(self, isdir, mkdir, _open):
        self.remote_unit.return_value = 'nova-compute/0'
        isdir.return_value = False
        self.assertEquals(utils.ssh_directory_for_unit(),
                          '/etc/nova/compute_ssh/nova-compute')
        self.assertIn([
            call('/etc/nova/compute_ssh/nova-compute/authorized_keys', 'w'),
            call('/etc/nova/compute_ssh/nova-compute/known_hosts', 'w')
        ], _open.call_args_list)

    @patch.object(utils, 'ssh_directory_for_unit')
    def test_known_hosts(self, ssh_dir):
        ssh_dir.return_value = '/tmp/foo'
        self.assertEquals(utils.known_hosts(), '/tmp/foo/known_hosts')
        ssh_dir.assert_called_with(None, None)
        self.assertEquals(utils.known_hosts('bar'), '/tmp/foo/known_hosts')
        ssh_dir.assert_called_with('bar', None)

    @patch.object(utils, 'ssh_directory_for_unit')
    def test_authorized_keys(self, ssh_dir):
        ssh_dir.return_value = '/tmp/foo'
        self.assertEquals(utils.authorized_keys(), '/tmp/foo/authorized_keys')
        ssh_dir.assert_called_with(None, None)
        self.assertEquals(
            utils.authorized_keys('bar'),
            '/tmp/foo/authorized_keys')
        ssh_dir.assert_called_with('bar', None)

    @patch.object(utils, 'known_hosts')
    @patch('subprocess.check_call')
    def test_remove_host_key(self, check_call, known_hosts):
        known_hosts.return_value = '/tmp/known_hosts'
        utils.remove_known_host('foo')
        check_call.assert_called_with([
            'ssh-keygen', '-f', known_hosts(), '-R', 'foo'])

    @patch.object(utils, 'authorized_keys')
    def test_ssh_authorized_key_exists(self, keys):
        key = 'BBBBB3NzaC1yc2EBBBBDBQBBBBBBBQC27Us7lSjCpa7bumXBgc'
        with patch_open() as (_open, _file):
            _file.read.return_value = AUTHORIZED_KEYS
            self.assertTrue(utils.ssh_authorized_key_exists(key))

    @patch.object(utils, 'authorized_keys')
    def test_ssh_authorized_key_doesnt_exist(self, keys):
        key = ('xxxx')
        with patch_open() as (_open, _file):
            _file.read = MagicMock()
            _file.readreturn_value = AUTHORIZED_KEYS
            self.assertFalse(utils.ssh_authorized_key_exists(key))

    @patch.object(utils, 'known_hosts')
    @patch.object(utils, 'authorized_keys')
    @patch('os.path.isfile')
    def test_ssh_compute_remove(self, isfile,
                                auth_key, known_host):
        isfile.return_value = False

        removed_key = AUTHORIZED_KEYS.split('\n')[2]

        keys_removed = (
            "\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC27Us7lSjCpa7bumXAgc "
            "nova-compute-1\n"
            "ssh-rsa CCCCB3NzaC1yc2ECCCCDCQCBCCCBCQC27Us7lSjCpa7bumXCgc "
            "nova-compute-3\n"
        )
        isfile.return_value = True
        self.remote_unit.return_value = 'nova-compute/2'
        with patch_open() as (_open, _file):
            _file.readlines = MagicMock()
            _file.write = MagicMock()
            _file.readlines.return_value = AUTHORIZED_KEYS.split('\n')
            utils.ssh_compute_remove(removed_key)
            _file.write.assert_called_with(keys_removed)

    def test_network_manager_untranslated(self):
        self.test_config.set('network-manager', 'foo')
        self.os_release.return_value = 'folsom'

    def test_determine_endpoints_base(self):
        self.is_relation_made.return_value = False
        self.relation_ids.return_value = []
        self.assertEquals(
            BASE_ENDPOINTS, utils.determine_endpoints('http://foohost.com',
                                                      'http://foohost.com',
                                                      'http://foohost.com'))

    def test_determine_endpoints_nova_volume(self):
        self.is_relation_made.return_value = False
        self.relation_ids.side_effect = [['nova-volume-service/0'], []]
        endpoints = deepcopy(BASE_ENDPOINTS)
        endpoints.update({
            'nova-volume_admin_url':
            'http://foohost.com:8774/v1/$(tenant_id)s',
            'nova-volume_internal_url':
            'http://foohost.com:8774/v1/$(tenant_id)s',
            'nova-volume_public_url':
            'http://foohost.com:8774/v1/$(tenant_id)s',
            'nova-volume_region': 'RegionOne',
            'nova-volume_service': 'nova-volume'})
        self.assertEquals(
            endpoints, utils.determine_endpoints('http://foohost.com',
                                                 'http://foohost.com',
                                                 'http://foohost.com'))

    def test_determine_endpoints_quantum_neutron(self):
        self.is_relation_made.return_value = False
        self.relation_ids.return_value = []
        self.network_manager.return_value = 'quantum'
        endpoints = deepcopy(BASE_ENDPOINTS)
        endpoints.update({
            'quantum_admin_url': 'http://foohost.com:9696',
            'quantum_internal_url': 'http://foohost.com:9696',
            'quantum_public_url': 'http://foohost.com:9696',
            'quantum_region': 'RegionOne',
            'quantum_service': 'quantum'})
        self.assertEquals(
            endpoints, utils.determine_endpoints('http://foohost.com',
                                                 'http://foohost.com',
                                                 'http://foohost.com'))

    def test_determine_endpoints_neutron_api_rel(self):
        self.is_relation_made.return_value = True
        self.relation_ids.side_effect = [[], ['neutron-api:1']]
        self.network_manager.return_value = 'quantum'
        endpoints = deepcopy(BASE_ENDPOINTS)
        endpoints.update({
            'quantum_admin_url': None,
            'quantum_internal_url': None,
            'quantum_public_url': None,
            'quantum_region': None,
            'quantum_service': None})
        self.assertEquals(
            endpoints, utils.determine_endpoints('http://foohost.com',
                                                 'http://foohost.com',
                                                 'http://foohost.com'))

    @patch.object(utils, 'known_hosts')
    @patch('subprocess.check_output')
    def test_ssh_known_host_key(self, _check_output, _known_hosts):
        _known_hosts.return_value = '/foo/known_hosts'
        utils.ssh_known_host_key('test')
        _check_output.assert_called_with(
            ['ssh-keygen', '-f', '/foo/known_hosts',
             '-H', '-F', 'test'])
        _known_hosts.assert_called_with(None, None)
        utils.ssh_known_host_key('test', 'bar')
        _known_hosts.assert_called_with('bar', None)

    @patch.object(utils, 'known_hosts')
    @patch('subprocess.check_output')
    def test_ssh_known_host_key_bug1500589(self, _check_output, _known_hosts):
        """On precise ssh-keygen does not error if host not found in file. So
         check charm processes empty output properly"""
        _known_hosts.return_value = '/foo/known_hosts'
        _check_output.return_value = ''
        key = utils.ssh_known_host_key('test')
        self.assertEquals(key, None)

    @patch.object(utils, 'known_hosts')
    @patch('subprocess.check_call')
    def test_remove_known_host(self, _check_call, _known_hosts):
        _known_hosts.return_value = '/foo/known_hosts'
        utils.remove_known_host('test')
        _check_call.assert_called_with(
            ['ssh-keygen', '-f', '/foo/known_hosts',
             '-R', 'test'])
        _known_hosts.assert_called_with(None, None)
        utils.remove_known_host('test', 'bar')
        _known_hosts.assert_called_with('bar', None)

    @patch('subprocess.check_output')
    def test_migrate_nova_database(self, check_output):
        "Migrate database with nova-manage"
        self.relation_ids.return_value = []
        utils.migrate_nova_database()
        check_output.assert_called_with(['nova-manage', 'db', 'sync'])
        self.assertTrue(self.enable_services.called)
        self.cmd_all_services.assert_called_with('start')

    @patch('subprocess.check_output')
    def test_migrate_nova_database_cluster(self, check_output):
        "Migrate database with nova-manage in a clustered env"
        self.relation_ids.return_value = ['cluster:1']
        utils.migrate_nova_database()
        check_output.assert_called_with(['nova-manage', 'db', 'sync'])
        self.peer_store.assert_called_with('dbsync_state', 'complete')
        self.assertTrue(self.enable_services.called)
        self.cmd_all_services.assert_called_with('start')

    @patch.object(utils, 'get_step_upgrade_source')
    @patch.object(utils, 'migrate_nova_database')
    @patch.object(utils, 'determine_packages')
    def test_upgrade_grizzly_icehouse(self, determine_packages,
                                      migrate_nova_database,
                                      get_step_upgrade_source):
        "Simulate a call to do_openstack_upgrade() for grizzly->icehouse"
        self.test_config.set('openstack-origin', 'cloud:precise-icehouse')
        get_step_upgrade_source.return_value = 'cloud:precise-havana'
        self.os_release.side_effect = ['grizzly', 'havana']
        self.get_os_codename_install_source.side_effect = [
            'havana',
            'icehouse']
        self.is_elected_leader.return_value = True
        self.relation_ids.return_value = []
        utils.do_openstack_upgrade(self.register_configs())
        expected = [call(['stamp', 'grizzly']), call(['upgrade', 'head']),
                    call(['stamp', 'havana']), call(['upgrade', 'head'])]
        self.assertEquals(self.neutron_db_manage.call_args_list, expected)
        self.apt_update.assert_called_with(fatal=True)
        self.apt_upgrade.assert_called_with(options=DPKG_OPTS, fatal=True,
                                            dist=True)
        self.apt_install.assert_called_with(determine_packages(), fatal=True)
        expected = [call(), call(release='havana'), call(release='icehouse')]
        self.assertEquals(self.register_configs.call_args_list, expected)
        self.assertEquals(self.ml2_migration.call_count, 1)
        self.assertTrue(migrate_nova_database.call_count, 2)

    @patch.object(utils, 'get_step_upgrade_source')
    @patch.object(utils, 'migrate_nova_database')
    @patch.object(utils, 'determine_packages')
    def test_upgrade_havana_icehouse(self, determine_packages,
                                     migrate_nova_database,
                                     get_step_upgrade_source):
        "Simulate a call to do_openstack_upgrade() for havana->icehouse"
        self.test_config.set('openstack-origin', 'cloud:precise-icehouse')
        get_step_upgrade_source.return_value = None
        self.os_release.return_value = 'havana'
        self.get_os_codename_install_source.return_value = 'icehouse'
        self.is_elected_leader.return_value = True
        self.relation_ids.return_value = []
        utils.do_openstack_upgrade(self.register_configs())
        self.neutron_db_manage.assert_called_with(['upgrade', 'head'])
        self.apt_update.assert_called_with(fatal=True)
        self.apt_upgrade.assert_called_with(options=DPKG_OPTS, fatal=True,
                                            dist=True)
        self.apt_install.assert_called_with(determine_packages(), fatal=True)
        self.register_configs.assert_called_with(release='icehouse')
        self.assertEquals(self.ml2_migration.call_count, 1)
        self.assertTrue(migrate_nova_database.call_count, 1)

    @patch.object(utils, 'get_step_upgrade_source')
    @patch.object(utils, 'migrate_nova_database')
    @patch.object(utils, 'determine_packages')
    def test_upgrade_icehouse_juno(self, determine_packages,
                                   migrate_nova_database,
                                   get_step_upgrade_source):
        "Simulate a call to do_openstack_upgrade() for icehouse->juno"
        self.test_config.set('openstack-origin', 'cloud:trusty-juno')
        get_step_upgrade_source.return_value = None
        self.os_release.return_value = 'icehouse'
        self.get_os_codename_install_source.return_value = 'juno'
        self.is_elected_leader.return_value = True
        self.relation_ids.return_value = []
        utils.do_openstack_upgrade(self.register_configs())
        neutron_db_calls = [call(['stamp', 'icehouse']),
                            call(['upgrade', 'head'])]
        self.neutron_db_manage.assert_has_calls(neutron_db_calls,
                                                any_order=False)
        self.apt_update.assert_called_with(fatal=True)
        self.apt_upgrade.assert_called_with(options=DPKG_OPTS, fatal=True,
                                            dist=True)
        self.apt_install.assert_called_with(determine_packages(), fatal=True)
        self.register_configs.assert_called_with(release='juno')
        self.assertEquals(self.ml2_migration.call_count, 0)
        self.assertTrue(migrate_nova_database.call_count, 1)

    @patch.object(utils, 'get_step_upgrade_source')
    @patch.object(utils, 'migrate_nova_database')
    @patch.object(utils, 'determine_packages')
    def test_upgrade_juno_kilo(self, determine_packages,
                               migrate_nova_database,
                               get_step_upgrade_source):
        "Simulate a call to do_openstack_upgrade() for juno->kilo"
        self.test_config.set('openstack-origin', 'cloud:trusty-kilo')
        get_step_upgrade_source.return_value = None
        self.os_release.return_value = 'juno'
        self.get_os_codename_install_source.return_value = 'kilo'
        self.is_elected_leader.return_value = True
        self.relation_ids.return_value = []
        utils.do_openstack_upgrade(self.register_configs())
        self.assertEquals(self.neutron_db_manage.call_count, 0)
        self.apt_update.assert_called_with(fatal=True)
        self.apt_upgrade.assert_called_with(options=DPKG_OPTS, fatal=True,
                                            dist=True)
        self.apt_install.assert_called_with(determine_packages(), fatal=True)
        self.register_configs.assert_called_with(release='kilo')
        self.assertEquals(self.ml2_migration.call_count, 0)
        self.assertTrue(migrate_nova_database.call_count, 1)

    @patch.object(utils, '_do_openstack_upgrade')
    def test_upgrade_grizzly_icehouse_source(self, _do_openstack_upgrade):
        "Verify get_step_upgrade_source() for grizzly->icehouse"
        self.config.side_effect = None
        self.config.return_value = 'cloud:precise-icehouse'
        with patch_open() as (_open, _file):
            _file.read = MagicMock()
            _file.readline.return_value = ("deb url"
                                           " precise-updates/grizzly main")
            utils.do_openstack_upgrade(self.register_configs())
            expected = [call('cloud:precise-havana'),
                        call('cloud:precise-icehouse')]
            self.assertEquals(_do_openstack_upgrade.call_args_list, expected)

    @patch.object(utils, '_do_openstack_upgrade')
    def test_upgrade_havana_icehouse_source(self, _do_openstack_upgrade):
        "Verify get_step_upgrade_source() for havana->icehouse"
        self.config.side_effect = None
        self.config.return_value = 'cloud:precise-icehouse'
        with patch_open() as (_open, _file):
            _file.read = MagicMock()
            _file.readline.return_value = "deb url precise-updates/havana main"
            utils.do_openstack_upgrade(self.register_configs())
            expected = [call('cloud:precise-icehouse')]
            self.assertEquals(_do_openstack_upgrade.call_args_list, expected)

    def test_guard_map_nova(self):
        self.relation_ids.return_value = []
        self.os_release.return_value = 'havana'
        self.assertEqual(
            {'nova-api-ec2': ['identity-service', 'amqp', 'shared-db'],
             'nova-api-os-compute': ['identity-service', 'amqp', 'shared-db'],
             'nova-cert': ['identity-service', 'amqp', 'shared-db'],
             'nova-conductor': ['identity-service', 'amqp', 'shared-db'],
             'nova-objectstore': ['identity-service', 'amqp', 'shared-db'],
             'nova-scheduler': ['identity-service', 'amqp', 'shared-db']},
            utils.guard_map()
        )
        self.os_release.return_value = 'essex'
        self.assertEqual(
            {'nova-api-ec2': ['identity-service', 'amqp', 'shared-db'],
             'nova-api-os-compute': ['identity-service', 'amqp', 'shared-db'],
             'nova-cert': ['identity-service', 'amqp', 'shared-db'],
             'nova-objectstore': ['identity-service', 'amqp', 'shared-db'],
             'nova-scheduler': ['identity-service', 'amqp', 'shared-db']},
            utils.guard_map()
        )

    def test_guard_map_neutron(self):
        self.relation_ids.return_value = []
        self.network_manager.return_value = 'neutron'
        self.os_release.return_value = 'icehouse'
        self.is_relation_made.return_value = False
        self.assertEqual(
            {'neutron-server': ['identity-service', 'amqp', 'shared-db'],
             'nova-api-ec2': ['identity-service', 'amqp', 'shared-db'],
             'nova-api-os-compute': ['identity-service', 'amqp', 'shared-db'],
             'nova-cert': ['identity-service', 'amqp', 'shared-db'],
             'nova-conductor': ['identity-service', 'amqp', 'shared-db'],
             'nova-objectstore': ['identity-service', 'amqp', 'shared-db'],
             'nova-scheduler': ['identity-service', 'amqp', 'shared-db'], },
            utils.guard_map()
        )
        self.network_manager.return_value = 'quantum'
        self.os_release.return_value = 'grizzly'
        self.assertEqual(
            {'quantum-server': ['identity-service', 'amqp', 'shared-db'],
             'nova-api-ec2': ['identity-service', 'amqp', 'shared-db'],
             'nova-api-os-compute': ['identity-service', 'amqp', 'shared-db'],
             'nova-cert': ['identity-service', 'amqp', 'shared-db'],
             'nova-conductor': ['identity-service', 'amqp', 'shared-db'],
             'nova-objectstore': ['identity-service', 'amqp', 'shared-db'],
             'nova-scheduler': ['identity-service', 'amqp', 'shared-db'], },
            utils.guard_map()
        )

    def test_guard_map_pgsql(self):
        self.relation_ids.return_value = ['pgsql:1']
        self.network_manager.return_value = 'neutron'
        self.is_relation_made.return_value = False
        self.os_release.return_value = 'icehouse'
        self.assertEqual(
            {'neutron-server': ['identity-service', 'amqp',
                                'pgsql-neutron-db'],
             'nova-api-ec2': ['identity-service', 'amqp', 'pgsql-nova-db'],
             'nova-api-os-compute': ['identity-service', 'amqp',
                                     'pgsql-nova-db'],
             'nova-cert': ['identity-service', 'amqp', 'pgsql-nova-db'],
             'nova-conductor': ['identity-service', 'amqp', 'pgsql-nova-db'],
             'nova-objectstore': ['identity-service', 'amqp',
                                  'pgsql-nova-db'],
             'nova-scheduler': ['identity-service', 'amqp',
                                'pgsql-nova-db'], },
            utils.guard_map()
        )

    def test_service_guard_inactive(self):
        '''Ensure that if disabled, service guards nothing'''
        contexts = MagicMock()

        @utils.service_guard({'test': ['interfacea', 'interfaceb']},
                             contexts, False)
        def dummy_func():
            pass
        dummy_func()
        self.assertFalse(self.service_running.called)
        self.assertFalse(contexts.complete_contexts.called)

    def test_service_guard_active_guard(self):
        '''Ensure services with incomplete interfaces are stopped'''
        contexts = MagicMock()
        contexts.complete_contexts.return_value = ['interfacea']
        self.service_running.return_value = True

        @utils.service_guard({'test': ['interfacea', 'interfaceb']},
                             contexts, True)
        def dummy_func():
            pass
        dummy_func()
        self.service_running.assert_called_with('test')
        self.service_stop.assert_called_with('test')
        self.assertTrue(contexts.complete_contexts.called)

    def test_service_guard_active_release(self):
        '''Ensure services with complete interfaces are not stopped'''
        contexts = MagicMock()
        contexts.complete_contexts.return_value = ['interfacea',
                                                   'interfaceb']

        @utils.service_guard({'test': ['interfacea', 'interfaceb']},
                             contexts, True)
        def dummy_func():
            pass
        dummy_func()
        self.assertFalse(self.service_running.called)
        self.assertFalse(self.service_stop.called)
        self.assertTrue(contexts.complete_contexts.called)

    @patch.object(utils, 'git_install_requested')
    @patch.object(utils, 'git_clone_and_install')
    @patch.object(utils, 'git_post_install')
    @patch.object(utils, 'git_pre_install')
    def test_git_install(self, git_pre, git_post, git_clone_and_install,
                         git_requested):
        projects_yaml = openstack_origin_git
        git_requested.return_value = True
        utils.git_install(projects_yaml)
        self.assertTrue(git_pre.called)
        git_clone_and_install.assert_called_with(openstack_origin_git,
                                                 core_project='nova')
        self.assertTrue(git_post.called)

    @patch.object(utils, 'mkdir')
    @patch.object(utils, 'add_user_to_group')
    @patch.object(utils, 'add_group')
    @patch.object(utils, 'adduser')
    @patch('subprocess.check_call')
    def test_git_pre_install(self, check_call, adduser, add_group,
                             add_user_to_group, mkdir):
        utils.git_pre_install()
        expected = [
            call('nova', shell='/bin/bash', system_user=True),
            call('neutron', shell='/bin/bash', system_user=True),
        ]
        self.assertEquals(adduser.call_args_list, expected)
        check_call.assert_called_with(['usermod', '--home', '/var/lib/nova',
                                       'nova'])
        expected = [
            call('nova', system_group=True),
            call('neutron', system_group=True),
        ]
        self.assertEquals(add_group.call_args_list, expected)
        expected = [
            call('nova', 'nova'),
            call('neutron', 'neutron'),
        ]
        self.assertEquals(add_user_to_group.call_args_list, expected)
        expected = [
            call('/var/lib/nova', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/var/lib/nova/buckets', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/var/lib/nova/CA', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/var/lib/nova/CA/INTER', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/var/lib/nova/CA/newcerts', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/var/lib/nova/CA/private', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/var/lib/nova/CA/reqs', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/var/lib/nova/images', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/var/lib/nova/instances', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/var/lib/nova/keys', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/var/lib/nova/networks', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/var/lib/nova/tmp', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/var/lib/neutron', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/var/lib/neutron/lock', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/var/log/nova', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/etc/neutron', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/etc/neutron/plugins', owner='nova',
                 group='nova', perms=0755, force=False),
            call('/etc/neutron/plugins/ml2', owner='nova',
                 group='nova', perms=0755, force=False),
        ]
        self.assertEquals(mkdir.call_args_list, expected)

    @patch.object(utils, 'git_src_dir')
    @patch.object(utils, 'render')
    @patch.object(utils, 'git_pip_venv_dir')
    @patch.object(utils, 'pip_install')
    @patch('os.path.join')
    @patch('os.path.exists')
    @patch('os.symlink')
    @patch('shutil.copytree')
    @patch('shutil.rmtree')
    def test_git_post_install(self, rmtree, copytree, symlink,
                              exists, join, pip_install, venv, render,
                              git_src_dir):
        projects_yaml = openstack_origin_git
        join.return_value = 'joined-string'
        venv.return_value = '/mnt/openstack-git/venv'
        utils.git_post_install(projects_yaml)
        expected = [
            call('joined-string', '/etc/nova'),
        ]
        copytree.assert_has_calls(expected)
        expected = [
            call('joined-string', '/usr/local/bin/nova-manage'),
            call('joined-string', '/usr/local/bin/nova-rootwrap'),
        ]

        nova_cc = 'nova-cloud-controller'
        nova_user = 'nova'
        start_dir = '/var/lib/nova'
        nova_conf = '/etc/nova/nova.conf'
        nova_ec2_api_context = {
            'service_description': 'Nova EC2 API server',
            'service_name': nova_cc,
            'user_name': nova_user,
            'start_dir': start_dir,
            'process_name': 'nova-api-ec2',
            'executable_name': 'joined-string',
            'config_files': [nova_conf],
        }
        nova_api_os_compute_context = {
            'service_description': 'Nova OpenStack Compute API server',
            'service_name': nova_cc,
            'user_name': nova_user,
            'start_dir': start_dir,
            'process_name': 'nova-api-os-compute',
            'executable_name': 'joined-string',
            'config_files': [nova_conf],
        }
        nova_cells_context = {
            'service_description': 'Nova cells',
            'service_name': nova_cc,
            'user_name': nova_user,
            'start_dir': start_dir,
            'process_name': 'nova-cells',
            'executable_name': 'joined-string',
            'config_files': [nova_conf],
        }
        nova_cert_context = {
            'service_description': 'Nova cert',
            'service_name': nova_cc,
            'user_name': nova_user,
            'start_dir': start_dir,
            'process_name': 'nova-cert',
            'executable_name': 'joined-string',
            'config_files': [nova_conf],
        }
        nova_conductor_context = {
            'service_description': 'Nova conductor',
            'service_name': nova_cc,
            'user_name': nova_user,
            'start_dir': start_dir,
            'process_name': 'nova-conductor',
            'executable_name': 'joined-string',
            'config_files': [nova_conf],
        }
        nova_consoleauth_context = {
            'service_description': 'Nova console auth',
            'service_name': nova_cc,
            'user_name': nova_user,
            'start_dir': start_dir,
            'process_name': 'nova-consoleauth',
            'executable_name': 'joined-string',
            'config_files': [nova_conf],
        }
        nova_console_context = {
            'service_description': 'Nova console',
            'service_name': nova_cc,
            'user_name': nova_user,
            'start_dir': start_dir,
            'process_name': 'nova-console',
            'executable_name': 'joined-string',
            'config_files': [nova_conf],
        }
        nova_novncproxy_context = {
            'service_description': 'Nova NoVNC proxy',
            'service_name': nova_cc,
            'user_name': nova_user,
            'start_dir': start_dir,
            'process_name': 'nova-novncproxy',
            'executable_name': 'joined-string',
            'config_files': [nova_conf],
        }
        nova_objectstore_context = {
            'service_description': 'Nova object store',
            'service_name': nova_cc,
            'user_name': nova_user,
            'start_dir': start_dir,
            'process_name': 'nova-objectstore',
            'executable_name': 'joined-string',
            'config_files': [nova_conf],
        }
        nova_scheduler_context = {
            'service_description': 'Nova scheduler',
            'service_name': nova_cc,
            'user_name': nova_user,
            'start_dir': start_dir,
            'process_name': 'nova-scheduler',
            'executable_name': 'joined-string',
            'config_files': [nova_conf],
        }
        nova_spiceproxy_context = {
            'service_description': 'Nova spice proxy',
            'service_name': nova_cc,
            'user_name': nova_user,
            'start_dir': start_dir,
            'process_name': 'nova-spicehtml5proxy',
            'executable_name': 'joined-string',
            'config_files': [nova_conf],
        }
        nova_xvpvncproxy_context = {
            'service_description': 'Nova XVPVNC proxy',
            'service_name': nova_cc,
            'user_name': nova_user,
            'start_dir': start_dir,
            'process_name': 'nova-xvpvncproxy',
            'executable_name': 'joined-string',
            'config_files': [nova_conf],
        }
        expected = [
            call('git/nova_sudoers', '/etc/sudoers.d/nova_sudoers',
                 {}, perms=0o440),
            call('git.upstart', '/etc/init/nova-api-ec2.conf',
                 nova_ec2_api_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart', '/etc/init/nova-api-os-compute.conf',
                 nova_api_os_compute_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart', '/etc/init/nova-cells.conf',
                 nova_cells_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart', '/etc/init/nova-cert.conf',
                 nova_cert_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart', '/etc/init/nova-conductor.conf',
                 nova_conductor_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart', '/etc/init/nova-consoleauth.conf',
                 nova_consoleauth_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart', '/etc/init/nova-console.conf',
                 nova_console_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart', '/etc/init/nova-novncproxy.conf',
                 nova_novncproxy_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart', '/etc/init/nova-objectstore.conf',
                 nova_objectstore_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart', '/etc/init/nova-scheduler.conf',
                 nova_scheduler_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart', '/etc/init/nova-spiceproxy.conf',
                 nova_spiceproxy_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart', '/etc/init/nova-xvpvncproxy.conf',
                 nova_xvpvncproxy_context, perms=0o644,
                 templates_dir='joined-string'),
        ]
        self.assertEquals(render.call_args_list, expected)
        self.assertTrue(self.apt_update.called)
        self.apt_install.assert_called_with(['novnc', 'spice-html5',
                                             'websockify'], fatal=True)
