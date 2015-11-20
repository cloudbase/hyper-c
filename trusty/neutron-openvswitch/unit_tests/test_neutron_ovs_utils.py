
from mock import MagicMock, patch, call
from collections import OrderedDict
import charmhelpers.contrib.openstack.templating as templating

templating.OSConfigRenderer = MagicMock()

import neutron_ovs_utils as nutils
import neutron_ovs_context

from test_utils import (
    CharmTestCase,
)
import charmhelpers
import charmhelpers.core.hookenv as hookenv


TO_PATCH = [
    'add_bridge',
    'add_bridge_port',
    'apt_install',
    'apt_update',
    'config',
    'os_release',
    'filter_installed_packages',
    'neutron_plugin_attribute',
    'full_restart',
    'service_restart',
    'service_running',
    'ExternalPortContext',
    'determine_dkms_package',
    'headers_package',
    'status_set',
]

head_pkg = 'linux-headers-3.15.0-5-generic'

openstack_origin_git = \
    """repositories:
         - {name: requirements,
            repository: 'git://git.openstack.org/openstack/requirements',
            branch: stable/juno}
         - {name: neutron,
            repository: 'git://git.openstack.org/openstack/neutron',
            branch: stable/juno}"""


def _mock_npa(plugin, attr, net_manager=None):
    plugins = {
        'ovs': {
            'config': '/etc/neutron/plugins/ml2/ml2_conf.ini',
            'driver': 'neutron.plugins.ml2.plugin.Ml2Plugin',
            'contexts': [],
            'services': ['neutron-plugin-openvswitch-agent'],
            'packages': [[head_pkg], ['neutron-plugin-openvswitch-agent']],
            'server_packages': ['neutron-server',
                                'neutron-plugin-ml2'],
            'server_services': ['neutron-server']
        },
    }
    return plugins[plugin][attr]


class DummyContext():

    def __init__(self, return_value):
        self.return_value = return_value

    def __call__(self):
        return self.return_value


class TestNeutronOVSUtils(CharmTestCase):

    def setUp(self):
        super(TestNeutronOVSUtils, self).setUp(nutils, TO_PATCH)
        self.neutron_plugin_attribute.side_effect = _mock_npa
        self.config.side_effect = self.test_config.get

    def tearDown(self):
        # Reset cached cache
        hookenv.cache = {}

    @patch.object(nutils, 'determine_packages')
    def test_install_packages(self, _determine_packages):
        _determine_packages.return_value = 'randompkg'
        nutils.install_packages()
        self.apt_update.assert_called_with()
        self.apt_install.assert_called_with(self.filter_installed_packages())

    @patch.object(nutils, 'determine_packages')
    def test_install_packages_dkms_needed(self, _determine_packages):
        _determine_packages.return_value = 'randompkg'
        self.determine_dkms_package.return_value = \
            ['openvswitch-datapath-dkms']
        self.headers_package.return_value = 'linux-headers-foobar'
        nutils.install_packages()
        self.apt_update.assert_called_with()
        self.apt_install.assert_has_calls([
            call(['linux-headers-foobar',
                  'openvswitch-datapath-dkms'], fatal=True),
            call(self.filter_installed_packages()),
        ])

    @patch.object(nutils, 'use_dvr')
    @patch.object(nutils, 'git_install_requested')
    @patch.object(charmhelpers.contrib.openstack.neutron, 'os_release')
    @patch.object(charmhelpers.contrib.openstack.neutron, 'headers_package')
    def test_determine_packages(self, _head_pkgs, _os_rel, _git_requested,
                                _use_dvr):
        self.test_config.set('enable-local-dhcp-and-metadata', False)
        _git_requested.return_value = False
        _use_dvr.return_value = False
        _os_rel.return_value = 'trusty'
        _head_pkgs.return_value = head_pkg
        pkg_list = nutils.determine_packages()
        expect = ['neutron-plugin-openvswitch-agent', head_pkg]
        self.assertItemsEqual(pkg_list, expect)

    @patch.object(nutils, 'use_dvr')
    @patch.object(nutils, 'git_install_requested')
    @patch.object(charmhelpers.contrib.openstack.neutron, 'os_release')
    @patch.object(charmhelpers.contrib.openstack.neutron, 'headers_package')
    def test_determine_packages_metadata(self, _head_pkgs, _os_rel,
                                         _git_requested, _use_dvr):
        self.test_config.set('enable-local-dhcp-and-metadata', True)
        _git_requested.return_value = False
        _use_dvr.return_value = False
        _os_rel.return_value = 'trusty'
        _head_pkgs.return_value = head_pkg
        pkg_list = nutils.determine_packages()
        expect = ['neutron-plugin-openvswitch-agent', head_pkg,
                  'neutron-metadata-agent', 'neutron-dhcp-agent']
        self.assertItemsEqual(pkg_list, expect)

    @patch.object(nutils, 'use_dvr')
    @patch.object(nutils, 'git_install_requested')
    @patch.object(charmhelpers.contrib.openstack.neutron, 'os_release')
    @patch.object(charmhelpers.contrib.openstack.neutron, 'headers_package')
    def test_determine_packages_git(self, _head_pkgs, _os_rel,
                                    _git_requested, _use_dvr):
        self.test_config.set('enable-local-dhcp-and-metadata', False)
        _git_requested.return_value = True
        _use_dvr.return_value = True
        _os_rel.return_value = 'trusty'
        _head_pkgs.return_value = head_pkg
        pkg_list = nutils.determine_packages()
        self.assertFalse('neutron-l3-agent' in pkg_list)

    @patch.object(nutils, 'use_dvr')
    def test_register_configs(self, _use_dvr):
        class _mock_OSConfigRenderer():
            def __init__(self, templates_dir=None, openstack_release=None):
                self.configs = []
                self.ctxts = []

            def register(self, config, ctxt):
                self.configs.append(config)
                self.ctxts.append(ctxt)

        _use_dvr.return_value = False
        self.os_release.return_value = 'trusty'
        templating.OSConfigRenderer.side_effect = _mock_OSConfigRenderer
        _regconfs = nutils.register_configs()
        confs = ['/etc/neutron/neutron.conf',
                 '/etc/neutron/plugins/ml2/ml2_conf.ini',
                 '/etc/init/os-charm-phy-nic-mtu.conf']
        self.assertItemsEqual(_regconfs.configs, confs)

    @patch.object(nutils, 'use_dvr')
    def test_resource_map(self, _use_dvr):
        _use_dvr.return_value = False
        _map = nutils.resource_map()
        svcs = ['neutron-plugin-openvswitch-agent']
        confs = [nutils.NEUTRON_CONF]
        [self.assertIn(q_conf, _map.keys()) for q_conf in confs]
        self.assertEqual(_map[nutils.NEUTRON_CONF]['services'], svcs)

    @patch.object(nutils, 'use_dvr')
    def test_resource_map_dvr(self, _use_dvr):
        _use_dvr.return_value = True
        _map = nutils.resource_map()
        svcs = ['neutron-plugin-openvswitch-agent', 'neutron-metadata-agent',
                'neutron-l3-agent']
        confs = [nutils.NEUTRON_CONF]
        [self.assertIn(q_conf, _map.keys()) for q_conf in confs]
        self.assertEqual(_map[nutils.NEUTRON_CONF]['services'], svcs)

    @patch.object(nutils, 'enable_local_dhcp')
    @patch.object(nutils, 'use_dvr')
    def test_resource_map_dhcp(self, _use_dvr, _enable_local_dhcp):
        _enable_local_dhcp.return_value = True
        _use_dvr.return_value = False
        _map = nutils.resource_map()
        svcs = ['neutron-plugin-openvswitch-agent', 'neutron-metadata-agent',
                'neutron-dhcp-agent']
        confs = [nutils.NEUTRON_CONF, nutils.NEUTRON_METADATA_AGENT_CONF,
                 nutils.NEUTRON_DHCP_AGENT_CONF]
        [self.assertIn(q_conf, _map.keys()) for q_conf in confs]
        self.assertEqual(_map[nutils.NEUTRON_CONF]['services'], svcs)

    @patch.object(nutils, 'use_dvr')
    def test_restart_map(self, _use_dvr):
        _use_dvr.return_value = False
        _restart_map = nutils.restart_map()
        ML2CONF = "/etc/neutron/plugins/ml2/ml2_conf.ini"
        expect = OrderedDict([
            (nutils.NEUTRON_CONF, ['neutron-plugin-openvswitch-agent']),
            (ML2CONF, ['neutron-plugin-openvswitch-agent']),
            (nutils.PHY_NIC_MTU_CONF, ['os-charm-phy-nic-mtu'])
        ])
        self.assertEqual(expect, _restart_map)
        for item in _restart_map:
            self.assertTrue(item in _restart_map)
            self.assertTrue(expect[item] == _restart_map[item])

    @patch.object(nutils, 'use_dvr')
    @patch('charmhelpers.contrib.openstack.context.config')
    def test_configure_ovs_ovs_data_port(self, mock_config, _use_dvr):
        _use_dvr.return_value = False
        mock_config.side_effect = self.test_config.get
        self.config.side_effect = self.test_config.get
        self.ExternalPortContext.return_value = \
            DummyContext(return_value=None)
        # Test back-compatibility i.e. port but no bridge (so br-data is
        # assumed)
        self.test_config.set('data-port', 'eth0')
        nutils.configure_ovs()
        self.add_bridge.assert_has_calls([
            call('br-int'),
            call('br-ex'),
            call('br-data')
        ])
        self.assertTrue(self.add_bridge_port.called)

        # Now test with bridge:port format
        self.test_config.set('data-port', 'br-foo:eth0')
        self.add_bridge.reset_mock()
        self.add_bridge_port.reset_mock()
        nutils.configure_ovs()
        self.add_bridge.assert_has_calls([
            call('br-int'),
            call('br-ex'),
            call('br-data')
        ])
        # Not called since we have a bogus bridge in data-ports
        self.assertFalse(self.add_bridge_port.called)

    @patch.object(nutils, 'use_dvr')
    @patch('charmhelpers.contrib.openstack.context.config')
    def test_configure_ovs_starts_service_if_required(self, mock_config,
                                                      _use_dvr):
        _use_dvr.return_value = False
        mock_config.side_effect = self.test_config.get
        self.config.return_value = 'ovs'
        self.service_running.return_value = False
        nutils.configure_ovs()
        self.assertTrue(self.full_restart.called)

    @patch.object(nutils, 'use_dvr')
    @patch('charmhelpers.contrib.openstack.context.config')
    def test_configure_ovs_doesnt_restart_service(self, mock_config, _use_dvr):
        _use_dvr.return_value = False
        mock_config.side_effect = self.test_config.get
        self.config.side_effect = self.test_config.get
        self.service_running.return_value = True
        nutils.configure_ovs()
        self.assertFalse(self.full_restart.called)

    @patch.object(nutils, 'use_dvr')
    @patch('charmhelpers.contrib.openstack.context.config')
    def test_configure_ovs_ovs_ext_port(self, mock_config, _use_dvr):
        _use_dvr.return_value = True
        mock_config.side_effect = self.test_config.get
        self.config.side_effect = self.test_config.get
        self.test_config.set('ext-port', 'eth0')
        self.ExternalPortContext.return_value = \
            DummyContext(return_value={'ext_port': 'eth0'})
        nutils.configure_ovs()
        self.add_bridge.assert_has_calls([
            call('br-int'),
            call('br-ex'),
            call('br-data')
        ])
        self.add_bridge_port.assert_called_with('br-ex', 'eth0')

    @patch.object(neutron_ovs_context, 'SharedSecretContext')
    def test_get_shared_secret(self, _dvr_secret_ctxt):
        _dvr_secret_ctxt.return_value = \
            DummyContext(return_value={'shared_secret': 'supersecret'})
        self.assertEqual(nutils.get_shared_secret(), 'supersecret')

    @patch.object(nutils, 'git_install_requested')
    @patch.object(nutils, 'git_clone_and_install')
    @patch.object(nutils, 'git_post_install')
    @patch.object(nutils, 'git_pre_install')
    def test_git_install(self, git_pre, git_post, git_clone_and_install,
                         git_requested):
        projects_yaml = openstack_origin_git
        git_requested.return_value = True
        nutils.git_install(projects_yaml)
        self.assertTrue(git_pre.called)
        git_clone_and_install.assert_called_with(openstack_origin_git,
                                                 core_project='neutron')
        self.assertTrue(git_post.called)

    @patch.object(nutils, 'mkdir')
    @patch.object(nutils, 'write_file')
    @patch.object(nutils, 'add_user_to_group')
    @patch.object(nutils, 'add_group')
    @patch.object(nutils, 'adduser')
    def test_git_pre_install(self, adduser, add_group, add_user_to_group,
                             write_file, mkdir):
        nutils.git_pre_install()
        adduser.assert_called_with('neutron', shell='/bin/bash',
                                   system_user=True)
        add_group.assert_called_with('neutron', system_group=True)
        add_user_to_group.assert_called_with('neutron', 'neutron')
        expected = [
            call('/var/lib/neutron', owner='neutron',
                 group='neutron', perms=0755, force=False),
            call('/var/lib/neutron/lock', owner='neutron',
                 group='neutron', perms=0755, force=False),
            call('/var/log/neutron', owner='neutron',
                 group='neutron', perms=0755, force=False),
        ]
        self.assertEquals(mkdir.call_args_list, expected)
        expected = [
            call('/var/log/neutron/server.log', '', owner='neutron',
                 group='neutron', perms=0600),
        ]
        self.assertEquals(write_file.call_args_list, expected)

    @patch.object(nutils, 'git_src_dir')
    @patch.object(nutils, 'service_restart')
    @patch.object(nutils, 'render')
    @patch('os.path.join')
    @patch('os.path.exists')
    @patch('os.symlink')
    @patch('shutil.copytree')
    @patch('shutil.rmtree')
    def test_git_post_install(self, rmtree, copytree, symlink, exists, join,
                              render, service_restart, git_src_dir):
        projects_yaml = openstack_origin_git
        join.return_value = 'joined-string'
        nutils.git_post_install(projects_yaml)
        expected = [
            call('joined-string', '/etc/neutron'),
            call('joined-string', '/etc/neutron/plugins'),
            call('joined-string', '/etc/neutron/rootwrap.d'),
        ]
        copytree.assert_has_calls(expected)
        expected = [
            call('joined-string', '/usr/local/bin/neutron-rootwrap'),
        ]
        symlink.assert_has_calls(expected, any_order=True)
        neutron_ovs_agent_context = {
            'service_description': 'Neutron OpenvSwitch Plugin Agent',
            'charm_name': 'neutron-openvswitch',
            'process_name': 'neutron-openvswitch-agent',
            'executable_name': 'joined-string',
            'cleanup_process_name': 'neutron-ovs-cleanup',
            'plugin_config': '/etc/neutron/plugins/ml2/ml2_conf.ini',
            'log_file': '/var/log/neutron/openvswitch-agent.log',
        }
        neutron_ovs_cleanup_context = {
            'service_description': 'Neutron OpenvSwitch Cleanup',
            'charm_name': 'neutron-openvswitch',
            'process_name': 'neutron-ovs-cleanup',
            'executable_name': 'joined-string',
            'log_file': '/var/log/neutron/ovs-cleanup.log',
        }
        expected = [
            call('git/neutron_sudoers', '/etc/sudoers.d/neutron_sudoers', {},
                 perms=0o440),
            call('git/upstart/neutron-plugin-openvswitch-agent.upstart',
                 '/etc/init/neutron-plugin-openvswitch-agent.conf',
                 neutron_ovs_agent_context, perms=0o644),
            call('git/upstart/neutron-ovs-cleanup.upstart',
                 '/etc/init/neutron-ovs-cleanup.conf',
                 neutron_ovs_cleanup_context, perms=0o644),
        ]
        self.assertEquals(render.call_args_list, expected)
        expected = [
            call('neutron-plugin-openvswitch-agent'),
        ]
        self.assertEquals(service_restart.call_args_list, expected)
