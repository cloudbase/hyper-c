from mock import MagicMock, patch, call
import yaml
import horizon_utils as utils
_register_configs = utils.register_configs
utils.register_configs = MagicMock()
import horizon_hooks as hooks
RESTART_MAP = utils.restart_map()
utils.register_configs = _register_configs
from charmhelpers.contrib.hahelpers.cluster import HAIncompleteConfig
from test_utils import CharmTestCase

TO_PATCH = [
    'config',
    'relation_set',
    'relation_get',
    'configure_installation_source',
    'apt_update',
    'apt_install',
    'filter_installed_packages',
    'open_port',
    'CONFIGS',
    'get_hacluster_config',
    'relation_ids',
    'enable_ssl',
    'openstack_upgrade_available',
    'do_openstack_upgrade',
    'save_script_rc',
    'install_ca_cert',
    'unit_get',
    'log',
    'execd_preinstall',
    'b64decode',
    'os_release',
    'get_iface_for_address',
    'get_netmask_for_address',
    'git_install',
    'git_post_install_late',
    'update_nrpe_config',
    'lsb_release',
    'status_set',
]


def passthrough(value):
    return value


class TestHorizonHooks(CharmTestCase):

    def setUp(self):
        super(TestHorizonHooks, self).setUp(hooks, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.b64decode.side_effect = passthrough
        hooks.hooks._config_save = False

    def _call_hook(self, hookname):
        hooks.hooks.execute([
            'hooks/{}'.format(hookname)])

    @patch.object(utils, 'git_install_requested')
    def test_install_hook(self, _git_requested):
        _git_requested.return_value = False
        self.filter_installed_packages.return_value = ['foo', 'bar']
        self.os_release.return_value = 'icehouse'
        self._call_hook('install')
        self.configure_installation_source.assert_called_with('distro')
        self.apt_update.assert_called_with(fatal=True)
        self.apt_install.assert_called_with(['foo', 'bar'], fatal=True)

    @patch.object(utils, 'git_install_requested')
    def test_install_hook_precise(self, _git_requested):
        _git_requested.return_value = False
        self.filter_installed_packages.return_value = ['foo', 'bar']
        self.os_release.return_value = 'icehouse'
        self.lsb_release.return_value = {'DISTRIB_CODENAME': 'precise'}
        self._call_hook('install')
        self.configure_installation_source.assert_called_with('distro')
        self.apt_update.assert_called_with(fatal=True)
        calls = [
            call('python-six', fatal=True),
            call(['foo', 'bar'], fatal=True),
        ]
        self.apt_install.assert_has_calls(calls)

    @patch.object(utils, 'git_install_requested')
    def test_install_hook_icehouse_pkgs(self, _git_requested):
        _git_requested.return_value = False
        self.os_release.return_value = 'icehouse'
        self._call_hook('install.real')
        for pkg in ['nodejs', 'node-less']:
            self.assertFalse(
                pkg in self.filter_installed_packages.call_args[0][0]
            )
        self.assertTrue(self.apt_install.called)

    @patch.object(utils, 'git_install_requested')
    def test_install_hook_pre_icehouse_pkgs(self, _git_requested):
        _git_requested.return_value = False
        self.os_release.return_value = 'grizzly'
        self._call_hook('install.real')
        for pkg in ['nodejs', 'node-less']:
            self.assertTrue(
                pkg in self.filter_installed_packages.call_args[0][0]
            )
        self.assertTrue(self.apt_install.called)

    @patch.object(utils, 'git_install_requested')
    def test_install_hook_git(self, _git_requested):
        _git_requested.return_value = True
        self.filter_installed_packages.return_value = ['foo', 'bar']
        repo = 'cloud:trusty-juno'
        openstack_origin_git = {
            'repositories': [
                {'name': 'requirements',
                 'repository': 'git://git.openstack.org/openstack/requirements',  # noqa
                 'branch': 'stable/juno'},
                {'name': 'horizon',
                 'repository': 'git://git.openstack.org/openstack/horizon',
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
        self.apt_update.assert_called_with(fatal=True)
        self.apt_install.assert_called_with(['foo', 'bar'], fatal=True)
        self.git_install.assert_called_with(projects_yaml)

    @patch('charmhelpers.core.host.path_hash')
    @patch('charmhelpers.core.host.service')
    @patch.object(utils, 'git_install_requested')
    def test_upgrade_charm_hook(self, _git_requested, _service, _hash):
        _git_requested.return_value = False
        side_effects = []
        [side_effects.append(None) for f in RESTART_MAP.keys()]
        [side_effects.append('bar') for f in RESTART_MAP.keys()]
        _hash.side_effect = side_effects
        self.filter_installed_packages.return_value = ['foo']
        self._call_hook('upgrade-charm')
        self.apt_install.assert_called_with(['foo'], fatal=True)
        self.assertTrue(self.CONFIGS.write_all.called)
        ex = [
            call('restart', 'apache2'),
            call('restart', 'haproxy')
        ]
        self.assertEquals(ex, _service.call_args_list)

    def test_ha_joined_complete_config(self):
        conf = {
            'ha-bindiface': 'eth100',
            'ha-mcastport': '37373',
            'vip': '192.168.25.163',
            'vip_iface': 'eth101',
            'vip_cidr': '19'
        }
        self.get_iface_for_address.return_value = 'eth101'
        self.get_netmask_for_address.return_value = '19'
        self.get_hacluster_config.return_value = conf
        self._call_hook('ha-relation-joined')
        ex_args = {
            'corosync_mcastport': '37373',
            'init_services': {
                'res_horizon_haproxy': 'haproxy'},
            'resource_params': {
                'res_horizon_eth101_vip':
                'params ip="192.168.25.163" cidr_netmask="19"'
                ' nic="eth101"',
                'res_horizon_haproxy': 'op monitor interval="5s"'},
            'corosync_bindiface': 'eth100',
            'clones': {
                'cl_horizon_haproxy': 'res_horizon_haproxy'},
            'resources': {
                'res_horizon_eth101_vip': 'ocf:heartbeat:IPaddr2',
                'res_horizon_haproxy': 'lsb:haproxy'}
        }
        self.relation_set.assert_called_with(**ex_args)

    def test_ha_joined_no_bound_ip(self):
        conf = {
            'ha-bindiface': 'eth100',
            'ha-mcastport': '37373',
            'vip': '192.168.25.163',
        }
        self.test_config.set('vip_iface', 'eth120')
        self.test_config.set('vip_cidr', '21')
        self.get_iface_for_address.return_value = None
        self.get_netmask_for_address.return_value = None
        self.get_hacluster_config.return_value = conf
        self._call_hook('ha-relation-joined')
        ex_args = {
            'corosync_mcastport': '37373',
            'init_services': {
                'res_horizon_haproxy': 'haproxy'},
            'resource_params': {
                'res_horizon_eth120_vip':
                'params ip="192.168.25.163" cidr_netmask="21"'
                ' nic="eth120"',
                'res_horizon_haproxy': 'op monitor interval="5s"'},
            'corosync_bindiface': 'eth100',
            'clones': {
                'cl_horizon_haproxy': 'res_horizon_haproxy'},
            'resources': {
                'res_horizon_eth120_vip': 'ocf:heartbeat:IPaddr2',
                'res_horizon_haproxy': 'lsb:haproxy'}
        }
        self.relation_set.assert_called_with(**ex_args)

    def test_ha_joined_incomplete_config(self):
        self.get_hacluster_config.side_effect = HAIncompleteConfig(1, 'bang')
        self.assertRaises(HAIncompleteConfig, self._call_hook,
                          'ha-relation-joined')

    @patch('horizon_hooks.keystone_joined')
    @patch.object(hooks, 'git_install_requested')
    def test_config_changed_no_upgrade(self, _git_requested, _joined):
        _git_requested.return_value = False
        self.relation_ids.return_value = ['identity/0']
        self.openstack_upgrade_available.return_value = False
        self._call_hook('config-changed')
        _joined.assert_called_with('identity/0')
        self.openstack_upgrade_available.assert_called_with(
            'openstack-dashboard'
        )
        self.assertTrue(self.enable_ssl.called)
        self.do_openstack_upgrade.assert_not_called()
        self.assertTrue(self.save_script_rc.called)
        self.assertTrue(self.CONFIGS.write_all.called)
        self.open_port.assert_has_calls([call(80), call(443)])

    @patch.object(hooks, 'git_install_requested')
    def test_config_changed_do_upgrade(self, _git_requested):
        _git_requested.return_value = False
        self.relation_ids.return_value = []
        self.test_config.set('openstack-origin', 'cloud:precise-grizzly')
        self.openstack_upgrade_available.return_value = True
        self._call_hook('config-changed')
        self.assertTrue(self.do_openstack_upgrade.called)

    @patch.object(hooks, 'git_install_requested')
    @patch.object(hooks, 'config_value_changed')
    def test_config_changed_git_updated(self, _config_val_changed,
                                        _git_requested):
        _git_requested.return_value = True
        repo = 'cloud:trusty-juno'
        openstack_origin_git = {
            'repositories': [
                {'name': 'requirements',
                 'repository': 'git://git.openstack.org/openstack/requirements',  # noqa
                 'branch': 'stable/juno'},
                {'name': 'horizon',
                 'repository': 'git://git.openstack.org/openstack/horizon',
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

    def test_keystone_joined_in_relation(self):
        self._call_hook('identity-service-relation-joined')
        self.relation_set.assert_called_with(
            relation_id=None, service='None', region='None',
            public_url='None', admin_url='None', internal_url='None',
            requested_roles='Member'
        )

    def test_keystone_joined_not_in_relation(self):
        hooks.keystone_joined('identity/0')
        self.relation_set.assert_called_with(
            relation_id='identity/0', service='None', region='None',
            public_url='None', admin_url='None', internal_url='None',
            requested_roles='Member'
        )

    def test_keystone_changed_no_cert(self):
        self.relation_get.return_value = None
        self._call_hook('identity-service-relation-changed')
        self.CONFIGS.write.assert_called_with(
            '/etc/openstack-dashboard/local_settings.py'
        )
        self.install_ca_cert.assert_not_called()

    def test_keystone_changed_cert(self):
        self.relation_get.return_value = 'certificate'
        self._call_hook('identity-service-relation-changed')
        self.CONFIGS.write.assert_called_with(
            '/etc/openstack-dashboard/local_settings.py'
        )
        self.install_ca_cert.assert_called_with('certificate')

    def test_cluster_departed(self):
        self._call_hook('cluster-relation-departed')
        self.CONFIGS.write.assert_called_with('/etc/haproxy/haproxy.cfg')

    def test_cluster_changed(self):
        self._call_hook('cluster-relation-changed')
        self.CONFIGS.write.assert_called_with('/etc/haproxy/haproxy.cfg')

    def test_website_joined(self):
        self.unit_get.return_value = '192.168.1.1'
        self._call_hook('website-relation-joined')
        self.relation_set.assert_called_with(port=70, hostname='192.168.1.1')

    @patch.object(hooks, 'os_release')
    @patch.object(hooks, 'git_install_requested')
    def test_dashboard_config_joined_not_git(
            self, _git_requested, _os_release):
        _git_requested.return_value = False
        _os_release.return_value = 'vivid'
        self._call_hook('dashboard-plugin-relation-joined')
        self.relation_set.assert_called_with(
            release='vivid',
            bin_path='/usr/bin',
            openstack_dir='/usr/share/openstack-dashboard',
            relation_id=None
        )

    @patch.object(hooks, 'os_release')
    @patch.object(hooks, 'git_pip_venv_dir')
    @patch.object(hooks, 'git_install_requested')
    def test_dashboard_config_joined_git(
            self, _git_requested, _git_pip_venv_dir, _os_release):
        expected_bin_path = '/mnt/fuji/venv'
        _git_requested.return_value = True
        _git_pip_venv_dir.return_value = expected_bin_path
        _os_release.return_value = 'wily'
        self._call_hook('dashboard-plugin-relation-joined')
        self.relation_set.assert_called_with(
            release='wily',
            bin_path=expected_bin_path,
            openstack_dir='/usr/share/openstack-dashboard',
            relation_id=None
        )
