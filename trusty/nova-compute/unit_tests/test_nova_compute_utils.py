import itertools
import tempfile

import nova_compute_context as compute_context
import nova_compute_utils as utils

from mock import (
    patch,
    MagicMock,
    call
)
from test_utils import (
    CharmTestCase,
    patch_open
)


TO_PATCH = [
    'config',
    'os_release',
    'log',
    'neutron_plugin_attribute',
    'pip_install',
    'related_units',
    'relation_ids',
    'relation_get',
    'service_restart',
    'mkdir',
    'install_alternative',
    'add_user_to_group',
    'MetadataServiceContext',
    'lsb_release',
    'charm_dir',
    'hugepage_support',
    'rsync',
    'fstab_mount',
]

OVS_PKGS = [
    ['quantum-plugin-openvswitch-agent'],
    ['openvswitch-datapath-dkms'],
]

OVS_PKGS_FLAT = list(itertools.chain.from_iterable(OVS_PKGS))

openstack_origin_git = \
    """repositories:
         - {name: requirements,
            repository: 'git://git.openstack.org/openstack/requirements',
            branch: stable/juno}
         - {name: nova,
            repository: 'git://git.openstack.org/openstack/nova',
            branch: stable/juno}"""


class NovaComputeUtilsTests(CharmTestCase):

    def setUp(self):
        super(NovaComputeUtilsTests, self).setUp(utils, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.charm_dir.return_value = 'mycharm'

    @patch.object(utils, 'enable_nova_metadata')
    @patch.object(utils, 'network_manager')
    @patch.object(utils, 'git_install_requested')
    def test_determine_packages_nova_network(self, git_requested, net_man,
                                             en_meta):
        git_requested.return_value = False
        en_meta.return_value = False
        net_man.return_value = 'flatdhcpmanager'
        self.relation_ids.return_value = []
        result = utils.determine_packages()
        ex = utils.BASE_PACKAGES + [
            'nova-api',
            'nova-network',
            'nova-compute-kvm'
        ]
        self.assertEquals(ex, result)

    @patch.object(utils, 'enable_nova_metadata')
    @patch.object(utils, 'neutron_plugin')
    @patch.object(utils, 'network_manager')
    @patch.object(utils, 'git_install_requested')
    def test_determine_packages_quantum(self, git_requested, net_man, n_plugin,
                                        en_meta):
        git_requested.return_value = False
        en_meta.return_value = False
        self.neutron_plugin_attribute.return_value = OVS_PKGS
        net_man.return_value = 'quantum'
        n_plugin.return_value = 'ovs'
        self.relation_ids.return_value = []
        result = utils.determine_packages()
        ex = utils.BASE_PACKAGES + OVS_PKGS_FLAT + ['nova-compute-kvm']
        self.assertEquals(ex, result)

    @patch.object(utils, 'neutron_plugin_legacy_mode')
    @patch.object(utils, 'enable_nova_metadata')
    @patch.object(utils, 'neutron_plugin')
    @patch.object(utils, 'network_manager')
    @patch.object(utils, 'git_install_requested')
    def test_determine_packages_quantum_legacy_off(self, git_requested,
                                                   net_man, n_plugin,
                                                   en_meta, leg_mode):
        git_requested.return_value = False
        en_meta.return_value = False
        leg_mode.return_value = False
        self.neutron_plugin_attribute.return_value = OVS_PKGS
        net_man.return_value = 'quantum'
        n_plugin.return_value = 'ovs'
        self.relation_ids.return_value = []
        result = utils.determine_packages()
        ex = utils.BASE_PACKAGES + ['nova-compute-kvm']
        self.assertEquals(ex, result)

    @patch.object(utils, 'neutron_plugin_legacy_mode')
    @patch.object(utils, 'enable_nova_metadata')
    @patch.object(utils, 'neutron_plugin')
    @patch.object(utils, 'network_manager')
    @patch.object(utils, 'git_install_requested')
    def test_determine_packages_quantum_ceph(self, git_requested, net_man,
                                             n_plugin, en_meta, leg_mode):
        git_requested.return_value = False
        en_meta.return_value = False
        leg_mode.return_value = True
        self.neutron_plugin_attribute.return_value = OVS_PKGS
        net_man.return_value = 'quantum'
        n_plugin.return_value = 'ovs'
        self.relation_ids.return_value = ['ceph:0']
        result = utils.determine_packages()
        ex = (utils.BASE_PACKAGES + OVS_PKGS_FLAT +
              ['ceph-common', 'nova-compute-kvm'])
        self.assertEquals(ex, result)

    @patch.object(utils, 'enable_nova_metadata')
    @patch.object(utils, 'neutron_plugin')
    @patch.object(utils, 'network_manager')
    @patch.object(utils, 'git_install_requested')
    def test_determine_packages_metadata(self, git_requested, net_man,
                                         n_plugin, en_meta):
        git_requested.return_value = False
        en_meta.return_value = True
        self.neutron_plugin_attribute.return_value = OVS_PKGS
        net_man.return_value = 'bob'
        n_plugin.return_value = 'ovs'
        self.relation_ids.return_value = []
        result = utils.determine_packages()
        self.assertTrue('nova-api-metadata' in result)

    @patch.object(utils, 'network_manager')
    def test_resource_map_nova_network_no_multihost(self, net_man):
        self.skipTest('skipped until contexts are properly mocked')
        self.test_config.set('multi-host', 'no')
        net_man.return_value = 'FlatDHCPManager'
        result = utils.resource_map()
        ex = {
            '/etc/default/libvirt-bin': {
                'contexts': [],
                'services': ['libvirt-bin']
            },
            '/etc/libvirt/qemu.conf': {
                'contexts': [],
                'services': ['libvirt-bin']
            },
            '/etc/nova/nova-compute.conf': {
                'contexts': [],
                'services': ['nova-compute']
            },
            '/etc/nova/nova.conf': {
                'contexts': [],
                'services': ['nova-compute']
            },
        }
        self.assertEquals(ex, result)

    @patch.object(utils, 'network_manager')
    def test_resource_map_nova_network(self, net_man):

        self.skipTest('skipped until contexts are properly mocked')
        net_man.return_value = 'FlatDHCPManager'
        result = utils.resource_map()
        ex = {
            '/etc/default/libvirt-bin': {
                'contexts': [], 'services': ['libvirt-bin']
            },
            '/etc/libvirt/qemu.conf': {
                'contexts': [],
                'services': ['libvirt-bin']
            },
            '/etc/nova/nova-compute.conf': {
                'contexts': [],
                'services': ['nova-compute']
            },
            '/etc/nova/nova.conf': {
                'contexts': [],
                'services': ['nova-compute', 'nova-api', 'nova-network']
            }
        }
        self.assertEquals(ex, result)

    @patch.object(utils, 'neutron_plugin')
    @patch.object(utils, 'network_manager')
    def test_resource_map_quantum_ovs(self, net_man, _plugin):
        self.skipTest('skipped until contexts are properly mocked.')
        net_man.return_value = 'Quantum'
        _plugin.return_value = 'ovs'
        result = utils.resource_map()
        ex = {
            '/etc/default/libvirt-bin': {
                'contexts': [],
                'services': ['libvirt-bin']
            },
            '/etc/libvirt/qemu.conf': {
                'contexts': [],
                'services': ['libvirt-bin']
            },
            '/etc/nova/nova-compute.conf': {
                'contexts': [],
                'services': ['nova-compute']
            },
            '/etc/nova/nova.conf': {
                'contexts': [],
                'services': ['nova-compute']
            },
            '/etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini': {
                'contexts': [],
                'services': ['quantum-plugin-openvswitch-agent']
            },
            '/etc/quantum/quantum.conf': {
                'contexts': [],
                'services': ['quantum-plugin-openvswitch-agent']}
        }

        self.assertEquals(ex, result)

    @patch.object(utils, 'neutron_plugin')
    @patch.object(utils, 'network_manager')
    def test_resource_map_neutron_ovs_plugin(self, net_man, _plugin):
        self.skipTest('skipped until contexts are properly mocked.')
        self.is_relation_made = True
        net_man.return_value = 'Neutron'
        _plugin.return_value = 'ovs'
        result = utils.resource_map()
        self.assertTrue('/etc/neutron/neutron.conf' not in result)

    @patch.object(utils, 'enable_nova_metadata')
    @patch.object(utils, 'neutron_plugin')
    @patch.object(utils, 'network_manager')
    def test_resource_map_metadata(self, net_man, _plugin, _metadata):
        _metadata.return_value = True
        net_man.return_value = 'bob'
        _plugin.return_value = 'ovs'
        self.relation_ids.return_value = []
        result = utils.resource_map()['/etc/nova/nova.conf']['services']
        self.assertTrue('nova-api-metadata' in result)

    def fake_user(self, username='foo'):
        user = MagicMock()
        user.pw_dir = '/home/' + username
        return user

    @patch('__builtin__.open')
    @patch('pwd.getpwnam')
    def test_public_ssh_key_not_found(self, getpwnam, _open):
        _open.side_effect = Exception
        getpwnam.return_value = self.fake_user('foo')
        self.assertEquals(None, utils.public_ssh_key())

    @patch('pwd.getpwnam')
    def test_public_ssh_key(self, getpwnam):
        getpwnam.return_value = self.fake_user('foo')
        with patch_open() as (_open, _file):
            _file.read.return_value = 'mypubkey'
            result = utils.public_ssh_key('foo')
        self.assertEquals(result, 'mypubkey')

    def test_import_authorized_keys_missing_data(self):
        self.relation_get.return_value = None
        with patch_open() as (_open, _file):
            utils.import_authorized_keys(user='foo')
            self.assertFalse(_open.called)

    @patch('pwd.getpwnam')
    def _test_import_authorized_keys_base(self, getpwnam, prefix=None,
                                          auth_key_path='/home/foo/.ssh/'
                                                        'authorized_keys'):
        getpwnam.return_value = self.fake_user('foo')
        self.relation_get.side_effect = [
            3,          # relation_get('known_hosts_max_index')
            'k_h_0',    # relation_get_('known_hosts_0')
            'k_h_1',    # relation_get_('known_hosts_1')
            'k_h_2',    # relation_get_('known_hosts_2')
            3,          # relation_get('authorized_keys_max_index')
            'auth_0',   # relation_get('authorized_keys_0')
            'auth_1',   # relation_get('authorized_keys_1')
            'auth_2',   # relation_get('authorized_keys_2')
        ]

        ex_open = [
            call('/home/foo/.ssh/known_hosts', 'wb'),
            call(auth_key_path, 'wb')
        ]
        ex_write = [
            call('k_h_0\n'),
            call('k_h_1\n'),
            call('k_h_2\n'),
            call('auth_0\n'),
            call('auth_1\n'),
            call('auth_2\n')
        ]

        with patch_open() as (_open, _file):
            utils.import_authorized_keys(user='foo', prefix=prefix)
            self.assertEquals(ex_open, _open.call_args_list)
            self.assertEquals(ex_write, _file.write.call_args_list)
            authkey_root = 'authorized_keys_'
            known_hosts_root = 'known_hosts_'
            if prefix:
                authkey_root = prefix + '_authorized_keys_'
                known_hosts_root = prefix + '_known_hosts_'
            expected_relations = [
                call(known_hosts_root + 'max_index'),
                call(known_hosts_root + '0'),
                call(known_hosts_root + '1'),
                call(known_hosts_root + '2'),
                call(authkey_root + 'max_index'),
                call(authkey_root + '0'),
                call(authkey_root + '1'),
                call(authkey_root + '2')
                ]
            self.assertEquals(sorted(self.relation_get.call_args_list),
                              sorted(expected_relations))

    def test_import_authorized_keys_noprefix(self):
        self._test_import_authorized_keys_base()

    def test_import_authorized_keys_prefix(self):
        self._test_import_authorized_keys_base(prefix='bar')

    def test_import_authorized_keys_authkeypath(self):
        nonstandard_path = '/etc/ssh/user-authorized-keys/{username}'
        self.test_config.set('authorized-keys-path', nonstandard_path)
        self._test_import_authorized_keys_base(
            auth_key_path='/etc/ssh/user-authorized-keys/foo')

    @patch('subprocess.check_call')
    def test_import_keystone_cert_missing_data(self, check_call):
        self.relation_get.return_value = None
        with patch_open() as (_open, _file):
            utils.import_keystone_ca_cert()
            self.assertFalse(_open.called)
        self.assertFalse(check_call.called)

    @patch.object(utils, 'check_call')
    def test_import_keystone_cert(self, check_call):
        self.relation_get.return_value = 'Zm9vX2NlcnQK'
        with patch_open() as (_open, _file):
            utils.import_keystone_ca_cert()
            _open.assert_called_with(utils.CA_CERT_PATH, 'wb')
            _file.write.assert_called_with('foo_cert\n')
        check_call.assert_called_with(['update-ca-certificates'])

    @patch.object(utils, 'ceph_config_file')
    @patch('charmhelpers.contrib.openstack.templating.OSConfigRenderer')
    @patch.object(utils, 'quantum_enabled')
    @patch.object(utils, 'resource_map')
    def test_register_configs(self, resource_map, quantum, renderer,
                              mock_ceph_config_file):
        quantum.return_value = False
        self.os_release.return_value = 'havana'
        fake_renderer = MagicMock()
        fake_renderer.register = MagicMock()
        renderer.return_value = fake_renderer
        ctxt1 = MagicMock()
        ctxt2 = MagicMock()
        rsc_map = {
            '/etc/nova/nova.conf': {
                'services': ['nova-compute'],
                'contexts': [ctxt1],
            },
            '/etc/nova/nova-compute.conf': {
                'services': ['nova-compute'],
                'contexts': [ctxt2],
            },
        }
        resource_map.return_value = rsc_map
        with tempfile.NamedTemporaryFile() as tmpfile:
            mock_ceph_config_file.return_value = tmpfile.name
            utils.register_configs()
            renderer.assert_called_with(
                openstack_release='havana', templates_dir='templates/')
            ex_reg = [
                call('/etc/nova/nova-compute.conf', [ctxt2]),
                call('/etc/nova/nova.conf', [ctxt1])
            ]
            self.assertEquals(fake_renderer.register.call_args_list, ex_reg)

    @patch.object(utils, 'check_call')
    def test_enable_shell(self, _check_call):
        utils.enable_shell('dummy')
        _check_call.assert_called_with(['usermod', '-s', '/bin/bash', 'dummy'])

    @patch.object(utils, 'check_call')
    def test_disable_shell(self, _check_call):
        utils.disable_shell('dummy')
        _check_call.assert_called_with(['usermod', '-s', '/bin/false',
                                        'dummy'])

    @patch.object(utils, 'check_call')
    def test_configure_subuid(self, _check_call):
        utils.configure_subuid('dummy')
        _check_call.assert_called_with(['usermod', '-v', '100000-200000',
                                        '-w', '100000-200000', 'dummy'])

    @patch.object(utils, 'check_call')
    @patch.object(utils, 'check_output')
    def test_create_libvirt_key(self, _check_output, _check_call):
        key = 'AQCR2dRUaFQSOxAAC5fr79sLL3d7wVvpbbRFMg=='
        self.test_config.set('virt-type', 'kvm')
        utils.create_libvirt_secret(utils.CEPH_SECRET,
                                    compute_context.CEPH_SECRET_UUID, key)
        _check_output.assert_called_with(['virsh', '-c',
                                          utils.LIBVIRT_URIS['kvm'],
                                          'secret-list'])
        _check_call.assert_called_with(['virsh', '-c',
                                        utils.LIBVIRT_URIS['kvm'],
                                        'secret-set-value', '--secret',
                                        compute_context.CEPH_SECRET_UUID,
                                        '--base64', key])

    @patch.object(utils, 'check_call')
    @patch.object(utils, 'check_output')
    def test_create_libvirt_key_existing(self, _check_output, _check_call):
        key = 'AQCR2dRUaFQSOxAAC5fr79sLL3d7wVvpbbRFMg=='
        self.test_config.set('virt-type', 'kvm')
        _check_output.side_effect = [compute_context.CEPH_SECRET_UUID, key]
        utils.create_libvirt_secret(utils.CEPH_SECRET,
                                    compute_context.CEPH_SECRET_UUID, key)
        expected = [call(['virsh', '-c',
                          utils.LIBVIRT_URIS['kvm'], 'secret-list']),
                    call(['virsh', '-c',
                          utils.LIBVIRT_URIS['kvm'], 'secret-get-value',
                          compute_context.CEPH_SECRET_UUID])]
        _check_output.assert_has_calls(expected)

    @patch.object(utils, 'check_call')
    @patch.object(utils, 'check_output')
    def test_create_libvirt_key_stale(self, _check_output, _check_call):
        key = 'AQCR2dRUaFQSOxAAC5fr79sLL3d7wVvpbbRFMg=='
        old_key = 'CCCCCdRUaFQSOxAAC5fr79sLL3d7wVvpbbRFMg=='
        self.test_config.set('virt-type', 'kvm')
        _check_output.side_effect = [compute_context.CEPH_SECRET_UUID, old_key]
        utils.create_libvirt_secret(utils.CEPH_SECRET,
                                    compute_context.CEPH_SECRET_UUID, key)
        expected = [call(['virsh', '-c',
                          utils.LIBVIRT_URIS['kvm'], 'secret-list']),
                    call(['virsh', '-c',
                          utils.LIBVIRT_URIS['kvm'], 'secret-get-value',
                          compute_context.CEPH_SECRET_UUID])]
        _check_output.assert_has_calls(expected)
        _check_call.assert_any_call(['virsh', '-c',
                                     utils.LIBVIRT_URIS['kvm'],
                                     'secret-set-value', '--secret',
                                     compute_context.CEPH_SECRET_UUID,
                                     '--base64', key])

    @patch.object(utils, 'lxc_list')
    @patch.object(utils, 'configure_subuid')
    def test_configure_lxd_vivid(self, _configure_subuid, _lxc_list):
        self.lsb_release.return_value = {
            'DISTRIB_CODENAME': 'vivid'
        }
        utils.configure_lxd('nova')
        _configure_subuid.assert_called_with('nova')
        _lxc_list.assert_called_with('nova')

    @patch.object(utils, 'git_install_requested')
    @patch.object(utils, 'lxc_list')
    @patch.object(utils, 'configure_subuid')
    def test_configure_lxd_pre_vivid(self, _configure_subuid, _lxc_list,
                                     _git_install):
        _git_install.return_value = False
        self.lsb_release.return_value = {
            'DISTRIB_CODENAME': 'trusty'
        }
        with self.assertRaises(Exception):
            utils.configure_lxd('nova')
        self.assertFalse(_configure_subuid.called)

    def test_enable_nova_metadata(self):
        class DummyContext():

            def __init__(self, return_value):
                self.return_value = return_value

            def __call__(self):
                return self.return_value

        self.MetadataServiceContext.return_value = \
            DummyContext(return_value={'metadata_shared_secret':
                                       'sharedsecret'})
        self.assertEqual(utils.enable_nova_metadata(), True)

    def test_neutron_plugin_legacy_mode_plugin(self):
        self.relation_ids.return_value = ['neutron-plugin:0']
        self.assertFalse(utils.neutron_plugin_legacy_mode())

    def test_neutron_plugin_legacy_mode_legacy_off(self):
        self.relation_ids.return_value = []
        self.test_config.set('manage-neutron-plugin-legacy-mode', False)
        self.assertFalse(utils.neutron_plugin_legacy_mode())

    def test_neutron_plugin_legacy_mode_legacy_on(self):
        self.relation_ids.return_value = []
        self.test_config.set('manage-neutron-plugin-legacy-mode', True)
        self.assertTrue(utils.neutron_plugin_legacy_mode())

    @patch.object(utils, 'neutron_plugin_legacy_mode')
    def test_manage_ovs_legacy_mode_legacy_off(self,
                                               _neutron_plugin_legacy_mode):
        _neutron_plugin_legacy_mode.return_value = False
        self.assertFalse(utils.manage_ovs())

    @patch.object(utils, 'neutron_plugin')
    @patch.object(utils, 'neutron_plugin_legacy_mode')
    def test_manage_ovs_legacy_mode_legacy_on(self,
                                              _neutron_plugin_legacy_mode,
                                              _neutron_plugin):
        _neutron_plugin_legacy_mode.return_value = True
        _neutron_plugin.return_value = 'ovs'
        self.assertTrue(utils.manage_ovs())

    @patch.object(utils, 'neutron_plugin')
    @patch.object(utils, 'neutron_plugin_legacy_mode')
    def test_manage_ovs_legacy_mode_not_ovs(self, _neutron_plugin_legacy_mode,
                                            _neutron_plugin):
        _neutron_plugin_legacy_mode.return_value = True
        _neutron_plugin.return_value = 'bobvs'
        self.assertFalse(utils.manage_ovs())

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
    @patch.object(utils, 'write_file')
    @patch.object(utils, 'add_user_to_group')
    @patch.object(utils, 'add_group')
    @patch.object(utils, 'adduser')
    @patch.object(utils, 'check_call')
    def test_git_pre_install(self, check_call, adduser, add_group,
                             add_user_to_group, write_file, mkdir):
        utils.git_pre_install()
        adduser.assert_called_with('nova', shell='/bin/bash',
                                   system_user=True)
        check_call.assert_called_with(['usermod', '--home', '/var/lib/nova',
                                       'nova'])
        add_group.assert_called_with('nova', system_group=True)
        expected = [
            call('nova', 'nova'),
            call('nova', 'libvirtd'),
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
            call('/var/log/nova', owner='nova',
                 group='nova', perms=0755, force=False),
        ]
        self.assertEquals(mkdir.call_args_list, expected)
        expected = [
            call('/var/log/nova/nova-api.log', '', owner='nova',
                 group='nova', perms=0644),
            call('/var/log/nova/nova-compute.log', '', owner='nova',
                 group='nova', perms=0644),
            call('/var/log/nova/nova-manage.log', '', owner='nova',
                 group='nova', perms=0644),
            call('/var/log/nova/nova-network.log', '', owner='nova',
                 group='nova', perms=0644),
        ]
        self.assertEquals(write_file.call_args_list, expected)

    @patch.object(utils, 'git_src_dir')
    @patch.object(utils, 'service_restart')
    @patch.object(utils, 'render')
    @patch.object(utils, 'git_pip_venv_dir')
    @patch('os.path.join')
    @patch('os.path.exists')
    @patch('os.symlink')
    @patch('shutil.copytree')
    @patch('shutil.rmtree')
    @patch('subprocess.check_call')
    @patch.object(utils, 'apt_install')
    @patch.object(utils, 'apt_update')
    def test_git_post_install(self, apt_update, apt_install, check_call,
                              rmtree, copytree, symlink, exists, join, venv,
                              render, service_restart, git_src_dir):
        projects_yaml = openstack_origin_git
        join.return_value = 'joined-string'
        venv.return_value = '/mnt/openstack-git/venv'
        utils.git_post_install(projects_yaml)
        expected = [
            call('joined-string', '/etc/nova'),
        ]
        copytree.assert_has_calls(expected)
        expected = [
            call('joined-string', '/usr/local/bin/nova-rootwrap'),
        ]
        symlink.assert_has_calls(expected, any_order=True)

        service_name = 'nova-compute'
        nova_user = 'nova'
        start_dir = '/var/lib/nova'
        nova_conf = '/etc/nova/nova.conf'
        nova_api_metadata_context = {
            'service_description': 'Nova Metadata API server',
            'service_name': service_name,
            'user_name': nova_user,
            'start_dir': start_dir,
            'process_name': 'nova-api-metadata',
            'executable_name': 'joined-string',
            'config_files': [nova_conf],
        }
        nova_api_context = {
            'service_description': 'Nova API server',
            'service_name': service_name,
            'user_name': nova_user,
            'start_dir': start_dir,
            'process_name': 'nova-api',
            'executable_name': 'joined-string',
            'config_files': [nova_conf],
        }
        nova_compute_context = {
            'service_description': 'Nova compute worker',
            'service_name': service_name,
            'user_name': nova_user,
            'process_name': 'nova-compute',
            'executable_name': 'joined-string',
            'config_files': [nova_conf, '/etc/nova/nova-compute.conf'],
        }
        nova_network_context = {
            'service_description': 'Nova network worker',
            'service_name': service_name,
            'user_name': nova_user,
            'start_dir': start_dir,
            'process_name': 'nova-network',
            'executable_name': 'joined-string',
            'config_files': [nova_conf],
        }
        expected = [
            call('git/nova-compute-kvm.conf', '/etc/nova/nova-compute.conf',
                 {}, perms=0o644),
            call('git/nova_sudoers', '/etc/sudoers.d/nova_sudoers',
                 {}, perms=0o440),
            call('git.upstart', '/etc/init/nova-api-metadata.conf',
                 nova_api_metadata_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git.upstart', '/etc/init/nova-api.conf',
                 nova_api_context, perms=0o644,
                 templates_dir='joined-string'),
            call('git/upstart/nova-compute.upstart',
                 '/etc/init/nova-compute.conf',
                 nova_compute_context, perms=0o644),
            call('git.upstart', '/etc/init/nova-network.conf',
                 nova_network_context, perms=0o644,
                 templates_dir='joined-string'),
        ]
        self.assertEquals(render.call_args_list, expected)
        self.assertTrue(apt_update.called)
        apt_install.assert_called_with(
            ['bridge-utils', 'dnsmasq-base',
             'dnsmasq-utils', 'ebtables', 'genisoimage', 'iptables',
             'iputils-arping', 'kpartx', 'kvm', 'netcat', 'open-iscsi',
             'parted', 'python-libvirt', 'qemu', 'qemu-system',
             'qemu-utils', 'vlan', 'xen-system-amd64'], fatal=True)

    @patch('psutil.virtual_memory')
    @patch('subprocess.check_call')
    @patch('subprocess.call')
    def test_install_hugepages(self, _call, _check_call, _virt_mem):
        class mem(object):
            def __init__(self):
                self.total = 10000000
        self.test_config.set('hugepages', '10%')
        _virt_mem.side_effect = mem
        _call.return_value = 1
        utils.install_hugepages()
        self.hugepage_support.assert_called_with(
            'nova',
            mnt_point='/run/hugepages/kvm',
            group='root',
            nr_hugepages=488,
            mount=False,
            set_shmmax=True,
        )
        check_call_calls = [
            call('/etc/init.d/qemu-hugefsdir'),
            call(['update-rc.d', 'qemu-hugefsdir', 'defaults']),
        ]
        _check_call.assert_has_calls(check_call_calls)
        self.fstab_mount.assert_called_with('/run/hugepages/kvm')

    @patch('psutil.virtual_memory')
    @patch('subprocess.check_call')
    @patch('subprocess.call')
    def test_install_hugepages_explicit_size(self, _call, _check_call,
                                             _virt_mem):
        self.test_config.set('hugepages', '2048')
        utils.install_hugepages()
        self.hugepage_support.assert_called_with(
            'nova',
            mnt_point='/run/hugepages/kvm',
            group='root',
            nr_hugepages=2048,
            mount=False,
            set_shmmax=True,
        )

    @patch('psutil.virtual_memory')
    @patch('subprocess.check_call')
    @patch('subprocess.call')
    def test_install_hugepages_already_mounted(self, _call, _check_call,
                                               _virt_mem):
        self.test_config.set('hugepages', '2048')
        _call.return_value = 0
        utils.install_hugepages()
        self.assertEqual(self.fstab_mount.call_args_list, [])
