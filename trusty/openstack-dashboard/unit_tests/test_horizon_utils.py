from mock import MagicMock, patch, call
import os
from collections import OrderedDict
import charmhelpers.contrib.openstack.templating as templating
templating.OSConfigRenderer = MagicMock()
import horizon_utils as horizon_utils

from test_utils import (
    CharmTestCase
)

TO_PATCH = [
    'config',
    'get_os_codename_install_source',
    'apt_update',
    'apt_upgrade',
    'configure_installation_source',
    'log',
    'cmp_pkgrevno',
    'os_release',
]

openstack_origin_git = \
    """repositories:
         - {name: requirements,
            repository: 'git://git.openstack.org/openstack/requirements',
            branch: stable/juno}
         - {name: horizon,
            repository: 'git://git.openstack.org/openstack/horizon',
            branch: stable/juno}"""


class TestHorizohorizon_utils(CharmTestCase):

    def setUp(self):
        super(TestHorizohorizon_utils, self).setUp(horizon_utils, TO_PATCH)

    @patch('subprocess.call')
    def test_enable_ssl(self, _call):
        horizon_utils.enable_ssl()
        _call.assert_has_calls([
            call(['a2ensite', 'default-ssl']),
            call(['a2enmod', 'ssl'])
        ])

    def test_restart_map(self):
        ex_map = OrderedDict([
            ('/etc/openstack-dashboard/local_settings.py', ['apache2']),
            ('/etc/apache2/conf.d/openstack-dashboard.conf', ['apache2']),
            ('/etc/apache2/conf-available/openstack-dashboard.conf',
             ['apache2']),
            ('/etc/apache2/sites-available/default-ssl', ['apache2']),
            ('/etc/apache2/sites-available/default-ssl.conf', ['apache2']),
            ('/etc/apache2/sites-available/default', ['apache2']),
            ('/etc/apache2/sites-available/000-default.conf', ['apache2']),
            ('/etc/apache2/ports.conf', ['apache2']),
            ('/etc/haproxy/haproxy.cfg', ['haproxy']),
            ('/usr/share/openstack-dashboard/openstack_dashboard/enabled/'
             '_40_router.py', ['apache2']),
        ])
        self.assertEquals(horizon_utils.restart_map(), ex_map)

    def test_do_openstack_upgrade(self):
        self.config.return_value = 'cloud:precise-havana'
        self.get_os_codename_install_source.return_value = 'havana'
        configs = MagicMock()
        horizon_utils.do_openstack_upgrade(configs)
        configs.set_release.assert_called_with(openstack_release='havana')
        self.assertTrue(self.log.called)
        self.apt_update.assert_called_with(fatal=True)
        dpkg_opts = [
            '--option', 'Dpkg::Options::=--force-confnew',
            '--option', 'Dpkg::Options::=--force-confdef',
        ]
        self.apt_upgrade.assert_called_with(options=dpkg_opts,
                                            dist=True, fatal=True)
        self.configure_installation_source.assert_called_with(
            'cloud:precise-havana'
        )

    @patch('os.path.isdir')
    def test_register_configs(self, _isdir):
        _isdir.return_value = True
        self.os_release.return_value = 'havana'
        self.cmp_pkgrevno.return_value = -1
        configs = horizon_utils.register_configs()
        confs = [horizon_utils.LOCAL_SETTINGS,
                 horizon_utils.HAPROXY_CONF,
                 horizon_utils.PORTS_CONF,
                 horizon_utils.APACHE_DEFAULT,
                 horizon_utils.APACHE_CONF,
                 horizon_utils.APACHE_SSL]
        calls = []
        for conf in confs:
            calls.append(
                call(conf,
                     horizon_utils.CONFIG_FILES[conf]['hook_contexts']))
        configs.register.assert_has_calls(calls)

    @patch('os.remove')
    @patch('os.path.isfile')
    @patch('os.path.isdir')
    def test_register_configs_apache24(self, _isdir, _isfile, _remove):
        _isdir.return_value = True
        _isfile.return_value = True
        self.os_release.return_value = 'havana'
        self.cmp_pkgrevno.return_value = 1
        configs = horizon_utils.register_configs()
        confs = [horizon_utils.LOCAL_SETTINGS,
                 horizon_utils.HAPROXY_CONF,
                 horizon_utils.PORTS_CONF,
                 horizon_utils.APACHE_24_DEFAULT,
                 horizon_utils.APACHE_24_CONF,
                 horizon_utils.APACHE_24_SSL]
        calls = []
        for conf in confs:
            calls.append(
                call(conf, horizon_utils.CONFIG_FILES[conf]['hook_contexts']))
        configs.register.assert_has_calls(calls)
        oldconfs = [horizon_utils.APACHE_CONF,
                    horizon_utils.APACHE_SSL,
                    horizon_utils.APACHE_DEFAULT]
        rmcalls = []
        for conf in oldconfs:
            rmcalls.append(call(conf))
        _remove.assert_has_calls(rmcalls)

    @patch('os.path.isdir')
    def test_register_configs_pre_install(self, _isdir):
        _isdir.return_value = False
        self.os_release.return_value = None
        configs = horizon_utils.register_configs()
        confs = [horizon_utils.LOCAL_SETTINGS,
                 horizon_utils.HAPROXY_CONF,
                 horizon_utils.PORTS_CONF,
                 horizon_utils.APACHE_DEFAULT,
                 horizon_utils.APACHE_CONF,
                 horizon_utils.APACHE_SSL]
        calls = []
        for conf in confs:
            calls.append(
                call(conf, horizon_utils.CONFIG_FILES[conf]['hook_contexts']))
        configs.register.assert_has_calls(calls)

    @patch.object(horizon_utils, 'git_install_requested')
    @patch.object(horizon_utils, 'git_clone_and_install')
    @patch.object(horizon_utils, 'git_post_install')
    @patch.object(horizon_utils, 'git_pre_install')
    def test_git_install(self, git_pre, git_post, git_clone_and_install,
                         git_requested):
        projects_yaml = openstack_origin_git
        git_requested.return_value = True
        horizon_utils.git_install(projects_yaml)
        self.assertTrue(git_pre.called)
        git_clone_and_install.assert_called_with(openstack_origin_git,
                                                 core_project='horizon')
        self.assertTrue(git_post.called)

    @patch.object(horizon_utils, 'mkdir')
    @patch.object(horizon_utils, 'add_user_to_group')
    @patch.object(horizon_utils, 'add_group')
    @patch.object(horizon_utils, 'adduser')
    @patch('subprocess.check_call')
    def test_git_pre_install(self, check_call, adduser, add_group,
                             add_user_to_group, mkdir):
        horizon_utils.git_pre_install()
        adduser.assert_called_with('horizon', shell='/bin/bash',
                                   system_user=True)
        check_call.assert_called_with(['usermod', '--home',
                                       '/usr/share/openstack-dashboard/',
                                       'horizon'])
        add_group.assert_called_with('horizon', system_group=True)
        add_user_to_group.assert_called_with('horizon', 'horizon')
        them_dir = '/usr/share/openstack-dashboard-ubuntu-theme'
        expected = [
            call('/etc/openstack-dashboard', owner='root',
                 group='root', perms=0755, force=False),
            call('/usr/share/openstack-dashboard', owner='root',
                 group='root', perms=0755, force=False),
            call('/usr/share/openstack-dashboard/bin/less', owner='root',
                 group='root', perms=0755, force=False),
            call(os.path.join(them_dir, 'static/ubuntu/css'),
                 owner='root', group='root', perms=0755, force=False),
            call(os.path.join(them_dir, 'static/ubuntu/img'),
                 owner='root', group='root', perms=0755, force=False),
            call(os.path.join(them_dir, 'templates'),
                 owner='root', group='root', perms=0755, force=False),
            call('/var/lib/openstack-dashboard', owner='horizon',
                 group='horizon', perms=0700, force=False),
        ]
        self.assertEquals(mkdir.call_args_list, expected)

    @patch.object(horizon_utils, 'git_src_dir')
    @patch.object(horizon_utils, 'service_restart')
    @patch('shutil.copyfile')
    @patch('shutil.copytree')
    @patch('os.path.join')
    @patch('os.path.exists')
    @patch('os.symlink')
    @patch('os.chmod')
    @patch('os.chown')
    @patch('os.lchown')
    @patch('os.walk')
    @patch('subprocess.check_call')
    @patch('pwd.getpwnam')
    @patch('grp.getgrnam')
    def test_git_post_install(self, grnam, pwnam, check_call, walk, lchown,
                              chown, chmod, symlink, exists, join, copytree,
                              copyfile, service_restart, git_src_dir):
        class IDs(object):
            pw_uid = 999
            gr_gid = 999
        pwnam.return_value = IDs
        grnam.return_value = IDs
        projects_yaml = openstack_origin_git
        join.return_value = 'joined-string'
        walk.return_value = yield '/root', ['dir'], ['file']
        exists.return_value = False
        horizon_utils.git_post_install(projects_yaml)
        expected = [
            call('joined-string',
                 '/usr/share/openstack-dashboard/manage.py'),
            call('joined-string',
                 '/usr/share/openstack-dashboard/settings.py'),
            call('joined-string',
                 '/etc/openstack-dashboard/local_settings.py'),
            call('joined-string',
                 '/etc/apache2/conf-available/openstack-dashboard.conf'),
            call('joined-string',
                 '/etc/openstack-dashboard/ubuntu_theme.py'),
        ]
        copyfile.assert_has_calls(expected, any_order=True)
        expected = [
            call('joined-string',
                 '/usr/share/openstack-dashboard/openstack_dashboard'),
            call('joined-string', 'joined-string'),
            call('joined-string', 'joined-string'),
            call('joined-string', 'joined-string'),
        ]
        copytree.assert_has_calls(expected)
        expected = [
            call('/usr/share/openstack-dashboard/static'),
            call('joined-string'),
            call('joined-string'),
            call('joined-string'),
            call('joined-string'),
        ]
        exists.assert_has_calls(expected, any_order=True)
        dist_pkgs_dir = '/usr/local/lib/python2.7/dist-packages'
        expected = [
            call('/usr/share/openstack-dashboard/openstack_dashboard/static',
                 '/usr/share/openstack-dashboard/static'),
            call('/etc/openstack-dashboard/ubuntu_theme.py', 'joined-string'),
            call('/usr/share/openstack-dashboard-ubuntu-theme/static/ubuntu',
                 'joined-string'),
            call('/etc/openstack-dashboard/local_settings.py',
                 'joined-string'),
            call(os.path.join(dist_pkgs_dir, 'horizon/static/horizon/'),
                 'joined-string'),
        ]
        symlink.assert_has_calls(expected, any_order=True)
        expected = [
            call('/var/lib/openstack-dashboard', 0o750),
            call('/share/openstack-dashboard/manage.py', 0o755),
        ]
        chmod.assert_has_calls(expected)
        expected = [
            call(['/usr/share/openstack-dashboard/manage.py',
                  'collectstatic', '--noinput']),
            call(['/usr/share/openstack-dashboard/manage.py',
                 'compress', '--force']),
            call(['a2enconf', 'openstack-dashboard']),
        ]
        check_call.assert_has_calls(expected)
        expected = [
            call('horizon'),
        ]
        pwnam.assert_has_calls(expected)
        grnam.assert_has_calls(expected)
        expected = [
            call('/etc/openstack-dashboard', 999, 999),
            call('/usr/share/openstack-dashboard/openstack_dashboard/static',
                 999, 999),
            call('/var/lib/openstack-dashboard', 999, 999),
        ]
        chown.assert_has_calls(expected)
        expected = [
            call('/share/openstack-dashboard/openstack_dashboard/static'),
        ]
        walk.assert_has_calls(expected)
        expected = [
            call('/root/dir', 999, 999),
            call('/root/file', 999, 999),
        ]
        lchown.assert_has_calls(expected)
        expected = [
            call('apache2'),
        ]
        self.assertEquals(service_restart.call_args_list, expected)
