from mock import patch, MagicMock

with patch('charmhelpers.core.hookenv.config') as config:
    config.return_value = 'neutron'
    import neutron_utils as utils  # noqa

from test_utils import (
    CharmTestCase
)

# Need to do some early patching to get the module loaded.
_register_configs = utils.register_configs
_restart_map = utils.restart_map

utils.register_configs = MagicMock()
utils.restart_map = MagicMock()

with patch('charmhelpers.core.hookenv.status_set'):
    import git_reinstall

# Unpatch it now that its loaded.
utils.register_configs = _register_configs
utils.restart_map = _restart_map

TO_PATCH = [
    'config',
]


openstack_origin_git = \
    """repositories:
         - {name: requirements,
            repository: 'git://git.openstack.org/openstack/requirements',
            branch: stable/juno}
         - {name: neutron,
            repository: 'git://git.openstack.org/openstack/neutron',
            branch: stable/juno}"""


class TestNeutronAPIActions(CharmTestCase):

    def setUp(self):
        super(TestNeutronAPIActions, self).setUp(git_reinstall, TO_PATCH)
        self.config.side_effect = self.test_config.get

    @patch.object(git_reinstall, 'action_set')
    @patch.object(git_reinstall, 'action_fail')
    @patch.object(git_reinstall, 'git_install')
    @patch.object(git_reinstall, 'config_changed')
    def test_git_reinstall(self, config_changed, git_install, action_fail,
                           action_set):
        self.test_config.set('openstack-origin-git', openstack_origin_git)

        git_reinstall.git_reinstall()

        git_install.assert_called_with(openstack_origin_git)
        self.assertTrue(git_install.called)
        self.assertTrue(config_changed.called)
        self.assertFalse(action_set.called)
        self.assertFalse(action_fail.called)

    @patch.object(git_reinstall, 'action_set')
    @patch.object(git_reinstall, 'action_fail')
    @patch.object(git_reinstall, 'git_install')
    @patch.object(git_reinstall, 'config_changed')
    @patch('charmhelpers.contrib.openstack.utils.config')
    def test_git_reinstall_not_configured(self, _config, config_changed,
                                          git_install, action_fail,
                                          action_set):
        _config.return_value = None

        git_reinstall.git_reinstall()

        msg = 'openstack-origin-git is not configured'
        action_fail.assert_called_with(msg)
        self.assertFalse(git_install.called)
        self.assertFalse(action_set.called)

    @patch.object(git_reinstall, 'action_set')
    @patch.object(git_reinstall, 'action_fail')
    @patch.object(git_reinstall, 'git_install')
    @patch.object(git_reinstall, 'config_changed')
    @patch('traceback.format_exc')
    @patch('charmhelpers.contrib.openstack.utils.config')
    def test_git_reinstall_exception(self, _config, format_exc,
                                     config_changed, git_install, action_fail,
                                     action_set):
        _config.return_value = openstack_origin_git
        e = OSError('something bad happened')
        git_install.side_effect = e
        traceback = (
            "Traceback (most recent call last):\n"
            "  File \"actions/git_reinstall.py\", line 37, in git_reinstall\n"
            "    git_install(config(\'openstack-origin-git\'))\n"
            "  File \"/usr/lib/python2.7/dist-packages/mock.py\", line 964, in __call__\n"  # noqa
            "    return _mock_self._mock_call(*args, **kwargs)\n"
            "  File \"/usr/lib/python2.7/dist-packages/mock.py\", line 1019, in _mock_call\n"  # noqa
            "    raise effect\n"
            "OSError: something bad happened\n")
        format_exc.return_value = traceback

        git_reinstall.git_reinstall()

        msg = 'git-reinstall resulted in an unexpected error'
        action_fail.assert_called_with(msg)
        action_set.assert_called_with({'traceback': traceback})
