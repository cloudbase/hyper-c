#!/usr/bin/python
import sys

sys.path.append('hooks/')

from charmhelpers.contrib.openstack.utils import (
    do_action_openstack_upgrade,
)

from keystone_hooks import (
    config_changed,
    CONFIGS,
)

from keystone_utils import (
    do_openstack_upgrade,
)


def openstack_upgrade():
    """Perform action-managed OpenStack upgrade.

    Upgrades packages to the configured openstack-origin version and sets
    the corresponding action status as a result.

    If the charm was installed from source we cannot upgrade it.
    For backwards compatibility a config flag (action-managed-upgrade) must
    be set for this code to run, otherwise a full service level upgrade will
    fire on config-changed."""

    if (do_action_openstack_upgrade('keystone',
                                    do_openstack_upgrade,
                                    CONFIGS)):
        config_changed()

if __name__ == '__main__':
    openstack_upgrade()
