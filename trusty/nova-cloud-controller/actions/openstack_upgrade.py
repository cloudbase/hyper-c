#!/usr/bin/python
import sys

sys.path.append('hooks/')

from charmhelpers.contrib.openstack.utils import (
    do_action_openstack_upgrade,
)

from charmhelpers.core.hookenv import (
    relation_ids,
)

from nova_cc_utils import (
    do_openstack_upgrade,
)

from nova_cc_hooks import (
    config_changed,
    CONFIGS,
    neutron_api_relation_joined,
)


def openstack_upgrade():
    """Upgrade packages to config-set Openstack version.

    If the charm was installed from source we cannot upgrade it.
    For backwards compatibility a config flag must be set for this
    code to run, otherwise a full service level upgrade will fire
    on config-changed."""

    if (do_action_openstack_upgrade('nova-common',
                                    do_openstack_upgrade,
                                    CONFIGS)):
        [neutron_api_relation_joined(rid=rid, remote_restart=True)
            for rid in relation_ids('neutron-api')]
        config_changed()

if __name__ == '__main__':
    openstack_upgrade()
