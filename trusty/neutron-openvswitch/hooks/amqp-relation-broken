#!/usr/bin/python

import sys

from charmhelpers.contrib.openstack.utils import (
    config_value_changed,
    git_install_requested,
)

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    relation_set,
    relation_ids,
)

from charmhelpers.core.host import (
    restart_on_change
)

from charmhelpers.contrib.openstack.utils import (
    os_requires_version,
    set_os_workload_status,
)

from neutron_ovs_utils import (
    DHCP_PACKAGES,
    DVR_PACKAGES,
    configure_ovs,
    git_install,
    get_topics,
    get_shared_secret,
    register_configs,
    restart_map,
    use_dvr,
    enable_nova_metadata,
    enable_local_dhcp,
    install_packages,
    purge_packages,
    REQUIRED_INTERFACES,
    check_optional_relations,
)

hooks = Hooks()
CONFIGS = register_configs()


@hooks.hook()
def install():
    install_packages()
    git_install(config('openstack-origin-git'))


@hooks.hook('neutron-plugin-relation-changed')
@hooks.hook('config-changed')
@restart_on_change(restart_map())
def config_changed():
    install_packages()
    if git_install_requested():
        if config_value_changed('openstack-origin-git'):
            git_install(config('openstack-origin-git'))

    configure_ovs()
    CONFIGS.write_all()
    for rid in relation_ids('zeromq-configuration'):
        zeromq_configuration_relation_joined(rid)
    for rid in relation_ids('neutron-plugin'):
        neutron_plugin_joined(relation_id=rid)


@hooks.hook('neutron-plugin-api-relation-changed')
@restart_on_change(restart_map())
def neutron_plugin_api_changed():
    if use_dvr():
        install_packages()
    else:
        purge_packages(DVR_PACKAGES)
    configure_ovs()
    CONFIGS.write_all()
    # If dvr setting has changed, need to pass that on
    for rid in relation_ids('neutron-plugin'):
        neutron_plugin_joined(relation_id=rid)


@hooks.hook('neutron-plugin-relation-joined')
def neutron_plugin_joined(relation_id=None):
    if enable_local_dhcp():
        install_packages()
    else:
        purge_packages(DHCP_PACKAGES)
    secret = get_shared_secret() if enable_nova_metadata() else None
    rel_data = {
        'metadata-shared-secret': secret,
    }
    relation_set(relation_id=relation_id, **rel_data)


@hooks.hook('amqp-relation-joined')
def amqp_joined(relation_id=None):
    relation_set(relation_id=relation_id,
                 username=config('rabbit-user'),
                 vhost=config('rabbit-vhost'))


@hooks.hook('amqp-relation-changed')
@hooks.hook('amqp-relation-departed')
@restart_on_change(restart_map())
def amqp_changed():
    if 'amqp' not in CONFIGS.complete_contexts():
        log('amqp relation incomplete. Peer not ready?')
        return
    CONFIGS.write_all()


@hooks.hook('zeromq-configuration-relation-joined')
@os_requires_version('kilo', 'neutron-common')
def zeromq_configuration_relation_joined(relid=None):
    relation_set(relation_id=relid,
                 topics=" ".join(get_topics()),
                 users="neutron")


@hooks.hook('zeromq-configuration-relation-changed')
@restart_on_change(restart_map(), stopstart=True)
def zeromq_configuration_relation_changed():
    CONFIGS.write_all()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    set_os_workload_status(CONFIGS, REQUIRED_INTERFACES,
                           charm_func=check_optional_relations)


if __name__ == '__main__':
    main()
