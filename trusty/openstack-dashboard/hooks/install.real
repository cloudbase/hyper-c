#!/usr/bin/python
# vim: set ts=4:et

import sys
from charmhelpers.core.hookenv import (
    Hooks, UnregisteredHookError,
    log,
    open_port,
    config,
    relation_set,
    relation_get,
    relation_ids,
    unit_get,
    status_set,
)
from charmhelpers.fetch import (
    apt_update, apt_install,
    filter_installed_packages,
)
from charmhelpers.core.host import (
    lsb_release,
    restart_on_change
)
from charmhelpers.contrib.openstack.utils import (
    config_value_changed,
    configure_installation_source,
    git_install_requested,
    git_pip_venv_dir,
    openstack_upgrade_available,
    os_release,
    save_script_rc,
    set_os_workload_status,
)
from horizon_utils import (
    determine_packages,
    register_configs,
    restart_map,
    services,
    LOCAL_SETTINGS, HAPROXY_CONF,
    enable_ssl,
    do_openstack_upgrade,
    git_install,
    git_post_install_late,
    setup_ipv6,
    INSTALL_DIR,
    REQUIRED_INTERFACES,
)
from charmhelpers.contrib.network.ip import (
    get_iface_for_address,
    get_netmask_for_address,
    get_ipv6_addr,
    is_ipv6
)
from charmhelpers.contrib.hahelpers.apache import install_ca_cert
from charmhelpers.contrib.hahelpers.cluster import get_hacluster_config
from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.contrib.charmsupport import nrpe
from base64 import b64decode

hooks = Hooks()
CONFIGS = register_configs()


@hooks.hook('install.real')
def install():
    execd_preinstall()
    configure_installation_source(config('openstack-origin'))

    apt_update(fatal=True)
    packages = determine_packages()
    if os_release('openstack-dashboard') < 'icehouse':
        packages += ['nodejs', 'node-less']
    if lsb_release()['DISTRIB_CODENAME'] == 'precise':
        # Explicitly upgrade python-six Bug#1420708
        apt_install('python-six', fatal=True)
    packages = filter_installed_packages(packages)
    if packages:
        status_set('maintenance', 'Installing packages')
        apt_install(packages, fatal=True)

    git_install(config('openstack-origin-git'))


@hooks.hook('upgrade-charm')
@restart_on_change(restart_map())
def upgrade_charm():
    execd_preinstall()
    apt_install(filter_installed_packages(determine_packages()), fatal=True)
    update_nrpe_config()
    CONFIGS.write_all()


@hooks.hook('config-changed')
@restart_on_change(restart_map())
def config_changed():
    if config('prefer-ipv6'):
        setup_ipv6()
        localhost = 'ip6-localhost'
    else:
        localhost = 'localhost'

    if (os_release('openstack-dashboard') == 'icehouse' and
            config('offline-compression') in ['no', 'False']):
        apt_install(filter_installed_packages(['python-lesscpy']),
                    fatal=True)

    # Ensure default role changes are propagated to keystone
    for relid in relation_ids('identity-service'):
        keystone_joined(relid)
    enable_ssl()

    if git_install_requested():
        if config_value_changed('openstack-origin-git'):
            git_install(config('openstack-origin-git'))
    elif not config('action-managed-upgrade'):
        if openstack_upgrade_available('openstack-dashboard'):
            status_set('maintenance', 'Upgrading to new OpenStack release')
            do_openstack_upgrade(configs=CONFIGS)

    env_vars = {
        'OPENSTACK_URL_HORIZON':
        "http://{}:70{}|Login+-+OpenStack".format(
            localhost,
            config('webroot')
        ),
        'OPENSTACK_SERVICE_HORIZON': "apache2",
        'OPENSTACK_PORT_HORIZON_SSL': 433,
        'OPENSTACK_PORT_HORIZON': 70
    }
    save_script_rc(**env_vars)
    update_nrpe_config()
    CONFIGS.write_all()
    open_port(80)
    open_port(443)

    if git_install_requested():
        git_post_install_late(config('openstack-origin-git'))


@hooks.hook('identity-service-relation-joined')
def keystone_joined(rel_id=None):
    relation_set(relation_id=rel_id,
                 service="None",
                 region="None",
                 public_url="None",
                 admin_url="None",
                 internal_url="None",
                 requested_roles=config('default-role'))


@hooks.hook('identity-service-relation-changed')
@restart_on_change(restart_map())
def keystone_changed():
    CONFIGS.write(LOCAL_SETTINGS)
    if relation_get('ca_cert'):
        install_ca_cert(b64decode(relation_get('ca_cert')))


@hooks.hook('cluster-relation-joined')
def cluster_joined(relation_id=None):
    if config('prefer-ipv6'):
        private_addr = get_ipv6_addr(exc_list=[config('vip')])[0]
        relation_set(relation_id=relation_id,
                     relation_settings={'private-address': private_addr})


@hooks.hook('cluster-relation-departed',
            'cluster-relation-changed')
@restart_on_change(restart_map())
def cluster_relation():
    CONFIGS.write(HAPROXY_CONF)


@hooks.hook('ha-relation-joined')
def ha_relation_joined():
    cluster_config = get_hacluster_config()
    resources = {
        'res_horizon_haproxy': 'lsb:haproxy'
    }

    resource_params = {
        'res_horizon_haproxy': 'op monitor interval="5s"'
    }

    vip_group = []
    for vip in cluster_config['vip'].split():
        if is_ipv6(vip):
            res_vip = 'ocf:heartbeat:IPv6addr'
            vip_params = 'ipv6addr'
        else:
            res_vip = 'ocf:heartbeat:IPaddr2'
            vip_params = 'ip'

        iface = (get_iface_for_address(vip) or
                 config('vip_iface'))
        netmask = (get_netmask_for_address(vip) or
                   config('vip_cidr'))

        if iface is not None:
            vip_key = 'res_horizon_{}_vip'.format(iface)
            resources[vip_key] = res_vip
            resource_params[vip_key] = (
                'params {ip}="{vip}" cidr_netmask="{netmask}"'
                ' nic="{iface}"'.format(ip=vip_params,
                                        vip=vip,
                                        iface=iface,
                                        netmask=netmask)
            )
            vip_group.append(vip_key)

    if len(vip_group) > 1:
        relation_set(groups={'grp_horizon_vips': ' '.join(vip_group)})

    init_services = {
        'res_horizon_haproxy': 'haproxy'
    }
    clones = {
        'cl_horizon_haproxy': 'res_horizon_haproxy'
    }
    relation_set(init_services=init_services,
                 corosync_bindiface=cluster_config['ha-bindiface'],
                 corosync_mcastport=cluster_config['ha-mcastport'],
                 resources=resources,
                 resource_params=resource_params,
                 clones=clones)


@hooks.hook('website-relation-joined')
def website_relation_joined():
    relation_set(port=70,
                 hostname=unit_get('private-address'))


@hooks.hook('nrpe-external-master-relation-joined',
            'nrpe-external-master-relation-changed')
def update_nrpe_config():
    # python-dbus is used by check_upstart_job
    apt_install('python-dbus')
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe.copy_nrpe_checks()
    nrpe.add_init_service_checks(nrpe_setup, services(), current_unit)
    nrpe.add_haproxy_checks(nrpe_setup, current_unit)
    conf = nrpe_setup.config
    check_http_params = conf.get('nagios_check_http_params')
    if check_http_params:
        nrpe_setup.add_check(
            shortname='vhost',
            description='Check Virtual Host {%s}' % current_unit,
            check_cmd='check_http %s' % check_http_params
        )
    nrpe_setup.write()


@hooks.hook('dashboard-plugin-relation-joined')
def plugin_relation_joined(rel_id=None):
    if git_install_requested():
        bin_path = git_pip_venv_dir(config('openstack-origin-git'))
    else:
        bin_path = '/usr/bin'
    relation_set(release=os_release("openstack-dashboard"),
                 relation_id=rel_id,
                 bin_path=bin_path,
                 openstack_dir=INSTALL_DIR)


@hooks.hook('dashboard-plugin-relation-changed')
@restart_on_change(restart_map())
def update_plugin_config():
    CONFIGS.write(LOCAL_SETTINGS)


def main():
    print sys.argv
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    set_os_workload_status(CONFIGS, REQUIRED_INTERFACES)


if __name__ == '__main__':
    main()
