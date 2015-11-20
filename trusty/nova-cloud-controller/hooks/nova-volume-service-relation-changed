#!/usr/bin/python

import os
import shutil
import sys
import uuid

from subprocess import (
    check_call,
)

from urlparse import urlparse

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    charm_dir,
    is_relation_made,
    log,
    local_unit,
    ERROR,
    relation_get,
    relation_ids,
    relation_set,
    related_units,
    open_port,
    unit_get,
    status_set,
)

from charmhelpers.core.host import (
    restart_on_change,
    service_running,
    service_stop,
    service_reload,
    service_restart,
)

from charmhelpers.fetch import (
    apt_install,
    apt_update,
    filter_installed_packages
)

from charmhelpers.contrib.openstack.utils import (
    config_value_changed,
    configure_installation_source,
    git_install_requested,
    openstack_upgrade_available,
    os_release,
    os_requires_version,
    sync_db_with_multi_ipv6_addresses,
    set_os_workload_status,
)

from charmhelpers.contrib.openstack.neutron import (
    network_manager,
    neutron_plugin_attribute,
)

from nova_cc_context import (
    NeutronAPIContext,
    NovaCellContext,
)

from charmhelpers.contrib.peerstorage import (
    peer_retrieve,
    peer_echo,
)

from nova_cc_utils import (
    api_port,
    auth_token_config,
    cmd_all_services,
    determine_endpoints,
    determine_packages,
    determine_ports,
    disable_services,
    do_openstack_upgrade,
    enable_services,
    git_install,
    keystone_ca_cert_b64,
    migrate_neutron_database,
    migrate_nova_database,
    neutron_plugin,
    save_script_rc,
    services,
    ssh_compute_add,
    ssh_compute_remove,
    ssh_known_hosts_lines,
    ssh_authorized_keys_lines,
    register_configs,
    restart_map,
    volume_service,
    CLUSTER_RES,
    NOVA_CONF,
    QUANTUM_CONF,
    NEUTRON_CONF,
    QUANTUM_API_PASTE,
    console_attributes,
    service_guard,
    guard_map,
    get_topics,
    setup_ipv6,
    REQUIRED_INTERFACES,
    check_optional_relations,
)

from charmhelpers.contrib.hahelpers.cluster import (
    is_elected_leader,
    get_hacluster_config,
    https,
)

from charmhelpers.payload.execd import execd_preinstall

from charmhelpers.contrib.openstack.ip import (
    canonical_url,
    PUBLIC, INTERNAL, ADMIN,
    resolve_address,
)

from charmhelpers.contrib.network.ip import (
    format_ipv6_addr,
    get_iface_for_address,
    get_netmask_for_address,
    get_address_in_network,
    get_ipv6_addr,
    is_ipv6,
)

from charmhelpers.contrib.openstack.context import ADDRESS_TYPES

from charmhelpers.contrib.charmsupport import nrpe

try:
    FileNotFoundError
except NameError:
    # python3 compatibility
    FileNotFoundError = OSError

hooks = Hooks()
CONFIGS = register_configs()
COLO_CONSOLEAUTH = 'inf: res_nova_consoleauth grp_nova_vips'
AGENT_CONSOLEAUTH = 'ocf:openstack:nova-consoleauth'
AGENT_CA_PARAMS = 'op monitor interval="5s"'
NOVA_CONSOLEAUTH_OVERRIDE = '/etc/init/nova-consoleauth.override'


@hooks.hook('install.real')
def install():
    status_set('maintenance', 'Executing pre-install')
    execd_preinstall()
    configure_installation_source(config('openstack-origin'))

    status_set('maintenance', 'Installing apt packages')
    apt_update()
    apt_install(determine_packages(), fatal=True)

    git_install(config('openstack-origin-git'))

    _files = os.path.join(charm_dir(), 'files')
    if os.path.isdir(_files):
        for f in os.listdir(_files):
            f = os.path.join(_files, f)
            if os.path.isfile(f):
                log('Installing %s to /usr/bin' % f)
                shutil.copy2(f, '/usr/bin')
    [open_port(port) for port in determine_ports()]
    msg = 'Disabling services into db relation joined'
    log(msg)
    status_set('maintenance', msg)
    disable_services()
    cmd_all_services('stop')


@hooks.hook('config-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map(), stopstart=True)
def config_changed():
    if config('prefer-ipv6'):
        status_set('maintenance', 'configuring ipv6')
        setup_ipv6()
        sync_db_with_multi_ipv6_addresses(config('database'),
                                          config('database-user'),
                                          relation_prefix='nova')

    global CONFIGS
    if git_install_requested():
        status_set('maintenance', 'Running Git install')
        if config_value_changed('openstack-origin-git'):
            git_install(config('openstack-origin-git'))
    elif not config('action-managed-upgrade'):
        if openstack_upgrade_available('nova-common'):
            status_set('maintenance', 'Running openstack upgrade')
            CONFIGS = do_openstack_upgrade(CONFIGS)
            [neutron_api_relation_joined(rid=rid, remote_restart=True)
                for rid in relation_ids('neutron-api')]
    save_script_rc()
    configure_https()
    CONFIGS.write_all()
    if console_attributes('protocol'):
        if not git_install_requested():
            status_set('maintenance', 'Configuring guest console access')
            apt_update()
            packages = console_attributes('packages') or []
            filtered = filter_installed_packages(packages)
            if filtered:
                apt_install(filtered, fatal=True)

        [compute_joined(rid=rid)
            for rid in relation_ids('cloud-compute')]

    for r_id in relation_ids('identity-service'):
        identity_joined(rid=r_id)
    for rid in relation_ids('zeromq-configuration'):
        zeromq_configuration_relation_joined(rid)
    [cluster_joined(rid) for rid in relation_ids('cluster')]
    update_nrpe_config()

    update_nova_consoleauth_config()


@hooks.hook('amqp-relation-joined')
def amqp_joined(relation_id=None):
    relation_set(relation_id=relation_id,
                 username=config('rabbit-user'), vhost=config('rabbit-vhost'))


@hooks.hook('amqp-relation-changed')
@hooks.hook('amqp-relation-departed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def amqp_changed():
    if 'amqp' not in CONFIGS.complete_contexts():
        log('amqp relation incomplete. Peer not ready?')
        return
    CONFIGS.write(NOVA_CONF)
    if not is_relation_made('neutron-api'):
        if network_manager() == 'quantum':
            CONFIGS.write(QUANTUM_CONF)
        if network_manager() == 'neutron':
            CONFIGS.write(NEUTRON_CONF)
    [nova_cell_relation_joined(rid=rid)
        for rid in relation_ids('cell')]


def conditional_neutron_migration():
    if os_release('nova-common') <= 'icehouse':
        log('Not running neutron database migration as migrations are handled '
            'by the neutron-server process.')
    elif os_release('nova-common') >= 'kilo':
        log('Not running neutron database migration as migrations are by '
            'the neutron-api charm.')
    else:
        status_set('maintenance', 'Running neutron db migration')
        migrate_neutron_database()
        # neutron-api service may have appeared while the migration was
        # running so prod it just in case
        [neutron_api_relation_joined(rid=rid, remote_restart=True)
            for rid in relation_ids('neutron-api')]
        if 'neutron-server' in services():
            service_restart('neutron-server')


@hooks.hook('shared-db-relation-joined')
def db_joined():
    if is_relation_made('pgsql-nova-db') or \
            is_relation_made('pgsql-neutron-db'):
        # error, postgresql is used
        e = ('Attempting to associate a mysql database when there is already '
             'associated a postgresql one')
        log(e, level=ERROR)
        raise Exception(e)

    if network_manager() in ['quantum', 'neutron']:
        config_neutron = True
    else:
        config_neutron = False

    if config('prefer-ipv6'):
        sync_db_with_multi_ipv6_addresses(config('database'),
                                          config('database-user'),
                                          relation_prefix='nova')

        if config_neutron:
            sync_db_with_multi_ipv6_addresses(config('neutron-database'),
                                              config('neutron-database-user'),
                                              relation_prefix='neutron')
    else:
        host = unit_get('private-address')
        relation_set(nova_database=config('database'),
                     nova_username=config('database-user'),
                     nova_hostname=host)

        if config_neutron:
            # XXX: Renaming relations from quantum_* to neutron_* here.
            relation_set(neutron_database=config('neutron-database'),
                         neutron_username=config('neutron-database-user'),
                         neutron_hostname=host)


@hooks.hook('pgsql-nova-db-relation-joined')
def pgsql_nova_db_joined():
    if is_relation_made('shared-db'):
        # raise error
        e = ('Attempting to associate a postgresql database'
             ' when there is already associated a mysql one')
        log(e, level=ERROR)
        raise Exception(e)

    relation_set(database=config('database'))


@hooks.hook('pgsql-neutron-db-relation-joined')
def pgsql_neutron_db_joined():
    if is_relation_made('shared-db'):
        # raise error
        e = ('Attempting to associate a postgresql database'
             ' when there is already associated a mysql one')
        log(e, level=ERROR)
        raise Exception(e)

    relation_set(database=config('neutron-database'))


@hooks.hook('shared-db-relation-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def db_changed():
    if 'shared-db' not in CONFIGS.complete_contexts():
        log('shared-db relation incomplete. Peer not ready?')
        return
    CONFIGS.write_all()

    if is_elected_leader(CLUSTER_RES):
        # Bugs 1353135 & 1187508. Dbs can appear to be ready before the units
        # acl entry has been added. So, if the db supports passing a list of
        # permitted units then check if we're in the list.
        allowed_units = relation_get('nova_allowed_units')
        if allowed_units and local_unit() in allowed_units.split():
            status_set('maintenance', 'Running nova db migration')
            migrate_nova_database()
            log('Triggering remote cloud-compute restarts.')
            [compute_joined(rid=rid, remote_restart=True)
                for rid in relation_ids('cloud-compute')]
            log('Triggering remote cell restarts.')
            [nova_cell_relation_joined(rid=rid, remote_restart=True)
                for rid in relation_ids('cell')]
            conditional_neutron_migration()
        else:
            log('allowed_units either not presented, or local unit '
                'not in acl list: %s' % repr(allowed_units))


@hooks.hook('pgsql-nova-db-relation-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def postgresql_nova_db_changed():
    if 'pgsql-nova-db' not in CONFIGS.complete_contexts():
        log('pgsql-nova-db relation incomplete. Peer not ready?')
        return
    CONFIGS.write_all()

    if is_elected_leader(CLUSTER_RES):
        status_set('maintenance', 'Running nova db migration')
        migrate_nova_database()
        log('Triggering remote cloud-compute restarts.')
        [compute_joined(rid=rid, remote_restart=True)
         for rid in relation_ids('cloud-compute')]
        conditional_neutron_migration()


@hooks.hook('pgsql-neutron-db-relation-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def postgresql_neutron_db_changed():
    if network_manager() in ['neutron', 'quantum']:
        plugin = neutron_plugin()
        # DB config might have been moved to main neutron.conf in H?
        CONFIGS.write(neutron_plugin_attribute(plugin, 'config'))


@hooks.hook('image-service-relation-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def image_service_changed():
    if 'image-service' not in CONFIGS.complete_contexts():
        log('image-service relation incomplete. Peer not ready?')
        return
    CONFIGS.write(NOVA_CONF)
    # TODO: special case config flag for essex (strip protocol)


@hooks.hook('identity-service-relation-joined')
def identity_joined(rid=None):
    public_url = canonical_url(CONFIGS, PUBLIC)
    internal_url = canonical_url(CONFIGS, INTERNAL)
    admin_url = canonical_url(CONFIGS, ADMIN)
    relation_set(relation_id=rid, **determine_endpoints(public_url,
                                                        internal_url,
                                                        admin_url))


@hooks.hook('identity-service-relation-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def identity_changed():
    if 'identity-service' not in CONFIGS.complete_contexts():
        log('identity-service relation incomplete. Peer not ready?')
        return
    CONFIGS.write('/etc/nova/api-paste.ini')
    CONFIGS.write(NOVA_CONF)
    if not is_relation_made('neutron-api'):
        if network_manager() == 'quantum':
            CONFIGS.write(QUANTUM_API_PASTE)
            CONFIGS.write(QUANTUM_CONF)
            save_novarc()
        if network_manager() == 'neutron':
            CONFIGS.write(NEUTRON_CONF)
    [compute_joined(rid) for rid in relation_ids('cloud-compute')]
    [quantum_joined(rid) for rid in relation_ids('quantum-network-service')]
    [nova_vmware_relation_joined(rid) for rid in relation_ids('nova-vmware')]
    [neutron_api_relation_joined(rid) for rid in relation_ids('neutron-api')]
    configure_https()


@hooks.hook('nova-volume-service-relation-joined',
            'cinder-volume-service-relation-joined')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def volume_joined():
    CONFIGS.write(NOVA_CONF)
    # kick identity_joined() to publish possibly new nova-volume endpoint.
    [identity_joined(rid) for rid in relation_ids('identity-service')]


def _auth_config():
    '''Grab all KS auth token config from api-paste.ini, or return empty {}'''
    ks_auth_host = auth_token_config('auth_host')
    if not ks_auth_host:
        # if there is no auth_host set, identity-service changed hooks
        # have not fired, yet.
        return {}
    cfg = {
        'auth_host': ks_auth_host,
        'auth_port': auth_token_config('auth_port'),
        'auth_protocol': auth_token_config('auth_protocol'),
        'service_protocol': auth_token_config('service_protocol'),
        'service_port': auth_token_config('service_port'),
        'service_username': auth_token_config('admin_user'),
        'service_password': auth_token_config('admin_password'),
        'service_tenant_name': auth_token_config('admin_tenant_name'),
        'auth_uri': auth_token_config('auth_uri'),
        # quantum-gateway interface deviates a bit.
        'keystone_host': ks_auth_host,
        'service_tenant': auth_token_config('admin_tenant_name'),
    }
    return cfg


def save_novarc():
    auth = _auth_config()
    # XXX hard-coded http
    ks_url = '%s://%s:%s/v2.0' % (auth['auth_protocol'],
                                  auth['auth_host'], auth['auth_port'])
    with open('/etc/quantum/novarc', 'wb') as out:
        out.write('export OS_USERNAME=%s\n' % auth['service_username'])
        out.write('export OS_PASSWORD=%s\n' % auth['service_password'])
        out.write('export OS_TENANT_NAME=%s\n' % auth['service_tenant_name'])
        out.write('export OS_AUTH_URL=%s\n' % ks_url)
        out.write('export OS_REGION_NAME=%s\n' % config('region'))


def neutron_settings():
    neutron_settings = {}
    if is_relation_made('neutron-api', 'neutron-plugin'):
        neutron_api_info = NeutronAPIContext()()
        neutron_settings.update({
            # XXX: Rename these relations settings?
            'quantum_plugin': neutron_api_info['neutron_plugin'],
            'region': config('region'),
            'quantum_security_groups':
            neutron_api_info['neutron_security_groups'],
            'quantum_url': neutron_api_info['neutron_url'],
        })
    else:
        neutron_settings.update({
            # XXX: Rename these relations settings?
            'quantum_plugin': neutron_plugin(),
            'region': config('region'),
            'quantum_security_groups': config('quantum-security-groups'),
            'quantum_url': "{}:{}".format(canonical_url(CONFIGS, INTERNAL),
                                          str(api_port('neutron-server'))),
        })
    neutron_url = urlparse(neutron_settings['quantum_url'])
    neutron_settings['quantum_host'] = neutron_url.hostname
    neutron_settings['quantum_port'] = neutron_url.port
    return neutron_settings


def keystone_compute_settings():
    ks_auth_config = _auth_config()
    rel_settings = {}

    if network_manager() in ['quantum', 'neutron']:
        if ks_auth_config:
            rel_settings.update(ks_auth_config)
        rel_settings.update(neutron_settings())
    ks_ca = keystone_ca_cert_b64()
    if ks_auth_config and ks_ca:
        rel_settings['ca_cert'] = ks_ca
    return rel_settings


def console_settings():
    rel_settings = {}
    proto = console_attributes('protocol')
    if not proto:
        return {}
    rel_settings['console_keymap'] = config('console-keymap')
    rel_settings['console_access_protocol'] = proto

    console_ssl = False
    if config('console-ssl-cert') and config('console-ssl-key'):
        console_ssl = True

    if config('console-proxy-ip') == 'local':
        if console_ssl:
            address = resolve_address(endpoint_type=PUBLIC)
            address = format_ipv6_addr(address) or address
            proxy_base_addr = 'https://%s' % address
        else:
            # canonical_url will only return 'https:' if API SSL are enabled.
            proxy_base_addr = canonical_url(CONFIGS, PUBLIC)
    else:
        if console_ssl or https():
            schema = "https"
        else:
            schema = "http"

        proxy_base_addr = "%s://%s" % (schema, config('console-proxy-ip'))

    if proto == 'vnc':
        protocols = ['novnc', 'xvpvnc']
    else:
        protocols = [proto]
    for _proto in protocols:
        rel_settings['console_proxy_%s_address' % (_proto)] = \
            "%s:%s%s" % (proxy_base_addr,
                         console_attributes('proxy-port', proto=_proto),
                         console_attributes('proxy-page', proto=_proto))
        rel_settings['console_proxy_%s_host' % (_proto)] = \
            urlparse(proxy_base_addr).hostname
        rel_settings['console_proxy_%s_port' % (_proto)] = \
            console_attributes('proxy-port', proto=_proto)

    return rel_settings


@hooks.hook('cloud-compute-relation-joined')
def compute_joined(rid=None, remote_restart=False):
    cons_settings = console_settings()
    relation_set(relation_id=rid, **cons_settings)
    rel_settings = {
        'network_manager': network_manager(),
        'volume_service': volume_service(),
        # (comment from bash vers) XXX Should point to VIP if clustered, or
        # this may not even be needed.
        'ec2_host': unit_get('private-address'),
    }
    # update relation setting if we're attempting to restart remote
    # services
    if remote_restart:
        rel_settings['restart_trigger'] = str(uuid.uuid4())

    rel_settings.update(keystone_compute_settings())
    relation_set(relation_id=rid, **rel_settings)


@hooks.hook('cloud-compute-relation-changed')
def compute_changed(rid=None, unit=None):
    rel_settings = relation_get(rid=rid, unit=unit)
    if 'migration_auth_type' not in rel_settings:
        return
    if rel_settings['migration_auth_type'] == 'ssh':
        status_set('maintenance', 'configuring live migration')
        key = rel_settings.get('ssh_public_key')
        if not key:
            log('SSH migration set but peer did not publish key.')
            return
        ssh_compute_add(key, rid=rid, unit=unit)
        index = 0
        for line in ssh_known_hosts_lines(unit=unit):
            relation_set(
                relation_id=rid,
                relation_settings={
                    'known_hosts_{}'.format(index): line})
            index += 1
        relation_set(relation_id=rid, known_hosts_max_index=index)
        index = 0
        for line in ssh_authorized_keys_lines(unit=unit):
            relation_set(
                relation_id=rid,
                relation_settings={
                    'authorized_keys_{}'.format(index): line})
            index += 1
        relation_set(relation_id=rid, authorized_keys_max_index=index)
    if 'nova_ssh_public_key' not in rel_settings:
        return
    if rel_settings['nova_ssh_public_key']:
        ssh_compute_add(rel_settings['nova_ssh_public_key'],
                        rid=rid, unit=unit, user='nova')
        index = 0
        for line in ssh_known_hosts_lines(unit=unit, user='nova'):
            relation_set(
                relation_id=rid,
                relation_settings={
                    '{}_known_hosts_{}'.format(
                        'nova',
                        index): line})
            index += 1
        relation_set(
            relation_id=rid,
            relation_settings={
                '{}_known_hosts_max_index'.format('nova'): index})
        index = 0
        for line in ssh_authorized_keys_lines(unit=unit, user='nova'):
            relation_set(
                relation_id=rid,
                relation_settings={
                    '{}_authorized_keys_{}'.format(
                        'nova',
                        index): line})
            index += 1
        relation_set(
            relation_id=rid,
            relation_settings={
                '{}_authorized_keys_max_index'.format('nova'): index})


@hooks.hook('cloud-compute-relation-departed')
def compute_departed():
    ssh_compute_remove(public_key=relation_get('ssh_public_key'))


@hooks.hook('neutron-network-service-relation-joined',
            'quantum-network-service-relation-joined')
def quantum_joined(rid=None):
    rel_settings = neutron_settings()

    # inform quantum about local keystone auth config
    ks_auth_config = _auth_config()
    rel_settings.update(ks_auth_config)

    # must pass the keystone CA cert, if it exists.
    ks_ca = keystone_ca_cert_b64()
    if ks_auth_config and ks_ca:
        rel_settings['ca_cert'] = ks_ca
    relation_set(relation_id=rid, **rel_settings)


@hooks.hook('cluster-relation-joined')
def cluster_joined(relation_id=None):
    for addr_type in ADDRESS_TYPES:
        address = get_address_in_network(
            config('os-{}-network'.format(addr_type))
        )
        if address:
            relation_set(
                relation_id=relation_id,
                relation_settings={'{}-address'.format(addr_type): address}
            )
    if config('prefer-ipv6'):
        private_addr = get_ipv6_addr(exc_list=[config('vip')])[0]
        relation_set(relation_id=relation_id,
                     relation_settings={'private-address': private_addr})


@hooks.hook('cluster-relation-changed',
            'cluster-relation-departed',
            'leader-settings-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map(), stopstart=True)
def cluster_changed():
    CONFIGS.write_all()
    if relation_ids('cluster'):
        peer_echo(includes=['dbsync_state'])
        dbsync_state = peer_retrieve('dbsync_state')
        if dbsync_state == 'complete':
            enable_services()
            cmd_all_services('start')
        else:
            log('Database sync not ready. Shutting down services')
            disable_services()
            cmd_all_services('stop')


@hooks.hook('ha-relation-joined')
def ha_joined():
    cluster_config = get_hacluster_config()
    resources = {
        'res_nova_haproxy': 'lsb:haproxy',
    }
    resource_params = {
        'res_nova_haproxy': 'op monitor interval="5s"',
    }

    vip_group = []
    for vip in cluster_config['vip'].split():
        if is_ipv6(vip):
            res_nova_vip = 'ocf:heartbeat:IPv6addr'
            vip_params = 'ipv6addr'
        else:
            res_nova_vip = 'ocf:heartbeat:IPaddr2'
            vip_params = 'ip'

        iface = (get_iface_for_address(vip) or
                 config('vip_iface'))
        netmask = (get_netmask_for_address(vip) or
                   config('vip_cidr'))

        if iface is not None:
            vip_key = 'res_nova_{}_vip'.format(iface)
            resources[vip_key] = res_nova_vip
            resource_params[vip_key] = (
                'params {ip}="{vip}" cidr_netmask="{netmask}"'
                ' nic="{iface}"'.format(ip=vip_params,
                                        vip=vip,
                                        iface=iface,
                                        netmask=netmask)
            )
            vip_group.append(vip_key)

    if len(vip_group) >= 1:
        relation_set(groups={'grp_nova_vips': ' '.join(vip_group)})

    init_services = {
        'res_nova_haproxy': 'haproxy'
    }
    clones = {
        'cl_nova_haproxy': 'res_nova_haproxy'
    }
    colocations = {}

    if config('single-nova-consoleauth') and console_attributes('protocol'):
        colocations['vip_consoleauth'] = COLO_CONSOLEAUTH
        init_services['res_nova_consoleauth'] = 'nova-consoleauth'
        resources['res_nova_consoleauth'] = AGENT_CONSOLEAUTH
        resource_params['res_nova_consoleauth'] = AGENT_CA_PARAMS

    relation_set(init_services=init_services,
                 corosync_bindiface=cluster_config['ha-bindiface'],
                 corosync_mcastport=cluster_config['ha-mcastport'],
                 resources=resources,
                 resource_params=resource_params,
                 clones=clones,
                 colocations=colocations)


@hooks.hook('ha-relation-changed')
def ha_changed():
    clustered = relation_get('clustered')
    if not clustered or clustered in [None, 'None', '']:
        log('ha_changed: hacluster subordinate not fully clustered.')
        return

    CONFIGS.write(NOVA_CONF)
    if not is_relation_made('neutron-api'):
        if network_manager() == 'quantum':
            CONFIGS.write(QUANTUM_CONF)
        if network_manager() == 'neutron':
            CONFIGS.write(NEUTRON_CONF)

    log('Cluster configured, notifying other services and updating '
        'keystone endpoint configuration')
    for rid in relation_ids('identity-service'):
        identity_joined(rid=rid)

    update_nova_consoleauth_config()


@hooks.hook('shared-db-relation-broken',
            'pgsql-nova-db-relation-broken')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
def db_departed():
    CONFIGS.write_all()
    for r_id in relation_ids('cluster'):
        relation_set(relation_id=r_id, dbsync_state='incomplete')
    disable_services()
    cmd_all_services('stop')


@hooks.hook('amqp-relation-broken',
            'cinder-volume-service-relation-broken',
            'identity-service-relation-broken',
            'image-service-relation-broken',
            'nova-volume-service-relation-broken',
            'pgsql-neutron-db-relation-broken',
            'quantum-network-service-relation-broken')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
def relation_broken():
    CONFIGS.write_all()
    [nova_cell_relation_joined(rid=rid)
        for rid in relation_ids('cell')]


def configure_https():
    '''
    Enables SSL API Apache config if appropriate and kicks identity-service
    with any required api updates.
    '''
    # need to write all to ensure changes to the entire request pipeline
    # propagate (c-api, haprxy, apache)
    CONFIGS.write_all()
    if 'https' in CONFIGS.complete_contexts():
        cmd = ['a2ensite', 'openstack_https_frontend']
        check_call(cmd)
    else:
        cmd = ['a2dissite', 'openstack_https_frontend']
        check_call(cmd)

    # TODO: improve this by checking if local CN certs are available
    # first then checking reload status (see LP #1433114).
    service_reload('apache2', restart_on_failure=True)

    for rid in relation_ids('identity-service'):
        identity_joined(rid=rid)


@hooks.hook()
def nova_vmware_relation_joined(rid=None):
    rel_settings = {'network_manager': network_manager()}

    ks_auth = _auth_config()
    if ks_auth:
        rel_settings.update(ks_auth)
        rel_settings.update({
            'quantum_plugin': neutron_plugin(),
            'quantum_security_groups': config('quantum-security-groups'),
            'quantum_url': "{}:{}".format(canonical_url(CONFIGS, INTERNAL),
                                          str(api_port('neutron-server')))})

    relation_set(relation_id=rid, **rel_settings)


@hooks.hook('nova-vmware-relation-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def nova_vmware_relation_changed():
    CONFIGS.write('/etc/nova/nova.conf')


@hooks.hook('upgrade-charm')
def upgrade_charm():
    apt_install(filter_installed_packages(determine_packages()),
                fatal=True)
    for r_id in relation_ids('amqp'):
        amqp_joined(relation_id=r_id)
    for r_id in relation_ids('identity-service'):
        identity_joined(rid=r_id)
    for r_id in relation_ids('cloud-compute'):
        for unit in related_units(r_id):
            compute_changed(r_id, unit)
    update_nrpe_config()
    update_nova_consoleauth_config()


# remote_restart is defaulted to true as nova-cells may have started the
# nova-cell process before the db migration was run so it will need a
# kick
@hooks.hook('cell-relation-joined')
def nova_cell_relation_joined(rid=None, remote_restart=True):
    rel_settings = {
        'nova_url': "%s:8774/v2" % canonical_url(CONFIGS, INTERNAL)
    }
    if remote_restart:
        rel_settings['restart_trigger'] = str(uuid.uuid4())
    relation_set(relation_id=rid, **rel_settings)


@hooks.hook('cell-relation-changed')
@restart_on_change(restart_map())
def nova_cell_relation_changed():
    CONFIGS.write(NOVA_CONF)


def get_cell_type():
    cell_info = NovaCellContext()()
    if 'cell_type' in cell_info:
        return cell_info['cell_type']
    return None


@hooks.hook('neutron-api-relation-joined')
def neutron_api_relation_joined(rid=None, remote_restart=False):
    with open('/etc/init/neutron-server.override', 'wb') as out:
        out.write('manual\n')
    if os.path.isfile(NEUTRON_CONF):
        os.rename(NEUTRON_CONF, NEUTRON_CONF + '_unused')
    if service_running('neutron-server'):
        service_stop('neutron-server')
    for id_rid in relation_ids('identity-service'):
        identity_joined(rid=id_rid)
    rel_settings = {
        'nova_url': canonical_url(CONFIGS, INTERNAL) + ":8774/v2"
    }
    if get_cell_type():
        rel_settings['cell_type'] = get_cell_type()
    if remote_restart:
        rel_settings['restart_trigger'] = str(uuid.uuid4())
    relation_set(relation_id=rid, **rel_settings)


@hooks.hook('neutron-api-relation-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def neutron_api_relation_changed():
    CONFIGS.write(NOVA_CONF)
    for rid in relation_ids('cloud-compute'):
        compute_joined(rid=rid)
    for rid in relation_ids('quantum-network-service'):
        quantum_joined(rid=rid)


@hooks.hook('neutron-api-relation-broken')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def neutron_api_relation_broken():
    if os.path.isfile('/etc/init/neutron-server.override'):
        os.remove('/etc/init/neutron-server.override')
    CONFIGS.write_all()
    for rid in relation_ids('cloud-compute'):
        compute_joined(rid=rid)
    for rid in relation_ids('quantum-network-service'):
        quantum_joined(rid=rid)


@hooks.hook('zeromq-configuration-relation-joined')
@os_requires_version('kilo', 'nova-common')
def zeromq_configuration_relation_joined(relid=None):
    relation_set(relation_id=relid,
                 topics=" ".join(get_topics()),
                 users="nova")


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
    nrpe_setup.write()


@hooks.hook('memcache-relation-joined',
            'memcache-relation-departed',
            'memcache-relation-changed',
            'memcache-relation-broken')
@restart_on_change(restart_map())
def memcached_joined():
    CONFIGS.write(NOVA_CONF)


@hooks.hook('zeromq-configuration-relation-changed')
@restart_on_change(restart_map(), stopstart=True)
def zeromq_configuration_relation_changed():
    CONFIGS.write(NOVA_CONF)


def update_nova_consoleauth_config():
    """
    Configure nova-consoleauth pacemaker resources
    """
    relids = relation_ids('ha')
    if len(relids) == 0:
        log('Related to {} ha services'.format(len(relids)), level='DEBUG')
        ha_relid = None
        data = {}
    else:
        ha_relid = relids[0]
        data = relation_get(rid=ha_relid) or {}

    # initialize keys in case this is a new dict
    data.setdefault('delete_resources', [])
    for k in ['colocations', 'init_services', 'resources', 'resource_params']:
        data.setdefault(k, {})

    if config('single-nova-consoleauth') and console_attributes('protocol'):
        for item in ['vip_consoleauth', 'res_nova_consoleauth']:
            try:
                data['delete_resources'].remove(item)
            except ValueError:
                pass  # nothing to remove, we are good

        # the new pcmkr resources have to be added to the existing ones
        data['colocations']['vip_consoleauth'] = COLO_CONSOLEAUTH
        data['init_services']['res_nova_consoleauth'] = 'nova-consoleauth'
        data['resources']['res_nova_consoleauth'] = AGENT_CONSOLEAUTH
        data['resource_params']['res_nova_consoleauth'] = AGENT_CA_PARAMS

        for rid in relation_ids('ha'):
            relation_set(rid, **data)

        # nova-consoleauth will be managed by pacemaker, so mark it as manual
        if relation_ids('ha'):
            with open(NOVA_CONSOLEAUTH_OVERRIDE, 'w') as fp:
                fp.write('manual\n')
                fp.flush()

    elif (not config('single-nova-consoleauth')
          and console_attributes('protocol')):
        for item in ['vip_consoleauth', 'res_nova_consoleauth']:
            if item not in data['delete_resources']:
                data['delete_resources'].append(item)

        # remove them from the rel, so they aren't recreated when the hook
        # is recreated
        data['colocations'].pop('vip_consoleauth', None)
        data['init_services'].pop('res_nova_consoleauth', None)
        data['resources'].pop('res_nova_consoleauth', None)
        data['resource_params'].pop('res_nova_consoleauth', None)

        for rid in relation_ids('ha'):
            relation_set(rid, **data)

        try:
            os.remove(NOVA_CONSOLEAUTH_OVERRIDE)
        except FileNotFoundError as e:
            log(str(e), level='DEBUG')


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    set_os_workload_status(CONFIGS, REQUIRED_INTERFACES,
                           charm_func=check_optional_relations)

if __name__ == '__main__':
    main()
