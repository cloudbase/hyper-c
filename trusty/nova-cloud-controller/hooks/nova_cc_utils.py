import os
import shutil
import subprocess
import ConfigParser

from base64 import b64encode
from collections import OrderedDict
from copy import deepcopy

from charmhelpers.contrib.openstack import context, templating
from charmhelpers.contrib.openstack.neutron import (
    network_manager, neutron_plugin_attribute)

from charmhelpers.contrib.hahelpers.cluster import (
    is_elected_leader,
    get_hacluster_config,
)

from charmhelpers.contrib.peerstorage import peer_store

from charmhelpers.contrib.python.packages import (
    pip_install,
)

from charmhelpers.contrib.openstack.utils import (
    configure_installation_source,
    get_host_ip,
    get_hostname,
    get_os_codename_install_source,
    git_install_requested,
    git_clone_and_install,
    git_src_dir,
    git_pip_venv_dir,
    git_yaml_value,
    is_ip,
    os_release,
    save_script_rc as _save_script_rc,
    set_os_workload_status,
)

from charmhelpers.fetch import (
    apt_upgrade,
    apt_update,
    apt_install,
    add_source
)

from charmhelpers.core.hookenv import (
    charm_dir,
    config,
    log,
    relation_get,
    relation_ids,
    remote_unit,
    is_relation_made,
    INFO,
    ERROR,
    status_get,
)

from charmhelpers.core.host import (
    adduser,
    add_group,
    add_user_to_group,
    mkdir,
    service,
    service_start,
    service_stop,
    service_running,
    lsb_release,
)

from charmhelpers.core.templating import render

from charmhelpers.contrib.network.ip import (
    is_ipv6
)

from charmhelpers.core.decorators import (
    retry_on_exception,
)

import nova_cc_context

TEMPLATES = 'templates/'

CLUSTER_RES = 'grp_nova_vips'

# The interface is said to be satisfied if anyone of the interfaces in the
# list has a complete context.
REQUIRED_INTERFACES = {
    'database': ['shared-db', 'pgsql-db'],
    'messaging': ['amqp', 'zeromq-configuration'],
    'identity': ['identity-service'],
    'image': ['image-service'],
    'compute': ['nova-compute'],
}

# removed from original: charm-helper-sh
BASE_PACKAGES = [
    'apache2',
    'haproxy',
    'python-keystoneclient',
    'python-mysqldb',
    'python-psycopg2',
    'python-psutil',
    'python-six',
    'uuid',
    'python-memcache',
]

BASE_GIT_PACKAGES = [
    'libffi-dev',
    'libmysqlclient-dev',
    'libssl-dev',
    'libxml2-dev',
    'libxslt1-dev',
    'libyaml-dev',
    'python-dev',
    'python-pip',
    'python-setuptools',
    'zlib1g-dev',
]

LATE_GIT_PACKAGES = [
    'novnc',
    'spice-html5',
    'websockify',
]

# ubuntu packages that should not be installed when deploying from git
GIT_PACKAGE_BLACKLIST = [
    'neutron-common',
    'neutron-server',
    'neutron-plugin-ml2',
    'nova-api-ec2',
    'nova-api-os-compute',
    'nova-api-os-volume',
    'nova-cert',
    'nova-conductor',
    'nova-consoleauth',
    'nova-novncproxy',
    'nova-objectstore',
    'nova-scheduler',
    'nova-spiceproxy',
    'nova-xvpvncproxy',
    'python-keystoneclient',
    'python-six',
    'quantum-server',
]

BASE_SERVICES = [
    'nova-api-ec2',
    'nova-api-os-compute',
    'nova-objectstore',
    'nova-cert',
    'nova-scheduler',
]

API_PORTS = {
    'nova-api-ec2': 8773,
    'nova-api-os-compute': 8774,
    'nova-api-os-volume': 8776,
    'nova-objectstore': 3333,
    'neutron-server': 9696,
    'quantum-server': 9696,
}

NOVA_CONF_DIR = "/etc/nova"
QUANTUM_CONF_DIR = "/etc/quantum"
NEUTRON_CONF_DIR = "/etc/neutron"

NOVA_CONF = '%s/nova.conf' % NOVA_CONF_DIR
NOVA_API_PASTE = '%s/api-paste.ini' % NOVA_CONF_DIR
QUANTUM_CONF = '%s/quantum.conf' % QUANTUM_CONF_DIR
QUANTUM_API_PASTE = '%s/api-paste.ini' % QUANTUM_CONF_DIR
NEUTRON_CONF = '%s/neutron.conf' % NEUTRON_CONF_DIR
HAPROXY_CONF = '/etc/haproxy/haproxy.cfg'
APACHE_CONF = '/etc/apache2/sites-available/openstack_https_frontend'
APACHE_24_CONF = '/etc/apache2/sites-available/openstack_https_frontend.conf'
NEUTRON_DEFAULT = '/etc/default/neutron-server'
QUANTUM_DEFAULT = '/etc/default/quantum-server'

BASE_RESOURCE_MAP = OrderedDict([
    (NOVA_CONF, {
        'services': BASE_SERVICES,
        'contexts': [context.AMQPContext(ssl_dir=NOVA_CONF_DIR),
                     context.SharedDBContext(
                         relation_prefix='nova', ssl_dir=NOVA_CONF_DIR),
                     context.OSConfigFlagContext(
                         charm_flag='nova-alchemy-flags',
                         template_flag='nova_alchemy_flags'),
                     nova_cc_context.NovaPostgresqlDBContext(),
                     context.ImageServiceContext(),
                     context.OSConfigFlagContext(),
                     context.SubordinateConfigContext(
                         interface='nova-vmware',
                         service='nova',
                         config_file=NOVA_CONF),
                     nova_cc_context.NovaCellContext(),
                     context.SyslogContext(),
                     context.LogLevelContext(),
                     nova_cc_context.HAProxyContext(),
                     nova_cc_context.IdentityServiceContext(
                         service='nova',
                         service_user='nova'),
                     nova_cc_context.VolumeServiceContext(),
                     context.ZeroMQContext(),
                     context.NotificationDriverContext(),
                     nova_cc_context.NovaIPv6Context(),
                     nova_cc_context.NeutronCCContext(),
                     nova_cc_context.NovaConfigContext(),
                     nova_cc_context.InstanceConsoleContext(),
                     nova_cc_context.ConsoleSSLContext(),
                     nova_cc_context.CloudComputeContext()],
    }),
    (NOVA_API_PASTE, {
        'services': [s for s in BASE_SERVICES if 'api' in s],
        'contexts': [nova_cc_context.IdentityServiceContext(),
                     nova_cc_context.APIRateLimitingContext()],
    }),
    (QUANTUM_CONF, {
        'services': ['quantum-server'],
        'contexts': [context.AMQPContext(ssl_dir=QUANTUM_CONF_DIR),
                     context.SharedDBContext(
                         user=config('neutron-database-user'),
                         database=config('neutron-database'),
                         relation_prefix='neutron',
                         ssl_dir=QUANTUM_CONF_DIR),
                     nova_cc_context.NeutronPostgresqlDBContext(),
                     nova_cc_context.HAProxyContext(),
                     nova_cc_context.IdentityServiceContext(
                         service='neutron',
                         service_user='neutron'),
                     nova_cc_context.NeutronCCContext(),
                     context.SyslogContext()],
    }),
    (QUANTUM_DEFAULT, {
        'services': ['quantum-server'],
        'contexts': [nova_cc_context.NeutronCCContext()],
    }),
    (QUANTUM_API_PASTE, {
        'services': ['quantum-server'],
        'contexts': [nova_cc_context.IdentityServiceContext()],
    }),
    (NEUTRON_CONF, {
        'services': ['neutron-server'],
        'contexts': [context.AMQPContext(ssl_dir=NEUTRON_CONF_DIR),
                     context.SharedDBContext(
                         user=config('neutron-database-user'),
                         database=config('neutron-database'),
                         relation_prefix='neutron',
                         ssl_dir=NEUTRON_CONF_DIR),
                     nova_cc_context.NeutronPostgresqlDBContext(),
                     nova_cc_context.IdentityServiceContext(
                         service='neutron',
                         service_user='neutron'),
                     nova_cc_context.NeutronCCContext(),
                     nova_cc_context.HAProxyContext(),
                     context.SyslogContext(),
                     nova_cc_context.NovaConfigContext(),
                     context.BindHostContext()],
    }),
    (NEUTRON_DEFAULT, {
        'services': ['neutron-server'],
        'contexts': [nova_cc_context.NeutronCCContext()],
    }),
    (HAPROXY_CONF, {
        'contexts': [context.HAProxyContext(singlenode_mode=True),
                     nova_cc_context.HAProxyContext()],
        'services': ['haproxy'],
    }),
    (APACHE_CONF, {
        'contexts': [nova_cc_context.ApacheSSLContext()],
        'services': ['apache2'],
    }),
    (APACHE_24_CONF, {
        'contexts': [nova_cc_context.ApacheSSLContext()],
        'services': ['apache2'],
    }),
])

CA_CERT_PATH = '/usr/local/share/ca-certificates/keystone_juju_ca_cert.crt'

NOVA_SSH_DIR = '/etc/nova/compute_ssh/'

CONSOLE_CONFIG = {
    'spice': {
        'packages': ['nova-spiceproxy', 'nova-consoleauth'],
        'services': ['nova-spiceproxy', 'nova-consoleauth'],
        'proxy-page': '/spice_auto.html',
        'proxy-port': 6082,
    },
    'novnc': {
        'packages': ['nova-novncproxy', 'nova-consoleauth'],
        'services': ['nova-novncproxy', 'nova-consoleauth'],
        'proxy-page': '/vnc_auto.html',
        'proxy-port': 6080,
    },
    'xvpvnc': {
        'packages': ['nova-xvpvncproxy', 'nova-consoleauth'],
        'services': ['nova-xvpvncproxy', 'nova-consoleauth'],
        'proxy-page': '/console',
        'proxy-port': 6081,
    },
}


def resource_map():
    '''
    Dynamically generate a map of resources that will be managed for a single
    hook execution.
    '''
    resource_map = deepcopy(BASE_RESOURCE_MAP)

    if relation_ids('nova-volume-service'):
        # if we have a relation to a nova-volume service, we're
        # also managing the nova-volume API endpoint (legacy)
        resource_map['/etc/nova/nova.conf']['services'].append(
            'nova-api-os-volume')

    net_manager = network_manager()

    if os.path.exists('/etc/apache2/conf-available'):
        resource_map.pop(APACHE_CONF)
    else:
        resource_map.pop(APACHE_24_CONF)

    resource_map[NOVA_CONF]['contexts'].append(
        nova_cc_context.NeutronCCContext())
    # pop out irrelevant resources from the OrderedDict (easier than adding
    # them late)
    if net_manager != 'quantum':
        [resource_map.pop(k) for k in list(resource_map.iterkeys())
         if 'quantum' in k]
    if net_manager != 'neutron':
        [resource_map.pop(k) for k in list(resource_map.iterkeys())
         if 'neutron' in k]
    # add neutron plugin requirements. nova-c-c only needs the
    # neutron-server associated with configs, not the plugin agent.
    if net_manager in ['quantum', 'neutron']:
        plugin = neutron_plugin()
        if plugin:
            conf = neutron_plugin_attribute(plugin, 'config', net_manager)
            ctxts = (neutron_plugin_attribute(plugin, 'contexts',
                                              net_manager)
                     or [])
            services = neutron_plugin_attribute(plugin, 'server_services',
                                                net_manager)
            resource_map[conf] = {}
            resource_map[conf]['services'] = services
            resource_map[conf]['contexts'] = ctxts
            resource_map[conf]['contexts'].append(
                nova_cc_context.NeutronCCContext())

            # update for postgres
            resource_map[conf]['contexts'].append(
                nova_cc_context.NeutronPostgresqlDBContext())

    if is_relation_made('neutron-api'):
        for k in list(resource_map.iterkeys()):
            # neutron-api runs neutron services
            if 'quantum' in k or 'neutron' in k:
                resource_map[k]['services'] = []
        resource_map[NOVA_CONF]['contexts'].append(
            nova_cc_context.NeutronAPIContext())

    # nova-conductor for releases >= G.
    if os_release('nova-common') not in ['essex', 'folsom']:
        resource_map['/etc/nova/nova.conf']['services'] += ['nova-conductor']

    if console_attributes('services'):
        resource_map['/etc/nova/nova.conf']['services'] += \
            console_attributes('services')

    # also manage any configs that are being updated by subordinates.
    vmware_ctxt = context.SubordinateConfigContext(interface='nova-vmware',
                                                   service='nova',
                                                   config_file=NOVA_CONF)
    vmware_ctxt = vmware_ctxt()
    if vmware_ctxt and 'services' in vmware_ctxt:
        for s in vmware_ctxt['services']:
            if s not in resource_map[NOVA_CONF]['services']:
                resource_map[NOVA_CONF]['services'].append(s)

    return resource_map


def register_configs(release=None):
    release = release or os_release('nova-common')
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)
    for cfg, rscs in resource_map().iteritems():
        configs.register(cfg, rscs['contexts'])
    return configs


def restart_map():
    return OrderedDict([(cfg, v['services'])
                        for cfg, v in resource_map().iteritems()
                        if v['services']])


def services():
    ''' Returns a list of services associate with this charm '''
    _services = []
    for v in restart_map().values():
        _services = _services + v
    return list(set(_services))


def determine_ports():
    '''Assemble a list of API ports for services we are managing'''
    ports = []
    for services in restart_map().values():
        for svc in services:
            try:
                ports.append(API_PORTS[svc])
            except KeyError:
                pass
    return list(set(ports))


def api_port(service):
    return API_PORTS[service]


def console_attributes(attr, proto=None):
    '''Leave proto unset to query attributes of the protocal specified at
    runtime'''
    if proto:
        console_proto = proto
    else:
        console_proto = config('console-access-protocol')
    if attr == 'protocol':
        return console_proto
    # 'vnc' is a virtual type made up of novnc and xvpvnc
    if console_proto == 'vnc':
        if attr in ['packages', 'services']:
            return list(set(CONSOLE_CONFIG['novnc'][attr] +
                        CONSOLE_CONFIG['xvpvnc'][attr]))
        else:
            return None
    if console_proto in CONSOLE_CONFIG:
        return CONSOLE_CONFIG[console_proto][attr]
    return None


def determine_packages():
    # currently all packages match service names
    packages = [] + BASE_PACKAGES
    for v in resource_map().values():
        packages.extend(v['services'])
    if network_manager() in ['neutron', 'quantum']:
        pkgs = neutron_plugin_attribute(neutron_plugin(), 'server_packages',
                                        network_manager())
        packages.extend(pkgs)
    if console_attributes('packages'):
        packages.extend(console_attributes('packages'))

    if git_install_requested():
        packages = list(set(packages))
        packages.extend(BASE_GIT_PACKAGES)
        # don't include packages that will be installed from git
        for p in GIT_PACKAGE_BLACKLIST:
            if p in packages:
                packages.remove(p)

    return list(set(packages))


def save_script_rc():
    env_vars = {
        'OPENSTACK_PORT_MCASTPORT': config('ha-mcastport'),
        'OPENSTACK_SERVICE_API_EC2': 'nova-api-ec2',
        'OPENSTACK_SERVICE_API_OS_COMPUTE': 'nova-api-os-compute',
        'OPENSTACK_SERVICE_CERT': 'nova-cert',
        'OPENSTACK_SERVICE_CONDUCTOR': 'nova-conductor',
        'OPENSTACK_SERVICE_OBJECTSTORE': 'nova-objectstore',
        'OPENSTACK_SERVICE_SCHEDULER': 'nova-scheduler',
    }
    if relation_ids('nova-volume-service'):
        env_vars['OPENSTACK_SERVICE_API_OS_VOL'] = 'nova-api-os-volume'
    if network_manager() == 'quantum':
        env_vars['OPENSTACK_SERVICE_API_QUANTUM'] = 'quantum-server'
    if network_manager() == 'neutron':
        env_vars['OPENSTACK_SERVICE_API_NEUTRON'] = 'neutron-server'
    _save_script_rc(**env_vars)


def get_step_upgrade_source(new_src):
    '''
    Determine if upgrade skips a release and, if so, return source
    of skipped release.
    '''
    sources = {
        # target_src: (cur_pocket, step_src)
        'cloud:precise-icehouse':
        ('precise-updates/grizzly', 'cloud:precise-havana'),
        'cloud:precise-icehouse/proposed':
        ('precise-proposed/grizzly', 'cloud:precise-havana/proposed')
    }

    configure_installation_source(new_src)

    with open('/etc/apt/sources.list.d/cloud-archive.list', 'r') as f:
        line = f.readline()
        for target_src, (cur_pocket, step_src) in sources.items():
            if target_src != new_src:
                continue
            if cur_pocket in line:
                return step_src

    return None

POLICY_RC_D = """#!/bin/bash

set -e

case $1 in
  neutron-server|quantum-server|nova-*)
    [ $2 = "start" ] && exit 101
    ;;
  *)
    ;;
esac

exit 0
"""


def enable_policy_rcd():
    with open('/usr/sbin/policy-rc.d', 'w') as policy:
        policy.write(POLICY_RC_D)
    os.chmod('/usr/sbin/policy-rc.d', 0o755)


def disable_policy_rcd():
    os.unlink('/usr/sbin/policy-rc.d')


QUANTUM_DB_MANAGE = "quantum-db-manage"
NEUTRON_DB_MANAGE = "neutron-db-manage"


def reset_os_release():
    # Ugly hack to make os_release re-read versions
    import charmhelpers.contrib.openstack.utils as utils
    utils.os_rel = None


def neutron_db_manage(actions):
    net_manager = network_manager()
    if net_manager in ['neutron', 'quantum']:
        plugin = neutron_plugin()
        conf = neutron_plugin_attribute(plugin, 'config', net_manager)
        if net_manager == 'quantum':
            cmd = QUANTUM_DB_MANAGE
        else:
            cmd = NEUTRON_DB_MANAGE
        subprocess.check_call([
            cmd, '--config-file=/etc/{mgr}/{mgr}.conf'.format(mgr=net_manager),
            '--config-file={}'.format(conf)] + actions
        )


def get_db_connection():
    config = ConfigParser.RawConfigParser()
    config.read('/etc/neutron/neutron.conf')
    try:
        return config.get('database', 'connection')
    except:
        return None


def ml2_migration():
    reset_os_release()
    net_manager = network_manager()
    if net_manager == 'neutron':
        plugin = neutron_plugin()
        if plugin == 'ovs':
            log('Migrating from openvswitch to ml2 plugin')
            cmd = [
                'python',
                '/usr/lib/python2.7/dist-packages/neutron'
                '/db/migration/migrate_to_ml2.py',
                '--tunnel-type', 'gre',
                '--release', 'icehouse',
                'openvswitch', get_db_connection()
            ]
            subprocess.check_call(cmd)


def _do_openstack_upgrade(new_src):
    enable_policy_rcd()
    cur_os_rel = os_release('nova-common')
    new_os_rel = get_os_codename_install_source(new_src)
    log('Performing OpenStack upgrade to %s.' % (new_os_rel))

    configure_installation_source(new_src)
    dpkg_opts = [
        '--option', 'Dpkg::Options::=--force-confnew',
        '--option', 'Dpkg::Options::=--force-confdef',
    ]

    # NOTE(jamespage) pre-stamp neutron database before upgrade from grizzly
    if cur_os_rel == 'grizzly':
        neutron_db_manage(['stamp', 'grizzly'])

    apt_update(fatal=True)
    apt_upgrade(options=dpkg_opts, fatal=True, dist=True)
    apt_install(determine_packages(), fatal=True)

    if cur_os_rel == 'grizzly':
        # NOTE(jamespage) when upgrading from grizzly->havana, config
        # files need to be generated prior to performing the db upgrade
        reset_os_release()
        configs = register_configs(release=new_os_rel)
        configs.write_all()
        neutron_db_manage(['upgrade', 'head'])
    else:
        if new_os_rel < 'kilo':
            neutron_db_manage(['stamp', cur_os_rel])
            migrate_neutron_database()
        # NOTE(jamespage) upgrade with existing config files as the
        # havana->icehouse migration enables new service_plugins which
        # create issues with db upgrades
        reset_os_release()
        configs = register_configs(release=new_os_rel)
        configs.write_all()

    if new_os_rel == 'icehouse':
        # NOTE(jamespage) default plugin switch to ml2@icehouse
        ml2_migration()

    if is_elected_leader(CLUSTER_RES):
        migrate_nova_database()
    [service_start(s) for s in services()]

    disable_policy_rcd()

    return configs


def do_openstack_upgrade(configs):
    new_src = config('openstack-origin')
    if new_src[:6] != 'cloud:':
        raise ValueError("Unable to perform upgrade to %s" % new_src)

    step_src = get_step_upgrade_source(new_src)
    if step_src is not None:
        _do_openstack_upgrade(step_src)
    return _do_openstack_upgrade(new_src)


def volume_service():
    '''Specifies correct volume API for specific OS release'''
    os_vers = os_release('nova-common')
    if os_vers == 'essex':
        return 'nova-volume'
    elif os_vers == 'folsom':  # support both drivers in folsom.
        if not relation_ids('cinder-volume-service'):
            return 'nova-volume'
    return 'cinder'


# NOTE(jamespage): Retry deals with sync issues during one-shot HA deploys.
#                  mysql might be restarting or suchlike.
@retry_on_exception(5, base_delay=3, exc_type=subprocess.CalledProcessError)
def migrate_nova_database():
    '''Runs nova-manage to initialize a new database or migrate existing'''
    log('Migrating the nova database.', level=INFO)
    cmd = ['nova-manage', 'db', 'sync']
    subprocess.check_output(cmd)
    if relation_ids('cluster'):
        log('Informing peers that dbsync is complete', level=INFO)
        peer_store('dbsync_state', 'complete')
    log('Enabling services', level=INFO)
    enable_services()
    cmd_all_services('start')


# NOTE(jamespage): Retry deals with sync issues during one-shot HA deploys.
#                  mysql might be restarting or suchlike.
@retry_on_exception(5, base_delay=3, exc_type=subprocess.CalledProcessError)
def migrate_neutron_database():
    '''Runs neutron-db-manage to init a new database or migrate existing'''
    log('Migrating the neutron database.', level=INFO)
    neutron_db_manage(['upgrade', 'head'])


def auth_token_config(setting):
    """
    Returns currently configured value for setting in api-paste.ini's
    authtoken section, or None.
    """
    config = ConfigParser.RawConfigParser()
    config.read('/etc/nova/api-paste.ini')
    try:
        value = config.get('filter:authtoken', setting)
    except:
        return None
    if value.startswith('%'):
        return None
    return value


def keystone_ca_cert_b64():
    '''Returns the local Keystone-provided CA cert if it exists, or None.'''
    if not os.path.isfile(CA_CERT_PATH):
        return None
    with open(CA_CERT_PATH) as _in:
        return b64encode(_in.read())


def ssh_directory_for_unit(unit=None, user=None):
    if unit:
        remote_service = unit.split('/')[0]
    else:
        remote_service = remote_unit().split('/')[0]
    if user:
        remote_service = "{}_{}".format(remote_service, user)
    _dir = os.path.join(NOVA_SSH_DIR, remote_service)
    for d in [NOVA_SSH_DIR, _dir]:
        if not os.path.isdir(d):
            os.mkdir(d)
    for f in ['authorized_keys', 'known_hosts']:
        f = os.path.join(_dir, f)
        if not os.path.isfile(f):
            open(f, 'w').close()
    return _dir


def known_hosts(unit=None, user=None):
    return os.path.join(ssh_directory_for_unit(unit, user), 'known_hosts')


def authorized_keys(unit=None, user=None):
    return os.path.join(ssh_directory_for_unit(unit, user), 'authorized_keys')


def ssh_known_host_key(host, unit=None, user=None):
    cmd = ['ssh-keygen', '-f', known_hosts(unit, user), '-H', '-F', host]
    try:
        # The first line of output is like '# Host xx found: line 1 type RSA',
        # which should be excluded.
        output = subprocess.check_output(cmd).strip()
    except subprocess.CalledProcessError:
        return None

    if output:
        # Bug #1500589 cmd has 0 rc on precise if entry not present
        lines = output.split('\n')
        if len(lines) > 1:
            return lines[1]

    return None


def remove_known_host(host, unit=None, user=None):
    log('Removing SSH known host entry for compute host at %s' % host)
    cmd = ['ssh-keygen', '-f', known_hosts(unit, user), '-R', host]
    subprocess.check_call(cmd)


def is_same_key(key_1, key_2):
    # The key format get will be like '|1|2rUumCavEXWVaVyB5uMl6m85pZo=|Cp'
    # 'EL6l7VTY37T/fg/ihhNb/GPgs= ssh-rsa AAAAB', we only need to compare
    # the part start with 'ssh-rsa' followed with '= ', because the hash
    # value in the beginning will change each time.
    k_1 = key_1.split('= ')[1]
    k_2 = key_2.split('= ')[1]
    return k_1 == k_2


def add_known_host(host, unit=None, user=None):
    '''Add variations of host to a known hosts file.'''
    cmd = ['ssh-keyscan', '-H', '-t', 'rsa', host]
    try:
        remote_key = subprocess.check_output(cmd).strip()
    except Exception as e:
        log('Could not obtain SSH host key from %s' % host, level=ERROR)
        raise e

    current_key = ssh_known_host_key(host, unit, user)
    if current_key and remote_key:
        if is_same_key(remote_key, current_key):
            log('Known host key for compute host %s up to date.' % host)
            return
        else:
            remove_known_host(host, unit, user)

    log('Adding SSH host key to known hosts for compute node at %s.' % host)
    with open(known_hosts(unit, user), 'a') as out:
        out.write(remote_key + '\n')


def ssh_authorized_key_exists(public_key, unit=None, user=None):
    with open(authorized_keys(unit, user)) as keys:
        return (' %s ' % public_key) in keys.read()


def add_authorized_key(public_key, unit=None, user=None):
    with open(authorized_keys(unit, user), 'a') as keys:
        keys.write(public_key + '\n')


def ssh_compute_add(public_key, rid=None, unit=None, user=None):
    # If remote compute node hands us a hostname, ensure we have a
    # known hosts entry for its IP, hostname and FQDN.
    private_address = relation_get(rid=rid, unit=unit,
                                   attribute='private-address')
    hosts = [private_address]

    if not is_ipv6(private_address):
        if relation_get('hostname'):
            hosts.append(relation_get('hostname'))

        if not is_ip(private_address):
            hosts.append(get_host_ip(private_address))
            hosts.append(private_address.split('.')[0])
        else:
            hn = get_hostname(private_address)
            hosts.append(hn)
            hosts.append(hn.split('.')[0])

    for host in list(set(hosts)):
        add_known_host(host, unit, user)

    if not ssh_authorized_key_exists(public_key, unit, user):
        log('Saving SSH authorized key for compute host at %s.' %
            private_address)
        add_authorized_key(public_key, unit, user)


def ssh_known_hosts_lines(unit=None, user=None):
    known_hosts_list = []

    with open(known_hosts(unit, user)) as hosts:
        for hosts_line in hosts:
            if hosts_line.rstrip():
                known_hosts_list.append(hosts_line.rstrip())
    return(known_hosts_list)


def ssh_authorized_keys_lines(unit=None, user=None):
    authorized_keys_list = []

    with open(authorized_keys(unit, user)) as keys:
        for authkey_line in keys:
            if authkey_line.rstrip():
                authorized_keys_list.append(authkey_line.rstrip())
    return(authorized_keys_list)


def ssh_compute_remove(public_key, unit=None, user=None):
    if not (os.path.isfile(authorized_keys(unit, user)) or
            os.path.isfile(known_hosts(unit, user))):
        return

    with open(authorized_keys(unit, user)) as _keys:
        keys = [k.strip() for k in _keys.readlines()]

    if public_key not in keys:
        return

    [keys.remove(key) for key in keys if key == public_key]

    with open(authorized_keys(unit, user), 'w') as _keys:
        keys = '\n'.join(keys)
        if not keys.endswith('\n'):
            keys += '\n'
        _keys.write(keys)


def determine_endpoints(public_url, internal_url, admin_url):
    '''Generates a dictionary containing all relevant endpoints to be
    passed to keystone as relation settings.'''
    region = config('region')
    os_rel = os_release('nova-common')

    if os_rel >= 'grizzly':
        nova_public_url = ('%s:%s/v2/$(tenant_id)s' %
                           (public_url, api_port('nova-api-os-compute')))
        nova_internal_url = ('%s:%s/v2/$(tenant_id)s' %
                             (internal_url, api_port('nova-api-os-compute')))
        nova_admin_url = ('%s:%s/v2/$(tenant_id)s' %
                          (admin_url, api_port('nova-api-os-compute')))
    else:
        nova_public_url = ('%s:%s/v1.1/$(tenant_id)s' %
                           (public_url, api_port('nova-api-os-compute')))
        nova_internal_url = ('%s:%s/v1.1/$(tenant_id)s' %
                             (internal_url, api_port('nova-api-os-compute')))
        nova_admin_url = ('%s:%s/v1.1/$(tenant_id)s' %
                          (admin_url, api_port('nova-api-os-compute')))

    ec2_public_url = '%s:%s/services/Cloud' % (
        public_url, api_port('nova-api-ec2'))
    ec2_internal_url = '%s:%s/services/Cloud' % (
        internal_url, api_port('nova-api-ec2'))
    ec2_admin_url = '%s:%s/services/Cloud' % (admin_url,
                                              api_port('nova-api-ec2'))

    nova_volume_public_url = ('%s:%s/v1/$(tenant_id)s' %
                              (public_url, api_port('nova-api-os-compute')))
    nova_volume_internal_url = ('%s:%s/v1/$(tenant_id)s' %
                                (internal_url,
                                 api_port('nova-api-os-compute')))
    nova_volume_admin_url = ('%s:%s/v1/$(tenant_id)s' %
                             (admin_url, api_port('nova-api-os-compute')))

    neutron_public_url = '%s:%s' % (public_url, api_port('neutron-server'))
    neutron_internal_url = '%s:%s' % (internal_url, api_port('neutron-server'))
    neutron_admin_url = '%s:%s' % (admin_url, api_port('neutron-server'))

    s3_public_url = '%s:%s' % (public_url, api_port('nova-objectstore'))
    s3_internal_url = '%s:%s' % (internal_url, api_port('nova-objectstore'))
    s3_admin_url = '%s:%s' % (admin_url, api_port('nova-objectstore'))

    # the base endpoints
    endpoints = {
        'nova_service': 'nova',
        'nova_region': region,
        'nova_public_url': nova_public_url,
        'nova_admin_url': nova_admin_url,
        'nova_internal_url': nova_internal_url,
        'ec2_service': 'ec2',
        'ec2_region': region,
        'ec2_public_url': ec2_public_url,
        'ec2_admin_url': ec2_admin_url,
        'ec2_internal_url': ec2_internal_url,
        's3_service': 's3',
        's3_region': region,
        's3_public_url': s3_public_url,
        's3_admin_url': s3_admin_url,
        's3_internal_url': s3_internal_url,
    }

    if relation_ids('nova-volume-service'):
        endpoints.update({
            'nova-volume_service': 'nova-volume',
            'nova-volume_region': region,
            'nova-volume_public_url': nova_volume_public_url,
            'nova-volume_admin_url': nova_volume_admin_url,
            'nova-volume_internal_url': nova_volume_internal_url,
        })

    # XXX: Keep these relations named quantum_*??
    if relation_ids('neutron-api'):
        endpoints.update({
            'quantum_service': None,
            'quantum_region': None,
            'quantum_public_url': None,
            'quantum_admin_url': None,
            'quantum_internal_url': None,
        })
    elif network_manager() in ['quantum', 'neutron']:
        endpoints.update({
            'quantum_service': 'quantum',
            'quantum_region': region,
            'quantum_public_url': neutron_public_url,
            'quantum_admin_url': neutron_admin_url,
            'quantum_internal_url': neutron_internal_url,
        })

    if os_rel >= 'kilo':
        # NOTE(jamespage) drop endpoints for ec2 and s3
        #  ec2 is deprecated
        #  s3 is insecure and should die in flames
        endpoints.update({
            'ec2_service': None,
            'ec2_region': None,
            'ec2_public_url': None,
            'ec2_admin_url': None,
            'ec2_internal_url': None,
            's3_service': None,
            's3_region': None,
            's3_public_url': None,
            's3_admin_url': None,
            's3_internal_url': None,
        })

    return endpoints


def neutron_plugin():
    # quantum-plugin config setting can be safely overriden
    # as we only supported OVS in G/neutron
    return config('neutron-plugin') or config('quantum-plugin')


def guard_map():
    '''Map of services and required interfaces that must be present before
    the service should be allowed to start'''
    gmap = {}
    nova_services = deepcopy(BASE_SERVICES)
    if os_release('nova-common') not in ['essex', 'folsom']:
        nova_services.append('nova-conductor')

    nova_interfaces = ['identity-service', 'amqp']
    if relation_ids('pgsql-nova-db'):
        nova_interfaces.append('pgsql-nova-db')
    else:
        nova_interfaces.append('shared-db')

    for svc in nova_services:
        gmap[svc] = nova_interfaces

    net_manager = network_manager()
    if net_manager in ['neutron', 'quantum'] and \
            not is_relation_made('neutron-api'):
        neutron_interfaces = ['identity-service', 'amqp']
        if relation_ids('pgsql-neutron-db'):
            neutron_interfaces.append('pgsql-neutron-db')
        else:
            neutron_interfaces.append('shared-db')
        if network_manager() == 'quantum':
            gmap['quantum-server'] = neutron_interfaces
        else:
            gmap['neutron-server'] = neutron_interfaces

    return gmap


def service_guard(guard_map, contexts, active=False):
    '''Inhibit services in guard_map from running unless
    required interfaces are found complete in contexts.'''
    def wrap(f):
        def wrapped_f(*args):
            if active is True:
                incomplete_services = []
                for svc in guard_map:
                    for interface in guard_map[svc]:
                        if interface not in contexts.complete_contexts():
                            incomplete_services.append(svc)
                f(*args)
                for svc in incomplete_services:
                    if service_running(svc):
                        log('Service {} has unfulfilled '
                            'interface requirements, stopping.'.format(svc))
                        service_stop(svc)
            else:
                f(*args)
        return wrapped_f
    return wrap


def get_topics():
    topics = ['scheduler', 'conductor']
    if 'nova-consoleauth' in services():
        topics.append('consoleauth')
    return topics


def cmd_all_services(cmd):
    if cmd == 'start':
        for svc in services():
            if not service_running(svc):
                service_start(svc)
    else:
        for svc in services():
            service(cmd, svc)


def disable_services():
    for svc in services():
        with open('/etc/init/{}.override'.format(svc), 'wb') as out:
            out.write('exec true\n')


def enable_services():
    for svc in services():
        override_file = '/etc/init/{}.override'.format(svc)
        if os.path.isfile(override_file):
            os.remove(override_file)


def setup_ipv6():
    ubuntu_rel = lsb_release()['DISTRIB_CODENAME'].lower()
    if ubuntu_rel < "trusty":
        raise Exception("IPv6 is not supported in the charms for Ubuntu "
                        "versions less than Trusty 14.04")

    # Need haproxy >= 1.5.3 for ipv6 so for Trusty if we are <= Kilo we need to
    # use trusty-backports otherwise we can use the UCA.
    if ubuntu_rel == 'trusty' and os_release('nova-api') < 'liberty':
        add_source('deb http://archive.ubuntu.com/ubuntu trusty-backports '
                   'main')
        apt_update()
        apt_install('haproxy/trusty-backports', fatal=True)


def git_install(projects_yaml):
    """Perform setup, and install git repos specified in yaml parameter."""
    if git_install_requested():
        git_pre_install()
        git_clone_and_install(projects_yaml, core_project='nova')
        git_post_install(projects_yaml)


def git_pre_install():
    """Perform pre-install setup."""
    dirs = [
        '/var/lib/nova',
        '/var/lib/nova/buckets',
        '/var/lib/nova/CA',
        '/var/lib/nova/CA/INTER',
        '/var/lib/nova/CA/newcerts',
        '/var/lib/nova/CA/private',
        '/var/lib/nova/CA/reqs',
        '/var/lib/nova/images',
        '/var/lib/nova/instances',
        '/var/lib/nova/keys',
        '/var/lib/nova/networks',
        '/var/lib/nova/tmp',
        '/var/lib/neutron',
        '/var/lib/neutron/lock',
        '/var/log/nova',
        '/etc/neutron',
        '/etc/neutron/plugins',
        '/etc/neutron/plugins/ml2',
    ]

    adduser('nova', shell='/bin/bash', system_user=True)
    subprocess.check_call(['usermod', '--home', '/var/lib/nova', 'nova'])
    add_group('nova', system_group=True)
    add_user_to_group('nova', 'nova')

    adduser('neutron', shell='/bin/bash', system_user=True)
    add_group('neutron', system_group=True)
    add_user_to_group('neutron', 'neutron')

    for d in dirs:
        mkdir(d, owner='nova', group='nova', perms=0755, force=False)


def git_post_install(projects_yaml):
    """Perform post-install setup."""
    http_proxy = git_yaml_value(projects_yaml, 'http_proxy')
    if http_proxy:
        pip_install('mysql-python', proxy=http_proxy,
                    venv=git_pip_venv_dir(projects_yaml))
    else:
        pip_install('mysql-python',
                    venv=git_pip_venv_dir(projects_yaml))

    src_etc = os.path.join(git_src_dir(projects_yaml, 'nova'), 'etc/nova')
    configs = [
        {'src': src_etc,
         'dest': '/etc/nova'},
    ]

    for c in configs:
        if os.path.exists(c['dest']):
            shutil.rmtree(c['dest'])
        shutil.copytree(c['src'], c['dest'])

    # NOTE(coreycb): Need to find better solution than bin symlinks.
    symlinks = [
        {'src': os.path.join(git_pip_venv_dir(projects_yaml),
                             'bin/nova-manage'),
         'link': '/usr/local/bin/nova-manage'},
        {'src': os.path.join(git_pip_venv_dir(projects_yaml),
                             'bin/nova-rootwrap'),
         'link': '/usr/local/bin/nova-rootwrap'},
        {'src': os.path.join(git_pip_venv_dir(projects_yaml),
                             'bin/neutron-db-manage'),
         'link': '/usr/local/bin/neutron-db-manage'},
    ]

    for s in symlinks:
        if os.path.lexists(s['link']):
            os.remove(s['link'])
        os.symlink(s['src'], s['link'])

    render('git/nova_sudoers', '/etc/sudoers.d/nova_sudoers', {}, perms=0o440)

    nova_cc = 'nova-cloud-controller'
    nova_user = 'nova'
    start_dir = '/var/lib/nova'
    bin_dir = os.path.join(git_pip_venv_dir(projects_yaml), 'bin')
    nova_conf = '/etc/nova/nova.conf'
    nova_ec2_api_context = {
        'service_description': 'Nova EC2 API server',
        'service_name': nova_cc,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-api-ec2',
        'executable_name': os.path.join(bin_dir, 'nova-api-ec2'),
        'config_files': [nova_conf],
    }
    nova_api_os_compute_context = {
        'service_description': 'Nova OpenStack Compute API server',
        'service_name': nova_cc,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-api-os-compute',
        'executable_name': os.path.join(bin_dir, 'nova-api-os-compute'),
        'config_files': [nova_conf],
    }
    nova_cells_context = {
        'service_description': 'Nova cells',
        'service_name': nova_cc,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-cells',
        'executable_name': os.path.join(bin_dir, 'nova-cells'),
        'config_files': [nova_conf],
    }
    nova_cert_context = {
        'service_description': 'Nova cert',
        'service_name': nova_cc,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-cert',
        'executable_name': os.path.join(bin_dir, 'nova-cert'),
        'config_files': [nova_conf],
    }
    nova_conductor_context = {
        'service_description': 'Nova conductor',
        'service_name': nova_cc,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-conductor',
        'executable_name': os.path.join(bin_dir, 'nova-conductor'),
        'config_files': [nova_conf],
    }
    nova_consoleauth_context = {
        'service_description': 'Nova console auth',
        'service_name': nova_cc,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-consoleauth',
        'executable_name': os.path.join(bin_dir, 'nova-consoleauth'),
        'config_files': [nova_conf],
    }
    nova_console_context = {
        'service_description': 'Nova console',
        'service_name': nova_cc,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-console',
        'executable_name': os.path.join(bin_dir, 'nova-console'),
        'config_files': [nova_conf],
    }
    nova_novncproxy_context = {
        'service_description': 'Nova NoVNC proxy',
        'service_name': nova_cc,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-novncproxy',
        'executable_name': os.path.join(bin_dir, 'nova-novncproxy'),
        'config_files': [nova_conf],
    }
    nova_objectstore_context = {
        'service_description': 'Nova object store',
        'service_name': nova_cc,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-objectstore',
        'executable_name': os.path.join(bin_dir, 'nova-objectstore'),
        'config_files': [nova_conf],
    }
    nova_scheduler_context = {
        'service_description': 'Nova scheduler',
        'service_name': nova_cc,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-scheduler',
        'executable_name': os.path.join(bin_dir, 'nova-scheduler'),
        'config_files': [nova_conf],
    }
    nova_serialproxy_context = {
        'service_description': 'Nova serial proxy',
        'service_name': nova_cc,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-serialproxy',
        'executable_name': os.path.join(bin_dir, 'nova-serialproxy'),
        'config_files': [nova_conf],
    }
    nova_spiceproxy_context = {
        'service_description': 'Nova spice proxy',
        'service_name': nova_cc,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-spicehtml5proxy',
        'executable_name': os.path.join(bin_dir, 'nova-spicehtml5proxy'),
        'config_files': [nova_conf],
    }
    nova_xvpvncproxy_context = {
        'service_description': 'Nova XVPVNC proxy',
        'service_name': nova_cc,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-xvpvncproxy',
        'executable_name': os.path.join(bin_dir, 'nova-xvpvncproxy'),
        'config_files': [nova_conf],
    }

    # NOTE(coreycb): Needs systemd support
    templates_dir = 'hooks/charmhelpers/contrib/openstack/templates'
    templates_dir = os.path.join(charm_dir(), templates_dir)
    os_rel = os_release('nova-common')
    render('git.upstart', '/etc/init/nova-api-ec2.conf',
           nova_ec2_api_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart', '/etc/init/nova-api-os-compute.conf',
           nova_api_os_compute_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart', '/etc/init/nova-cells.conf',
           nova_cells_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart', '/etc/init/nova-cert.conf',
           nova_cert_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart', '/etc/init/nova-conductor.conf',
           nova_conductor_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart', '/etc/init/nova-consoleauth.conf',
           nova_consoleauth_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart', '/etc/init/nova-console.conf',
           nova_console_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart', '/etc/init/nova-novncproxy.conf',
           nova_novncproxy_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart', '/etc/init/nova-objectstore.conf',
           nova_objectstore_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart', '/etc/init/nova-scheduler.conf',
           nova_scheduler_context, perms=0o644,
           templates_dir=templates_dir)
    if os_rel >= 'juno':
        render('git.upstart', '/etc/init/nova-serialproxy.conf',
               nova_serialproxy_context, perms=0o644,
               templates_dir=templates_dir)
    render('git.upstart', '/etc/init/nova-spiceproxy.conf',
           nova_spiceproxy_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart', '/etc/init/nova-xvpvncproxy.conf',
           nova_xvpvncproxy_context, perms=0o644,
           templates_dir=templates_dir)

    apt_update()
    apt_install(LATE_GIT_PACKAGES, fatal=True)


def check_optional_relations(configs):
    required_interfaces = {}
    if relation_ids('ha'):
        required_interfaces['ha'] = ['cluster']
        try:
            get_hacluster_config()
        except:
            return ('blocked',
                    'hacluster missing configuration: '
                    'vip, vip_iface, vip_cidr')
    if relation_ids('quantum-network-service'):
        required_interfaces['quantum'] = ['quantum-network-service']
    if relation_ids('cinder-volume-service'):
        required_interfaces['cinder'] = ['cinder-volume-service']
    if relation_ids('neutron-api'):
        required_interfaces['neutron-api'] = ['neutron-api']
    if required_interfaces:
        set_os_workload_status(configs, required_interfaces)
        return status_get()
    else:
        return 'unknown', 'No optional relations'
