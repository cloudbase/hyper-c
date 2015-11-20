from collections import OrderedDict
from copy import deepcopy
from functools import partial
import os
import shutil
import subprocess
import glob
from base64 import b64encode
from charmhelpers.contrib.openstack import context, templating
from charmhelpers.contrib.openstack.neutron import (
    neutron_plugin_attribute,
)

from charmhelpers.contrib.openstack.utils import (
    os_release,
    get_os_codename_install_source,
    git_install_requested,
    git_clone_and_install,
    git_src_dir,
    git_pip_venv_dir,
    git_yaml_value,
    configure_installation_source,
    set_os_workload_status,
)

from charmhelpers.contrib.python.packages import (
    pip_install,
)

from charmhelpers.core.hookenv import (
    config,
    log,
    relation_ids,
    status_get,
)

from charmhelpers.fetch import (
    apt_update,
    apt_install,
    apt_upgrade,
    add_source
)

from charmhelpers.core.host import (
    lsb_release,
    adduser,
    add_group,
    add_user_to_group,
    mkdir,
    service_stop,
    service_start,
    service_restart,
    write_file,
)

from charmhelpers.contrib.hahelpers.cluster import (
    get_hacluster_config,
)


from charmhelpers.core.templating import render
from charmhelpers.contrib.hahelpers.cluster import is_elected_leader

import neutron_api_context

TEMPLATES = 'templates/'

CLUSTER_RES = 'grp_neutron_vips'

# removed from original: charm-helper-sh
BASE_PACKAGES = [
    'apache2',
    'haproxy',
    'python-keystoneclient',
    'python-mysqldb',
    'python-psycopg2',
    'python-six',
    'uuid',
    'git',
]

KILO_PACKAGES = [
    'python-neutron-lbaas',
    'python-neutron-fwaas',
    'python-neutron-vpnaas',
]

BASE_GIT_PACKAGES = [
    'libffi-dev',
    'libmysqlclient-dev',
    'libssl-dev',
    'libxml2-dev',
    'libxslt1-dev',
    'libyaml-dev',
    'python-dev',
    'python-neutronclient',  # required for get_neutron_client() import
    'python-pip',
    'python-setuptools',
    'zlib1g-dev',
]

# ubuntu packages that should not be installed when deploying from git
GIT_PACKAGE_BLACKLIST = [
    'neutron-server',
    'neutron-plugin-ml2',
    'python-keystoneclient',
    'python-six',
]

GIT_PACKAGE_BLACKLIST_KILO = [
    'python-neutron-lbaas',
    'python-neutron-fwaas',
    'python-neutron-vpnaas',
]

BASE_SERVICES = [
    'neutron-server'
]
API_PORTS = {
    'neutron-server': 9696,
}

NEUTRON_CONF_DIR = "/etc/neutron"

NEUTRON_CONF = '%s/neutron.conf' % NEUTRON_CONF_DIR
NEUTRON_LBAAS_CONF = '%s/neutron_lbaas.conf' % NEUTRON_CONF_DIR
NEUTRON_VPNAAS_CONF = '%s/neutron_vpnaas.conf' % NEUTRON_CONF_DIR
HAPROXY_CONF = '/etc/haproxy/haproxy.cfg'
APACHE_CONF = '/etc/apache2/sites-available/openstack_https_frontend'
APACHE_24_CONF = '/etc/apache2/sites-available/openstack_https_frontend.conf'
NEUTRON_DEFAULT = '/etc/default/neutron-server'
CA_CERT_PATH = '/usr/local/share/ca-certificates/keystone_juju_ca_cert.crt'

BASE_RESOURCE_MAP = OrderedDict([
    (NEUTRON_CONF, {
        'services': ['neutron-server'],
        'contexts': [context.AMQPContext(ssl_dir=NEUTRON_CONF_DIR),
                     context.SharedDBContext(
                         user=config('database-user'),
                         database=config('database'),
                         ssl_dir=NEUTRON_CONF_DIR),
                     context.PostgresqlDBContext(database=config('database')),
                     neutron_api_context.IdentityServiceContext(
                         service='neutron',
                         service_user='neutron'),
                     neutron_api_context.NeutronCCContext(),
                     context.SyslogContext(),
                     context.ZeroMQContext(),
                     context.NotificationDriverContext(),
                     context.BindHostContext(),
                     context.WorkerConfigContext()],
    }),
    (NEUTRON_DEFAULT, {
        'services': ['neutron-server'],
        'contexts': [neutron_api_context.NeutronCCContext()],
    }),
    (APACHE_CONF, {
        'contexts': [neutron_api_context.ApacheSSLContext()],
        'services': ['apache2'],
    }),
    (APACHE_24_CONF, {
        'contexts': [neutron_api_context.ApacheSSLContext()],
        'services': ['apache2'],
    }),
    (HAPROXY_CONF, {
        'contexts': [context.HAProxyContext(singlenode_mode=True),
                     neutron_api_context.HAProxyContext()],
        'services': ['haproxy'],
    }),
])

# The interface is said to be satisfied if anyone of the interfaces in the
# list has a complete context.
REQUIRED_INTERFACES = {
    'database': ['shared-db', 'pgsql-db'],
    'messaging': ['amqp', 'zeromq-configuration'],
    'identity': ['identity-service'],
}

LIBERTY_RESOURCE_MAP = OrderedDict([
    (NEUTRON_LBAAS_CONF, {
        'services': ['neutron-server'],
        'contexts': [],
    }),
    (NEUTRON_VPNAAS_CONF, {
        'services': ['neutron-server'],
        'contexts': [],
    }),
])


def api_port(service):
    return API_PORTS[service]


def additional_install_locations(plugin, source):
    '''
    Add any required additional package locations for the charm, based
    on the Neutron plugin being used. This will also force an immediate
    package upgrade.
    '''
    if plugin == 'Calico':
        if config('calico-origin'):
            calico_source = config('calico-origin')
        else:
            release = get_os_codename_install_source(source)
            calico_source = 'ppa:project-calico/%s' % release

        add_source(calico_source)

        apt_update()
        apt_upgrade()


def force_etcd_restart():
    '''
    If etcd has been reconfigured we need to force it to fully restart.
    This is necessary because etcd has some config flags that it ignores
    after the first time it starts, so we need to make it forget them.
    '''
    service_stop('etcd')
    for directory in glob.glob('/var/lib/etcd/*'):
        shutil.rmtree(directory)
    service_start('etcd')


def manage_plugin():
    return config('manage-neutron-plugin-legacy-mode')


def determine_packages(source=None):
    # currently all packages match service names
    packages = [] + BASE_PACKAGES

    for v in resource_map().values():
        packages.extend(v['services'])
        if manage_plugin():
            pkgs = neutron_plugin_attribute(config('neutron-plugin'),
                                            'server_packages',
                                            'neutron')
            packages.extend(pkgs)

    if get_os_codename_install_source(source) >= 'kilo':
        packages.extend(KILO_PACKAGES)

    if git_install_requested():
        packages.extend(BASE_GIT_PACKAGES)
        # don't include packages that will be installed from git
        packages = list(set(packages))
        for p in GIT_PACKAGE_BLACKLIST:
            packages.remove(p)
        if get_os_codename_install_source(source) >= 'kilo':
            for p in GIT_PACKAGE_BLACKLIST_KILO:
                packages.remove(p)

    return list(set(packages))


def determine_ports():
    '''Assemble a list of API ports for services we are managing'''
    ports = []
    for services in restart_map().values():
        for service in services:
            try:
                ports.append(API_PORTS[service])
            except KeyError:
                pass
    return list(set(ports))


def resource_map(release=None):
    '''
    Dynamically generate a map of resources that will be managed for a single
    hook execution.
    '''
    release = release or os_release('neutron-common')

    resource_map = deepcopy(BASE_RESOURCE_MAP)
    if release >= 'liberty':
        resource_map.update(LIBERTY_RESOURCE_MAP)

    if os.path.exists('/etc/apache2/conf-available'):
        resource_map.pop(APACHE_CONF)
    else:
        resource_map.pop(APACHE_24_CONF)

    if manage_plugin():
        # add neutron plugin requirements. nova-c-c only needs the
        # neutron-server associated with configs, not the plugin agent.
        plugin = config('neutron-plugin')
        conf = neutron_plugin_attribute(plugin, 'config', 'neutron')
        ctxts = (neutron_plugin_attribute(plugin, 'contexts', 'neutron')
                 or [])
        services = neutron_plugin_attribute(plugin, 'server_services',
                                            'neutron')
        resource_map[conf] = {}
        resource_map[conf]['services'] = services
        resource_map[conf]['contexts'] = ctxts
        resource_map[conf]['contexts'].append(
            neutron_api_context.NeutronCCContext())

        # update for postgres
        resource_map[conf]['contexts'].append(
            context.PostgresqlDBContext(database=config('database')))

    else:
        resource_map[NEUTRON_CONF]['contexts'].append(
            neutron_api_context.NeutronApiSDNContext()
        )
        resource_map[NEUTRON_DEFAULT]['contexts'] = \
            [neutron_api_context.NeutronApiSDNConfigFileContext()]
    return resource_map


def register_configs(release=None):
    release = release or os_release('neutron-common')
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


def keystone_ca_cert_b64():
    '''Returns the local Keystone-provided CA cert if it exists, or None.'''
    if not os.path.isfile(CA_CERT_PATH):
        return None
    with open(CA_CERT_PATH) as _in:
        return b64encode(_in.read())


def do_openstack_upgrade(configs):
    """
    Perform an upgrade.  Takes care of upgrading packages, rewriting
    configs, database migrations and potentially any other post-upgrade
    actions.

    :param configs: The charms main OSConfigRenderer object.
    """
    cur_os_rel = os_release('neutron-common')
    new_src = config('openstack-origin')
    new_os_rel = get_os_codename_install_source(new_src)

    log('Performing OpenStack upgrade to %s.' % (new_os_rel))

    configure_installation_source(new_src)
    dpkg_opts = [
        '--option', 'Dpkg::Options::=--force-confnew',
        '--option', 'Dpkg::Options::=--force-confdef',
    ]
    apt_update(fatal=True)
    apt_upgrade(options=dpkg_opts, fatal=True, dist=True)
    pkgs = determine_packages(new_os_rel)
    # Sort packages just to make unit tests easier
    pkgs.sort()
    apt_install(packages=pkgs,
                options=dpkg_opts,
                fatal=True)

    # set CONFIGS to load templates from new release
    configs.set_release(openstack_release=new_os_rel)
    # Before kilo it's nova-cloud-controllers job
    if is_elected_leader(CLUSTER_RES) and new_os_rel >= 'kilo':
        stamp_neutron_database(cur_os_rel)
        migrate_neutron_database()


def stamp_neutron_database(release):
    '''Stamp the database with the current release before upgrade.'''
    log('Stamping the neutron database with release %s.' % release)
    plugin = config('neutron-plugin')
    cmd = ['neutron-db-manage',
           '--config-file', NEUTRON_CONF,
           '--config-file', neutron_plugin_attribute(plugin,
                                                     'config',
                                                     'neutron'),
           'stamp',
           release]
    subprocess.check_output(cmd)


def migrate_neutron_database():
    '''Initializes a new database or upgrades an existing database.'''
    log('Migrating the neutron database.')
    plugin = config('neutron-plugin')
    cmd = ['neutron-db-manage',
           '--config-file', NEUTRON_CONF,
           '--config-file', neutron_plugin_attribute(plugin,
                                                     'config',
                                                     'neutron'),
           'upgrade',
           'head']
    subprocess.check_output(cmd)


def get_topics():
    return ['q-l3-plugin',
            'q-firewall-plugin',
            'n-lbaas-plugin',
            'ipsec_driver',
            'q-metering-plugin',
            'q-plugin',
            'neutron']


def setup_ipv6():
    ubuntu_rel = lsb_release()['DISTRIB_CODENAME'].lower()
    if ubuntu_rel < "trusty":
        raise Exception("IPv6 is not supported in the charms for Ubuntu "
                        "versions less than Trusty 14.04")

    # Need haproxy >= 1.5.3 for ipv6 so for Trusty if we are <= Kilo we need to
    # use trusty-backports otherwise we can use the UCA.
    if ubuntu_rel == 'trusty' and os_release('neutron-server') < 'liberty':
        add_source('deb http://archive.ubuntu.com/ubuntu trusty-backports '
                   'main')
        apt_update()
        apt_install('haproxy/trusty-backports', fatal=True)


def get_neutron_client():
    ''' Return a neutron client if possible '''
    env = neutron_api_context.IdentityServiceContext()()
    if not env:
        log('Unable to check resources at this time')
        return

    auth_url = '%(auth_protocol)s://%(auth_host)s:%(auth_port)s/v2.0' % env
    # Late import to avoid install hook failures when pkg hasnt been installed
    from neutronclient.v2_0 import client
    neutron_client = client.Client(username=env['admin_user'],
                                   password=env['admin_password'],
                                   tenant_name=env['admin_tenant_name'],
                                   auth_url=auth_url,
                                   region_name=env['region'])
    return neutron_client


def router_feature_present(feature):
    ''' Check For dvr enabled routers '''
    neutron_client = get_neutron_client()
    for router in neutron_client.list_routers()['routers']:
        if router.get(feature, False):
            return True
    return False

l3ha_router_present = partial(router_feature_present, feature='ha')

dvr_router_present = partial(router_feature_present, feature='distributed')


def neutron_ready():
    ''' Check if neutron is ready by running arbitrary query'''
    neutron_client = get_neutron_client()
    if not neutron_client:
        log('No neutron client, neutron not ready')
        return False
    try:
        neutron_client.list_routers()
        log('neutron client ready')
        return True
    except:
        log('neutron query failed, neutron not ready ')
        return False


def git_install(projects_yaml):
    """Perform setup, and install git repos specified in yaml parameter."""
    if git_install_requested():
        git_pre_install()
        git_clone_and_install(projects_yaml, core_project='neutron')
        git_post_install(projects_yaml)


def git_pre_install():
    """Perform pre-install setup."""
    dirs = [
        '/var/lib/neutron',
        '/var/lib/neutron/lock',
        '/var/log/neutron',
    ]

    logs = [
        '/var/log/neutron/server.log',
    ]

    adduser('neutron', shell='/bin/bash', system_user=True)
    add_group('neutron', system_group=True)
    add_user_to_group('neutron', 'neutron')

    for d in dirs:
        mkdir(d, owner='neutron', group='neutron', perms=0755, force=False)

    for l in logs:
        write_file(l, '', owner='neutron', group='neutron', perms=0600)


def git_post_install(projects_yaml):
    """Perform post-install setup."""
    http_proxy = git_yaml_value(projects_yaml, 'http_proxy')
    if http_proxy:
        pip_install('mysql-python', proxy=http_proxy,
                    venv=git_pip_venv_dir(projects_yaml))
    else:
        pip_install('mysql-python',
                    venv=git_pip_venv_dir(projects_yaml))

    src_etc = os.path.join(git_src_dir(projects_yaml, 'neutron'), 'etc')
    configs = [
        {'src': src_etc,
         'dest': '/etc/neutron'},
        {'src': os.path.join(src_etc, 'neutron/plugins'),
         'dest': '/etc/neutron/plugins'},
        {'src': os.path.join(src_etc, 'neutron/rootwrap.d'),
         'dest': '/etc/neutron/rootwrap.d'},
    ]

    for c in configs:
        if os.path.exists(c['dest']):
            shutil.rmtree(c['dest'])
        shutil.copytree(c['src'], c['dest'])

    # NOTE(coreycb): Need to find better solution than bin symlinks.
    symlinks = [
        {'src': os.path.join(git_pip_venv_dir(projects_yaml),
                             'bin/neutron-rootwrap'),
         'link': '/usr/local/bin/neutron-rootwrap'},
        {'src': os.path.join(git_pip_venv_dir(projects_yaml),
                             'bin/neutron-db-manage'),
         'link': '/usr/local/bin/neutron-db-manage'},
    ]

    for s in symlinks:
        if os.path.lexists(s['link']):
            os.remove(s['link'])
        os.symlink(s['src'], s['link'])

    render('git/neutron_sudoers', '/etc/sudoers.d/neutron_sudoers', {},
           perms=0o440)

    bin_dir = os.path.join(git_pip_venv_dir(projects_yaml), 'bin')
    neutron_api_context = {
        'service_description': 'Neutron API server',
        'charm_name': 'neutron-api',
        'process_name': 'neutron-server',
        'executable_name': os.path.join(bin_dir, 'neutron-server'),
    }

    # NOTE(coreycb): Needs systemd support
    render('git/upstart/neutron-server.upstart',
           '/etc/init/neutron-server.conf',
           neutron_api_context, perms=0o644)

    service_restart('neutron-server')


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

    if required_interfaces:
        set_os_workload_status(configs, required_interfaces)
        return status_get()
    else:
        return 'unknown', 'No optional relations'
