import os
import shutil
import pwd
import subprocess

from base64 import b64decode
from copy import deepcopy
from subprocess import (
    check_call,
    check_output,
    CalledProcessError
)

from charmhelpers.fetch import (
    apt_update,
    apt_upgrade,
    apt_install,
)

from charmhelpers.core.host import (
    adduser,
    add_group,
    add_user_to_group,
    mkdir,
    service_restart,
    lsb_release,
    write_file,
)

from charmhelpers.core.hookenv import (
    charm_dir,
    config,
    log,
    related_units,
    relation_ids,
    relation_get,
    DEBUG,
    INFO,
    status_get,
)

from charmhelpers.core.templating import render
from charmhelpers.core.decorators import retry_on_exception
from charmhelpers.contrib.openstack.neutron import neutron_plugin_attribute
from charmhelpers.contrib.openstack import templating, context
from charmhelpers.contrib.openstack.alternatives import install_alternative

from charmhelpers.contrib.openstack.utils import (
    configure_installation_source,
    get_os_codename_install_source,
    git_install_requested,
    git_clone_and_install,
    git_src_dir,
    git_pip_venv_dir,
    git_yaml_value,
    os_release,
    set_os_workload_status,
)

from charmhelpers.contrib.python.packages import (
    pip_install,
)

from charmhelpers.core.hugepage import hugepage_support
from charmhelpers.core.host import (
    fstab_mount,
    rsync,
)

from nova_compute_context import (
    CloudComputeContext,
    MetadataServiceContext,
    NovaComputeLibvirtContext,
    NovaComputeLibvirtOverrideContext,
    NovaComputeCephContext,
    NeutronComputeContext,
    InstanceConsoleContext,
    CEPH_CONF,
    ceph_config_file,
    HostIPContext,
)

CA_CERT_PATH = '/usr/local/share/ca-certificates/keystone_juju_ca_cert.crt'

TEMPLATES = 'templates/'

BASE_PACKAGES = [
    'nova-compute',
    'genisoimage',  # was missing as a package dependency until raring.
    'librbd1',  # bug 1440953
    'python-six',
    'python-psutil',
]

BASE_GIT_PACKAGES = [
    'libffi-dev',
    'libssl-dev',
    'libvirt-bin',
    'libxml2-dev',
    'libxslt1-dev',
    'libvirt-dev',
    'libyaml-dev',
    'python-dev',
    'python-pip',
    'python-setuptools',
    'zlib1g-dev',
]

LATE_GIT_PACKAGES = [
    'bridge-utils',
    'dnsmasq-base',
    'dnsmasq-utils',
    'ebtables',
    'genisoimage',
    'iptables',
    'iputils-arping',
    'kpartx',
    'kvm',
    'netcat',
    'open-iscsi',
    'parted',
    'python-libvirt',
    'qemu',
    'qemu-system',
    'qemu-utils',
    'vlan',
    'xen-system-amd64',
]

# ubuntu packages that should not be installed when deploying from git
GIT_PACKAGE_BLACKLIST = [
    'neutron-plugin-openvswitch',
    'neutron-plugin-openvswitch-agent',
    'neutron-server',
    'nova-api',
    'nova-api-metadata',
    'nova-compute',
    'nova-compute-kvm',
    'nova-compute-lxc',
    'nova-compute-lxd',
    'nova-compute-qemu',
    'nova-compute-uml',
    'nova-compute-xen',
    'nova-network',
    'python-six',
    'quantum-plugin-openvswitch',
    'quantum-plugin-openvswitch-agent',
    'quantum-server',
]

DEFAULT_INSTANCE_PATH = '/var/lib/nova/instances'
NOVA_CONF_DIR = "/etc/nova"
QEMU_CONF = '/etc/libvirt/qemu.conf'
LIBVIRTD_CONF = '/etc/libvirt/libvirtd.conf'
LIBVIRT_BIN = '/etc/default/libvirt-bin'
LIBVIRT_BIN_OVERRIDES = '/etc/init/libvirt-bin.override'
NOVA_CONF = '%s/nova.conf' % NOVA_CONF_DIR

BASE_RESOURCE_MAP = {
    NOVA_CONF: {
        'services': ['nova-compute'],
        'contexts': [context.AMQPContext(ssl_dir=NOVA_CONF_DIR),
                     context.SharedDBContext(
                         relation_prefix='nova', ssl_dir=NOVA_CONF_DIR),
                     context.PostgresqlDBContext(),
                     context.ImageServiceContext(),
                     context.OSConfigFlagContext(),
                     CloudComputeContext(),
                     NovaComputeLibvirtContext(),
                     NovaComputeCephContext(),
                     context.SyslogContext(),
                     context.SubordinateConfigContext(
                         interface=['neutron-plugin', 'nova-ceilometer'],
                         service=['nova-compute', 'nova'],
                         config_file=NOVA_CONF),
                     InstanceConsoleContext(),
                     context.ZeroMQContext(),
                     context.NotificationDriverContext(),
                     MetadataServiceContext(),
                     HostIPContext(),
                     context.LogLevelContext()],
    },
}

LIBVIRT_RESOURCE_MAP = {
    QEMU_CONF: {
        'services': ['libvirt-bin'],
        'contexts': [NovaComputeLibvirtContext()],
    },
    LIBVIRTD_CONF: {
        'services': ['libvirt-bin'],
        'contexts': [NovaComputeLibvirtContext()],
    },
    LIBVIRT_BIN: {
        'services': ['libvirt-bin'],
        'contexts': [NovaComputeLibvirtContext()],
    },
    LIBVIRT_BIN_OVERRIDES: {
        'services': ['libvirt-bin'],
        'contexts': [NovaComputeLibvirtOverrideContext()],
    },
}
LIBVIRT_RESOURCE_MAP.update(BASE_RESOURCE_MAP)

CEPH_SECRET = '/etc/ceph/secret.xml'

CEPH_RESOURCES = {
    CEPH_SECRET: {
        'contexts': [NovaComputeCephContext()],
        'services': [],
    }
}

QUANTUM_CONF_DIR = "/etc/quantum"
QUANTUM_CONF = '%s/quantum.conf' % QUANTUM_CONF_DIR

QUANTUM_RESOURCES = {
    QUANTUM_CONF: {
        'services': [],
        'contexts': [NeutronComputeContext(),
                     context.AMQPContext(ssl_dir=QUANTUM_CONF_DIR),
                     context.SyslogContext()],
    },
}

NEUTRON_CONF_DIR = "/etc/neutron"
NEUTRON_CONF = '%s/neutron.conf' % NEUTRON_CONF_DIR

NEUTRON_RESOURCES = {
    NEUTRON_CONF: {
        'services': [],
        'contexts': [NeutronComputeContext(),
                     context.AMQPContext(ssl_dir=NEUTRON_CONF_DIR),
                     context.SyslogContext()],
    },
}


# Maps virt-type config to a compute package(s).
VIRT_TYPES = {
    'kvm': ['nova-compute-kvm'],
    'qemu': ['nova-compute-qemu'],
    'xen': ['nova-compute-xen'],
    'uml': ['nova-compute-uml'],
    'lxc': ['nova-compute-lxc'],
    'lxd': ['nova-compute-lxd'],
}

# Maps virt-type config to a libvirt URI.
LIBVIRT_URIS = {
    'kvm': 'qemu:///system',
    'qemu': 'qemu:///system',
    'xen': 'xen:///',
    'uml': 'uml:///system',
    'lxc': 'lxc:///',
}

# The interface is said to be satisfied if anyone of the interfaces in the
# list has a complete context.
REQUIRED_INTERFACES = {
    'messaging': ['amqp', 'zeromq-configuration'],
    'image': ['image-service'],
}


def resource_map():
    '''
    Dynamically generate a map of resources that will be managed for a single
    hook execution.
    '''
    # TODO: Cache this on first call?
    if config('virt-type').lower() == 'lxd':
        resource_map = deepcopy(BASE_RESOURCE_MAP)
    else:
        resource_map = deepcopy(LIBVIRT_RESOURCE_MAP)
    net_manager = network_manager()
    plugin = neutron_plugin()

    # Network manager gets set late by the cloud-compute interface.
    # FlatDHCPManager only requires some extra packages.
    if (net_manager in ['flatmanager', 'flatdhcpmanager'] and
            config('multi-host').lower() == 'yes'):
        resource_map[NOVA_CONF]['services'].extend(
            ['nova-api', 'nova-network']
        )

    # Neutron/quantum requires additional contexts, as well as new resources
    # depending on the plugin used.
    # NOTE(james-page): only required for ovs plugin right now
    if net_manager in ['neutron', 'quantum']:
        # This stanza supports the legacy case of ovs supported within
        # compute charm code (now moved to neutron-openvswitch subordinate)
        if manage_ovs():
            if net_manager == 'quantum':
                nm_rsc = QUANTUM_RESOURCES
            if net_manager == 'neutron':
                nm_rsc = NEUTRON_RESOURCES
            resource_map.update(nm_rsc)

            conf = neutron_plugin_attribute(plugin, 'config', net_manager)
            svcs = neutron_plugin_attribute(plugin, 'services', net_manager)
            ctxts = (neutron_plugin_attribute(plugin, 'contexts', net_manager)
                     or [])
            resource_map[conf] = {}
            resource_map[conf]['services'] = svcs
            resource_map[conf]['contexts'] = ctxts
            resource_map[conf]['contexts'].append(NeutronComputeContext())

            # associate the plugin agent with main network manager config(s)
            [resource_map[nmc]['services'].extend(svcs) for nmc in nm_rsc]

        resource_map[NOVA_CONF]['contexts'].append(NeutronComputeContext())

    if relation_ids('ceph'):
        CEPH_RESOURCES[ceph_config_file()] = {
            'contexts': [NovaComputeCephContext()],
            'services': ['nova-compute']
        }
        resource_map.update(CEPH_RESOURCES)

    if enable_nova_metadata():
        resource_map[NOVA_CONF]['services'].append('nova-api-metadata')
    return resource_map


def restart_map():
    '''
    Constructs a restart map based on charm config settings and relation
    state.
    '''
    return {k: v['services'] for k, v in resource_map().iteritems()}


def services():
    ''' Returns a list of services associate with this charm '''
    _services = []
    for v in restart_map().values():
        _services = _services + v
    return list(set(_services))


def register_configs():
    '''
    Returns an OSTemplateRenderer object with all required configs registered.
    '''
    release = os_release('nova-common')
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)

    if relation_ids('ceph'):
        # Add charm ceph configuration to resources and
        # ensure directory actually exists
        mkdir(os.path.dirname(ceph_config_file()))
        mkdir(os.path.dirname(CEPH_CONF))
        # Install ceph config as an alternative for co-location with
        # ceph and ceph-osd charms - nova-compute ceph.conf will be
        # lower priority that both of these but thats OK
        if not os.path.exists(ceph_config_file()):
            # touch file for pre-templated generation
            open(ceph_config_file(), 'w').close()
        install_alternative(os.path.basename(CEPH_CONF),
                            CEPH_CONF, ceph_config_file())

    for cfg, d in resource_map().iteritems():
        configs.register(cfg, d['contexts'])
    return configs


def determine_packages():
    packages = [] + BASE_PACKAGES

    net_manager = network_manager()
    if (net_manager in ['flatmanager', 'flatdhcpmanager'] and
            config('multi-host').lower() == 'yes'):
        packages.extend(['nova-api', 'nova-network'])
    elif (net_manager in ['quantum', 'neutron']
            and neutron_plugin_legacy_mode()):
        plugin = neutron_plugin()
        pkg_lists = neutron_plugin_attribute(plugin, 'packages', net_manager)
        for pkg_list in pkg_lists:
            packages.extend(pkg_list)

    if relation_ids('ceph'):
        packages.append('ceph-common')

    virt_type = config('virt-type')
    try:
        packages.extend(VIRT_TYPES[virt_type])
    except KeyError:
        log('Unsupported virt-type configured: %s' % virt_type)
        raise
    if enable_nova_metadata():
        packages.append('nova-api-metadata')

    if git_install_requested():
        packages = list(set(packages))
        packages.extend(BASE_GIT_PACKAGES)
        # don't include packages that will be installed from git
        for p in GIT_PACKAGE_BLACKLIST:
            if p in packages:
                packages.remove(p)

    return packages


def migration_enabled():
    # XXX: confirm juju-core bool behavior is the same.
    return config('enable-live-migration')


def quantum_enabled():
    manager = config('network-manager')
    if not manager:
        return False
    return manager.lower() == 'quantum'


def _network_config():
    '''
    Obtain all relevant network configuration settings from nova-c-c via
    cloud-compute interface.
    '''
    settings = ['network_manager', 'neutron_plugin', 'quantum_plugin']
    net_config = {}
    for rid in relation_ids('cloud-compute'):
        for unit in related_units(rid):
            for setting in settings:
                value = relation_get(setting, rid=rid, unit=unit)
                if value:
                    net_config[setting] = value
    return net_config


def neutron_plugin():
    return (_network_config().get('neutron_plugin') or
            _network_config().get('quantum_plugin'))


def network_manager():
    '''
    Obtain the network manager advertised by nova-c-c, renaming to Quantum
    if required
    '''
    manager = _network_config().get('network_manager')
    if manager:
        manager = manager.lower()
        if manager not in ['quantum', 'neutron']:
            return manager
        if os_release('nova-common') in ['folsom', 'grizzly']:
            return 'quantum'
        else:
            return 'neutron'
    return manager


def public_ssh_key(user='root'):
    home = pwd.getpwnam(user).pw_dir
    try:
        with open(os.path.join(home, '.ssh', 'id_rsa.pub')) as key:
            return key.read().strip()
    except:
        return None


def initialize_ssh_keys(user='root'):
    home_dir = pwd.getpwnam(user).pw_dir
    ssh_dir = os.path.join(home_dir, '.ssh')
    if not os.path.isdir(ssh_dir):
        os.mkdir(ssh_dir)

    priv_key = os.path.join(ssh_dir, 'id_rsa')
    if not os.path.isfile(priv_key):
        log('Generating new ssh key for user %s.' % user)
        cmd = ['ssh-keygen', '-q', '-N', '', '-t', 'rsa', '-b', '2048',
               '-f', priv_key]
        check_output(cmd)

    pub_key = '%s.pub' % priv_key
    if not os.path.isfile(pub_key):
        log('Generating missing ssh public key @ %s.' % pub_key)
        cmd = ['ssh-keygen', '-y', '-f', priv_key]
        p = check_output(cmd).strip()
        with open(pub_key, 'wb') as out:
            out.write(p)
    check_output(['chown', '-R', user, ssh_dir])


def import_authorized_keys(user='root', prefix=None):
    """Import SSH authorized_keys + known_hosts from a cloud-compute relation.
    Store known_hosts in user's $HOME/.ssh and authorized_keys in a path
    specified using authorized-keys-path config option.
    """
    known_hosts = []
    authorized_keys = []
    if prefix:
        known_hosts_index = relation_get(
            '{}_known_hosts_max_index'.format(prefix))
        if known_hosts_index:
            for index in range(0, int(known_hosts_index)):
                known_hosts.append(relation_get(
                                   '{}_known_hosts_{}'.format(prefix, index)))
        authorized_keys_index = relation_get(
            '{}_authorized_keys_max_index'.format(prefix))
        if authorized_keys_index:
            for index in range(0, int(authorized_keys_index)):
                authorized_keys.append(relation_get(
                    '{}_authorized_keys_{}'.format(prefix, index)))
    else:
        # XXX: Should this be managed via templates + contexts?
        known_hosts_index = relation_get('known_hosts_max_index')
        if known_hosts_index:
            for index in range(0, int(known_hosts_index)):
                known_hosts.append(relation_get(
                    'known_hosts_{}'.format(index)))
        authorized_keys_index = relation_get('authorized_keys_max_index')
        if authorized_keys_index:
            for index in range(0, int(authorized_keys_index)):
                authorized_keys.append(relation_get(
                    'authorized_keys_{}'.format(index)))

    # XXX: Should partial return of known_hosts or authorized_keys
    #      be allowed ?
    if not len(known_hosts) or not len(authorized_keys):
        return
    homedir = pwd.getpwnam(user).pw_dir
    dest_auth_keys = config('authorized-keys-path').format(
        homedir=homedir, username=user)
    dest_known_hosts = os.path.join(homedir, '.ssh/known_hosts')
    log('Saving new known_hosts file to %s and authorized_keys file to: %s.' %
        (dest_known_hosts, dest_auth_keys))

    with open(dest_known_hosts, 'wb') as _hosts:
        for index in range(0, int(known_hosts_index)):
            _hosts.write('{}\n'.format(known_hosts[index]))
    with open(dest_auth_keys, 'wb') as _keys:
        for index in range(0, int(authorized_keys_index)):
            _keys.write('{}\n'.format(authorized_keys[index]))


def do_openstack_upgrade(configs):
    # NOTE(jamespage) horrible hack to make utils forget a cached value
    import charmhelpers.contrib.openstack.utils as utils
    utils.os_rel = None
    new_src = config('openstack-origin')
    new_os_rel = get_os_codename_install_source(new_src)
    log('Performing OpenStack upgrade to %s.' % (new_os_rel))

    configure_installation_source(new_src)
    apt_update(fatal=True)

    dpkg_opts = [
        '--option', 'Dpkg::Options::=--force-confnew',
        '--option', 'Dpkg::Options::=--force-confdef',
    ]

    apt_upgrade(options=dpkg_opts, fatal=True, dist=True)
    apt_install(determine_packages(), fatal=True)

    # Regenerate configs in full for new release
    configs.write_all()
    [service_restart(s) for s in services()]


def import_keystone_ca_cert():
    """If provided, improt the Keystone CA cert that gets forwarded
    to compute nodes via the cloud-compute interface
    """
    ca_cert = relation_get('ca_cert')
    if not ca_cert:
        return
    log('Writing Keystone CA certificate to %s' % CA_CERT_PATH)
    with open(CA_CERT_PATH, 'wb') as out:
        out.write(b64decode(ca_cert))
    check_call(['update-ca-certificates'])


def create_libvirt_secret(secret_file, secret_uuid, key):
    uri = LIBVIRT_URIS[config('virt-type')]
    if secret_uuid in check_output(['virsh', '-c', uri, 'secret-list']):
        old_key = check_output(['virsh', '-c', uri, 'secret-get-value',
                                secret_uuid])
        if old_key == key:
            log('Libvirt secret already exists for uuid %s.' % secret_uuid,
                level=DEBUG)
            return
        else:
            log('Libvirt secret changed for uuid %s.' % secret_uuid,
                level=INFO)
    log('Defining new libvirt secret for uuid %s.' % secret_uuid)
    cmd = ['virsh', '-c', uri, 'secret-define', '--file', secret_file]
    check_call(cmd)
    cmd = ['virsh', '-c', uri, 'secret-set-value', '--secret', secret_uuid,
           '--base64', key]
    check_call(cmd)


def configure_lxd(user='nova'):
    ''' Configure lxd use for nova user '''
    if not git_install_requested():
        if lsb_release()['DISTRIB_CODENAME'].lower() < "vivid":
            raise Exception("LXD is not supported for Ubuntu "
                            "versions less than 15.04 (vivid)")

    configure_subuid(user)
    lxc_list(user)


@retry_on_exception(5, base_delay=2, exc_type=CalledProcessError)
def lxc_list(user):
    cmd = ['sudo', '-u', user, 'lxc', 'list']
    check_call(cmd)


def configure_subuid(user):
    cmd = ['usermod', '-v', '100000-200000', '-w', '100000-200000', user]
    check_call(cmd)


def enable_shell(user):
    cmd = ['usermod', '-s', '/bin/bash', user]
    check_call(cmd)


def disable_shell(user):
    cmd = ['usermod', '-s', '/bin/false', user]
    check_call(cmd)


def fix_path_ownership(path, user='nova'):
    cmd = ['chown', user, path]
    check_call(cmd)


def get_topics():
    return ['compute']


def assert_charm_supports_ipv6():
    """Check whether we are able to support charms ipv6."""
    if lsb_release()['DISTRIB_CODENAME'].lower() < "trusty":
        raise Exception("IPv6 is not supported in the charms for Ubuntu "
                        "versions less than Trusty 14.04")


def enable_nova_metadata():
    ctxt = MetadataServiceContext()()
    return 'metadata_shared_secret' in ctxt


def neutron_plugin_legacy_mode():
    # If a charm is attatched to the neutron-plugin relation then its managing
    # neutron
    if relation_ids('neutron-plugin'):
        return False
    else:
        return config('manage-neutron-plugin-legacy-mode')


def manage_ovs():
    return neutron_plugin_legacy_mode() and neutron_plugin() == 'ovs'


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
        '/var/log/nova',
    ]

    logs = [
        '/var/log/nova/nova-api.log',
        '/var/log/nova/nova-compute.log',
        '/var/log/nova/nova-manage.log',
        '/var/log/nova/nova-network.log',
    ]

    adduser('nova', shell='/bin/bash', system_user=True)
    check_call(['usermod', '--home', '/var/lib/nova', 'nova'])
    add_group('nova', system_group=True)
    add_user_to_group('nova', 'nova')
    add_user_to_group('nova', 'libvirtd')

    for d in dirs:
        mkdir(d, owner='nova', group='nova', perms=0755, force=False)

    for l in logs:
        write_file(l, '', owner='nova', group='nova', perms=0644)


def git_post_install(projects_yaml):
    """Perform post-install setup."""
    http_proxy = git_yaml_value(projects_yaml, 'http_proxy')
    if http_proxy:
        pip_install('libvirt-python', proxy=http_proxy,
                    venv=git_pip_venv_dir(projects_yaml))
    else:
        pip_install('libvirt-python',
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
                             'bin/nova-rootwrap'),
         'link': '/usr/local/bin/nova-rootwrap'},
    ]

    for s in symlinks:
        if os.path.lexists(s['link']):
            os.remove(s['link'])
        os.symlink(s['src'], s['link'])

    virt_type = VIRT_TYPES[config('virt-type')][0]
    nova_compute_conf = 'git/{}.conf'.format(virt_type)
    render(nova_compute_conf, '/etc/nova/nova-compute.conf', {}, perms=0o644)
    render('git/nova_sudoers', '/etc/sudoers.d/nova_sudoers', {}, perms=0o440)

    service_name = 'nova-compute'
    nova_user = 'nova'
    start_dir = '/var/lib/nova'
    bin_dir = os.path.join(git_pip_venv_dir(projects_yaml), 'bin')
    nova_conf = '/etc/nova/nova.conf'
    nova_api_metadata_context = {
        'service_description': 'Nova Metadata API server',
        'service_name': service_name,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-api-metadata',
        'executable_name': os.path.join(bin_dir, 'nova-api-metadata'),
        'config_files': [nova_conf],
    }
    nova_api_context = {
        'service_description': 'Nova API server',
        'service_name': service_name,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-api',
        'executable_name': os.path.join(bin_dir, 'nova-api'),
        'config_files': [nova_conf],
    }
    nova_compute_context = {
        'service_description': 'Nova compute worker',
        'service_name': service_name,
        'user_name': nova_user,
        'process_name': 'nova-compute',
        'executable_name': os.path.join(bin_dir, 'nova-compute'),
        'config_files': [nova_conf, '/etc/nova/nova-compute.conf'],
    }
    nova_network_context = {
        'service_description': 'Nova network worker',
        'service_name': service_name,
        'user_name': nova_user,
        'start_dir': start_dir,
        'process_name': 'nova-network',
        'executable_name': os.path.join(bin_dir, 'nova-network'),
        'config_files': [nova_conf],
    }

    # NOTE(coreycb): Needs systemd support
    templates_dir = 'hooks/charmhelpers/contrib/openstack/templates'
    templates_dir = os.path.join(charm_dir(), templates_dir)
    render('git.upstart', '/etc/init/nova-api-metadata.conf',
           nova_api_metadata_context, perms=0o644, templates_dir=templates_dir)
    render('git.upstart', '/etc/init/nova-api.conf',
           nova_api_context, perms=0o644, templates_dir=templates_dir)
    render('git/upstart/nova-compute.upstart', '/etc/init/nova-compute.conf',
           nova_compute_context, perms=0o644)
    render('git.upstart', '/etc/init/nova-network.conf',
           nova_network_context, perms=0o644, templates_dir=templates_dir)

    apt_update()
    apt_install(LATE_GIT_PACKAGES, fatal=True)


def install_hugepages():
    """ Configure hugepages """
    hugepage_config = config('hugepages')
    if hugepage_config:
        # TODO: defaults to 2M - this should probably be configurable
        #       and support multiple pool sizes - e.g. 2M and 1G.
        hugepage_size = 2048
        if hugepage_config.endswith('%'):
            import psutil
            mem = psutil.virtual_memory()
            hugepage_config_pct = hugepage_config.strip('%')
            hugepage_multiplier = float(hugepage_config_pct) / 100
            hugepages = int((mem.total * hugepage_multiplier) / hugepage_size)
        else:
            hugepages = int(hugepage_config)
        mnt_point = '/run/hugepages/kvm'
        hugepage_support(
            'nova',
            mnt_point=mnt_point,
            group='root',
            nr_hugepages=hugepages,
            mount=False,
            set_shmmax=True,
        )
        if subprocess.call(['mountpoint', mnt_point]):
            fstab_mount(mnt_point)
        rsync(
            charm_dir() + '/files/qemu-hugefsdir',
            '/etc/init.d/qemu-hugefsdir'
        )
        subprocess.check_call('/etc/init.d/qemu-hugefsdir')
        subprocess.check_call(['update-rc.d', 'qemu-hugefsdir', 'defaults'])


def check_optional_relations(configs):
    required_interfaces = {}
    if relation_ids('ceph'):
        required_interfaces['storage-backend'] = ['ceph']

    if relation_ids('neutron-plugin'):
        required_interfaces['neutron-plugin'] = ['neutron-plugin']

    if relation_ids('shared-db') or relation_ids('pgsql-db'):
        required_interfaces['database'] = ['shared-db', 'pgsql-db']

    if required_interfaces:
        set_os_workload_status(configs, required_interfaces)
        return status_get()
    else:
        return 'unknown', 'No optional relations'
