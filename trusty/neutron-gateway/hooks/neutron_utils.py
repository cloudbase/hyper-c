import os
import shutil
import subprocess
from shutil import copy2
from charmhelpers.core.host import (
    adduser,
    add_group,
    add_user_to_group,
    lsb_release,
    mkdir,
    service_running,
    service_stop,
    service_restart,
    write_file,
)
from charmhelpers.core.hookenv import (
    charm_dir,
    log,
    DEBUG,
    INFO,
    ERROR,
    config,
    relations_of_type,
    unit_private_ip,
    is_relation_made,
    relation_ids,
    status_get,
)
from charmhelpers.core.templating import render
from charmhelpers.fetch import (
    apt_upgrade,
    apt_update,
    apt_install,
)
from charmhelpers.contrib.network.ovs import (
    add_bridge,
    add_bridge_port,
    full_restart
)
from charmhelpers.contrib.hahelpers.cluster import (
    get_hacluster_config,
)
from charmhelpers.contrib.openstack.utils import (
    configure_installation_source,
    get_os_codename_install_source,
    get_os_codename_package,
    git_install_requested,
    git_clone_and_install,
    git_src_dir,
    git_pip_venv_dir,
    get_hostname,
    set_os_workload_status,
)

from charmhelpers.contrib.openstack.neutron import (
    determine_dkms_package
)

import charmhelpers.contrib.openstack.context as context
from charmhelpers.contrib.openstack.context import (
    SyslogContext,
    NeutronAPIContext,
    NetworkServiceContext,
    ExternalPortContext,
    PhyNICMTUContext,
    DataPortContext,
)
import charmhelpers.contrib.openstack.templating as templating
from charmhelpers.contrib.openstack.neutron import headers_package
from neutron_contexts import (
    CORE_PLUGIN, OVS, NVP, NSX, N1KV, OVS_ODL,
    NEUTRON, QUANTUM,
    networking_name,
    NeutronGatewayContext,
    L3AgentContext,
    remap_plugin,
)
from charmhelpers.contrib.openstack.neutron import (
    parse_bridge_mappings,
)

from copy import deepcopy


def valid_plugin():
    return config('plugin') in CORE_PLUGIN[networking_name()]

QUANTUM_CONF_DIR = '/etc/quantum'

QUANTUM_OVS_PLUGIN_CONF = \
    "/etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini"
QUANTUM_NVP_PLUGIN_CONF = \
    "/etc/quantum/plugins/nicira/nvp.ini"
QUANTUM_PLUGIN_CONF = {
    OVS: QUANTUM_OVS_PLUGIN_CONF,
    NVP: QUANTUM_NVP_PLUGIN_CONF,
}

NEUTRON_CONF_DIR = '/etc/neutron'

NEUTRON_OVS_PLUGIN_CONF = \
    "/etc/neutron/plugins/openvswitch/ovs_neutron_plugin.ini"
NEUTRON_ML2_PLUGIN_CONF = \
    "/etc/neutron/plugins/ml2/ml2_conf.ini"
NEUTRON_NVP_PLUGIN_CONF = \
    "/etc/neutron/plugins/nicira/nvp.ini"
NEUTRON_NSX_PLUGIN_CONF = \
    "/etc/neutron/plugins/vmware/nsx.ini"

NEUTRON_PLUGIN_CONF = {
    OVS: NEUTRON_OVS_PLUGIN_CONF,
    NVP: NEUTRON_NVP_PLUGIN_CONF,
    NSX: NEUTRON_NSX_PLUGIN_CONF,
}

QUANTUM_GATEWAY_PKGS = {
    OVS: [
        "quantum-plugin-openvswitch-agent",
        "quantum-l3-agent",
        "quantum-dhcp-agent",
        'python-mysqldb',
        'python-psycopg2',
        "nova-api-metadata"
    ],
    NVP: [
        "openvswitch-switch",
        "quantum-dhcp-agent",
        'python-mysqldb',
        'python-psycopg2',
        "nova-api-metadata"
    ]
}

NEUTRON_GATEWAY_PKGS = {
    OVS: [
        "neutron-plugin-openvswitch-agent",
        "openvswitch-switch",
        "neutron-l3-agent",
        "neutron-dhcp-agent",
        'python-mysqldb',
        'python-psycopg2',
        'python-oslo.config',  # Force upgrade
        "nova-api-metadata",
        "neutron-plugin-metering-agent",
        "neutron-lbaas-agent",
    ],
    NVP: [
        "neutron-dhcp-agent",
        'python-mysqldb',
        'python-psycopg2',
        'python-oslo.config',  # Force upgrade
        "nova-api-metadata"
    ],
    N1KV: [
        "neutron-plugin-cisco",
        "neutron-dhcp-agent",
        "python-mysqldb",
        "python-psycopg2",
        "nova-api-metadata",
        "neutron-common",
        "neutron-l3-agent"
    ],
    OVS_ODL: [
        "openvswitch-switch",
        "neutron-l3-agent",
        "neutron-dhcp-agent",
        "nova-api-metadata",
        "neutron-plugin-metering-agent",
        "neutron-lbaas-agent",
    ],
}
NEUTRON_GATEWAY_PKGS[NSX] = NEUTRON_GATEWAY_PKGS[NVP]

GATEWAY_PKGS = {
    QUANTUM: QUANTUM_GATEWAY_PKGS,
    NEUTRON: NEUTRON_GATEWAY_PKGS,
}

EARLY_PACKAGES = {
    OVS: ['openvswitch-datapath-dkms'],
    NVP: [],
    N1KV: [],
    OVS_ODL: [],
}

LEGACY_HA_TEMPLATE_FILES = 'files'
LEGACY_FILES_MAP = {
    'neutron-ha-monitor.py': {
        'path': '/usr/local/bin/',
        'permissions': 0o755
    },
    'neutron-ha-monitor.conf': {
        'path': '/var/lib/juju-neutron-ha/',
    },
    'NeutronAgentMon': {
        'path': '/usr/lib/ocf/resource.d/canonical',
        'permissions': 0o755
    },
}
LEGACY_RES_MAP = ['res_monitor']
L3HA_PACKAGES = ['keepalived', 'conntrack']

BASE_GIT_PACKAGES = [
    'dnsmasq',
    'libffi-dev',
    'libssl-dev',
    'libxml2-dev',
    'libxslt1-dev',
    'libyaml-dev',
    'python-dev',
    'python-pip',
    'python-setuptools',
    'zlib1g-dev',
]

# ubuntu packages that should not be installed when deploying from git
GIT_PACKAGE_BLACKLIST = [
    'nova-api-metadata',
    'neutron-common',
    'neutron-dhcp-agent',
    'neutron-l3-agent',
    'neutron-lbaas-agent',
    'neutron-metadata-agent',
    'neutron-metering-agent',
    'neutron-plugin-cisco',
    'neutron-plugin-metering-agent',
    'neutron-plugin-openvswitch-agent',
    'neutron-plugin-vpn-agent',
    'neutron-vpn-agent',
    'python-neutron-fwaas',
    'python-oslo.config',
    'quantum-common',
    'quantum-dhcp-agent',
    'quantum-l3-agent',
    'quantum-metadata-agent',
    'quantum-plugin-openvswitch-agent',
]

# The interface is said to be satisfied if anyone of the interfaces in the
# list has a complete context.
REQUIRED_INTERFACES = {
    'messaging': ['amqp', 'zeromq-configuration'],
    'neutron-plugin-api': ['neutron-plugin-api'],
}


def get_early_packages():
    '''Return a list of package for pre-install based on configured plugin'''
    if config('plugin') in [OVS]:
        pkgs = determine_dkms_package()
    else:
        return []

    # ensure headers are installed build any required dkms packages
    if [p for p in pkgs if 'dkms' in p]:
        return pkgs + [headers_package()]
    return pkgs


def get_packages():
    '''Return a list of packages for install based on the configured plugin'''
    plugin = remap_plugin(config('plugin'))
    packages = deepcopy(GATEWAY_PKGS[networking_name()][plugin])
    source = get_os_codename_install_source(config('openstack-origin'))
    if plugin == 'ovs':
        if (source >= 'icehouse' and
                lsb_release()['DISTRIB_CODENAME'] < 'utopic'):
            # NOTE(jamespage) neutron-vpn-agent supercedes l3-agent for
            # icehouse but openswan was removed in utopic.
            packages.remove('neutron-l3-agent')
            packages.append('neutron-vpn-agent')
            packages.append('openswan')
        if source >= 'kilo':
            packages.append('python-neutron-fwaas')
        if source >= 'liberty':
            # Switch out mysql driver
            packages.remove('python-mysqldb')
            packages.append('python-pymysql')
            # Switch out to actual metering agent package
            packages.remove('neutron-plugin-metering-agent')
            packages.append('neutron-metering-agent')
    packages.extend(determine_l3ha_packages())

    if git_install_requested():
        packages = list(set(packages))
        packages.extend(BASE_GIT_PACKAGES)
        # don't include packages that will be installed from git
        for p in GIT_PACKAGE_BLACKLIST:
            if p in packages:
                packages.remove(p)

    return packages


def determine_l3ha_packages():
    if use_l3ha():
        return L3HA_PACKAGES
    return []


def get_common_package():
    if get_os_codename_package('quantum-common', fatal=False) is not None:
        return 'quantum-common'
    else:
        return 'neutron-common'


def use_l3ha():
    return NeutronAPIContext()()['enable_l3ha']

EXT_PORT_CONF = '/etc/init/ext-port.conf'
PHY_NIC_MTU_CONF = '/etc/init/os-charm-phy-nic-mtu.conf'
TEMPLATES = 'templates'

QUANTUM_CONF = "/etc/quantum/quantum.conf"
QUANTUM_L3_AGENT_CONF = "/etc/quantum/l3_agent.ini"
QUANTUM_DHCP_AGENT_CONF = "/etc/quantum/dhcp_agent.ini"
QUANTUM_METADATA_AGENT_CONF = "/etc/quantum/metadata_agent.ini"

NEUTRON_CONF = "/etc/neutron/neutron.conf"
NEUTRON_L3_AGENT_CONF = "/etc/neutron/l3_agent.ini"
NEUTRON_DHCP_AGENT_CONF = "/etc/neutron/dhcp_agent.ini"
NEUTRON_DNSMASQ_CONF = "/etc/neutron/dnsmasq.conf"
NEUTRON_METADATA_AGENT_CONF = "/etc/neutron/metadata_agent.ini"
NEUTRON_METERING_AGENT_CONF = "/etc/neutron/metering_agent.ini"
NEUTRON_LBAAS_AGENT_CONF = "/etc/neutron/lbaas_agent.ini"
NEUTRON_VPNAAS_AGENT_CONF = "/etc/neutron/vpn_agent.ini"
NEUTRON_FWAAS_CONF = "/etc/neutron/fwaas_driver.ini"

NOVA_CONF_DIR = '/etc/nova'
NOVA_CONF = "/etc/nova/nova.conf"

NOVA_CONFIG_FILES = {
    NOVA_CONF: {
        'hook_contexts': [NetworkServiceContext(),
                          NeutronGatewayContext(),
                          SyslogContext(),
                          context.ZeroMQContext(),
                          context.NotificationDriverContext()],
        'services': ['nova-api-metadata']
    },
}

QUANTUM_SHARED_CONFIG_FILES = {
    QUANTUM_DHCP_AGENT_CONF: {
        'hook_contexts': [NeutronGatewayContext()],
        'services': ['quantum-dhcp-agent']
    },
    QUANTUM_METADATA_AGENT_CONF: {
        'hook_contexts': [NetworkServiceContext(),
                          NeutronGatewayContext()],
        'services': ['quantum-metadata-agent']
    },
}
QUANTUM_SHARED_CONFIG_FILES.update(NOVA_CONFIG_FILES)

NEUTRON_SHARED_CONFIG_FILES = {
    NEUTRON_DHCP_AGENT_CONF: {
        'hook_contexts': [NeutronGatewayContext()],
        'services': ['neutron-dhcp-agent']
    },
    NEUTRON_DNSMASQ_CONF: {
        'hook_contexts': [NeutronGatewayContext()],
        'services': ['neutron-dhcp-agent']
    },
    NEUTRON_METADATA_AGENT_CONF: {
        'hook_contexts': [NetworkServiceContext(),
                          NeutronGatewayContext()],
        'services': ['neutron-metadata-agent']
    },
}
NEUTRON_SHARED_CONFIG_FILES.update(NOVA_CONFIG_FILES)

QUANTUM_OVS_CONFIG_FILES = {
    QUANTUM_CONF: {
        'hook_contexts': [context.AMQPContext(ssl_dir=QUANTUM_CONF_DIR),
                          NeutronGatewayContext(),
                          SyslogContext(),
                          context.ZeroMQContext(),
                          context.NotificationDriverContext()],
        'services': ['quantum-l3-agent',
                     'quantum-dhcp-agent',
                     'quantum-metadata-agent',
                     'quantum-plugin-openvswitch-agent']
    },
    QUANTUM_L3_AGENT_CONF: {
        'hook_contexts': [NetworkServiceContext(),
                          NeutronGatewayContext()],
        'services': ['quantum-l3-agent']
    },
    QUANTUM_OVS_PLUGIN_CONF: {
        'hook_contexts': [NeutronGatewayContext()],
        'services': ['quantum-plugin-openvswitch-agent']
    },
    EXT_PORT_CONF: {
        'hook_contexts': [ExternalPortContext()],
        'services': ['ext-port']
    },
    PHY_NIC_MTU_CONF: {
        'hook_contexts': [PhyNICMTUContext()],
        'services': ['os-charm-phy-nic-mtu']
    }
}
QUANTUM_OVS_CONFIG_FILES.update(QUANTUM_SHARED_CONFIG_FILES)

NEUTRON_OVS_CONFIG_FILES = {
    NEUTRON_CONF: {
        'hook_contexts': [context.AMQPContext(ssl_dir=NEUTRON_CONF_DIR),
                          NeutronGatewayContext(),
                          SyslogContext(),
                          context.ZeroMQContext(),
                          context.NotificationDriverContext()],
        'services': ['neutron-l3-agent',
                     'neutron-dhcp-agent',
                     'neutron-metadata-agent',
                     'neutron-plugin-openvswitch-agent',
                     'neutron-plugin-metering-agent',
                     'neutron-metering-agent',
                     'neutron-lbaas-agent',
                     'neutron-plugin-vpn-agent',
                     'neutron-vpn-agent']
    },
    NEUTRON_L3_AGENT_CONF: {
        'hook_contexts': [NetworkServiceContext(),
                          L3AgentContext(),
                          NeutronGatewayContext()],
        'services': ['neutron-l3-agent', 'neutron-vpn-agent']
    },
    NEUTRON_METERING_AGENT_CONF: {
        'hook_contexts': [NeutronGatewayContext()],
        'services': ['neutron-plugin-metering-agent',
                     'neutron-metering-agent']
    },
    NEUTRON_LBAAS_AGENT_CONF: {
        'hook_contexts': [NeutronGatewayContext()],
        'services': ['neutron-lbaas-agent']
    },
    NEUTRON_VPNAAS_AGENT_CONF: {
        'hook_contexts': [NeutronGatewayContext()],
        'services': ['neutron-plugin-vpn-agent',
                     'neutron-vpn-agent']
    },
    NEUTRON_FWAAS_CONF: {
        'hook_contexts': [NeutronGatewayContext()],
        'services': ['neutron-l3-agent', 'neutron-vpn-agent']
    },
    NEUTRON_OVS_PLUGIN_CONF: {
        'hook_contexts': [NeutronGatewayContext()],
        'services': ['neutron-plugin-openvswitch-agent']
    },
    NEUTRON_ML2_PLUGIN_CONF: {
        'hook_contexts': [NeutronGatewayContext()],
        'services': ['neutron-plugin-openvswitch-agent']
    },
    EXT_PORT_CONF: {
        'hook_contexts': [ExternalPortContext()],
        'services': ['ext-port']
    },
    PHY_NIC_MTU_CONF: {
        'hook_contexts': [PhyNICMTUContext()],
        'services': ['os-charm-phy-nic-mtu']
    }
}
NEUTRON_OVS_CONFIG_FILES.update(NEUTRON_SHARED_CONFIG_FILES)

NEUTRON_OVS_ODL_CONFIG_FILES = {
    NEUTRON_CONF: {
        'hook_contexts': [context.AMQPContext(ssl_dir=NEUTRON_CONF_DIR),
                          NeutronGatewayContext(),
                          SyslogContext(),
                          context.ZeroMQContext(),
                          context.NotificationDriverContext()],
        'services': ['neutron-l3-agent',
                     'neutron-dhcp-agent',
                     'neutron-metadata-agent',
                     'neutron-plugin-metering-agent',
                     'neutron-metering-agent',
                     'neutron-lbaas-agent',
                     'neutron-plugin-vpn-agent',
                     'neutron-vpn-agent']
    },
    NEUTRON_L3_AGENT_CONF: {
        'hook_contexts': [NetworkServiceContext(),
                          L3AgentContext(),
                          NeutronGatewayContext()],
        'services': ['neutron-l3-agent', 'neutron-vpn-agent']
    },
    NEUTRON_METERING_AGENT_CONF: {
        'hook_contexts': [NeutronGatewayContext()],
        'services': ['neutron-plugin-metering-agent',
                     'neutron-metering-agent']
    },
    NEUTRON_LBAAS_AGENT_CONF: {
        'hook_contexts': [NeutronGatewayContext()],
        'services': ['neutron-lbaas-agent']
    },
    NEUTRON_VPNAAS_AGENT_CONF: {
        'hook_contexts': [NeutronGatewayContext()],
        'services': ['neutron-plugin-vpn-agent',
                     'neutron-vpn-agent']
    },
    NEUTRON_FWAAS_CONF: {
        'hook_contexts': [NeutronGatewayContext()],
        'services': ['neutron-l3-agent', 'neutron-vpn-agent']
    },
    EXT_PORT_CONF: {
        'hook_contexts': [ExternalPortContext()],
        'services': ['ext-port']
    },
    PHY_NIC_MTU_CONF: {
        'hook_contexts': [PhyNICMTUContext()],
        'services': ['os-charm-phy-nic-mtu']
    }
}
NEUTRON_OVS_ODL_CONFIG_FILES.update(NEUTRON_SHARED_CONFIG_FILES)


QUANTUM_NVP_CONFIG_FILES = {
    QUANTUM_CONF: {
        'hook_contexts': [context.AMQPContext(ssl_dir=QUANTUM_CONF_DIR),
                          NeutronGatewayContext(),
                          SyslogContext()],
        'services': ['quantum-dhcp-agent', 'quantum-metadata-agent']
    },
}
QUANTUM_NVP_CONFIG_FILES.update(QUANTUM_SHARED_CONFIG_FILES)

NEUTRON_NVP_CONFIG_FILES = {
    NEUTRON_CONF: {
        'hook_contexts': [context.AMQPContext(ssl_dir=NEUTRON_CONF_DIR),
                          NeutronGatewayContext(),
                          SyslogContext()],
        'services': ['neutron-dhcp-agent', 'neutron-metadata-agent']
    },
}
NEUTRON_NVP_CONFIG_FILES.update(NEUTRON_SHARED_CONFIG_FILES)

NEUTRON_N1KV_CONFIG_FILES = {
    NEUTRON_CONF: {
        'hook_contexts': [context.AMQPContext(ssl_dir=NEUTRON_CONF_DIR),
                          NeutronGatewayContext(),
                          SyslogContext()],
        'services': ['neutron-l3-agent',
                     'neutron-dhcp-agent',
                     'neutron-metadata-agent']
    },
    NEUTRON_L3_AGENT_CONF: {
        'hook_contexts': [NetworkServiceContext(),
                          L3AgentContext(),
                          NeutronGatewayContext()],
        'services': ['neutron-l3-agent']
    },
}
NEUTRON_N1KV_CONFIG_FILES.update(NEUTRON_SHARED_CONFIG_FILES)

CONFIG_FILES = {
    QUANTUM: {
        NVP: QUANTUM_NVP_CONFIG_FILES,
        OVS: QUANTUM_OVS_CONFIG_FILES,
    },
    NEUTRON: {
        NSX: NEUTRON_NVP_CONFIG_FILES,
        NVP: NEUTRON_NVP_CONFIG_FILES,
        OVS: NEUTRON_OVS_CONFIG_FILES,
        N1KV: NEUTRON_N1KV_CONFIG_FILES,
        OVS_ODL: NEUTRON_OVS_ODL_CONFIG_FILES
    },
}


def register_configs():
    ''' Register config files with their respective contexts. '''
    release = get_os_codename_install_source(config('openstack-origin'))
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)

    plugin = remap_plugin(config('plugin'))
    name = networking_name()
    if plugin == 'ovs':
        # NOTE: deal with switch to ML2 plugin for >= icehouse
        drop_config = NEUTRON_ML2_PLUGIN_CONF
        if release >= 'icehouse':
            drop_config = NEUTRON_OVS_PLUGIN_CONF
        if drop_config in CONFIG_FILES[name][plugin]:
            CONFIG_FILES[name][plugin].pop(drop_config)

    if is_relation_made('amqp-nova'):
        amqp_nova_ctxt = context.AMQPContext(
            ssl_dir=NOVA_CONF_DIR,
            rel_name='amqp-nova',
            relation_prefix='nova')
    else:
        amqp_nova_ctxt = context.AMQPContext(
            ssl_dir=NOVA_CONF_DIR,
            rel_name='amqp')
    CONFIG_FILES[name][plugin][NOVA_CONF][
        'hook_contexts'].append(amqp_nova_ctxt)
    for conf in CONFIG_FILES[name][plugin]:
        configs.register(conf,
                         CONFIG_FILES[name][plugin][conf]['hook_contexts'])
    return configs


def stop_services():
    name = networking_name()
    svcs = set()
    for ctxt in CONFIG_FILES[name][config('plugin')].itervalues():
        for svc in ctxt['services']:
            svcs.add(svc)
    for svc in svcs:
        service_stop(svc)


def restart_map():
    '''
    Determine the correct resource map to be passed to
    charmhelpers.core.restart_on_change() based on the services configured.

    :returns: dict: A dictionary mapping config file to lists of services
                    that should be restarted when file changes.
    '''
    _map = {}
    plugin = config('plugin')
    name = networking_name()
    for f, ctxt in CONFIG_FILES[name][plugin].iteritems():
        svcs = []
        for svc in ctxt['services']:
            svcs.append(svc)
        if svcs:
            _map[f] = svcs
    return _map


INT_BRIDGE = "br-int"
EXT_BRIDGE = "br-ex"

DHCP_AGENT = "DHCP Agent"
L3_AGENT = "L3 Agent"


# TODO: make work with neutron
def reassign_agent_resources():
    ''' Use agent scheduler API to detect down agents and re-schedule '''
    env = NetworkServiceContext()()
    if not env:
        log('Unable to re-assign resources at this time')
        return
    try:
        from quantumclient.v2_0 import client
    except ImportError:
        ''' Try to import neutronclient instead for havana+ '''
        from neutronclient.v2_0 import client

    auth_url = '%(auth_protocol)s://%(keystone_host)s:%(auth_port)s/v2.0' % env
    quantum = client.Client(username=env['service_username'],
                            password=env['service_password'],
                            tenant_name=env['service_tenant'],
                            auth_url=auth_url,
                            region_name=env['region'])

    partner_gateways = [unit_private_ip().split('.')[0]]
    for partner_gateway in relations_of_type(reltype='cluster'):
        gateway_hostname = get_hostname(partner_gateway['private-address'])
        partner_gateways.append(gateway_hostname.partition('.')[0])

    agents = quantum.list_agents(agent_type=DHCP_AGENT)
    dhcp_agents = []
    l3_agents = []
    networks = {}
    for agent in agents['agents']:
        if not agent['alive']:
            log('DHCP Agent %s down' % agent['id'])
            for network in \
                    quantum.list_networks_on_dhcp_agent(
                        agent['id'])['networks']:
                networks[network['id']] = agent['id']
        else:
            if agent['host'].partition('.')[0] in partner_gateways:
                dhcp_agents.append(agent['id'])

    agents = quantum.list_agents(agent_type=L3_AGENT)
    routers = {}
    for agent in agents['agents']:
        if not agent['alive']:
            log('L3 Agent %s down' % agent['id'])
            for router in \
                    quantum.list_routers_on_l3_agent(
                        agent['id'])['routers']:
                routers[router['id']] = agent['id']
        else:
            if agent['host'].split('.')[0] in partner_gateways:
                l3_agents.append(agent['id'])

    if len(dhcp_agents) == 0 or len(l3_agents) == 0:
        log('Unable to relocate resources, there are %s dhcp_agents and %s \
             l3_agents in this cluster' % (len(dhcp_agents), len(l3_agents)))
        return

    index = 0
    for router_id in routers:
        agent = index % len(l3_agents)
        log('Moving router %s from %s to %s' %
            (router_id, routers[router_id], l3_agents[agent]))
        quantum.remove_router_from_l3_agent(l3_agent=routers[router_id],
                                            router_id=router_id)
        quantum.add_router_to_l3_agent(l3_agent=l3_agents[agent],
                                       body={'router_id': router_id})
        index += 1

    index = 0
    for network_id in networks:
        agent = index % len(dhcp_agents)
        log('Moving network %s from %s to %s' %
            (network_id, networks[network_id], dhcp_agents[agent]))
        quantum.remove_network_from_dhcp_agent(dhcp_agent=networks[network_id],
                                               network_id=network_id)
        quantum.add_network_to_dhcp_agent(dhcp_agent=dhcp_agents[agent],
                                          body={'network_id': network_id})
        index += 1


def services():
    ''' Returns a list of services associate with this charm '''
    _services = []
    for v in restart_map().values():
        _services = _services + v
    return list(set(_services))


def do_openstack_upgrade(configs):
    """
    Perform an upgrade.  Takes care of upgrading packages, rewriting
    configs, database migrations and potentially any other post-upgrade
    actions.
    """
    new_src = config('openstack-origin')
    new_os_rel = get_os_codename_install_source(new_src)
    log('Performing OpenStack upgrade to %s.' % (new_os_rel))

    configure_installation_source(new_src)
    dpkg_opts = [
        '--option', 'Dpkg::Options::=--force-confnew',
        '--option', 'Dpkg::Options::=--force-confdef',
    ]
    apt_update(fatal=True)
    apt_upgrade(options=dpkg_opts,
                fatal=True, dist=True)
    apt_install(get_early_packages(), fatal=True)
    apt_install(get_packages(), fatal=True)
    configs.write_all()


def configure_ovs():
    if config('plugin') in [OVS, OVS_ODL]:
        if not service_running('openvswitch-switch'):
            full_restart()
        add_bridge(INT_BRIDGE)
        add_bridge(EXT_BRIDGE)
        ext_port_ctx = ExternalPortContext()()
        if ext_port_ctx and ext_port_ctx['ext_port']:
            add_bridge_port(EXT_BRIDGE, ext_port_ctx['ext_port'])

        portmaps = DataPortContext()()
        bridgemaps = parse_bridge_mappings(config('bridge-mappings'))
        for provider, br in bridgemaps.iteritems():
            add_bridge(br)
            if not portmaps:
                continue

            for port, _br in portmaps.iteritems():
                if _br == br:
                    add_bridge_port(br, port, promisc=True)

        # Ensure this runs so that mtu is applied to data-port interfaces if
        # provided.
        service_restart('os-charm-phy-nic-mtu')


def copy_file(src, dst, perms=None, force=False):
    """Copy file to destination and optionally set permissionss.

    If destination does not exist it will be created.
    """
    if not os.path.isdir(dst):
        log('Creating directory %s' % dst, level=DEBUG)
        mkdir(dst)

    fdst = os.path.join(dst, os.path.basename(src))
    if not os.path.isfile(fdst) or force:
        try:
            copy2(src, fdst)
            if perms:
                os.chmod(fdst, perms)
        except IOError:
            log('Failed to copy file from %s to %s.' % (src, dst), level=ERROR)
            raise


def remove_file(path):
    if not os.path.isfile(path):
        log('File %s does not exist.' % path, level=INFO)
        return

    try:
        os.remove(path)
    except IOError:
        log('Failed to remove file %s.' % path, level=ERROR)


def install_legacy_ha_files(force=False):
    for f, p in LEGACY_FILES_MAP.iteritems():
        srcfile = os.path.join(LEGACY_HA_TEMPLATE_FILES, f)
        copy_file(srcfile, p['path'], p.get('permissions', None), force=force)


def remove_legacy_ha_files():
    for f, p in LEGACY_FILES_MAP.iteritems():
        remove_file(os.path.join(p['path'], f))


def update_legacy_ha_files(force=False):
    if config('ha-legacy-mode'):
        install_legacy_ha_files(force=force)
    else:
        remove_legacy_ha_files()


def cache_env_data():
    env = NetworkServiceContext()()
    if not env:
        log('Unable to get NetworkServiceContext at this time', level=ERROR)
        return

    no_envrc = False
    envrc_f = '/etc/legacy_ha_envrc'
    if os.path.isfile(envrc_f):
        with open(envrc_f, 'r') as f:
            data = f.read()

        data = data.strip().split('\n')
        diff = False
        for line in data:
            k = line.split('=')[0]
            v = line.split('=')[1]
            if k not in env or v != env[k]:
                diff = True
                break
    else:
        no_envrc = True

    if no_envrc or diff:
        with open(envrc_f, 'w') as f:
            for k, v in env.items():
                f.write(''.join([k, '=', v, '\n']))


def stop_neutron_ha_monitor_daemon():
    try:
        cmd = ['pgrep', '-f', 'neutron-ha-monitor.py']
        res = subprocess.check_output(cmd).decode('UTF-8')
        pid = res.strip()
        if pid:
            subprocess.call(['sudo', 'kill', '-9', pid])
    except subprocess.CalledProcessError as e:
        log('Faild to kill neutron-ha-monitor daemon, %s' % e, level=ERROR)


def cleanup_ovs_netns():
    try:
        subprocess.call('neutron-ovs-cleanup')
        subprocess.call('neutron-netns-cleanup')
    except subprocess.CalledProcessError as e:
        log('Faild to cleanup ovs and netns, %s' % e, level=ERROR)


def get_topics():
    # metering_agent
    topics = []
    if 'neutron-l3-agent' in services():
        topics.append('l3_agent')
    if 'neutron-dhcp-agent' in services():
        topics.append('dhcp_agent')
    if 'neutron-metering-agent' in services():
        topics.append('metering_agent')
    if 'neutron-lbaas-agent' in services():
        topics.append('n-lbaas_agent')
    if 'neutron-plugin-openvswitch-agent' in services():
        topics.append('q-agent-notifier-port-update')
        topics.append('q-agent-notifier-network-delete')
        topics.append('q-agent-notifier-tunnel-update')
        topics.append('q-agent-notifier-security_group-update')
        topics.append('q-agent-notifier-dvr-update')
    topics.append('q-agent-notifier-l2population-update')
    return topics


def git_install(projects_yaml):
    """Perform setup, and install git repos specified in yaml parameter."""
    if git_install_requested():
        git_pre_install()
        git_clone_and_install(projects_yaml, core_project='neutron')
        git_post_install(projects_yaml)


def git_pre_install():
    """Perform pre-install setup."""
    dirs = [
        '/etc/neutron',
        '/etc/neutron/rootwrap.d',
        '/etc/neutron/plugins',
        '/etc/nova',
        '/var/lib/neutron',
        '/var/lib/neutron/lock',
        '/var/log/neutron',
    ]

    logs = [
        '/var/log/neutron/bigswitch-agent.log',
        '/var/log/neutron/dhcp-agent.log',
        '/var/log/neutron/l3-agent.log',
        '/var/log/neutron/lbaas-agent.log',
        '/var/log/neutron/ibm-agent.log',
        '/var/log/neutron/linuxbridge-agent.log',
        '/var/log/neutron/metadata-agent.log',
        '/var/log/neutron/metering_agent.log',
        '/var/log/neutron/mlnx-agent.log',
        '/var/log/neutron/nec-agent.log',
        '/var/log/neutron/nvsd-agent.log',
        '/var/log/neutron/openflow-agent.log',
        '/var/log/neutron/openvswitch-agent.log',
        '/var/log/neutron/ovs-cleanup.log',
        '/var/log/neutron/ryu-agent.log',
        '/var/log/neutron/server.log',
        '/var/log/neutron/sriov-agent.log',
        '/var/log/neutron/vpn_agent.log',
    ]

    adduser('neutron', shell='/bin/bash', system_user=True)
    add_group('neutron', system_group=True)
    add_user_to_group('neutron', 'neutron')

    for d in dirs:
        mkdir(d, owner='neutron', group='neutron', perms=0755, force=False)

    for l in logs:
        write_file(l, '', owner='neutron', group='neutron', perms=0644)


def git_post_install(projects_yaml):
    """Perform post-install setup."""
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
        {'src': '/usr/local/bin/neutron-rootwrap',
         'link': '/usr/bin/neutron-rootwrap'},
    ]

    for s in symlinks:
        if os.path.lexists(s['link']):
            os.remove(s['link'])
        os.symlink(s['src'], s['link'])

    render('git/neutron_sudoers',
           '/etc/sudoers.d/neutron_sudoers', {}, perms=0o440)
    render('git/cron.d/neutron-dhcp-agent-netns-cleanup',
           '/etc/cron.d/neutron-dhcp-agent-netns-cleanup', {}, perms=0o755)
    render('git/cron.d/neutron-l3-agent-netns-cleanup',
           '/etc/cron.d/neutron-l3-agent-netns-cleanup', {}, perms=0o755)
    render('git/cron.d/neutron-lbaas-agent-netns-cleanup',
           '/etc/cron.d/neutron-lbaas-agent-netns-cleanup', {}, perms=0o755)

    service_name = 'quantum-gateway'
    user_name = 'neutron'
    bin_dir = os.path.join(git_pip_venv_dir(projects_yaml), 'bin')
    neutron_api_context = {
        'service_description': 'Neutron API server',
        'service_name': service_name,
        'process_name': 'neutron-server',
        'executable_name': os.path.join(bin_dir, 'neutron-server'),
    }
    neutron_dhcp_agent_context = {
        'service_description': 'Neutron DHCP Agent',
        'service_name': service_name,
        'process_name': 'neutron-dhcp-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-dhcp-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/dhcp_agent.ini'],
        'log_file': '/var/log/neutron/dhcp-agent.log',
    }
    neutron_l3_agent_context = {
        'service_description': 'Neutron L3 Agent',
        'service_name': service_name,
        'process_name': 'neutron-l3-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-l3-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/l3_agent.ini',
                         '/etc/neutron/fwaas_driver.ini'],
        'log_file': '/var/log/neutron/l3-agent.log',
    }
    neutron_lbaas_agent_context = {
        'service_description': 'Neutron LBaaS Agent',
        'service_name': service_name,
        'user_name': user_name,
        'start_dir': '/var/lib/neutron',
        'process_name': 'neutron-lbaas-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-lbaas-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/lbaas_agent.ini'],
        'log_file': '/var/log/neutron/lbaas-agent.log',
    }
    neutron_metadata_agent_context = {
        'service_description': 'Neutron Metadata Agent',
        'service_name': service_name,
        'user_name': user_name,
        'start_dir': '/var/lib/neutron',
        'process_name': 'neutron-metadata-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-metadata-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/metadata_agent.ini'],
        'log_file': '/var/log/neutron/metadata-agent.log',
    }
    neutron_metering_agent_context = {
        'service_description': 'Neutron Metering Agent',
        'service_name': service_name,
        'user_name': user_name,
        'start_dir': '/var/lib/neutron',
        'process_name': 'neutron-metering-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-metering-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/metering_agent.ini'],
        'log_file': '/var/log/neutron/metering-agent.log',
    }
    neutron_ovs_cleanup_context = {
        'service_description': 'Neutron OVS cleanup',
        'service_name': service_name,
        'user_name': user_name,
        'start_dir': '/var/lib/neutron',
        'process_name': 'neutron-ovs-cleanup',
        'executable_name': os.path.join(bin_dir, 'neutron-ovs-cleanup'),
        'config_file': '/etc/neutron/neutron.conf',
        'log_file': '/var/log/neutron/ovs-cleanup.log',
    }
    neutron_plugin_bigswitch_context = {
        'service_description': 'Neutron BigSwitch Plugin Agent',
        'service_name': service_name,
        'user_name': user_name,
        'start_dir': '/var/lib/neutron',
        'process_name': 'neutron-restproxy-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-restproxy-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/plugins/bigswitch/restproxy.ini'],
        'log_file': '/var/log/neutron/bigswitch-agent.log',
    }
    neutron_plugin_ibm_context = {
        'service_description': 'Neutron IBM SDN Plugin Agent',
        'service_name': service_name,
        'user_name': user_name,
        'start_dir': '/var/lib/neutron',
        'process_name': 'neutron-ibm-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-ibm-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/plugins/ibm/sdnve_neutron_plugin.ini'],
        'log_file': '/var/log/neutron/ibm-agent.log',
    }
    neutron_plugin_linuxbridge_context = {
        'service_description': 'Neutron Linux Bridge Plugin Agent',
        'service_name': service_name,
        'user_name': user_name,
        'start_dir': '/var/lib/neutron',
        'process_name': 'neutron-linuxbridge-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-linuxbridge-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/plugins/ml2/ml2_conf.ini'],
        'log_file': '/var/log/neutron/linuxbridge-agent.log',
    }
    neutron_plugin_mlnx_context = {
        'service_description': 'Neutron MLNX Plugin Agent',
        'service_name': service_name,
        'user_name': user_name,
        'start_dir': '/var/lib/neutron',
        'process_name': 'neutron-mlnx-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-mlnx-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/plugins/mlnx/mlnx_conf.ini'],
        'log_file': '/var/log/neutron/mlnx-agent.log',
    }
    neutron_plugin_nec_context = {
        'service_description': 'Neutron NEC Plugin Agent',
        'service_name': service_name,
        'start_dir': '/var/lib/neutron',
        'process_name': 'neutron-nec-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-nec-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/plugins/nec/nec.ini'],
        'log_file': '/var/log/neutron/nec-agent.log',
    }
    neutron_plugin_oneconvergence_context = {
        'service_description': 'Neutron One Convergence Plugin Agent',
        'service_name': service_name,
        'user_name': user_name,
        'start_dir': '/var/lib/neutron',
        'process_name': 'neutron-nvsd-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-nvsd-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/plugins/oneconvergence/nvsdplugin.ini'],
        'log_file': '/var/log/neutron/nvsd-agent.log',
    }
    neutron_plugin_openflow_context = {
        'service_description': 'Neutron OpenFlow Plugin Agent',
        'service_name': service_name,
        'user_name': user_name,
        'start_dir': '/var/lib/neutron',
        'process_name': 'neutron-ofagent-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-ofagent-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/plugins/ml2/ml2_conf_ofa.ini'],
        'log_file': '/var/log/neutron/openflow-agent.log',
    }
    neutron_plugin_openvswitch_context = {
        'service_description': 'Neutron OpenvSwitch Plugin Agent',
        'service_name': service_name,
        'user_name': user_name,
        'start_dir': '/var/lib/neutron',
        'process_name': 'neutron-openvswitch-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-openvswitch-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/plugins/ml2/ml2_conf.ini'],
        'log_file': '/var/log/neutron/openvswitch-agent.log',
    }
    neutron_plugin_ryu_context = {
        'service_description': 'Neutron RYU Plugin Agent',
        'service_name': service_name,
        'user_name': user_name,
        'start_dir': '/var/lib/neutron',
        'process_name': 'neutron-ryu-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-ryu-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/plugins/ryu/ryu.ini'],
        'log_file': '/var/log/neutron/ryu-agent.log',
    }
    neutron_plugin_sriov_context = {
        'service_description': 'Neutron SRIOV SDN Plugin Agent',
        'service_name': service_name,
        'user_name': user_name,
        'start_dir': '/var/lib/neutron',
        'process_name': 'neutron-sriov-nic-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-sriov-nic-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/plugins/ml2/ml2_conf_sriov'],
        'log_file': '/var/log/neutron/sriov-agent.log',
    }
    neutron_vpn_agent_context = {
        'service_description': 'Neutron VPN Agent',
        'service_name': service_name,
        'process_name': 'neutron-vpn-agent',
        'executable_name': os.path.join(bin_dir, 'neutron-vpn-agent'),
        'config_files': ['/etc/neutron/neutron.conf',
                         '/etc/neutron/vpn_agent.ini',
                         '/etc/neutron/l3_agent.ini',
                         '/etc/neutron/fwaas_driver.ini'],
        'log_file': '/var/log/neutron/vpn_agent.log',
    }

    # NOTE(coreycb): Needs systemd support
    templates_dir = 'hooks/charmhelpers/contrib/openstack/templates'
    templates_dir = os.path.join(charm_dir(), templates_dir)
    render('git/upstart/neutron-agent.upstart',
           '/etc/init/neutron-dhcp-agent.conf',
           neutron_dhcp_agent_context, perms=0o644)
    render('git/upstart/neutron-agent.upstart',
           '/etc/init/neutron-l3-agent.conf',
           neutron_l3_agent_context, perms=0o644)
    render('git.upstart',
           '/etc/init/neutron-lbaas-agent.conf',
           neutron_lbaas_agent_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart',
           '/etc/init/neutron-metadata-agent.conf',
           neutron_metadata_agent_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart',
           '/etc/init/neutron-metering-agent.conf',
           neutron_metering_agent_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart',
           '/etc/init/neutron-ovs-cleanup.conf',
           neutron_ovs_cleanup_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart',
           '/etc/init/neutron-plugin-bigswitch-agent.conf',
           neutron_plugin_bigswitch_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart',
           '/etc/init/neutron-plugin-ibm-agent.conf',
           neutron_plugin_ibm_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart',
           '/etc/init/neutron-plugin-linuxbridge-agent.conf',
           neutron_plugin_linuxbridge_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart',
           '/etc/init/neutron-plugin-mlnx-agent.conf',
           neutron_plugin_mlnx_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart',
           '/etc/init/neutron-plugin-nec-agent.conf',
           neutron_plugin_nec_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart',
           '/etc/init/neutron-plugin-oneconvergence-agent.conf',
           neutron_plugin_oneconvergence_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart',
           '/etc/init/neutron-plugin-openflow-agent.conf',
           neutron_plugin_openflow_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart',
           '/etc/init/neutron-plugin-openvswitch-agent.conf',
           neutron_plugin_openvswitch_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart',
           '/etc/init/neutron-plugin-ryu-agent.conf',
           neutron_plugin_ryu_context, perms=0o644,
           templates_dir=templates_dir)
    render('git.upstart',
           '/etc/init/neutron-plugin-sriov-agent.conf',
           neutron_plugin_sriov_context, perms=0o644,
           templates_dir=templates_dir)
    render('git/upstart/neutron-server.upstart',
           '/etc/init/neutron-server.conf',
           neutron_api_context, perms=0o644)
    render('git/upstart/neutron-agent.upstart',
           '/etc/init/neutron-vpn-agent.conf',
           neutron_vpn_agent_context, perms=0o644)


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
