import os
import uuid
from charmhelpers.core.hookenv import (
    config,
    relation_get,
    relation_ids,
    related_units,
    unit_get,
)
from charmhelpers.contrib.openstack.ip import resolve_address
from charmhelpers.contrib.openstack import context
from charmhelpers.contrib.openstack.utils import get_host_ip
from charmhelpers.contrib.network.ip import get_address_in_network
from charmhelpers.contrib.openstack.context import (
    OSContextGenerator,
    NeutronAPIContext,
)


class OVSPluginContext(context.NeutronContext):
    interfaces = []

    @property
    def plugin(self):
        return 'ovs'

    @property
    def network_manager(self):
        return 'neutron'

    @property
    def neutron_security_groups(self):
        if config('disable-security-groups'):
            return False
        neutron_api_settings = NeutronAPIContext()()
        return neutron_api_settings['neutron_security_groups']

    def ovs_ctxt(self):
        # In addition to generating config context, ensure the OVS service
        # is running and the OVS bridge exists. Also need to ensure
        # local_ip points to actual IP, not hostname.
        ovs_ctxt = super(OVSPluginContext, self).ovs_ctxt()
        if not ovs_ctxt:
            return {}

        conf = config()
        ovs_ctxt['local_ip'] = \
            get_address_in_network(config('os-data-network'),
                                   get_host_ip(unit_get('private-address')))
        neutron_api_settings = NeutronAPIContext()()
        ovs_ctxt['neutron_security_groups'] = self.neutron_security_groups
        ovs_ctxt['l2_population'] = neutron_api_settings['l2_population']
        ovs_ctxt['distributed_routing'] = neutron_api_settings['enable_dvr']
        ovs_ctxt['overlay_network_type'] = \
            neutron_api_settings['overlay_network_type']
        # TODO: We need to sort out the syslog and debug/verbose options as a
        # general context helper
        ovs_ctxt['use_syslog'] = conf['use-syslog']
        ovs_ctxt['verbose'] = conf['verbose']
        ovs_ctxt['debug'] = conf['debug']

        net_dev_mtu = neutron_api_settings.get('network_device_mtu')
        if net_dev_mtu:
            # neutron.conf
            ovs_ctxt['network_device_mtu'] = net_dev_mtu
            # ml2 conf
            ovs_ctxt['veth_mtu'] = net_dev_mtu

        mappings = config('bridge-mappings')
        if mappings:
            ovs_ctxt['bridge_mappings'] = ','.join(mappings.split())

        flat_providers = config('flat-network-providers')
        if flat_providers:
            ovs_ctxt['network_providers'] = ','.join(flat_providers.split())

        vlan_ranges = config('vlan-ranges')
        if vlan_ranges:
            ovs_ctxt['vlan_ranges'] = ','.join(vlan_ranges.split())

        return ovs_ctxt


class L3AgentContext(OSContextGenerator):

    def __call__(self):
        neutron_api_settings = NeutronAPIContext()()
        ctxt = {}
        if neutron_api_settings['enable_dvr']:
            ctxt['agent_mode'] = 'dvr'
        else:
            ctxt['agent_mode'] = 'legacy'
        return ctxt


SHARED_SECRET = "/etc/neutron/secret.txt"


def get_shared_secret():
    secret = None
    if not os.path.exists(SHARED_SECRET):
        secret = str(uuid.uuid4())
        with open(SHARED_SECRET, 'w') as secret_file:
            secret_file.write(secret)
    else:
        with open(SHARED_SECRET, 'r') as secret_file:
            secret = secret_file.read().strip()
    return secret


class SharedSecretContext(OSContextGenerator):

    def __call__(self):
        if NeutronAPIContext()()['enable_dvr'] or \
                config('enable-local-dhcp-and-metadata'):
            ctxt = {
                'shared_secret': get_shared_secret(),
                'local_ip': resolve_address(),
            }
        else:
            ctxt = {}
        return ctxt


class APIIdentityServiceContext(context.IdentityServiceContext):

    def __init__(self):
        super(APIIdentityServiceContext,
              self).__init__(rel_name='neutron-plugin-api')

    def __call__(self):
        ctxt = super(APIIdentityServiceContext, self).__call__()
        if not ctxt:
            return
        for rid in relation_ids('neutron-plugin-api'):
            for unit in related_units(rid):
                rdata = relation_get(rid=rid, unit=unit)
                ctxt['region'] = rdata.get('region')
                if ctxt['region']:
                    return ctxt
        return ctxt
