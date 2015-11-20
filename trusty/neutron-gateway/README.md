Overview
--------

Neutron provides flexible software defined networking (SDN) for OpenStack.

This charm is designed to be used in conjunction with the rest of the OpenStack
related charms in the charm store to virtualize the network that Nova Compute
instances plug into.

It's designed as a replacement for nova-network; however it does not yet
support all of the features of nova-network (such as multihost) so may not
be suitable for all.

Neutron supports a rich plugin/extension framework for propriety networking
solutions and supports (in core) Nicira NVP, NEC, Cisco and others...

See the upstream [Neutron documentation](http://docs.openstack.org/trunk/openstack-network/admin/content/use_cases_single_router.html)
for more details.

Usage
-----

In order to use Neutron with OpenStack, you will need to deploy the
nova-compute and nova-cloud-controller charms with the network-manager
configuration set to 'Neutron':

    nova-cloud-controller:
        network-manager: Neutron

This decision must be made prior to deploying OpenStack with Juju as
Neutron is deployed baked into these charms from install onwards:

    juju deploy nova-compute
    juju deploy --config config.yaml nova-cloud-controller
    juju add-relation nova-compute nova-cloud-controller

The Neutron Gateway can then be added to the deploying:

    juju deploy neutron-gateway
    juju add-relation neutron-gateway mysql
    juju add-relation neutron-gateway rabbitmq-server
    juju add-relation neutron-gateway nova-cloud-controller

The gateway provides two key services; L3 network routing and DHCP services.

These are both required in a fully functional Neutron OpenStack deployment.

See upstream [Neutron multi extnet](http://docs.openstack.org/trunk/config-reference/content/adv_cfg_l3_agent_multi_extnet.html)

Configuration Options
---------------------

External Port Configuration
===========================

If the port to be used for external traffic is consistent across all physical
servers then is can be specified by simply setting ext-port to the nic id:

    neutron-gateway:
        ext-port: eth2

However, if it varies between hosts then the mac addresses of the external
nics for each host can be passed as a space separated list:

    neutron-gateway:
        ext-port: <MAC ext port host 1> <MAC ext port host 2> <MAC ext port host 3>


Multiple Floating Pools
=======================

If multiple floating pools are needed then an L3 agent (which corresponds to
a neutron-gateway for the sake of this charm) is needed for each one. Each
gateway needs to be deployed as a separate service so that the external
network id can be set differently for each gateway e.g.

    juju deploy neutron-gateway neutron-gateway-extnet1
    juju add-relation neutron-gateway-extnet1 mysql
    juju add-relation neutron-gateway-extnet1 rabbitmq-server
    juju add-relation neutron-gateway-extnet1 nova-cloud-controller
    juju deploy neutron-gateway neutron-gateway-extnet2
    juju add-relation neutron-gateway-extnet2 mysql
    juju add-relation neutron-gateway-extnet2 rabbitmq-server
    juju add-relation neutron-gateway-extnet2 nova-cloud-controller

    Create extnet1 and extnet2 via neutron client and take a note of their ids

    juju set neutron-gateway-extnet1 "run-internal-router=leader"
    juju set neutron-gateway-extnet2 "run-internal-router=none"
    juju set neutron-gateway-extnet1 "external-network-id=<extnet1 id>"
    juju set neutron-gateway-extnet2 "external-network-id=<extnet2 id>"

Instance MTU
============

When using Open vSwitch plugin with GRE tunnels default MTU of 1500 can cause
packet fragmentation due to GRE overhead. One solution is to increase the MTU on
physical hosts and network equipment. When this is not possible or practical the
charm's instance-mtu option can be used to reduce instance MTU via DHCP.

    juju set neutron-gateway instance-mtu=1400

OpenStack upstream documentation recommends a MTU value of 1400:
[OpenStack documentation](http://docs.openstack.org/admin-guide-cloud/content/openvswitch_plugin.html)

Note that this option was added in Havana and will be ignored in older releases.

Deploying from source
=====================

The minimum openstack-origin-git config required to deploy from source is:

    openstack-origin-git: include-file://neutron-juno.yaml

    neutron-juno.yaml
    -----------------
    repositories:
    - {name: requirements,
       repository: 'git://github.com/openstack/requirements',
       branch: stable/juno}
    - {name: neutron,
       repository: 'git://github.com/openstack/neutron',
       branch: stable/juno}

Note that there are only two 'name' values the charm knows about: 'requirements'
and 'neutron'. These repositories must correspond to these 'name' values.
Additionally, the requirements repository must be specified first and the
neutron repository must be specified last. All other repositories are installed
in the order in which they are specified.

The following is a full list of current tip repos (may not be up-to-date):

    openstack-origin-git: include-file://neutron-master.yaml

    neutron-master.yaml
    -------------------
    repositories:
    - {name: requirements,
       repository: 'git://github.com/openstack/requirements',
       branch: master}
    - {name: oslo-concurrency,
       repository: 'git://github.com/openstack/oslo.concurrency',
       branch: master}
    - {name: oslo-config,
       repository: 'git://github.com/openstack/oslo.config',
       branch: master}
    - {name: oslo-context,
       repository: 'git://github.com/openstack/oslo.context',
       branch: master}
    - {name: oslo-db,
       repository: 'git://github.com/openstack/oslo.db',
       branch: master}
    - {name: oslo-i18n,
       repository: 'git://github.com/openstack/oslo.i18n',
       branch: master}
    - {name: oslo-messaging,
       repository: 'git://github.com/openstack/oslo.messaging',
       branch: master}
    - {name: oslo-middleware,
       repository': 'git://github.com/openstack/oslo.middleware',
       branch: master}
    - {name: oslo-rootwrap',
       repository: 'git://github.com/openstack/oslo.rootwrap',
       branch: master}
    - {name: oslo-serialization,
       repository: 'git://github.com/openstack/oslo.serialization',
       branch: master}
    - {name: oslo-utils,
       repository: 'git://github.com/openstack/oslo.utils',
       branch: master}
    - {name: pbr,
       repository: 'git://github.com/openstack-dev/pbr',
       branch: master}
    - {name: stevedore,
       repository: 'git://github.com/openstack/stevedore',
       branch: 'master'}
    - {name: python-keystoneclient,
       repository: 'git://github.com/openstack/python-keystoneclient',
       branch: master}
    - {name: python-neutronclient,
       repository: 'git://github.com/openstack/python-neutronclient',
       branch: master}
    - {name: python-novaclient,
       repository': 'git://github.com/openstack/python-novaclient',
       branch: master}
    - {name: keystonemiddleware,
       repository: 'git://github.com/openstack/keystonemiddleware',
       branch: master}
    - {name: neutron-fwaas,
       repository': 'git://github.com/openstack/neutron-fwaas',
       branch: master}
    - {name: neutron-lbaas,
       repository: 'git://github.com/openstack/neutron-lbaas',
       branch: master}
    - {name: neutron-vpnaas,
       repository: 'git://github.com/openstack/neutron-vpnaas',
       branch: master}
    - {name: neutron,
       repository: 'git://github.com/openstack/neutron',
       branch: master}
