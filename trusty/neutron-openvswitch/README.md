# Overview

This subordinate charm provides the Neutron OpenvSwitch configuration for a compute node.

Once deployed it takes over the management of the Neutron base and plugin configuration on the compute node.

# Usage

To deploy (partial deployment of linked charms only):

    juju deploy rabbitmq-server
    juju deploy neutron-api
    juju deploy nova-compute
    juju deploy neutron-openvswitch
    juju add-relation neutron-openvswitch nova-compute
    juju add-relation neutron-openvswitch neutron-api
    juju add-relation neutron-openvswitch rabbitmq-server

Note that the rabbitmq-server can optionally be a different instance of the rabbitmq-server charm than used by OpenStack Nova:

    juju deploy rabbitmq-server rmq-neutron
    juju add-relation neutron-openvswitch rmq-neutron
    juju add-relation neutron-api rmq-neutron

The neutron-api and neutron-openvswitch charms must be related to the same instance of the rabbitmq-server charm.

# Restrictions

It should only be used with OpenStack Icehouse and above and requires a seperate neutron-api service to have been deployed.

# Disabling security group management

WARNING: this feature allows you to effectively disable security on your cloud!

This charm has a configuration option to allow users to disable any per-instance security group management; this must used with neutron-security-groups enabled in the neutron-api charm and could be used to turn off security on selected set of compute nodes:

    juju deploy neutron-openvswitch neutron-openvswitch-insecure
    juju set neutron-openvswitch-insecure disable-security-groups=True
    juju deploy nova-compute nova-compute-insecure
    juju add-relation nova-compute-insecure neutron-openvswitch-insecure
    ...

These compute nodes could then be accessed by cloud users via use of host aggregates with specific flavors to target instances to hypervisors with no per-instance security.

# Deploying from source

The minimum openstack-origin-git config required to deploy from source is:

    openstack-origin-git: include-file://neutron-juno.yaml

    neutron-juno.yaml
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
neutron repository must be specified last. All other repostories are installed
in the order in which they are specified.

The following is a full list of current tip repos (may not be up-to-date):

    openstack-origin-git: include-file://neutron-master.yaml

    neutron-master.yaml
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
