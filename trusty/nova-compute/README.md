Overview
========

This charm provides Nova Compute, the Openstack compute service. It's target
platform is Ubuntu (preferably LTS) + Openstack.

Usage
=====

The following interfaces are provided:

  - cloud-compute - Used to relate (at least) with one or more of
    nova-cloud-controller, glance, ceph, cinder, mysql, ceilometer-agent,
    rabbitmq-server, neutron

  - nrpe-external-master - Used to generate Nagios checks.

Database
========

Nova compute only requires database access if using nova-network. If using
Neutron, no direct database access is required and the shared-db relation need
not be added.

Networking
==========
This charm support nova-network (legacy) and Neutron networking.

Storage
=======
This charm supports a number of different storage backends depending on
your hypervisor type and storage relations.

Deploying from source
=====================

The minimum openstack-origin-git config required to deploy from source is:

    openstack-origin-git: include-file://nova-juno.yaml

    nova-juno.yaml
        repositories:
        - {name: requirements,
           repository: 'git://github.com/openstack/requirements',
           branch: stable/juno}
        - {name: nova,
           repository: 'git://github.com/openstack/nova',
           branch: stable/juno}

Note that there are only two 'name' values the charm knows about: 'requirements'
and 'nova'. These repositories must correspond to these 'name' values.
Additionally, the requirements repository must be specified first and the
nova repository must be specified last. All other repostories are installed
in the order in which they are specified.

The following is a full list of current tip repos (may not be up-to-date):

    openstack-origin-git: include-file://nova-master.yaml

    nova-master.yaml
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
        - {name: oslo-log,
           repository: 'git://github.com/openstack/oslo.log',
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
        - {name: sqlalchemy-migrate,
           repository: 'git://github.com/stackforge/sqlalchemy-migrate',
           branch: master}
        - {name: python-cinderclient,
           repository: 'git://github.com/openstack/python-cinderclient',
           branch: master}
        - {name: python-glanceclient,
           repository': 'git://github.com/openstack/python-glanceclient',
           branch: master}
        - {name: python-neutronlient,
           repository': 'git://github.com/openstack/python-neutronclient',
           branch: master}
        - {name: keystonemiddleware,
           repository: 'git://github.com/openstack/keystonemiddleware',
           branch: master}
        - {name: nova,
           repository: 'git://github.com/openstack/nova',
           branch: master}
