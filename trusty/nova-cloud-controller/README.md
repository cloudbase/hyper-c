# nova-cloud-controller

Cloud controller node for OpenStack nova. Contains nova-schedule, nova-api, nova-network and nova-objectstore.

The neutron-api interface can be used join this charm with an external neutron-api server. If this is done
then this charm will shutdown its neutron-api service and the external charm will be registered as the
neutron-api endpoint in keystone. It will also use the quantum-security-groups setting which is passed to
it by the api service rather than its own quantum-security-groups setting.

If console access is required then console-proxy-ip should be set to a client accessible IP that resolves
to the nova-cloud-controller. If running in HA mode then the public vip is used if console-proxy-ip is set
to local. Note: The console access protocol is baked into a guest when it is created, if you change it then
console access for existing guests will stop working

**Special considerations to be deployed using Postgresql**

    juju deploy nova-cloud-controller
    juju deploy postgresql
    juju add-relation "nova-cloud-controller:pgsql-nova-db" "postgresql:db"
    juju add-relation "nova-cloud-controller:pgsql-neutron-db" "postgresql:db"

## Deploying from source

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
nova repository must be specified last. All other repositories are installed
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
