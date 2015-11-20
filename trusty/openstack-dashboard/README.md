Overview
========

The OpenStack Dashboard provides a Django based web interface for use by both
administrators and users of an OpenStack Cloud.

It allows you to manage Nova, Glance, Cinder and Neutron resources within the
cloud.

Usage
=====

The OpenStack Dashboard is deployed and related to keystone:

    juju deploy openstack-dashboard
    juju add-unit openstack-dashboard keystone

The dashboard will use keystone for user authentication and authorization and
to interact with the catalog of services within the cloud.

The dashboard is accessible on:

    http(s)://service_unit_address/horizon

At a minimum, the cloud must provide Glance and Nova services.

SSL configuration
=================

To fully secure your dashboard services, you can provide a SSL key and
certificate for installation and configuration.  These are provided as
base64 encoded configuration options::

    juju set openstack-dashboard ssl_key="$(base64 my.key)" \
        ssl_cert="$(base64 my.cert)"

The service will be reconfigured to use the supplied information.

High Availability
=================

The OpenStack Dashboard charm supports HA in-conjunction with the hacluster
charm:

    juju deploy hacluster dashboard-hacluster
    juju set openstack-dashboard vip="192.168.1.200"
    juju add-relation openstack-dashboard dashboard-hacluster
    juju add-unit -n 2 openstack-dashboard

After addition of the extra 2 units completes, the dashboard will be
accessible on 192.168.1.200 with full load-balancing across all three units.

Please refer to the charm configuration for full details on all HA config
options.


Use with a Load Balancing Proxy
===============================

Instead of deploying with the hacluster charm for load balancing, its possible
to also deploy the dashboard with load balancing proxy such as HAProxy:

    juju deploy haproxy
    juju add-relation haproxy openstack-dashboard
    juju add-unit -n 2 openstack-dashboard

This option potentially provides better scale-out than using the charm in
conjunction with the hacluster charm.

Deploying from source
=====================

The minimum openstack-origin-git config required to deploy from source is:

    openstack-origin-git: include-file://horizon-juno.yaml

    horizon-juno.yaml
        repositories:
        - {name: requirements,
           repository: 'git://github.com/openstack/requirements',
           branch: stable/juno}
        - {name: horizon,
           repository: 'git://github.com/openstack/horizon',
           branch: stable/juno}

Note that there are only two 'name' values the charm knows about: 'requirements'
and 'horizon'. These repositories must correspond to these 'name' values.
Additionally, the requirements repository must be specified first and the
horizon repository must be specified last. All other repostories are installed
in the order in which they are specified.

The following is a full list of current tip repos (may not be up-to-date):

    openstack-origin-git: include-file://horizon-master.yaml

    horizon-master.yaml
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
        - {name: oslo-i18n,
           repository: 'git://github.com/openstack/oslo.i18n',
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
        - {name: python-ceilometerclient,
           repository: 'git://github.com/openstack/python-ceilometerclient',
           branch: master}
        - {name: python-cinderclient,
           repository: 'git://github.com/openstack/python-cinderclient',
           branch: master}
        - {name: python-glanceclient,
           repository: 'git://github.com/openstack/python-glanceclient',
           branch: master}
        - {name: python-heatclient,
           repository: 'git://github.com/openstack/python-heatclient',
           branch: master}
        - {name: python-keystoneclient,
           repository: 'git://github.com/openstack/python-keystoneclient',
           branch: master}
        - {name: python-neutronclient,
           repository: 'git://github.com/openstack/python-neutronclient',
           branch: master}
        - {name: python-novaclient,
           repository: 'git://github.com/openstack/python-novaclient',
           branch: master}
        - {name: python-saharaclient,
           repository: 'git://github.com/openstack/python-saharaclient',
           branch: master}
        - {name: python-swiftclient,
           repository: 'git://github.com/openstack/python-swiftclient',
           branch: master}
        - {name: python-troveclient,
           repository: 'git://github.com/openstack/python-troveclient',
           branch: master}
        - {name: xstatic-angular,
           repository: 'git://github.com/stackforge/xstatic-angular',
           branch: master}
        - {name: xstatic-angular-animate,
           repository: 'git://github.com/stackforge/xstatic-angular-animate',
           branch: master}
        - {name: xstatic-angular-bootstrap,
           repository: 'git://github.com/stackforge/xstatic-angular-bootstrap',
           branch: master}
        - {name: xstatic-angular-cookies,
           repository: 'git://github.com/stackforge/xstatic-angular-cookies',
           branch: master}
        - {name: xstatic-angular-fileupload,
           repository: 'git://github.com/stackforge/xstatic-angular-fileupload',
           branch: master}
        - {name: xstatic-angular-lrdragndrop,
           repository: 'git://github.com/stackforge/xstatic-angular-lrdragndrop',
           branch: master}
        - {name: xstatic-angular-mock,
           repository: 'git://github.com/stackforge/xstatic-angular-mock',
           branch: master}
        - {name: xstatic-angular-sanitize,
           repository: 'git://github.com/stackforge/xstatic-angular-sanitize',
           branch: master}
        - {name: xstatic-angular-smart-table,
           repository: 'git://github.com/stackforge/xstatic-angular-smart-table',
           branch: master}
        - {name: xstatic-bootstrap-datepicker,
           repository: 'git://github.com/stackforge/xstatic-bootstrap-datepicker',
           branch: master}
        - {name: xstatic-bootstrap-scss,
           repository: 'git://github.com/stackforge/xstatic-bootstrap-scss',
           branch: master}
        - {name: xstatic-d3,
           repository: 'git://github.com/stackforge/xstatic-d3',
           branch: master}
        - {name: xstatic-font-awesome,
           repository: 'git://github.com/stackforge/xstatic-font-awesome',
           branch: master}
        - {name: xstatic-hogan,
           repository: 'git://github.com/stackforge/xstatic-hogan',
           branch: master}
        - {name: xstatic-jasmine,
           repository: 'git://github.com/stackforge/xstatic-jasmine',
           branch: master}
        - {name: xstatic-jquery-migrate,
           repository: 'git://github.com/stackforge/xstatic-jquery-migrate',
           branch: master}
        - {name: xstatic-jquery.bootstrap.wizard,
           repository: 'git://github.com/stackforge/xstatic-jquery.bootstrap.wizard',
           branch: master}
        - {name: xstatic-jquery.quicksearch,
           repository: 'git://github.com/stackforge/xstatic-jquery.quicksearch',
           branch: master}
        - {name: xstatic-jquery.tablesorter,
           repository: 'git://github.com/stackforge/xstatic-jquery.tablesorter',
           branch: master}
        - {name: xstatic-jsencrypt,
           repository: 'git://github.com/stackforge/xstatic-jsencrypt',
           branch: master}
        - {name: xstatic-magic-search,
           repository: 'git://github.com/stackforge/xstatic-magic-search',
           branch: master}
        - {name: xstatic-qunit,
           repository: 'git://github.com/stackforge/xstatic-qunit',
           branch: master}
        - {name: xstatic-rickshaw,
           repository: 'git://github.com/stackforge/xstatic-rickshaw',
           branch: master}
        - {name: xstatic-spin,
           repository: 'git://github.com/stackforge/xstatic-spin',
           branch: master}
        - {name: horizon,
           repository: 'git://github.com/openstack/horizon',
           branch: master}
