#!/usr/bin/python
"""
Basic neutron-api functional test.
"""

import amulet
import os
import time
import yaml

from charmhelpers.contrib.openstack.amulet.deployment import (
    OpenStackAmuletDeployment
)

from charmhelpers.contrib.openstack.amulet.utils import (
    OpenStackAmuletUtils,
    DEBUG,
    # ERROR
)

# Use DEBUG to turn on debug logging
u = OpenStackAmuletUtils(DEBUG)


class NeutronAPIBasicDeployment(OpenStackAmuletDeployment):
    """Amulet tests on a basic neutron-api deployment."""

    def __init__(self, series, openstack=None, source=None, git=False,
                 stable=False):
        """Deploy the entire test environment."""
        super(NeutronAPIBasicDeployment, self).__init__(series, openstack,
                                                        source, stable)
        self.git = git
        self._add_services()
        self._add_relations()
        self._configure_services()
        self._deploy()
        self._initialize_tests()

    def _add_services(self):
        """Add services

           Add the services that we're testing, where neutron-api is local,
           and the rest of the service are from lp branches that are
           compatible with the local charm (e.g. stable or next).
           """
        this_service = {'name': 'neutron-api'}
        other_services = [{'name': 'mysql'},
                          {'name': 'rabbitmq-server'},
                          {'name': 'keystone'},
                          {'name': 'neutron-openvswitch'},
                          {'name': 'nova-cloud-controller'},
                          {'name': 'neutron-gateway'},
                          {'name': 'nova-compute'}]
        super(NeutronAPIBasicDeployment, self)._add_services(this_service,
                                                             other_services)

    def _add_relations(self):
        """Add all of the relations for the services."""
        relations = {
            'neutron-api:shared-db': 'mysql:shared-db',
            'neutron-api:amqp': 'rabbitmq-server:amqp',
            'neutron-api:neutron-api': 'nova-cloud-controller:neutron-api',
            'neutron-api:neutron-plugin-api': 'neutron-gateway:'
                                              'neutron-plugin-api',
            'neutron-api:identity-service': 'keystone:identity-service',
            'keystone:shared-db': 'mysql:shared-db',
            'nova-compute:neutron-plugin': 'neutron-openvswitch:'
                                           'neutron-plugin',
            'nova-cloud-controller:shared-db': 'mysql:shared-db',
        }

        # NOTE(beisner): relate this separately due to the resulting
        # duplicate dictionary key if included in the relations dict.
        relations_more = {
            'neutron-api:neutron-plugin-api': 'neutron-openvswitch:'
                                              'neutron-plugin-api',
        }
        super(NeutronAPIBasicDeployment, self)._add_relations(relations)
        super(NeutronAPIBasicDeployment, self)._add_relations(relations_more)

    def _configure_services(self):
        """Configure all of the services."""
        neutron_api_config = {}
        if self.git:
            amulet_http_proxy = os.environ.get('AMULET_HTTP_PROXY')

            branch = 'stable/' + self._get_openstack_release_string()

            if self._get_openstack_release() >= self.trusty_kilo:
                openstack_origin_git = {
                    'repositories': [
                        {'name': 'requirements',
                         'repository': 'git://github.com/openstack/requirements',  # noqa
                         'branch': branch},
                        {'name': 'neutron-fwaas',
                         'repository': 'git://github.com/openstack/neutron-fwaas',  # noqa
                         'branch': branch},
                        {'name': 'neutron-lbaas',
                         'repository': 'git://github.com/openstack/neutron-lbaas',  # noqa
                         'branch': branch},
                        {'name': 'neutron-vpnaas',
                         'repository': 'git://github.com/openstack/neutron-vpnaas',  # noqa
                         'branch': branch},
                        {'name': 'neutron',
                         'repository': 'git://github.com/openstack/neutron',
                         'branch': branch},
                    ],
                    'directory': '/mnt/openstack-git',
                    'http_proxy': amulet_http_proxy,
                    'https_proxy': amulet_http_proxy,
                }
            else:
                reqs_repo = 'git://github.com/openstack/requirements'
                neutron_repo = 'git://github.com/openstack/neutron'
                if self._get_openstack_release() == self.trusty_icehouse:
                    reqs_repo = 'git://github.com/coreycb/requirements'
                    neutron_repo = 'git://github.com/coreycb/neutron'

                openstack_origin_git = {
                    'repositories': [
                        {'name': 'requirements',
                         'repository': reqs_repo,
                         'branch': branch},
                        {'name': 'neutron',
                         'repository': neutron_repo,
                         'branch': branch},
                    ],
                    'directory': '/mnt/openstack-git',
                    'http_proxy': amulet_http_proxy,
                    'https_proxy': amulet_http_proxy,
                }
            neutron_api_config['openstack-origin-git'] = \
                yaml.dump(openstack_origin_git)

        keystone_config = {'admin-password': 'openstack',
                           'admin-token': 'ubuntutesting'}
        nova_cc_config = {'network-manager': 'Quantum',
                          'quantum-security-groups': 'yes'}
        configs = {'neutron-api': neutron_api_config,
                   'keystone': keystone_config,
                   'nova-cloud-controller': nova_cc_config}
        super(NeutronAPIBasicDeployment, self)._configure_services(configs)

    def _initialize_tests(self):
        """Perform final initialization before tests get run."""
        # Access the sentries for inspecting service units
        self.mysql_sentry = self.d.sentry.unit['mysql/0']
        self.keystone_sentry = self.d.sentry.unit['keystone/0']
        self.rabbitmq_sentry = self.d.sentry.unit['rabbitmq-server/0']
        self.nova_cc_sentry = self.d.sentry.unit['nova-cloud-controller/0']
        self.neutron_gw_sentry = self.d.sentry.unit['neutron-gateway/0']
        self.neutron_api_sentry = self.d.sentry.unit['neutron-api/0']
        self.neutron_ovs_sentry = self.d.sentry.unit['neutron-openvswitch/0']
        self.nova_compute_sentry = self.d.sentry.unit['nova-compute/0']

        u.log.debug('openstack release val: {}'.format(
            self._get_openstack_release()))
        u.log.debug('openstack release str: {}'.format(
            self._get_openstack_release_string()))
        # Let things settle a bit before moving forward
        time.sleep(30)

    def test_100_services(self):
        """Verify the expected services are running on the corresponding
           service units."""
        u.log.debug('Checking status of system services...')
        neutron_api_services = ['neutron-server']
        neutron_services = ['neutron-dhcp-agent',
                            'neutron-lbaas-agent',
                            'neutron-metadata-agent',
                            'neutron-plugin-openvswitch-agent',
                            'neutron-ovs-cleanup']

        if self._get_openstack_release() <= self.trusty_juno:
            neutron_services.append('neutron-vpn-agent')

        if self._get_openstack_release() < self.trusty_kilo:
            # Juno or earlier
            neutron_services.append('neutron-metering-agent')

        nova_cc_services = ['nova-api-ec2',
                            'nova-api-os-compute',
                            'nova-objectstore',
                            'nova-cert',
                            'nova-scheduler',
                            'nova-conductor']

        services = {
            self.mysql_sentry: ['mysql'],
            self.keystone_sentry: ['keystone'],
            self.nova_cc_sentry: nova_cc_services,
            self.neutron_gw_sentry: neutron_services,
            self.neutron_api_sentry: neutron_api_services,
        }

        ret = u.validate_services_by_name(services)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_200_neutron_api_shared_db_relation(self):
        """Verify the neutron-api to mysql shared-db relation data"""
        u.log.debug('Checking neutron-api:mysql db relation data...')
        unit = self.neutron_api_sentry
        relation = ['shared-db', 'mysql:shared-db']
        expected = {
            'private-address': u.valid_ip,
            'database': 'neutron',
            'username': 'neutron',
            'hostname': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('neutron-api shared-db', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_201_shared_db_neutron_api_relation(self):
        """Verify the mysql to neutron-api shared-db relation data"""
        u.log.debug('Checking mysql:neutron-api db relation data...')
        unit = self.mysql_sentry
        relation = ['shared-db', 'neutron-api:shared-db']
        expected = {
            'db_host': u.valid_ip,
            'private-address': u.valid_ip,
            'password': u.not_null
        }

        if self._get_openstack_release() == self.precise_icehouse:
            # Precise
            expected['allowed_units'] = 'nova-cloud-controller/0 neutron-api/0'
        else:
            # Not Precise
            expected['allowed_units'] = 'neutron-api/0'

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('mysql shared-db', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_202_neutron_api_amqp_relation(self):
        """Verify the neutron-api to rabbitmq-server amqp relation data"""
        u.log.debug('Checking neutron-api:amqp relation data...')
        unit = self.neutron_api_sentry
        relation = ['amqp', 'rabbitmq-server:amqp']
        expected = {
            'username': 'neutron',
            'private-address': u.valid_ip,
            'vhost': 'openstack'
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('neutron-api amqp', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_203_amqp_neutron_api_relation(self):
        """Verify the rabbitmq-server to neutron-api amqp relation data"""
        u.log.debug('Checking amqp:neutron-api relation data...')
        unit = self.rabbitmq_sentry
        relation = ['amqp', 'neutron-api:amqp']
        expected = {
            'hostname': u.valid_ip,
            'private-address': u.valid_ip,
            'password': u.not_null
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('rabbitmq amqp', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_204_neutron_api_keystone_identity_relation(self):
        """Verify the neutron-api to keystone identity-service relation data"""
        u.log.debug('Checking neutron-api:keystone id relation data...')
        unit = self.neutron_api_sentry
        relation = ['identity-service', 'keystone:identity-service']
        api_ip = unit.relation('identity-service',
                               'keystone:identity-service')['private-address']
        api_endpoint = 'http://{}:9696'.format(api_ip)
        expected = {
            'private-address': u.valid_ip,
            'quantum_region': 'RegionOne',
            'quantum_service': 'quantum',
            'quantum_admin_url': api_endpoint,
            'quantum_internal_url': api_endpoint,
            'quantum_public_url': api_endpoint,
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('neutron-api identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_205_keystone_neutron_api_identity_relation(self):
        """Verify the keystone to neutron-api identity-service relation data"""
        u.log.debug('Checking keystone:neutron-api id relation data...')
        unit = self.keystone_sentry
        relation = ['identity-service', 'neutron-api:identity-service']
        rel_ks_id = unit.relation('identity-service',
                                  'neutron-api:identity-service')
        id_ip = rel_ks_id['private-address']
        expected = {
            'admin_token': 'ubuntutesting',
            'auth_host': id_ip,
            'auth_port': "35357",
            'auth_protocol': 'http',
            'private-address': id_ip,
            'service_host': id_ip,
        }
        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('neutron-api identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_206_neutron_api_neutron_ovs_plugin_api_relation(self):
        """Verify neutron-api to neutron-openvswitch neutron-plugin-api"""
        u.log.debug('Checking neutron-api:neutron-ovs plugin-api '
                    'relation data...')
        unit = self.neutron_api_sentry
        relation = ['neutron-plugin-api',
                    'neutron-openvswitch:neutron-plugin-api']

        u.log.debug(unit.relation(relation[0], relation[1]))
        expected = {
            'auth_host': u.valid_ip,
            'auth_port': '35357',
            'auth_protocol': 'http',
            'enable-dvr': 'False',
            'enable-l3ha': 'False',
            'l2-population': 'True',
            'neutron-security-groups': 'False',
            'overlay-network-type': 'gre',
            'private-address': u.valid_ip,
            'region': 'RegionOne',
            'service_host': u.valid_ip,
            'service_password': u.not_null,
            'service_port': '5000',
            'service_protocol': 'http',
            'service_tenant': 'services',
            'service_username': 'quantum',
        }
        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error(
                'neutron-api neutron-ovs neutronplugin-api', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_207_neutron_ovs_neutron_api_plugin_api_relation(self):
        """Verify neutron-openvswitch to neutron-api neutron-plugin-api"""
        u.log.debug('Checking neutron-ovs:neutron-api plugin-api '
                    'relation data...')
        unit = self.neutron_ovs_sentry
        relation = ['neutron-plugin-api',
                    'neutron-api:neutron-plugin-api']
        expected = {
            'private-address': u.valid_ip,
        }
        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('neutron-api neutron-plugin-api', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_208_neutron_api_novacc_relation(self):
        """Verify the neutron-api to nova-cloud-controller relation data"""
        u.log.debug('Checking neutron-api:novacc relation data...')
        unit = self.neutron_api_sentry
        relation = ['neutron-api', 'nova-cloud-controller:neutron-api']
        api_ip = unit.relation('identity-service',
                               'keystone:identity-service')['private-address']
        api_endpoint = 'http://{}:9696'.format(api_ip)
        expected = {
            'private-address': api_ip,
            'neutron-plugin': 'ovs',
            'neutron-security-groups': "no",
            'neutron-url': api_endpoint,
        }
        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('neutron-api neutron-api', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_209_novacc_neutron_api_relation(self):
        """Verify the nova-cloud-controller to neutron-api relation data"""
        u.log.debug('Checking novacc:neutron-api relation data...')
        unit = self.nova_cc_sentry
        relation = ['neutron-api', 'neutron-api:neutron-api']
        cc_ip = unit.relation('neutron-api',
                              'neutron-api:neutron-api')['private-address']
        cc_endpoint = 'http://{}:8774/v2'.format(cc_ip)
        expected = {
            'private-address': cc_ip,
            'nova_url': cc_endpoint,
        }
        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc neutron-api', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_300_neutron_config(self):
        """Verify the data in the neutron config file."""
        u.log.debug('Checking neutron.conf config file data...')
        unit = self.neutron_api_sentry
        cc_relation = self.nova_cc_sentry.relation('neutron-api',
                                                   'neutron-api:neutron-api')
        rabbitmq_relation = self.rabbitmq_sentry.relation('amqp',
                                                          'neutron-api:amqp')
        rel_napi_ks = self.keystone_sentry.relation(
            'identity-service', 'neutron-api:identity-service')

        nova_auth_url = '{}://{}:{}/v2.0'.format(rel_napi_ks['auth_protocol'],
                                                 rel_napi_ks['auth_host'],
                                                 rel_napi_ks['auth_port'])
        rel_napi_db = self.mysql_sentry.relation('shared-db',
                                                 'neutron-api:shared-db')
        db_conn = 'mysql://neutron:{}@{}/neutron'.format(
            rel_napi_db['password'], rel_napi_db['db_host'])

        conf = '/etc/neutron/neutron.conf'
        expected = {
            'DEFAULT': {
                'verbose': 'False',
                'debug': 'False',
                'bind_port': '9686',
                'nova_url': cc_relation['nova_url'],
                'nova_region_name': 'RegionOne',
                'nova_admin_username': rel_napi_ks['service_username'],
                'nova_admin_tenant_id': rel_napi_ks['service_tenant_id'],
                'nova_admin_password': rel_napi_ks['service_password'],
                'nova_admin_auth_url': nova_auth_url,
            },
            'keystone_authtoken': {
                'signing_dir': '/var/cache/neutron',
                'admin_tenant_name': 'services',
                'admin_user': 'quantum',
                'admin_password': rel_napi_ks['service_password'],
            },
            'database': {
                'connection': db_conn,
            },
        }

        if self._get_openstack_release() >= self.trusty_kilo:
            # Kilo or later
            expected['oslo_messaging_rabbit'] = {
                'rabbit_userid': 'neutron',
                'rabbit_virtual_host': 'openstack',
                'rabbit_password': rabbitmq_relation['password'],
                'rabbit_host': rabbitmq_relation['hostname']
            }
        else:
            # Juno or earlier
            expected['DEFAULT'].update({
                'rabbit_userid': 'neutron',
                'rabbit_virtual_host': 'openstack',
                'rabbit_password': rabbitmq_relation['password'],
                'rabbit_host': rabbitmq_relation['hostname']
            })
            expected['keystone_authtoken'].update({
                'service_protocol': rel_napi_ks['service_protocol'],
                'service_host': rel_napi_ks['service_host'],
                'service_port': rel_napi_ks['service_port'],
                'auth_host': rel_napi_ks['auth_host'],
                'auth_port': rel_napi_ks['auth_port'],
                'auth_protocol':  rel_napi_ks['auth_protocol']
            })

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "neutron config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_301_ml2_config(self):
        """Verify the data in the ml2 config file. This is only available
           since icehouse."""
        u.log.debug('Checking ml2 config file data...')
        unit = self.neutron_api_sentry
        conf = '/etc/neutron/plugins/ml2/ml2_conf.ini'
        neutron_api_relation = unit.relation('shared-db', 'mysql:shared-db')

        expected = {
            'ml2': {
                'type_drivers': 'gre,vlan,flat,local',
                'tenant_network_types': 'gre,vlan,flat,local',
            },
            'ml2_type_gre': {
                'tunnel_id_ranges': '1:1000'
            },
            'ml2_type_vxlan': {
                'vni_ranges': '1001:2000'
            },
            'ovs': {
                'enable_tunneling': 'True',
                'local_ip': neutron_api_relation['private-address']
            },
            'agent': {
                'tunnel_types': 'gre',
            },
            'securitygroup': {
                'enable_security_group': 'False',
            }
        }

        if self._get_openstack_release() >= self.trusty_kilo:
            # Kilo or later
            expected['ml2'].update({
                'mechanism_drivers': 'openvswitch,l2population'
            })
        else:
            # Juno or earlier
            expected['ml2'].update({
                'mechanism_drivers': 'openvswitch,hyperv,l2population'
            })

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "ml2 config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_900_restart_on_config_change(self):
        """Verify that the specified services are restarted when the
        config is changed."""

        sentry = self.neutron_api_sentry
        juju_service = 'neutron-api'

        # Expected default and alternate values
        set_default = {'debug': 'False'}
        set_alternate = {'debug': 'True'}

        # Services which are expected to restart upon config change,
        # and corresponding config files affected by the change
        services = {'neutron-server': '/etc/neutron/neutron.conf'}

        # Make config change, check for service restarts
        u.log.debug('Making config change on {}...'.format(juju_service))
        mtime = u.get_sentry_time(sentry)
        self.d.configure(juju_service, set_alternate)

        for s, conf_file in services.iteritems():
            u.log.debug("Checking that service restarted: {}".format(s))
            if not u.validate_service_config_changed(sentry, mtime, s,
                                                     conf_file,
                                                     retry_count=4,
                                                     retry_sleep_time=20,
                                                     sleep_time=20):
                self.d.configure(juju_service, set_default)
                msg = "service {} didn't restart after config change".format(s)
                amulet.raise_status(amulet.FAIL, msg=msg)

        self.d.configure(juju_service, set_default)
        u.log.debug('OK')
