#!/usr/bin/python

import amulet
import os
import time
import yaml

from neutronclient.v2_0 import client as neutronclient

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


class NeutronGatewayBasicDeployment(OpenStackAmuletDeployment):
    """Amulet tests on a basic neutron-gateway deployment."""

    def __init__(self, series, openstack=None, source=None, git=False,
                 stable=False):
        """Deploy the entire test environment."""
        super(NeutronGatewayBasicDeployment, self).__init__(series, openstack,
                                                            source, stable)
        self.git = git
        self._add_services()
        self._add_relations()
        self._configure_services()
        self._deploy()
        self._initialize_tests()

    def _add_services(self):
        """Add services

           Add the services that we're testing, where neutron-gateway is local,
           and the rest of the service are from lp branches that are
           compatible with the local charm (e.g. stable or next).
           """
        this_service = {'name': 'neutron-gateway'}
        other_services = [{'name': 'mysql'},
                          {'name': 'rabbitmq-server'},
                          {'name': 'keystone'},
                          {'name': 'nova-cloud-controller'},
                          {'name': 'neutron-api'}]

        super(NeutronGatewayBasicDeployment, self)._add_services(
            this_service, other_services)

    def _add_relations(self):
        """Add all of the relations for the services."""
        relations = {
            'keystone:shared-db': 'mysql:shared-db',
            'neutron-gateway:shared-db': 'mysql:shared-db',
            'neutron-gateway:amqp': 'rabbitmq-server:amqp',
            'nova-cloud-controller:quantum-network-service':
            'neutron-gateway:quantum-network-service',
            'nova-cloud-controller:shared-db': 'mysql:shared-db',
            'nova-cloud-controller:identity-service': 'keystone:'
                                                      'identity-service',
            'nova-cloud-controller:amqp': 'rabbitmq-server:amqp',
            'neutron-api:shared-db': 'mysql:shared-db',
            'neutron-api:amqp': 'rabbitmq-server:amqp',
            'neutron-api:neutron-api': 'nova-cloud-controller:neutron-api',
            'neutron-api:identity-service': 'keystone:identity-service'
        }
        super(NeutronGatewayBasicDeployment, self)._add_relations(relations)

    def _configure_services(self):
        """Configure all of the services."""
        neutron_gateway_config = {}
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

            neutron_gateway_config['openstack-origin-git'] = \
                yaml.dump(openstack_origin_git)

        keystone_config = {'admin-password': 'openstack',
                           'admin-token': 'ubuntutesting'}
        nova_cc_config = {'network-manager': 'Quantum',
                          'quantum-security-groups': 'yes'}
        configs = {'neutron-gateway': neutron_gateway_config,
                   'keystone': keystone_config,
                   'nova-cloud-controller': nova_cc_config}
        super(NeutronGatewayBasicDeployment, self)._configure_services(configs)

    def _initialize_tests(self):
        """Perform final initialization before tests get run."""
        # Access the sentries for inspecting service units
        self.mysql_sentry = self.d.sentry.unit['mysql/0']
        self.keystone_sentry = self.d.sentry.unit['keystone/0']
        self.rmq_sentry = self.d.sentry.unit['rabbitmq-server/0']
        self.nova_cc_sentry = self.d.sentry.unit['nova-cloud-controller/0']
        self.neutron_gateway_sentry = self.d.sentry.unit['neutron-gateway/0']
        self.neutron_api_sentry = self.d.sentry.unit['neutron-api/0']

        # Let things settle a bit before moving forward
        time.sleep(30)

        # Authenticate admin with keystone
        self.keystone = u.authenticate_keystone_admin(self.keystone_sentry,
                                                      user='admin',
                                                      password='openstack',
                                                      tenant='admin')

        # Authenticate admin with neutron
        ep = self.keystone.service_catalog.url_for(service_type='identity',
                                                   endpoint_type='publicURL')
        self.neutron = neutronclient.Client(auth_url=ep,
                                            username='admin',
                                            password='openstack',
                                            tenant_name='admin',
                                            region_name='RegionOne')

    def test_100_services(self):
        """Verify the expected services are running on the corresponding
           service units."""
        neutron_services = ['neutron-dhcp-agent',
                            'neutron-lbaas-agent',
                            'neutron-metadata-agent',
                            'neutron-metering-agent',
                            'neutron-ovs-cleanup',
                            'neutron-plugin-openvswitch-agent']

        if self._get_openstack_release() <= self.trusty_juno:
            neutron_services.append('neutron-vpn-agent')

        nova_cc_services = ['nova-api-ec2',
                            'nova-api-os-compute',
                            'nova-objectstore',
                            'nova-cert',
                            'nova-scheduler',
                            'nova-conductor']

        commands = {
            self.mysql_sentry: ['mysql'],
            self.keystone_sentry: ['keystone'],
            self.nova_cc_sentry: nova_cc_services,
            self.neutron_gateway_sentry: neutron_services
        }

        ret = u.validate_services_by_name(commands)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_102_service_catalog(self):
        """Verify that the service catalog endpoint data is valid."""
        u.log.debug('Checking keystone service catalog...')
        endpoint_check = {
            'adminURL': u.valid_url,
            'id': u.not_null,
            'region': 'RegionOne',
            'publicURL': u.valid_url,
            'internalURL': u.valid_url
        }
        expected = {
            'network': [endpoint_check],
            'compute': [endpoint_check],
            'identity': [endpoint_check]
        }
        actual = self.keystone.service_catalog.get_endpoints()

        ret = u.validate_svc_catalog_endpoint_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_104_network_endpoint(self):
        """Verify the neutron network endpoint data."""
        u.log.debug('Checking neutron network api endpoint data...')
        endpoints = self.keystone.endpoints.list()
        admin_port = internal_port = public_port = '9696'
        expected = {
            'id': u.not_null,
            'region': 'RegionOne',
            'adminurl': u.valid_url,
            'internalurl': u.valid_url,
            'publicurl': u.valid_url,
            'service_id': u.not_null
        }
        ret = u.validate_endpoint_data(endpoints, admin_port, internal_port,
                                       public_port, expected)

        if ret:
            amulet.raise_status(amulet.FAIL,
                                msg='glance endpoint: {}'.format(ret))

    def test_110_users(self):
        """Verify expected users."""
        u.log.debug('Checking keystone users...')
        expected = [
            {'name': 'admin',
             'enabled': True,
             'tenantId': u.not_null,
             'id': u.not_null,
             'email': 'juju@localhost'},
            {'name': 'quantum',
             'enabled': True,
             'tenantId': u.not_null,
             'id': u.not_null,
             'email': 'juju@localhost'}
        ]

        if self._get_openstack_release() >= self.trusty_kilo:
            # Kilo or later
            expected.append({
                'name': 'nova',
                'enabled': True,
                'tenantId': u.not_null,
                'id': u.not_null,
                'email': 'juju@localhost'
            })
        else:
            # Juno and earlier
            expected.append({
                'name': 's3_ec2_nova',
                'enabled': True,
                'tenantId': u.not_null,
                'id': u.not_null,
                'email': 'juju@localhost'
            })

        actual = self.keystone.users.list()
        ret = u.validate_user_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_200_neutron_gateway_mysql_shared_db_relation(self):
        """Verify the neutron-gateway to mysql shared-db relation data"""
        u.log.debug('Checking neutron-gateway:mysql db relation data...')
        unit = self.neutron_gateway_sentry
        relation = ['shared-db', 'mysql:shared-db']
        expected = {
            'private-address': u.valid_ip,
            'database': 'nova',
            'username': 'nova',
            'hostname': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('neutron-gateway shared-db', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_201_mysql_neutron_gateway_shared_db_relation(self):
        """Verify the mysql to neutron-gateway shared-db relation data"""
        u.log.debug('Checking mysql:neutron-gateway db relation data...')
        unit = self.mysql_sentry
        relation = ['shared-db', 'neutron-gateway:shared-db']
        expected = {
            'private-address': u.valid_ip,
            'password': u.not_null,
            'db_host': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('mysql shared-db', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_202_neutron_gateway_rabbitmq_amqp_relation(self):
        """Verify the neutron-gateway to rabbitmq-server amqp relation data"""
        u.log.debug('Checking neutron-gateway:rmq amqp relation data...')
        unit = self.neutron_gateway_sentry
        relation = ['amqp', 'rabbitmq-server:amqp']
        expected = {
            'username': 'neutron',
            'private-address': u.valid_ip,
            'vhost': 'openstack'
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('neutron-gateway amqp', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_203_rabbitmq_neutron_gateway_amqp_relation(self):
        """Verify the rabbitmq-server to neutron-gateway amqp relation data"""
        u.log.debug('Checking rmq:neutron-gateway amqp relation data...')
        unit = self.rmq_sentry
        relation = ['amqp', 'neutron-gateway:amqp']
        expected = {
            'private-address': u.valid_ip,
            'password': u.not_null,
            'hostname': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('rabbitmq amqp', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_204_neutron_gateway_network_service_relation(self):
        """Verify the neutron-gateway to nova-cc quantum-network-service
           relation data"""
        u.log.debug('Checking neutron-gateway:nova-cc net svc '
                    'relation data...')
        unit = self.neutron_gateway_sentry
        relation = ['quantum-network-service',
                    'nova-cloud-controller:quantum-network-service']
        expected = {
            'private-address': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('neutron-gateway network-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_205_nova_cc_network_service_relation(self):
        """Verify the nova-cc to neutron-gateway quantum-network-service
           relation data"""
        u.log.debug('Checking nova-cc:neutron-gateway net svc '
                    'relation data...')
        unit = self.nova_cc_sentry
        relation = ['quantum-network-service',
                    'neutron-gateway:quantum-network-service']
        expected = {
            'service_protocol': 'http',
            'service_tenant': 'services',
            'quantum_url': u.valid_url,
            'quantum_port': '9696',
            'service_port': '5000',
            'region': 'RegionOne',
            'service_password': u.not_null,
            'quantum_host': u.valid_ip,
            'auth_port': '35357',
            'auth_protocol': 'http',
            'private-address': u.valid_ip,
            'keystone_host': u.valid_ip,
            'quantum_plugin': 'ovs',
            'auth_host': u.valid_ip,
            'service_tenant_name': 'services'
        }

        if self._get_openstack_release() >= self.trusty_kilo:
            # Kilo or later
            expected['service_username'] = 'nova'
        else:
            # Juno or earlier
            expected['service_username'] = 's3_ec2_nova'

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc network-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_206_neutron_api_shared_db_relation(self):
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

    def test_207_shared_db_neutron_api_relation(self):
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

    def test_208_neutron_api_amqp_relation(self):
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

    def test_209_amqp_neutron_api_relation(self):
        """Verify the rabbitmq-server to neutron-api amqp relation data"""
        u.log.debug('Checking amqp:neutron-api relation data...')
        unit = self.rmq_sentry
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

    def test_210_neutron_api_keystone_identity_relation(self):
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

    def test_211_keystone_neutron_api_identity_relation(self):
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

    def test_212_neutron_api_novacc_relation(self):
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

    def test_213_novacc_neutron_api_relation(self):
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
        u.log.debug('Checking neutron gateway config file data...')
        unit = self.neutron_gateway_sentry
        rmq_ng_rel = self.rmq_sentry.relation(
            'amqp', 'neutron-gateway:amqp')

        conf = '/etc/neutron/neutron.conf'
        expected = {
            'DEFAULT': {
                'verbose': 'False',
                'debug': 'False',
                'core_plugin': 'neutron.plugins.ml2.plugin.Ml2Plugin',
                'control_exchange': 'neutron',
                'notification_driver': 'neutron.openstack.common.notifier.'
                                       'list_notifier',
                'list_notifier_drivers': 'neutron.openstack.common.'
                                         'notifier.rabbit_notifier',
            },
            'agent': {
                'root_helper': 'sudo /usr/bin/neutron-rootwrap '
                               '/etc/neutron/rootwrap.conf'
            }
        }

        if self._get_openstack_release() >= self.trusty_kilo:
            # Kilo or later
            expected['oslo_messaging_rabbit'] = {
                'rabbit_userid': 'neutron',
                'rabbit_virtual_host': 'openstack',
                'rabbit_password': rmq_ng_rel['password'],
                'rabbit_host': rmq_ng_rel['hostname'],
            }
            expected['oslo_concurrency'] = {
                'lock_path': '/var/lock/neutron'
            }
        else:
            # Juno or earlier
            expected['DEFAULT'].update({
                'rabbit_userid': 'neutron',
                'rabbit_virtual_host': 'openstack',
                'rabbit_password': rmq_ng_rel['password'],
                'rabbit_host': rmq_ng_rel['hostname'],
                'lock_path': '/var/lock/neutron',
            })

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "neutron config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_301_neutron_ml2_config(self):
        """Verify the data in the ml2 config file. This is only available
           since icehouse."""
        u.log.debug('Checking neutron gateway ml2 config file data...')
        if self._get_openstack_release() < self.precise_icehouse:
            return

        unit = self.neutron_gateway_sentry
        conf = '/etc/neutron/plugins/ml2/ml2_conf.ini'
        ng_db_rel = unit.relation('shared-db', 'mysql:shared-db')

        expected = {
            'ml2': {
                'type_drivers': 'gre,vxlan,vlan,flat',
                'tenant_network_types': 'gre,vxlan,vlan,flat',
                'mechanism_drivers': 'openvswitch,hyperv,l2population'
            },
            'ml2_type_gre': {
                'tunnel_id_ranges': '1:1000'
            },
            'ml2_type_vxlan': {
                'vni_ranges': '1001:2000'
            },
            'ovs': {
                'enable_tunneling': 'True',
                'local_ip': ng_db_rel['private-address']
            },
            'agent': {
                'tunnel_types': 'gre',
                'l2_population': 'False'
            },
            'securitygroup': {
                'firewall_driver': 'neutron.agent.linux.iptables_firewall.'
                                   'OVSHybridIptablesFirewallDriver'
            }
        }

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "ml2 config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_302_neutron_dhcp_agent_config(self):
        """Verify the data in the dhcp agent config file."""
        u.log.debug('Checking neutron gateway dhcp agent config file data...')
        unit = self.neutron_gateway_sentry
        conf = '/etc/neutron/dhcp_agent.ini'
        expected = {
            'state_path': '/var/lib/neutron',
            'interface_driver': 'neutron.agent.linux.interface.'
                                'OVSInterfaceDriver',
            'dhcp_driver': 'neutron.agent.linux.dhcp.Dnsmasq',
            'root_helper': 'sudo /usr/bin/neutron-rootwrap '
                           '/etc/neutron/rootwrap.conf',
            'ovs_use_veth': 'True'
        }
        section = 'DEFAULT'

        ret = u.validate_config_data(unit, conf, section, expected)
        if ret:
            message = "dhcp agent config error: {}".format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_303_neutron_fwaas_driver_config(self):
        """Verify the data in the fwaas driver config file.  This is only
           available since havana."""
        u.log.debug('Checking neutron gateway fwaas config file data...')
        unit = self.neutron_gateway_sentry
        conf = '/etc/neutron/fwaas_driver.ini'
        expected = {
            'enabled': 'True'
        }
        section = 'fwaas'

        if self._get_openstack_release() >= self.trusty_kilo:
            # Kilo or later
            expected['driver'] = ('neutron_fwaas.services.firewall.drivers.'
                                  'linux.iptables_fwaas.IptablesFwaasDriver')
        else:
            # Juno or earlier
            expected['driver'] = ('neutron.services.firewall.drivers.linux.'
                                  'iptables_fwaas.IptablesFwaasDriver')

        ret = u.validate_config_data(unit, conf, section, expected)
        if ret:
            message = "fwaas driver config error: {}".format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_304_neutron_l3_agent_config(self):
        """Verify the data in the l3 agent config file."""
        u.log.debug('Checking neutron gateway l3 agent config file data...')
        unit = self.neutron_gateway_sentry
        ncc_ng_rel = self.nova_cc_sentry.relation(
            'quantum-network-service',
            'neutron-gateway:quantum-network-service')
        ep = self.keystone.service_catalog.url_for(service_type='identity',
                                                   endpoint_type='publicURL')

        conf = '/etc/neutron/l3_agent.ini'
        expected = {
            'interface_driver': 'neutron.agent.linux.interface.'
                                'OVSInterfaceDriver',
            'auth_url': ep,
            'auth_region': 'RegionOne',
            'admin_tenant_name': 'services',
            'admin_password': ncc_ng_rel['service_password'],
            'root_helper': 'sudo /usr/bin/neutron-rootwrap '
                           '/etc/neutron/rootwrap.conf',
            'ovs_use_veth': 'True',
            'handle_internal_only_routers': 'True'
        }
        section = 'DEFAULT'

        if self._get_openstack_release() >= self.trusty_kilo:
            # Kilo or later
            expected['admin_user'] = 'nova'
        else:
            # Juno or earlier
            expected['admin_user'] = 's3_ec2_nova'

        ret = u.validate_config_data(unit, conf, section, expected)
        if ret:
            message = "l3 agent config error: {}".format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_305_neutron_lbaas_agent_config(self):
        """Verify the data in the lbaas agent config file. This is only
           available since havana."""
        u.log.debug('Checking neutron gateway lbaas config file data...')
        if self._get_openstack_release() < self.precise_havana:
            return

        unit = self.neutron_gateway_sentry
        conf = '/etc/neutron/lbaas_agent.ini'
        expected = {
            'DEFAULT': {
                'interface_driver': 'neutron.agent.linux.interface.'
                                    'OVSInterfaceDriver',
                'periodic_interval': '10',
                'ovs_use_veth': 'False',
            },
            'haproxy': {
                'loadbalancer_state_path': '$state_path/lbaas',
                'user_group': 'nogroup'
            }
        }

        if self._get_openstack_release() >= self.trusty_kilo:
            # Kilo or later
            expected['DEFAULT']['device_driver'] = \
                ('neutron_lbaas.services.loadbalancer.drivers.haproxy.'
                 'namespace_driver.HaproxyNSDriver')
        else:
            # Juno or earlier
            expected['DEFAULT']['device_driver'] = \
                ('neutron.services.loadbalancer.drivers.haproxy.'
                 'namespace_driver.HaproxyNSDriver')

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "lbaas agent config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_306_neutron_metadata_agent_config(self):
        """Verify the data in the metadata agent config file."""
        u.log.debug('Checking neutron gateway metadata agent '
                    'config file data...')
        unit = self.neutron_gateway_sentry
        ep = self.keystone.service_catalog.url_for(service_type='identity',
                                                   endpoint_type='publicURL')
        ng_db_rel = unit.relation('shared-db',
                                  'mysql:shared-db')
        nova_cc_relation = self.nova_cc_sentry.relation(
            'quantum-network-service',
            'neutron-gateway:quantum-network-service')

        conf = '/etc/neutron/metadata_agent.ini'
        expected = {
            'auth_url': ep,
            'auth_region': 'RegionOne',
            'admin_tenant_name': 'services',
            'admin_password': nova_cc_relation['service_password'],
            'root_helper': 'sudo neutron-rootwrap '
                           '/etc/neutron/rootwrap.conf',
            'state_path': '/var/lib/neutron',
            'nova_metadata_ip': ng_db_rel['private-address'],
            'nova_metadata_port': '8775',
            'cache_url': 'memory://?default_ttl=5'
        }
        section = 'DEFAULT'

        if self._get_openstack_release() >= self.trusty_kilo:
            # Kilo or later
            expected['admin_user'] = 'nova'
        else:
            # Juno or earlier
            expected['admin_user'] = 's3_ec2_nova'

        ret = u.validate_config_data(unit, conf, section, expected)
        if ret:
            message = "metadata agent config error: {}".format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_307_neutron_metering_agent_config(self):
        """Verify the data in the metering agent config file.  This is only
           available since havana."""
        u.log.debug('Checking neutron gateway metering agent '
                    'config file data...')
        unit = self.neutron_gateway_sentry
        conf = '/etc/neutron/metering_agent.ini'
        expected = {
            'driver': 'neutron.services.metering.drivers.iptables.'
                      'iptables_driver.IptablesMeteringDriver',
            'measure_interval': '30',
            'report_interval': '300',
            'interface_driver': 'neutron.agent.linux.interface.'
                                'OVSInterfaceDriver',
            'use_namespaces': 'True'
        }
        section = 'DEFAULT'

        ret = u.validate_config_data(unit, conf, section, expected)
        if ret:
            message = "metering agent config error: {}".format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_308_neutron_nova_config(self):
        """Verify the data in the nova config file."""
        u.log.debug('Checking neutron gateway nova config file data...')
        unit = self.neutron_gateway_sentry
        conf = '/etc/nova/nova.conf'

        rabbitmq_relation = self.rmq_sentry.relation(
            'amqp', 'neutron-gateway:amqp')
        nova_cc_relation = self.nova_cc_sentry.relation(
            'quantum-network-service',
            'neutron-gateway:quantum-network-service')
        ep = self.keystone.service_catalog.url_for(service_type='identity',
                                                   endpoint_type='publicURL')

        expected = {
            'DEFAULT': {
                'logdir': '/var/log/nova',
                'state_path': '/var/lib/nova',
                'root_helper': 'sudo nova-rootwrap /etc/nova/rootwrap.conf',
                'verbose': 'False',
                'use_syslog': 'False',
                'api_paste_config': '/etc/nova/api-paste.ini',
                'enabled_apis': 'metadata',
                'multi_host': 'True',
                'network_api_class': 'nova.network.neutronv2.api.API',
            }
        }

        if self._get_openstack_release() >= self.trusty_kilo:
            # Kilo or later
            expected['oslo_messaging_rabbit'] = {
                'rabbit_userid': 'neutron',
                'rabbit_virtual_host': 'openstack',
                'rabbit_password': rabbitmq_relation['password'],
                'rabbit_host': rabbitmq_relation['hostname'],
            }
            expected['oslo_concurrency'] = {
                'lock_path': '/var/lock/nova'
            }
            expected['neutron'] = {
                'auth_strategy': 'keystone',
                'url': nova_cc_relation['quantum_url'],
                'admin_tenant_name': 'services',
                'admin_username': 'nova',
                'admin_password': nova_cc_relation['service_password'],
                'admin_auth_url': ep,
                'service_metadata_proxy': 'True',
                'metadata_proxy_shared_secret': u.not_null
            }
        else:
            # Juno or earlier
            expected['DEFAULT'].update({
                'rabbit_userid': 'neutron',
                'rabbit_virtual_host': 'openstack',
                'rabbit_password': rabbitmq_relation['password'],
                'rabbit_host': rabbitmq_relation['hostname'],
                'lock_path': '/var/lock/nova',
                'neutron_auth_strategy': 'keystone',
                'neutron_url': nova_cc_relation['quantum_url'],
                'neutron_admin_tenant_name': 'services',
                'neutron_admin_username': 's3_ec2_nova',
                'neutron_admin_password': nova_cc_relation['service_password'],
                'neutron_admin_auth_url': ep,
                'service_neutron_metadata_proxy': 'True',
            })

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "nova config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_309_neutron_vpn_agent_config(self):
        """Verify the data in the vpn agent config file.  This isn't available
           prior to havana."""
        u.log.debug('Checking neutron gateway vpn agent config file data...')
        unit = self.neutron_gateway_sentry
        conf = '/etc/neutron/vpn_agent.ini'
        expected = {
            'ipsec': {
                'ipsec_status_check_interval': '60'
            }
        }

        if self._get_openstack_release() >= self.trusty_kilo:
            # Kilo or later
            expected['vpnagent'] = {
                'vpn_device_driver': 'neutron_vpnaas.services.vpn.'
                                     'device_drivers.ipsec.OpenSwanDriver'
            }
        else:
            # Juno or earlier
            expected['vpnagent'] = {
                'vpn_device_driver': 'neutron.services.vpn.device_drivers.'
                                     'ipsec.OpenSwanDriver'
            }

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "vpn agent config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_400_create_network(self):
        """Create a network, verify that it exists, and then delete it."""
        u.log.debug('Creating neutron network...')
        self.neutron.format = 'json'
        net_name = 'ext_net'

        # Verify that the network doesn't exist
        networks = self.neutron.list_networks(name=net_name)
        net_count = len(networks['networks'])
        if net_count != 0:
            msg = "Expected zero networks, found {}".format(net_count)
            amulet.raise_status(amulet.FAIL, msg=msg)

        # Create a network and verify that it exists
        network = {'name': net_name}
        self.neutron.create_network({'network': network})

        networks = self.neutron.list_networks(name=net_name)
        net_len = len(networks['networks'])
        if net_len != 1:
            msg = "Expected 1 network, found {}".format(net_len)
            amulet.raise_status(amulet.FAIL, msg=msg)

        u.log.debug('Confirming new neutron network...')
        network = networks['networks'][0]
        if network['name'] != net_name:
            amulet.raise_status(amulet.FAIL, msg="network ext_net not found")

        # Cleanup
        u.log.debug('Deleting neutron network...')
        self.neutron.delete_network(network['id'])

    def test_900_restart_on_config_change(self):
        """Verify that the specified services are restarted when the
        config is changed."""

        sentry = self.neutron_gateway_sentry
        juju_service = 'neutron-gateway'

        # Expected default and alternate values
        set_default = {'debug': 'False'}
        set_alternate = {'debug': 'True'}

        # Services which are expected to restart upon config change,
        # and corresponding config files affected by the change
        conf_file = '/etc/neutron/neutron.conf'
        services = {
            'neutron-dhcp-agent': conf_file,
            'neutron-lbaas-agent': conf_file,
            'neutron-metadata-agent': conf_file,
            'neutron-metering-agent': conf_file,
            'neutron-openvswitch-agent': conf_file,
        }

        if self._get_openstack_release() <= self.trusty_juno:
            services.update({'neutron-vpn-agent': conf_file})

        # Make config change, check for svc restart, conf file mod time change
        u.log.debug('Making config change on {}...'.format(juju_service))
        mtime = u.get_sentry_time(sentry)
        self.d.configure(juju_service, set_alternate)

        # sleep_time = 90
        for s, conf_file in services.iteritems():
            u.log.debug("Checking that service restarted: {}".format(s))
            if not u.validate_service_config_changed(sentry, mtime, s,
                                                     conf_file):
                self.d.configure(juju_service, set_default)
                msg = "service {} didn't restart after config change".format(s)
                amulet.raise_status(amulet.FAIL, msg=msg)

            # Only do initial sleep on first service check
            # sleep_time = 0

        self.d.configure(juju_service, set_default)
