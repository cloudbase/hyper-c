import amulet
import os
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


class NovaCCBasicDeployment(OpenStackAmuletDeployment):
    """Amulet tests on a basic nova cloud controller deployment."""

    def __init__(self, series=None, openstack=None, source=None, git=False,
                 stable=False):
        """Deploy the entire test environment."""
        super(NovaCCBasicDeployment, self).__init__(series, openstack,
                                                    source, stable)
        self.git = git
        self._add_services()
        self._add_relations()
        self._configure_services()
        self._deploy()

        u.log.info('Waiting on extended status checks...')
        exclude_services = ['mysql']
        self._auto_wait_for_status(exclude_services=exclude_services)

        self._initialize_tests()

    def _add_services(self):
        """Add services

           Add the services that we're testing, where nova-cc is local,
           and the rest of the service are from lp branches that are
           compatible with the local charm (e.g. stable or next).
           """
        this_service = {'name': 'nova-cloud-controller'}
        other_services = [{'name': 'mysql'},
                          {'name': 'rabbitmq-server'},
                          {'name': 'nova-compute', 'units': 2},
                          {'name': 'keystone'},
                          {'name': 'glance'}]
        super(NovaCCBasicDeployment, self)._add_services(this_service,
                                                         other_services)

    def _add_relations(self):
        """Add all of the relations for the services."""
        relations = {
            'nova-cloud-controller:shared-db': 'mysql:shared-db',
            'nova-cloud-controller:identity-service': 'keystone:'
                                                      'identity-service',
            'nova-cloud-controller:amqp': 'rabbitmq-server:amqp',
            'nova-cloud-controller:cloud-compute': 'nova-compute:'
                                                   'cloud-compute',
            'nova-cloud-controller:image-service': 'glance:image-service',
            'nova-compute:image-service': 'glance:image-service',
            'nova-compute:shared-db': 'mysql:shared-db',
            'nova-compute:amqp': 'rabbitmq-server:amqp',
            'keystone:shared-db': 'mysql:shared-db',
            'glance:identity-service': 'keystone:identity-service',
            'glance:shared-db': 'mysql:shared-db',
            'glance:amqp': 'rabbitmq-server:amqp'
        }
        super(NovaCCBasicDeployment, self)._add_relations(relations)

    def _configure_services(self):
        """Configure all of the services."""
        nova_cc_config = {}
        nova_config = {}

        if self.git:
            amulet_http_proxy = os.environ.get('AMULET_HTTP_PROXY')

            reqs_repo = 'git://github.com/openstack/requirements'
            neutron_repo = 'git://github.com/openstack/neutron'
            nova_repo = 'git://github.com/openstack/nova'
            if self._get_openstack_release() == self.trusty_icehouse:
                reqs_repo = 'git://github.com/coreycb/requirements'
                neutron_repo = 'git://github.com/coreycb/neutron'
                nova_repo = 'git://github.com/coreycb/nova'

            branch = 'stable/' + self._get_openstack_release_string()

            openstack_origin_git = {
                'repositories': [
                    {'name': 'requirements',
                     'repository': reqs_repo,
                     'branch': branch},
                    {'name': 'neutron',
                     'repository': neutron_repo,
                     'branch': branch},
                    {'name': 'nova',
                     'repository': nova_repo,
                     'branch': branch},
                ],
                'directory': '/mnt/openstack-git',
                'http_proxy': amulet_http_proxy,
                'https_proxy': amulet_http_proxy,
            }

            nova_cc_config['openstack-origin-git'] = \
                yaml.dump(openstack_origin_git)

            nova_config['openstack-origin-git'] = \
                yaml.dump(openstack_origin_git)

        # Add some rate-limiting options to the charm. These will noop before
        # icehouse.
        nova_cc_config['api-rate-limit-rules'] = \
            "( POST, '*', .*, 9999, MINUTE );"

        keystone_config = {'admin-password': 'openstack',
                           'admin-token': 'ubuntutesting'}

        configs = {'nova-cloud-controller': nova_cc_config,
                   'keystone': keystone_config, 'nova-compute': nova_config}

        super(NovaCCBasicDeployment, self)._configure_services(configs)

    def _initialize_tests(self):
        """Perform final initialization before tests get run."""
        # Access the sentries for inspecting service units
        self.mysql_sentry = self.d.sentry.unit['mysql/0']
        self.keystone_sentry = self.d.sentry.unit['keystone/0']
        self.rabbitmq_sentry = self.d.sentry.unit['rabbitmq-server/0']
        self.nova_cc_sentry = self.d.sentry.unit['nova-cloud-controller/0']
        self.nova_compute_sentry = self.d.sentry.unit['nova-compute/0']
        self.glance_sentry = self.d.sentry.unit['glance/0']

        u.log.debug('openstack release val: {}'.format(
            self._get_openstack_release()))
        u.log.debug('openstack release str: {}'.format(
            self._get_openstack_release_string()))

        # Authenticate admin with keystone
        self.keystone = u.authenticate_keystone_admin(self.keystone_sentry,
                                                      user='admin',
                                                      password='openstack',
                                                      tenant='admin')

        # Authenticate admin with glance endpoint
        self.glance = u.authenticate_glance_admin(self.keystone)

        # Create a demo tenant/role/user
        self.demo_tenant = 'demoTenant'
        self.demo_role = 'demoRole'
        self.demo_user = 'demoUser'
        if not u.tenant_exists(self.keystone, self.demo_tenant):
            tenant = self.keystone.tenants.create(tenant_name=self.demo_tenant,
                                                  description='demo tenant',
                                                  enabled=True)
            self.keystone.roles.create(name=self.demo_role)
            self.keystone.users.create(name=self.demo_user,
                                       password='password',
                                       tenant_id=tenant.id,
                                       email='demo@demo.com')

        # Authenticate demo user with keystone
        self.keystone_demo = \
            u.authenticate_keystone_user(self.keystone, user=self.demo_user,
                                         password='password',
                                         tenant=self.demo_tenant)

        # Authenticate demo user with nova-api
        self.nova_demo = u.authenticate_nova_user(self.keystone,
                                                  user=self.demo_user,
                                                  password='password',
                                                  tenant=self.demo_tenant)

    def test_100_services(self):
        """Verify the expected services are running on the corresponding
           service units."""
        u.log.debug('Checking system services on units...')
        services = {
            self.mysql_sentry: ['mysql'],
            self.rabbitmq_sentry: ['rabbitmq-server'],
            self.nova_cc_sentry: ['nova-api-ec2',
                                  'nova-api-os-compute',
                                  'nova-conductor',
                                  'nova-objectstore',
                                  'nova-cert',
                                  'nova-scheduler'],
            self.nova_compute_sentry: ['nova-compute',
                                       'nova-network',
                                       'nova-api'],
            self.keystone_sentry: ['keystone'],
            self.glance_sentry: ['glance-registry', 'glance-api']
        }

        ret = u.validate_services_by_name(services)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_102_service_catalog(self):
        """Verify that the service catalog endpoint data is valid."""
        u.log.debug('Checking keystone service catalog...')
        endpoint_vol = {'adminURL': u.valid_url,
                        'region': 'RegionOne',
                        'publicURL': u.valid_url,
                        'internalURL': u.valid_url}
        endpoint_id = {'adminURL': u.valid_url,
                       'region': 'RegionOne',
                       'publicURL': u.valid_url,
                       'internalURL': u.valid_url}

        if self._get_openstack_release() >= self.precise_folsom:
            endpoint_vol['id'] = u.not_null
            endpoint_id['id'] = u.not_null

        if self._get_openstack_release() >= self.trusty_kilo:
            expected = {'compute': [endpoint_vol], 'identity': [endpoint_id]}
        else:
            expected = {'s3': [endpoint_vol], 'compute': [endpoint_vol],
                        'ec2': [endpoint_vol], 'identity': [endpoint_id]}

        actual = self.keystone_demo.service_catalog.get_endpoints()

        ret = u.validate_svc_catalog_endpoint_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_104_openstack_compute_api_endpoint(self):
        """Verify the openstack compute api (osapi) endpoint data."""
        u.log.debug('Checking compute endpoint data...')

        endpoints = self.keystone.endpoints.list()
        admin_port = internal_port = public_port = '8774'

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
            message = 'osapi endpoint: {}'.format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_106_ec2_api_endpoint(self):
        """Verify the EC2 api endpoint data."""
        if self._get_openstack_release() >= self.trusty_kilo:
            return

        u.log.debug('Checking ec2 endpoint data...')
        endpoints = self.keystone.endpoints.list()
        admin_port = internal_port = public_port = '8773'

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
            message = 'EC2 endpoint: {}'.format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_108_s3_api_endpoint(self):
        """Verify the S3 api endpoint data."""
        if self._get_openstack_release() >= self.trusty_kilo:
            return

        u.log.debug('Checking s3 endpoint data...')
        endpoints = self.keystone.endpoints.list()
        admin_port = internal_port = public_port = '3333'
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
            message = 'S3 endpoint: {}'.format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_200_nova_cc_shared_db_relation(self):
        """Verify the nova-cc to mysql shared-db relation data"""
        u.log.debug('Checking n-c-c:mysql db relation data...')
        unit = self.nova_cc_sentry
        relation = ['shared-db', 'mysql:shared-db']

        expected = {
            'private-address': u.valid_ip,
            'nova_database': 'nova',
            'nova_username': 'nova',
            'nova_hostname': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc shared-db', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_202_mysql_shared_db_relation(self):
        """Verify the mysql to nova-cc shared-db relation data"""
        u.log.debug('Checking mysql:n-c-c db relation data...')
        unit = self.mysql_sentry
        relation = ['shared-db', 'nova-cloud-controller:shared-db']
        expected = {
            'private-address': u.valid_ip,
            'nova_password': u.not_null,
            'db_host': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('mysql shared-db', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_204_nova_cc_identity_service_relation(self):
        """Verify the nova-cc to keystone identity-service relation data"""
        u.log.debug('Checking n-c-c:keystone identity relation data...')
        unit = self.nova_cc_sentry
        relation = ['identity-service', 'keystone:identity-service']
        expected = {
            'nova_internal_url': u.valid_url,
            'nova_public_url': u.valid_url,
            'nova_service': 'nova',
            'private-address': u.valid_ip,
            'nova_region': 'RegionOne',
            'nova_admin_url': u.valid_url,
        }
        if self._get_openstack_release() < self.trusty_kilo:
            expected['s3_admin_url'] = u.valid_url
            expected['s3_internal_url'] = u.valid_url
            expected['s3_public_url'] = u.valid_url
            expected['s3_region'] = 'RegionOne'
            expected['s3_service'] = 's3'
            expected['ec2_admin_url'] = u.valid_url
            expected['ec2_internal_url'] = u.valid_url
            expected['ec2_public_url'] = u.valid_url
            expected['ec2_region'] = 'RegionOne'
            expected['ec2_service'] = 'ec2'

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_206_keystone_identity_service_relation(self):
        """Verify the keystone to nova-cc identity-service relation data"""
        u.log.debug('Checking keystone:n-c-c identity relation data...')
        unit = self.keystone_sentry
        relation = ['identity-service',
                    'nova-cloud-controller:identity-service']
        expected = {
            'service_protocol': 'http',
            'service_tenant': 'services',
            'admin_token': 'ubuntutesting',
            'service_password': u.not_null,
            'service_port': '5000',
            'auth_port': '35357',
            'auth_protocol': 'http',
            'private-address': u.valid_ip,
            'auth_host': u.valid_ip,
            'service_username': 's3_ec2_nova',
            'service_tenant_id': u.not_null,
            'service_host': u.valid_ip
        }
        if self._get_openstack_release() >= self.trusty_kilo:
            expected['service_username'] = 'nova'

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('keystone identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_208_nova_cc_amqp_relation(self):
        """Verify the nova-cc to rabbitmq-server amqp relation data"""
        u.log.debug('Checking n-c-c:rmq amqp relation data...')
        unit = self.nova_cc_sentry
        relation = ['amqp', 'rabbitmq-server:amqp']
        expected = {
            'username': 'nova',
            'private-address': u.valid_ip,
            'vhost': 'openstack'
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc amqp', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_210_rabbitmq_amqp_relation(self):
        """Verify the rabbitmq-server to nova-cc amqp relation data"""
        u.log.debug('Checking rmq:n-c-c amqp relation data...')
        unit = self.rabbitmq_sentry
        relation = ['amqp', 'nova-cloud-controller:amqp']
        expected = {
            'private-address': u.valid_ip,
            'password': u.not_null,
            'hostname': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('rabbitmq amqp', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_212_nova_cc_cloud_compute_relation(self):
        """Verify the nova-cc to nova-compute cloud-compute relation data"""
        u.log.debug('Checking n-c-c:nova-compute '
                    'cloud-compute relation data...')

        unit = self.nova_cc_sentry
        relation = ['cloud-compute', 'nova-compute:cloud-compute']
        expected = {
            'volume_service': 'cinder',
            'network_manager': 'flatdhcpmanager',
            'ec2_host': u.valid_ip,
            'private-address': u.valid_ip,
            'restart_trigger': u.not_null
        }
        if self._get_openstack_release() == self.precise_essex:
            expected['volume_service'] = 'nova-volume'

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc cloud-compute', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_214_nova_cloud_compute_relation(self):
        """Verify the nova-compute to nova-cc cloud-compute relation data"""
        u.log.debug('Checking nova-compute:n-c-c '
                    'cloud-compute relation data...')

        unit = self.nova_compute_sentry
        relation = ['cloud-compute', 'nova-cloud-controller:cloud-compute']
        expected = {
            'private-address': u.valid_ip,
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-compute cloud-compute', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_216_nova_cc_image_service_relation(self):
        """Verify the nova-cc to glance image-service relation data"""
        u.log.debug('Checking n-c-c:glance image-service relation data...')
        unit = self.nova_cc_sentry
        relation = ['image-service', 'glance:image-service']
        expected = {
            'private-address': u.valid_ip,
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc image-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_218_glance_image_service_relation(self):
        """Verify the glance to nova-cc image-service relation data"""
        u.log.debug('Checking glance:n-c-c image-service relation data...')
        unit = self.glance_sentry
        relation = ['image-service', 'nova-cloud-controller:image-service']
        expected = {
            'private-address': u.valid_ip,
            'glance-api-server': u.valid_url
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('glance image-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_300_nova_default_config(self):
        """Verify the data in the nova config file's default section."""
        # NOTE(coreycb): Currently no way to test on essex because config file
        #                has no section headers.
        if self._get_openstack_release() == self.precise_essex:
            return

        u.log.debug('Checking nova config file data...')
        unit = self.nova_cc_sentry
        conf = '/etc/nova/nova.conf'

        rmq_ncc_rel = self.rabbitmq_sentry.relation(
            'amqp', 'nova-cloud-controller:amqp')

        gl_ncc_rel = self.glance_sentry.relation(
            'image-service', 'nova-cloud-controller:image-service')

        ks_ep = self.keystone_demo.service_catalog.url_for(
            service_type='identity', endpoint_type='publicURL')

        ks_ec2 = "{}/ec2tokens".format(ks_ep)

        ks_ncc_rel = self.keystone_sentry.relation(
            'identity-service', 'nova-cloud-controller:identity-service')

        ks_uri = "http://{}:{}/".format(ks_ncc_rel['service_host'],
                                        ks_ncc_rel['service_port'])

        id_uri = "{}://{}:{}/".format(ks_ncc_rel['auth_protocol'],
                                      ks_ncc_rel['service_host'],
                                      ks_ncc_rel['auth_port'])

        db_ncc_rel = self.mysql_sentry.relation(
            'shared-db', 'nova-cloud-controller:shared-db')

        db_uri = "mysql://{}:{}@{}/{}".format('nova',
                                              db_ncc_rel['nova_password'],
                                              db_ncc_rel['db_host'],
                                              'nova')

        expected = {
            'DEFAULT': {
                'dhcpbridge_flagfile': '/etc/nova/nova.conf',
                'dhcpbridge': '/usr/bin/nova-dhcpbridge',
                'logdir': '/var/log/nova',
                'state_path': '/var/lib/nova',
                'force_dhcp_release': 'True',
                'iscsi_helper': 'tgtadm',
                'libvirt_use_virtio_for_bridges': 'True',
                'connection_type': 'libvirt',
                'root_helper': 'sudo nova-rootwrap /etc/nova/rootwrap.conf',
                'verbose': 'False',
                'debug': 'False',
                'ec2_private_dns_show_ip': 'True',
                'api_paste_config': '/etc/nova/api-paste.ini',
                'volumes_path': '/var/lib/nova/volumes',
                'enabled_apis': 'ec2,osapi_compute,metadata',
                'auth_strategy': 'keystone',
                'compute_driver': 'libvirt.LibvirtDriver',
                'keystone_ec2_url': ks_ec2,
                'network_manager': 'nova.network.manager.FlatDHCPManager',
                's3_listen_port': '3323',
                'osapi_compute_listen_port': '8764',
                'ec2_listen_port': '8763'
            }
        }
        if self._get_openstack_release() < self.trusty_kilo:
            d = 'DEFAULT'
            if self._get_openstack_release() < self.precise_icehouse:
                expected[d]['sql_connection'] = db_uri
            else:
                database = {
                    'database': {
                        'connection': db_uri
                    }
                }
                keystone_authtoken = {
                    'keystone_authtoken': {
                        'auth_uri': ks_uri,
                        'auth_host': ks_ncc_rel['service_host'],
                        'auth_port': ks_ncc_rel['auth_port'],
                        'auth_protocol': ks_ncc_rel['auth_protocol'],
                        'admin_tenant_name': ks_ncc_rel['service_tenant'],
                        'admin_user': ks_ncc_rel['service_username'],
                        'admin_password': ks_ncc_rel['service_password'],
                    }
                }
                expected.update(database)
                expected.update(keystone_authtoken)
            expected[d]['lock_path'] = '/var/lock/nova'
            expected[d]['libvirt_use_virtio_for_bridges'] = 'True'
            expected[d]['compute_driver'] = 'libvirt.LibvirtDriver'
            expected[d]['rabbit_userid'] = 'nova'
            expected[d]['rabbit_virtual_host'] = 'openstack'
            expected[d]['rabbit_password'] = rmq_ncc_rel['password']
            expected[d]['rabbit_host'] = rmq_ncc_rel['hostname']
            expected[d]['glance_api_servers'] = gl_ncc_rel['glance-api-server']

        else:
            database = {
                'database': {
                    'connection': db_uri,
                    'max_pool_size': '2',
                }
            }
            glance = {
                'glance': {
                    'api_servers': gl_ncc_rel['glance-api-server'],
                }
            }
            keystone_authtoken = {
                'keystone_authtoken': {
                    'identity_uri': id_uri,
                    'auth_uri': ks_uri,
                    'admin_tenant_name': ks_ncc_rel['service_tenant'],
                    'admin_user': ks_ncc_rel['service_username'],
                    'admin_password': ks_ncc_rel['service_password'],
                    'signing_dir': '/var/cache/nova',
                }
            }
            osapi_v3 = {
                'osapi_v3': {
                    'enabled': 'True',
                }
            }
            conductor = {
                'conductor': {
                    'workers': '2',
                }
            }
            oslo_messaging_rabbit = {
                'oslo_messaging_rabbit': {
                    'rabbit_userid': 'nova',
                    'rabbit_virtual_host': 'openstack',
                    'rabbit_password': rmq_ncc_rel['password'],
                    'rabbit_host': rmq_ncc_rel['hostname'],
                }
            }
            oslo_concurrency = {
                'oslo_concurrency': {
                    'lock_path': '/var/lock/nova',
                }
            }
            expected.update(database)
            expected.update(glance)
            expected.update(keystone_authtoken)
            expected.update(osapi_v3)
            expected.update(conductor)
            expected.update(oslo_messaging_rabbit)
            expected.update(oslo_concurrency)

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "nova config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_302_api_rate_limiting_is_enabled_for_icehouse_or_more(self):
        """
        The API rate limiting is enabled for icehouse or more. Otherwise the
        api-paste.ini file is left untouched.
        """
        u.log.debug('Checking api-paste config file data...')

        unit = self.nova_cc_sentry
        conf = '/etc/nova/api-paste.ini'
        section = "filter:ratelimit"
        factory = ("nova.api.openstack.compute.limits:RateLimitingMiddleware"
                   ".factory")

        if self._get_openstack_release() >= self.precise_icehouse:
            expected = {"paste.filter_factory": factory,
                        "limits": "( POST, '*', .*, 9999, MINUTE );"}
        else:
            expected = {"paste.filter_factory": factory}

        ret = u.validate_config_data(unit, conf, section, expected)
        if ret:
            message = "api paste config error: {}".format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_400_image_instance_create(self):
        """Create an image/instance, verify they exist, and delete them."""
        # NOTE(coreycb): Skipping failing test on essex until resolved. essex
        #                nova API calls are getting "Malformed request url
        #                (HTTP 400)".
        if self._get_openstack_release() == self.precise_essex:
            u.log.error("Skipping test (due to Essex)")
            return

        u.log.debug('Checking nova instance creation...')

        image = u.create_cirros_image(self.glance, "cirros-image")
        if not image:
            amulet.raise_status(amulet.FAIL, msg="Image create failed")

        instance = u.create_instance(self.nova_demo, "cirros-image", "cirros",
                                     "m1.tiny")
        if not instance:
            amulet.raise_status(amulet.FAIL, msg="Instance create failed")

        found = False
        for instance in self.nova_demo.servers.list():
            if instance.name == 'cirros':
                found = True
                if instance.status != 'ACTIVE':
                    msg = "cirros instance is not active"
                    amulet.raise_status(amulet.FAIL, msg=msg)

        if not found:
            message = "nova cirros instance does not exist"
            amulet.raise_status(amulet.FAIL, msg=message)

        u.delete_resource(self.glance.images, image.id,
                          msg="glance image")

        u.delete_resource(self.nova_demo.servers, instance.id,
                          msg="nova instance")

    def test_900_restart_on_config_change(self):
        """Verify that the specified services are restarted when the config
           is changed."""
        if self._get_openstack_release() == self.precise_essex:
            u.log.error("Skipping test (due to Essex)")
            return

        u.log.info('Checking that conf files and system services respond '
                   'to a charm config change...')

        sentry = self.nova_cc_sentry
        juju_service = 'nova-cloud-controller'

        # Process names, corresponding conf files
        conf_file = '/etc/nova/nova.conf'
        services = {
            'nova-api-ec2': conf_file,
            'nova-api-os-compute': conf_file,
            'nova-objectstore': conf_file,
            'nova-cert': conf_file,
            'nova-scheduler': conf_file,
            'nova-conductor': conf_file
        }

        # Expected default and alternate values
        flags_default = 'quota_cores=20,quota_instances=40,quota_ram=102400'
        flags_alt = 'quota_cores=10,quota_instances=20,quota_ram=51200'
        set_default = {'config-flags': flags_default}
        set_alternate = {'config-flags': flags_alt}

        # Make config change, check for service restarts
        u.log.debug('Making config change on {}...'.format(juju_service))
        mtime = u.get_sentry_time(sentry)
        self.d.configure(juju_service, set_alternate)

        sleep_time = 60
        for s, conf_file in services.iteritems():
            u.log.debug("Checking that service restarted: {}".format(s))
            if not u.validate_service_config_changed(sentry, mtime, s,
                                                     conf_file,
                                                     sleep_time=sleep_time):
                self.d.configure(juju_service, set_default)
                msg = "service {} didn't restart after config change".format(s)
                amulet.raise_status(amulet.FAIL, msg=msg)
            sleep_time = 0

        self.d.configure(juju_service, set_default)
