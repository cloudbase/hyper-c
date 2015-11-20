#!/usr/bin/python

"""
Basic keystone amulet functional tests.
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


class KeystoneBasicDeployment(OpenStackAmuletDeployment):
    """Amulet tests on a basic keystone deployment."""

    def __init__(self, series=None, openstack=None,
                 source=None, git=False, stable=False):
        """Deploy the entire test environment."""
        super(KeystoneBasicDeployment, self).__init__(series, openstack,
                                                      source, stable)
        self.git = git
        self._add_services()
        self._add_relations()
        self._configure_services()
        self._deploy()
        self._initialize_tests()

    def _assert_services(self, should_run):
        u.get_unit_process_ids(
            {self.keystone_sentry: ("keystone-all", "apache2", "haproxy")},
            expect_success=should_run)

    def _add_services(self):
        """Add services

           Add the services that we're testing, where keystone is local,
           and the rest of the service are from lp branches that are
           compatible with the local charm (e.g. stable or next).
           """
        this_service = {'name': 'keystone'}
        other_services = [{'name': 'mysql'},
                          {'name': 'cinder'}]
        super(KeystoneBasicDeployment, self)._add_services(this_service,
                                                           other_services)

    def _add_relations(self):
        """Add all of the relations for the services."""
        relations = {'keystone:shared-db': 'mysql:shared-db',
                     'cinder:identity-service': 'keystone:identity-service'}
        super(KeystoneBasicDeployment, self)._add_relations(relations)

    def _configure_services(self):
        """Configure all of the services."""
        keystone_config = {'admin-password': 'openstack',
                           'admin-token': 'ubuntutesting'}
        if self.git:
            amulet_http_proxy = os.environ.get('AMULET_HTTP_PROXY')

            reqs_repo = 'git://github.com/openstack/requirements'
            keystone_repo = 'git://github.com/openstack/keystone'
            if self._get_openstack_release() == self.trusty_icehouse:
                reqs_repo = 'git://github.com/coreycb/requirements'
                keystone_repo = 'git://github.com/coreycb/keystone'

            branch = 'stable/' + self._get_openstack_release_string()

            openstack_origin_git = {
                'repositories': [
                    {'name': 'requirements',
                     'repository': reqs_repo,
                     'branch': branch},
                    {'name': 'keystone',
                     'repository': keystone_repo,
                     'branch': branch},
                ],
                'directory': '/mnt/openstack-git',
                'http_proxy': amulet_http_proxy,
                'https_proxy': amulet_http_proxy,
            }
            keystone_config['openstack-origin-git'] = \
                yaml.dump(openstack_origin_git)

        mysql_config = {'dataset-size': '50%'}
        cinder_config = {'block-device': 'None'}
        configs = {
            'keystone': keystone_config,
            'mysql': mysql_config,
            'cinder': cinder_config
        }
        super(KeystoneBasicDeployment, self)._configure_services(configs)

    def _initialize_tests(self):
        """Perform final initialization before tests get run."""
        # Access the sentries for inspecting service units
        self.mysql_sentry = self.d.sentry.unit['mysql/0']
        self.keystone_sentry = self.d.sentry.unit['keystone/0']
        self.cinder_sentry = self.d.sentry.unit['cinder/0']
        u.log.debug('openstack release val: {}'.format(
            self._get_openstack_release()))
        u.log.debug('openstack release str: {}'.format(
            self._get_openstack_release_string()))

        # Let things settle a bit before moving forward
        time.sleep(30)

        # Authenticate keystone admin
        self.keystone = u.authenticate_keystone_admin(self.keystone_sentry,
                                                      user='admin',
                                                      password='openstack',
                                                      tenant='admin')

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

        # Authenticate keystone demo
        self.keystone_demo = u.authenticate_keystone_user(
            self.keystone, user=self.demo_user,
            password='password', tenant=self.demo_tenant)

    def test_100_services(self):
        """Verify the expected services are running on the corresponding
           service units."""
        services = {
            self.mysql_sentry: ['mysql'],
            self.keystone_sentry: ['keystone'],
            self.cinder_sentry: ['cinder-api',
                                 'cinder-scheduler',
                                 'cinder-volume']
        }
        ret = u.validate_services_by_name(services)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_102_keystone_tenants(self):
        """Verify all existing tenants."""
        u.log.debug('Checking keystone tenants...')
        expected = [
            {'name': 'services',
             'enabled': True,
             'description': 'Created by Juju',
             'id': u.not_null},
            {'name': 'demoTenant',
             'enabled': True,
             'description': 'demo tenant',
             'id': u.not_null},
            {'name': 'admin',
             'enabled': True,
             'description': 'Created by Juju',
             'id': u.not_null}
        ]
        actual = self.keystone.tenants.list()

        ret = u.validate_tenant_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_104_keystone_roles(self):
        """Verify all existing roles."""
        u.log.debug('Checking keystone roles...')
        expected = [
            {'name': 'demoRole',
             'id': u.not_null},
            {'name': 'Admin',
             'id': u.not_null}
        ]
        actual = self.keystone.roles.list()

        ret = u.validate_role_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_106_keystone_users(self):
        """Verify all existing roles."""
        u.log.debug('Checking keystone users...')
        expected = [
            {'name': 'demoUser',
             'enabled': True,
             'tenantId': u.not_null,
             'id': u.not_null,
             'email': 'demo@demo.com'},
            {'name': 'admin',
             'enabled': True,
             'tenantId': u.not_null,
             'id': u.not_null,
             'email': 'juju@localhost'},
            {'name': 'cinder_cinderv2',
             'enabled': True,
             'tenantId': u.not_null,
             'id': u.not_null,
             'email': u'juju@localhost'}
        ]
        actual = self.keystone.users.list()
        ret = u.validate_user_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_108_service_catalog(self):
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
            'volume': [endpoint_check],
            'identity': [endpoint_check]
        }
        actual = self.keystone.service_catalog.get_endpoints()

        ret = u.validate_svc_catalog_endpoint_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_110_keystone_endpoint(self):
        """Verify the keystone endpoint data."""
        u.log.debug('Checking keystone api endpoint data...')
        endpoints = self.keystone.endpoints.list()
        admin_port = '35357'
        internal_port = public_port = '5000'
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
                                msg='keystone endpoint: {}'.format(ret))

    def test_112_cinder_endpoint(self):
        """Verify the cinder endpoint data."""
        u.log.debug('Checking cinder endpoint...')
        endpoints = self.keystone.endpoints.list()
        admin_port = internal_port = public_port = '8776'
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
                                msg='cinder endpoint: {}'.format(ret))

    def test_200_keystone_mysql_shared_db_relation(self):
        """Verify the keystone shared-db relation data"""
        u.log.debug('Checking keystone to mysql db relation data...')
        unit = self.keystone_sentry
        relation = ['shared-db', 'mysql:shared-db']
        expected = {
            'username': 'keystone',
            'private-address': u.valid_ip,
            'hostname': u.valid_ip,
            'database': 'keystone'
        }
        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('keystone shared-db', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_201_mysql_keystone_shared_db_relation(self):
        """Verify the mysql shared-db relation data"""
        u.log.debug('Checking mysql to keystone db relation data...')
        unit = self.mysql_sentry
        relation = ['shared-db', 'keystone:shared-db']
        expected_data = {
            'private-address': u.valid_ip,
            'password': u.not_null,
            'db_host': u.valid_ip
        }
        ret = u.validate_relation_data(unit, relation, expected_data)
        if ret:
            message = u.relation_error('mysql shared-db', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_202_keystone_cinder_identity_service_relation(self):
        """Verify the keystone identity-service relation data"""
        u.log.debug('Checking keystone to cinder id relation data...')
        unit = self.keystone_sentry
        relation = ['identity-service', 'cinder:identity-service']
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
            'service_username': 'cinder_cinderv2',
            'service_tenant_id': u.not_null,
            'service_host': u.valid_ip
        }
        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('keystone identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_203_cinder_keystone_identity_service_relation(self):
        """Verify the cinder identity-service relation data"""
        u.log.debug('Checking cinder to keystone id relation data...')
        unit = self.cinder_sentry
        relation = ['identity-service', 'keystone:identity-service']
        expected = {
            'cinder_service': 'cinder',
            'cinder_region': 'RegionOne',
            'cinder_public_url': u.valid_url,
            'cinder_internal_url': u.valid_url,
            'cinder_admin_url': u.valid_url,
            'cinderv2_service': 'cinderv2',
            'cinderv2_region': 'RegionOne',
            'cinderv2_public_url': u.valid_url,
            'cinderv2_internal_url': u.valid_url,
            'cinderv2_admin_url': u.valid_url,
            'private-address': u.valid_ip,
        }
        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('cinder identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_300_keystone_default_config(self):
        """Verify the data in the keystone config file,
           comparing some of the variables vs relation data."""
        u.log.debug('Checking keystone config file...')
        unit = self.keystone_sentry
        conf = '/etc/keystone/keystone.conf'
        ks_ci_rel = unit.relation('identity-service',
                                  'cinder:identity-service')
        my_ks_rel = self.mysql_sentry.relation('shared-db',
                                               'keystone:shared-db')
        db_uri = "mysql://{}:{}@{}/{}".format('keystone',
                                              my_ks_rel['password'],
                                              my_ks_rel['db_host'],
                                              'keystone')
        expected = {
            'DEFAULT': {
                'debug': 'False',
                'verbose': 'False',
                'admin_token': ks_ci_rel['admin_token'],
                'use_syslog': 'False',
                'log_config': '/etc/keystone/logging.conf',
                'public_endpoint': u.valid_url,  # get specific
                'admin_endpoint': u.valid_url,  # get specific
            },
            'extra_headers': {
                'Distribution': 'Ubuntu'
            },
            'database': {
                'connection': db_uri,
                'idle_timeout': '200'
            }
        }

        if self._get_openstack_release() >= self.trusty_kilo:
            # Kilo and later
            expected['eventlet_server'] = {
                'admin_bind_host': '0.0.0.0',
                'public_bind_host': '0.0.0.0',
                'admin_port': '35347',
                'public_port': '4990',
            }
        else:
            # Juno and earlier
            expected['DEFAULT'].update({
                'admin_port': '35347',
                'public_port': '4990',
                'bind_host': '0.0.0.0',
            })

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "keystone config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_302_keystone_logging_config(self):
        """Verify the data in the keystone logging config file"""
        u.log.debug('Checking keystone config file...')
        unit = self.keystone_sentry
        conf = '/etc/keystone/logging.conf'
        expected = {
            'logger_root': {
                'level': 'WARNING',
                'handlers': 'file',
            },
            'handlers': {
                'keys': 'production,file,devel'
            },
            'handler_file': {
                'level': 'DEBUG',
                'args': "('/var/log/keystone/keystone.log', 'a')"
            }
        }

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "keystone logging config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_900_keystone_restart_on_config_change(self):
        """Verify that the specified services are restarted when the config
           is changed."""
        sentry = self.keystone_sentry
        juju_service = 'keystone'

        # Expected default and alternate values
        set_default = {'use-syslog': 'False'}
        set_alternate = {'use-syslog': 'True'}

        # Services which are expected to restart upon config change,
        # and corresponding config files affected by the change
        services = {'keystone-all': '/etc/keystone/keystone.conf'}

        # Make config change, check for service restarts
        u.log.debug('Making config change on {}...'.format(juju_service))
        mtime = u.get_sentry_time(sentry)
        self.d.configure(juju_service, set_alternate)

        sleep_time = 30
        for s, conf_file in services.iteritems():
            u.log.debug("Checking that service restarted: {}".format(s))
            if not u.validate_service_config_changed(sentry, mtime, s,
                                                     conf_file,
                                                     sleep_time=sleep_time):

                self.d.configure(juju_service, set_default)
                msg = "service {} didn't restart after config change".format(s)
                amulet.raise_status(amulet.FAIL, msg=msg)

        self.d.configure(juju_service, set_default)

        u.log.debug('OK')

    def test_901_pause_resume(self):
        """Test pause and resume actions."""
        unit_name = "keystone/0"
        unit = self.d.sentry.unit[unit_name]
        self._assert_services(should_run=True)
        action_id = u.run_action(unit, "pause")
        assert u.wait_on_action(action_id), "Pause action failed."

        self._assert_services(should_run=False)

        action_id = u.run_action(unit, "resume")
        assert u.wait_on_action(action_id), "Resume action failed"
        self._assert_services(should_run=True)
