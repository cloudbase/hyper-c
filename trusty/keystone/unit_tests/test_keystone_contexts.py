import os

import keystone_context as context
from mock import patch, MagicMock

from test_utils import (
    CharmTestCase
)

TO_PATCH = [
    'config',
    'determine_apache_port',
    'determine_api_port',
    'is_cert_provided_in_config',
]


class TestKeystoneContexts(CharmTestCase):

    def setUp(self):
        super(TestKeystoneContexts, self).setUp(context, TO_PATCH)

    @patch.object(context, 'is_cert_provided_in_config')
    @patch.object(context, 'mkdir')
    @patch('keystone_utils.get_ca')
    @patch('keystone_utils.ensure_permissions')
    @patch('keystone_utils.determine_ports')
    @patch('keystone_utils.is_ssl_cert_master')
    @patch('keystone_utils.is_ssl_enabled')
    @patch.object(context, 'log')
    def test_apache_ssl_context_ssl_not_master(self,
                                               mock_log,
                                               mock_is_ssl_enabled,
                                               mock_is_ssl_cert_master,
                                               mock_determine_ports,
                                               mock_ensure_permissions,
                                               mock_get_ca,
                                               mock_mkdir,
                                               mock_cert_provided_in_config):
        mock_cert_provided_in_config.return_value = False
        mock_is_ssl_enabled.return_value = True
        mock_is_ssl_cert_master.return_value = False

        context.ApacheSSLContext().configure_cert('foo')
        context.ApacheSSLContext().configure_ca()
        self.assertTrue(mock_mkdir.called)
        self.assertTrue(mock_ensure_permissions.called)
        self.assertFalse(mock_get_ca.called)

    @patch('keystone_utils.determine_ports')
    @patch('keystone_utils.is_ssl_cert_master')
    @patch('keystone_utils.is_ssl_enabled')
    @patch('charmhelpers.contrib.openstack.context.config')
    @patch('charmhelpers.contrib.openstack.context.is_clustered')
    @patch('charmhelpers.contrib.openstack.context.determine_apache_port')
    @patch('charmhelpers.contrib.openstack.context.determine_api_port')
    @patch('charmhelpers.contrib.openstack.context.unit_get')
    @patch('charmhelpers.contrib.openstack.context.https')
    def test_apache_ssl_context_service_enabled(self, mock_https,
                                                mock_unit_get,
                                                mock_determine_api_port,
                                                mock_determine_apache_port,
                                                mock_is_clustered,
                                                mock_config,
                                                mock_is_ssl_enabled,
                                                mock_is_ssl_cert_master,
                                                mock_determine_ports):
        mock_is_ssl_enabled.return_value = True
        mock_is_ssl_cert_master.return_value = True
        mock_https.return_value = True
        mock_unit_get.return_value = '1.2.3.4'
        mock_determine_api_port.return_value = '12'
        mock_determine_apache_port.return_value = '34'
        mock_is_clustered.return_value = False
        mock_config.return_value = None
        mock_determine_ports.return_value = ['12']

        ctxt = context.ApacheSSLContext()
        ctxt.enable_modules = MagicMock()
        ctxt.configure_cert = MagicMock()
        ctxt.configure_ca = MagicMock()
        ctxt.canonical_names = MagicMock()
        self.assertEquals(ctxt(), {'endpoints': [('1.2.3.4',
                                                  '1.2.3.4',
                                                  34, 12)],
                                   'namespace': 'keystone',
                                   'ext_ports': [34]})
        self.assertTrue(mock_https.called)
        mock_unit_get.assert_called_with('private-address')

    @patch('keystone_utils.api_port')
    @patch('charmhelpers.contrib.openstack.context.get_netmask_for_address')
    @patch('charmhelpers.contrib.openstack.context.get_address_in_network')
    @patch('charmhelpers.contrib.openstack.context.config')
    @patch('charmhelpers.contrib.openstack.context.relation_ids')
    @patch('charmhelpers.contrib.openstack.context.unit_get')
    @patch('charmhelpers.contrib.openstack.context.related_units')
    @patch('charmhelpers.contrib.openstack.context.relation_get')
    @patch('charmhelpers.contrib.openstack.context.log')
    @patch('__builtin__.open')
    def test_haproxy_context_service_enabled(
        self, mock_open, mock_log, mock_relation_get, mock_related_units,
            mock_unit_get, mock_relation_ids, mock_config,
            mock_get_address_in_network, mock_get_netmask_for_address,
            mock_api_port):
        os.environ['JUJU_UNIT_NAME'] = 'keystone'

        mock_relation_ids.return_value = ['identity-service:0', ]
        mock_unit_get.return_value = '1.2.3.4'
        mock_relation_get.return_value = '10.0.0.0'
        mock_related_units.return_value = ['unit/0', ]
        mock_config.return_value = None
        mock_get_address_in_network.return_value = None
        mock_get_netmask_for_address.return_value = '255.255.255.0'
        self.determine_apache_port.return_value = '34'
        mock_api_port.return_value = '12'

        ctxt = context.HAProxyContext()

        self.maxDiff = None
        self.assertEquals(
            ctxt(),
            {'listen_ports': {'admin_port': '12',
                              'public_port': '12'},
             'local_host': '127.0.0.1',
             'haproxy_host': '0.0.0.0',
             'stat_port': ':8888',
             'service_ports': {'admin-port': ['12', '34'],
                               'public-port': ['12', '34']},
             'default_backend': '1.2.3.4',
             'frontends': {'1.2.3.4': {
                 'network': '1.2.3.4/255.255.255.0',
                 'backends': {
                     'keystone': '1.2.3.4',
                     'unit-0': '10.0.0.0'
                 }
             }}
             }
        )

    @patch('charmhelpers.contrib.openstack.context.log')
    @patch('charmhelpers.contrib.openstack.context.config')
    @patch('charmhelpers.contrib.openstack.context.unit_get')
    @patch('charmhelpers.contrib.openstack.context.is_clustered')
    @patch('charmhelpers.contrib.network.ip.get_address_in_network')
    def test_canonical_names_without_network_splits(self,
                                                    mock_get_address,
                                                    mock_is_clustered,
                                                    mock_unit_get,
                                                    mock_config,
                                                    mock_log):
        NET_CONFIG = {'vip': '10.0.3.1 10.0.3.2',
                      'os-internal-network': None,
                      'os-admin-network': None,
                      'os-public-network': None}

        mock_unit_get.return_value = '10.0.3.10'
        mock_is_clustered.return_value = True
        config = {}
        config.update(NET_CONFIG)
        mock_config.side_effect = lambda key: config[key]
        apache = context.ApacheSSLContext()
        apache.canonical_names()
        msg = "Multiple networks configured but net_type" \
              " is None (os-public-network)."
        mock_log.assert_called_with(msg, level="WARNING")

    @patch.object(context, 'config')
    def test_keystone_logger_context(self, mock_config):
        ctxt = context.KeystoneLoggingContext()

        mock_config.return_value = None
        self.assertEqual({}, ctxt())

        mock_config.return_value = 'True'
        self.assertEqual({'root_level': 'DEBUG'}, ctxt())
