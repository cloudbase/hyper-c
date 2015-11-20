import os
from testtools import TestCase
from mock import patch, MagicMock

os.environ['JUJU_UNIT_NAME'] = 'UNIT_TEST/0'  # noqa - needed for import
import rabbitmq_server_relations


class RelationUtil(TestCase):
    def setUp(self):
        self.fake_repo = {}
        super(RelationUtil, self).setUp()

    def _apt_cache(self):
        """Used for mocking out apt_pkg.Cache"""
        # mocks out the apt cache
        def cache_get(package):
            pkg = MagicMock()
            if package in self.fake_repo \
                    and 'pkg_vers' in self.fake_repo[package]:
                pkg.name = package
                pkg.current_ver.ver_str = self.fake_repo[package]['pkg_vers']
            elif (package in self.fake_repo and
                  'pkg_vers' not in self.fake_repo[package]):
                pkg.name = package
                pkg.current_ver = None
            else:
                raise KeyError
            return pkg
        cache = MagicMock()
        cache.__getitem__.side_effect = cache_get
        return cache

    @patch('rabbitmq_server_relations.peer_store_and_set')
    @patch('rabbitmq_server_relations.get_ipv6_addr')
    @patch('rabbitmq_server_relations.config')
    @patch('rabbitmq_server_relations.relation_set')
    @patch('apt_pkg.Cache')
    @patch('rabbitmq_server_relations.is_clustered')
    @patch('rabbitmq_server_relations.configure_client_ssl')
    @patch('rabbitmq_server_relations.unit_get')
    @patch('rabbitmq_server_relations.relation_get')
    @patch('rabbitmq_server_relations.is_elected_leader')
    def test_amqp_changed_compare_versions_ha_queues(
            self,
            is_elected_leader, relation_get, unit_get, configure_client_ssl,
            is_clustered, apt_cache, relation_set, mock_config,
            mock_get_ipv6_addr, mock_peer_store_and_set):
        """
        Compare version above and below 3.0.1.
        Make sure ha_queues is set correctly on each side.
        """

        def config(key):
            if key == 'prefer-ipv6':
                return False

            return None

        mock_config.side_effect = config
        host_addr = "10.1.2.3"
        unit_get.return_value = host_addr
        mock_get_ipv6_addr.return_value = [host_addr]
        is_elected_leader.return_value = True
        relation_get.return_value = {}
        is_clustered.return_value = False
        apt_cache.return_value = self._apt_cache()

        self.fake_repo = {'rabbitmq-server': {'pkg_vers': '3.0'}}
        rabbitmq_server_relations.amqp_changed(None, None)
        mock_peer_store_and_set.assert_called_with(
            relation_settings={'private-address': '10.1.2.3',
                               'hostname': host_addr,
                               'ha_queues': True},
            relation_id=None)

        self.fake_repo = {'rabbitmq-server': {'pkg_vers': '3.0.2'}}
        rabbitmq_server_relations.amqp_changed(None, None)
        mock_peer_store_and_set.assert_called_with(
            relation_settings={'private-address': '10.1.2.3',
                               'hostname': host_addr},
            relation_id=None)

    @patch('rabbitmq_server_relations.peer_store_and_set')
    @patch('rabbitmq_server_relations.get_ipv6_addr')
    @patch('rabbitmq_server_relations.config')
    @patch('rabbitmq_server_relations.relation_set')
    @patch('apt_pkg.Cache')
    @patch('rabbitmq_server_relations.is_clustered')
    @patch('rabbitmq_server_relations.configure_client_ssl')
    @patch('rabbitmq_server_relations.unit_get')
    @patch('rabbitmq_server_relations.relation_get')
    @patch('rabbitmq_server_relations.is_elected_leader')
    def test_amqp_changed_compare_versions_ha_queues_prefer_ipv6(
            self,
            is_elected_leader, relation_get, unit_get, configure_client_ssl,
            is_clustered, apt_cache, relation_set, mock_config,
            mock_get_ipv6_addr, mock_peer_store_and_set):
        """
        Compare version above and below 3.0.1.
        Make sure ha_queues is set correctly on each side.
        """

        def config(key):
            if key == 'prefer-ipv6':
                return True

            return None

        mock_config.side_effect = config
        ipv6_addr = "2001:db8:1:0:f816:3eff:fed6:c140"
        mock_get_ipv6_addr.return_value = [ipv6_addr]
        host_addr = "10.1.2.3"
        unit_get.return_value = host_addr
        is_elected_leader.return_value = True
        relation_get.return_value = {}
        is_clustered.return_value = False
        apt_cache.return_value = self._apt_cache()

        self.fake_repo = {'rabbitmq-server': {'pkg_vers': '3.0'}}
        rabbitmq_server_relations.amqp_changed(None, None)
        mock_peer_store_and_set.assert_called_with(
            relation_settings={'private-address': ipv6_addr,
                               'ha_queues': True},
            relation_id=None)

        self.fake_repo = {'rabbitmq-server': {'pkg_vers': '3.0.2'}}
        rabbitmq_server_relations.amqp_changed(None, None)
        mock_peer_store_and_set.assert_called_with(
            relation_settings={'private-address': ipv6_addr},
            relation_id=None)

    @patch.object(rabbitmq_server_relations, 'related_units')
    @patch.object(rabbitmq_server_relations, 'relation_ids')
    @patch.object(rabbitmq_server_relations, 'config')
    def test_is_sufficient_peers(self, mock_config, mock_relation_ids,
                                 mock_related_units):
        _config = {'min-cluster-size': None}
        mock_config.side_effect = lambda key: _config.get(key)
        self.assertTrue(rabbitmq_server_relations.is_sufficient_peers())

        mock_relation_ids.return_value = ['cluster:0']
        mock_related_units.return_value = ['test/0']
        _config = {'min-cluster-size': 3}
        self.assertFalse(rabbitmq_server_relations.is_sufficient_peers())

        mock_related_units.return_value = ['test/0', 'test/1']
        self.assertTrue(rabbitmq_server_relations.is_sufficient_peers())
