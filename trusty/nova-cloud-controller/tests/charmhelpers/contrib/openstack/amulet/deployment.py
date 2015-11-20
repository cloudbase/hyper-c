# Copyright 2014-2015 Canonical Limited.
#
# This file is part of charm-helpers.
#
# charm-helpers is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3 as
# published by the Free Software Foundation.
#
# charm-helpers is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with charm-helpers.  If not, see <http://www.gnu.org/licenses/>.

import re
import six
from collections import OrderedDict
from charmhelpers.contrib.amulet.deployment import (
    AmuletDeployment
)


class OpenStackAmuletDeployment(AmuletDeployment):
    """OpenStack amulet deployment.

       This class inherits from AmuletDeployment and has additional support
       that is specifically for use by OpenStack charms.
       """

    def __init__(self, series=None, openstack=None, source=None, stable=True):
        """Initialize the deployment environment."""
        super(OpenStackAmuletDeployment, self).__init__(series)
        self.openstack = openstack
        self.source = source
        self.stable = stable
        # Note(coreycb): this needs to be changed when new next branches come
        # out.
        self.current_next = "trusty"

    def _determine_branch_locations(self, other_services):
        """Determine the branch locations for the other services.

           Determine if the local branch being tested is derived from its
           stable or next (dev) branch, and based on this, use the corresonding
           stable or next branches for the other_services."""

        # Charms outside the lp:~openstack-charmers namespace
        base_charms = ['mysql', 'mongodb', 'nrpe']

        # Force these charms to current series even when using an older series.
        # ie. Use trusty/nrpe even when series is precise, as the P charm
        # does not possess the necessary external master config and hooks.
        force_series_current = ['nrpe']

        if self.series in ['precise', 'trusty']:
            base_series = self.series
        else:
            base_series = self.current_next

        for svc in other_services:
            if svc['name'] in force_series_current:
                base_series = self.current_next
            # If a location has been explicitly set, use it
            if svc.get('location'):
                continue
            if self.stable:
                temp = 'lp:charms/{}/{}'
                svc['location'] = temp.format(base_series,
                                              svc['name'])
            else:
                if svc['name'] in base_charms:
                    temp = 'lp:charms/{}/{}'
                    svc['location'] = temp.format(base_series,
                                                  svc['name'])
                else:
                    temp = 'lp:~openstack-charmers/charms/{}/{}/next'
                    svc['location'] = temp.format(self.current_next,
                                                  svc['name'])

        return other_services

    def _add_services(self, this_service, other_services):
        """Add services to the deployment and set openstack-origin/source."""
        other_services = self._determine_branch_locations(other_services)

        super(OpenStackAmuletDeployment, self)._add_services(this_service,
                                                             other_services)

        services = other_services
        services.append(this_service)

        # Charms which should use the source config option
        use_source = ['mysql', 'mongodb', 'rabbitmq-server', 'ceph',
                      'ceph-osd', 'ceph-radosgw']

        # Charms which can not use openstack-origin, ie. many subordinates
        no_origin = ['cinder-ceph', 'hacluster', 'neutron-openvswitch', 'nrpe']

        if self.openstack:
            for svc in services:
                if svc['name'] not in use_source + no_origin:
                    config = {'openstack-origin': self.openstack}
                    self.d.configure(svc['name'], config)

        if self.source:
            for svc in services:
                if svc['name'] in use_source and svc['name'] not in no_origin:
                    config = {'source': self.source}
                    self.d.configure(svc['name'], config)

    def _configure_services(self, configs):
        """Configure all of the services."""
        for service, config in six.iteritems(configs):
            self.d.configure(service, config)

    def _auto_wait_for_status(self, message=None, exclude_services=None,
                              timeout=1800):
        """Wait for all units to have a specific extended status, except
        for any defined as excluded.  Unless specified via message, any
        status containing any case of 'ready' will be considered a match.

        Examples of message usage:

          Wait for all unit status to CONTAIN any case of 'ready' or 'ok':
              message = re.compile('.*ready.*|.*ok.*', re.IGNORECASE)

          Wait for all units to reach this status (exact match):
              message = 'Unit is ready'

          Wait for all units to reach any one of these (exact match):
              message = re.compile('Unit is ready|OK|Ready')

          Wait for at least one unit to reach this status (exact match):
              message = {'ready'}

        See Amulet's sentry.wait_for_messages() for message usage detail.
        https://github.com/juju/amulet/blob/master/amulet/sentry.py

        :param message: Expected status match
        :param exclude_services: List of juju service names to ignore
        :param timeout: Maximum time in seconds to wait for status match
        :returns: None.  Raises if timeout is hit.
        """

        if not message:
            message = re.compile('.*ready.*', re.IGNORECASE)

        if not exclude_services:
            exclude_services = []

        services = list(set(self.d.services.keys()) - set(exclude_services))
        service_messages = {service: message for service in services}
        self.d.sentry.wait_for_messages(service_messages, timeout=timeout)

    def _get_openstack_release(self):
        """Get openstack release.

           Return an integer representing the enum value of the openstack
           release.
           """
        # Must be ordered by OpenStack release (not by Ubuntu release):
        (self.precise_essex, self.precise_folsom, self.precise_grizzly,
         self.precise_havana, self.precise_icehouse,
         self.trusty_icehouse, self.trusty_juno, self.utopic_juno,
         self.trusty_kilo, self.vivid_kilo, self.trusty_liberty,
         self.wily_liberty) = range(12)

        releases = {
            ('precise', None): self.precise_essex,
            ('precise', 'cloud:precise-folsom'): self.precise_folsom,
            ('precise', 'cloud:precise-grizzly'): self.precise_grizzly,
            ('precise', 'cloud:precise-havana'): self.precise_havana,
            ('precise', 'cloud:precise-icehouse'): self.precise_icehouse,
            ('trusty', None): self.trusty_icehouse,
            ('trusty', 'cloud:trusty-juno'): self.trusty_juno,
            ('trusty', 'cloud:trusty-kilo'): self.trusty_kilo,
            ('trusty', 'cloud:trusty-liberty'): self.trusty_liberty,
            ('utopic', None): self.utopic_juno,
            ('vivid', None): self.vivid_kilo,
            ('wily', None): self.wily_liberty}
        return releases[(self.series, self.openstack)]

    def _get_openstack_release_string(self):
        """Get openstack release string.

           Return a string representing the openstack release.
           """
        releases = OrderedDict([
            ('precise', 'essex'),
            ('quantal', 'folsom'),
            ('raring', 'grizzly'),
            ('saucy', 'havana'),
            ('trusty', 'icehouse'),
            ('utopic', 'juno'),
            ('vivid', 'kilo'),
            ('wily', 'liberty'),
        ])
        if self.openstack:
            os_origin = self.openstack.split(':')[1]
            return os_origin.split('%s-' % self.series)[1].split('/')[0]
        else:
            return releases[self.series]

    def get_ceph_expected_pools(self, radosgw=False):
        """Return a list of expected ceph pools in a ceph + cinder + glance
        test scenario, based on OpenStack release and whether ceph radosgw
        is flagged as present or not."""

        if self._get_openstack_release() >= self.trusty_kilo:
            # Kilo or later
            pools = [
                'rbd',
                'cinder',
                'glance'
            ]
        else:
            # Juno or earlier
            pools = [
                'data',
                'metadata',
                'rbd',
                'cinder',
                'glance'
            ]

        if radosgw:
            pools.extend([
                '.rgw.root',
                '.rgw.control',
                '.rgw',
                '.rgw.gc',
                '.users.uid'
            ])

        return pools
