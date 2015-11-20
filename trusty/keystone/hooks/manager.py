#!/usr/bin/python
from keystoneclient.v2_0 import client


class KeystoneManager(object):

    def __init__(self, endpoint, token):
        self.api = client.Client(endpoint=endpoint, token=token)

    def resolve_tenant_id(self, name):
        """Find the tenant_id of a given tenant"""
        tenants = [t._info for t in self.api.tenants.list()]
        for t in tenants:
            if name == t['name']:
                return t['id']

    def resolve_role_id(self, name):
        """Find the role_id of a given role"""
        roles = [r._info for r in self.api.roles.list()]
        for r in roles:
            if name == r['name']:
                return r['id']

    def resolve_user_id(self, name):
        """Find the user_id of a given user"""
        users = [u._info for u in self.api.users.list()]
        for u in users:
            if name == u['name']:
                return u['id']

    def resolve_service_id(self, name):
        """Find the service_id of a given service"""
        services = [s._info for s in self.api.services.list()]
        for s in services:
            if name == s['name']:
                return s['id']

    def resolve_service_id_by_type(self, type):
        """Find the service_id of a given service"""
        services = [s._info for s in self.api.services.list()]
        for s in services:
            if type == s['type']:
                return s['id']
