#!/usr/bin/python
#
# Create relations between a shared database to many peers.
# Join does nothing.   Peer requests access to $DATABASE from $REMOTE_HOST.
# It's up to the hooks to ensure database exists, peer has access and
# clean up grants after a broken/departed peer (TODO)
#
# Author: Adam Gandelman <adam.gandelman@canonical.com>


from common import (
    database_exists,
    create_database,
    grant_exists,
    create_grant)
import subprocess
import json
import socket
import os
import lib.utils as utils
import lib.cluster_utils as cluster
from charmhelpers.core import hookenv
from charmhelpers.contrib.network.ip import (
    get_ipv6_addr
)

LEADER_RES = 'res_mysql_vip'


def pwgen():
    return str(subprocess.check_output(['pwgen', '-s', '16'])).strip()


def relation_get():
    return json.loads(subprocess.check_output(['relation-get',
                                               '--format',
                                               'json']))


def unit_sorted(units):
    """Return a sorted list of unit names."""
    return sorted(
        units, lambda a, b: cmp(int(a.split('/')[-1]), int(b.split('/')[-1])))


def get_unit_addr(relid, unitid):
    return hookenv.relation_get(attribute='private-address',
                                unit=unitid,
                                rid=relid)


def shared_db_changed():

    def get_allowed_units(database, username):
        allowed_units = set()
        for relid in hookenv.relation_ids('shared-db'):
            for unit in hookenv.related_units(relid):
                attr = "%s_%s" % (database, 'hostname')
                hosts = hookenv.relation_get(attribute=attr, unit=unit,
                                             rid=relid)
                if not hosts:
                    hosts = [hookenv.relation_get(attribute='private-address',
                                                  unit=unit, rid=relid)]
                else:
                    # hostname can be json-encoded list of hostnames
                    try:
                        hosts = json.loads(hosts)
                    except ValueError:
                        pass

                if not isinstance(hosts, list):
                    hosts = [hosts]

                if hosts:
                    for host in hosts:
                        utils.juju_log('INFO', "Checking host '%s' grant" %
                                       (host))
                        if grant_exists(database, username, host):
                            if unit not in allowed_units:
                                allowed_units.add(unit)
                else:
                    utils.juju_log('INFO', "No hosts found for grant check")

        return allowed_units

    def configure_db(hostname,
                     database,
                     username):
        passwd_file = "/var/lib/mysql/mysql-{}.passwd".format(username)
        if hostname != local_hostname:
            try:
                remote_ip = socket.gethostbyname(hostname)
            except Exception:
                # socket.gethostbyname doesn't support ipv6
                remote_ip = hostname
        else:
            remote_ip = '127.0.0.1'

        if not os.path.exists(passwd_file):
            password = pwgen()
            with open(passwd_file, 'w') as pfile:
                pfile.write(password)
                os.chmod(pfile.name, 0600)
        else:
            with open(passwd_file) as pfile:
                password = pfile.read().strip()

        if not database_exists(database):
            create_database(database)
        if not grant_exists(database,
                            username,
                            remote_ip):
            create_grant(database,
                         username,
                         remote_ip, password)
        return password

    if not cluster.eligible_leader(LEADER_RES):
        utils.juju_log('INFO',
                       'MySQL service is peered, bailing shared-db relation'
                       ' as this service unit is not the leader')
        return

    if utils.config_get('prefer-ipv6'):
        local_hostname = get_ipv6_addr(exc_list=[utils.config_get('vip')])[0]
    else:
        local_hostname = utils.unit_get('private-address')

    settings = relation_get()
    singleset = set([
        'database',
        'username',
        'hostname'])

    if singleset.issubset(settings):
        # Process a single database configuration
        hostname = settings['hostname']
        database = settings['database']
        username = settings['username']

        # Hostname can be json-encoded list of hostnames
        try:
            hostname = json.loads(hostname)
        except ValueError:
            pass

        if isinstance(hostname, list):
            for host in hostname:
                password = configure_db(host, database, username)
        else:
            password = configure_db(hostname, database, username)

        allowed_units = " ".join(unit_sorted(get_allowed_units(database,
                                                               username)))

        if not cluster.is_clustered():
            utils.relation_set(db_host=local_hostname,
                               password=password,
                               allowed_units=allowed_units)
        else:
            utils.relation_set(db_host=utils.config_get("vip"),
                               password=password,
                               allowed_units=allowed_units)

    else:
        # Process multiple database setup requests.
        # from incoming relation data:
        #  nova_database=xxx nova_username=xxx nova_hostname=xxx
        #  quantum_database=xxx quantum_username=xxx quantum_hostname=xxx
        # create
        # {
        #   "nova": {
        #        "username": xxx,
        #        "database": xxx,
        #        "hostname": xxx
        #    },
        #    "quantum": {
        #        "username": xxx,
        #        "database": xxx,
        #        "hostname": xxx
        #    }
        # }
        #
        databases = {}
        for k, v in settings.iteritems():
            db = k.split('_')[0]
            x = '_'.join(k.split('_')[1:])
            if db not in databases:
                databases[db] = {}
            databases[db][x] = v

        return_data = {}
        for db in databases:
            if singleset.issubset(databases[db]):
                database = databases[db]['database']
                hostname = databases[db]['hostname']
                username = databases[db]['username']
                try:
                    hostname = json.loads(hostname)
                except ValueError:
                    hostname = hostname

                if isinstance(hostname, list):
                    for host in hostname:
                        password = configure_db(host, database, username)
                else:
                    password = configure_db(hostname, database, username)

                return_data['_'.join([db, 'password'])] = password
                allowed_units = unit_sorted(get_allowed_units(database,
                                                              username))
                return_data['_'.join([db, 'allowed_units'])] = \
                    " ".join(allowed_units)
        if len(return_data) > 0:
            utils.relation_set(**return_data)
        if not cluster.is_clustered():
            utils.relation_set(db_host=local_hostname)
        else:
            utils.relation_set(db_host=utils.config_get("vip"))


hooks = {"shared-db-relation-changed": shared_db_changed}

utils.do_hooks(hooks)
