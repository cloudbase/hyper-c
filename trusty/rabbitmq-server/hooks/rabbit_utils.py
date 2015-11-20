import os
import pwd
import grp
import re
import socket
import sys
import subprocess
import glob
import tempfile

from charmhelpers.contrib.openstack.utils import (
    get_hostname,
)

from charmhelpers.core.hookenv import (
    config,
    relation_ids,
    relation_get,
    related_units,
    log, ERROR,
    INFO,
    service_name
)

from charmhelpers.core.host import (
    pwgen,
    mkdir,
    write_file,
    lsb_release,
    cmp_pkgrevno
)

from charmhelpers.core.templating import render

from charmhelpers.contrib.peerstorage import (
    peer_store,
    peer_retrieve
)

from collections import OrderedDict

PACKAGES = ['rabbitmq-server', 'python-amqplib']

RABBITMQ_CTL = '/usr/sbin/rabbitmqctl'
COOKIE_PATH = '/var/lib/rabbitmq/.erlang.cookie'
ENV_CONF = '/etc/rabbitmq/rabbitmq-env.conf'
RABBITMQ_CONF = '/etc/rabbitmq/rabbitmq.config'
ENABLED_PLUGINS = '/etc/rabbitmq/enabled_plugins'
RABBIT_USER = 'rabbitmq'
LIB_PATH = '/var/lib/rabbitmq/'
HOSTS_FILE = '/etc/hosts'

_named_passwd = '/var/lib/charm/{}/{}.passwd'
_local_named_passwd = '/var/lib/charm/{}/{}.local_passwd'


# hook_contexts are used as a convenient mechanism to render templates
# logically, consider building a hook_context for template rendering so
# the charm doesn't concern itself with template specifics etc.
CONFIG_FILES = OrderedDict([
    (RABBITMQ_CONF, {
        'hook_contexts': None,
        'services': ['rabbitmq-server']
    }),
    (ENV_CONF, {
        'hook_contexts': None,
        'services': ['rabbitmq-server']
    }),
    (ENABLED_PLUGINS, {
        'hook_contexts': None,
        'services': ['rabbitmq-server']
    }),
])


class RabbitmqError(Exception):
    pass


def list_vhosts():
    """
    Returns a list of all the available vhosts
    """
    try:
        output = subprocess.check_output([RABBITMQ_CTL, 'list_vhosts'])

        # NOTE(jamespage): Earlier rabbitmqctl versions append "...done"
        #                  to the output of list_vhosts
        if '...done' in output:
            return output.split('\n')[1:-2]
        else:
            return output.split('\n')[1:-1]
    except Exception as ex:
        # if no vhosts, just raises an exception
        log(str(ex), level='DEBUG')
        return []


def vhost_exists(vhost):
    return vhost in list_vhosts()


def create_vhost(vhost):
    if vhost_exists(vhost):
        return
    cmd = [RABBITMQ_CTL, 'add_vhost', vhost]
    subprocess.check_call(cmd)
    log('Created new vhost (%s).' % vhost)


def user_exists(user):
    cmd = [RABBITMQ_CTL, 'list_users']
    out = subprocess.check_output(cmd)
    for line in out.split('\n')[1:]:
        _user = line.split('\t')[0]
        if _user == user:
            admin = line.split('\t')[1]
            return True, (admin == '[administrator]')
    return False, False


def create_user(user, password, admin=False):
    exists, is_admin = user_exists(user)

    if not exists:
        cmd = [RABBITMQ_CTL, 'add_user', user, password]
        subprocess.check_call(cmd)
        log('Created new user (%s).' % user)

    if admin == is_admin:
        return

    if admin:
        cmd = [RABBITMQ_CTL, 'set_user_tags', user, 'administrator']
        log('Granting user (%s) admin access.' % user)
    else:
        cmd = [RABBITMQ_CTL, 'set_user_tags', user]
        log('Revoking user (%s) admin access.' % user)
    subprocess.check_call(cmd)


def grant_permissions(user, vhost):
    cmd = [RABBITMQ_CTL, 'set_permissions', '-p',
           vhost, user, '.*', '.*', '.*']
    subprocess.check_call(cmd)


def set_policy(vhost, policy_name, match, value):
    cmd = [RABBITMQ_CTL, 'set_policy', '-p', vhost,
           policy_name, match, value]
    log("setting policy: %s" % str(cmd), level='DEBUG')
    subprocess.check_call(cmd)


def set_ha_mode(vhost, mode, params=None, sync_mode='automatic'):
    """Valid mode values:

      * 'all': Queue is mirrored across all nodes in the cluster. When a new
         node is added to the cluster, the queue will be mirrored to that node.
      * 'exactly': Queue is mirrored to count nodes in the cluster.
      * 'nodes': Queue is mirrored to the nodes listed in node names

    More details at http://www.rabbitmq.com./ha.html

    :param vhost: virtual host name
    :param mode: ha mode
    :param params: values to pass to the policy, possible values depend on the
                   mode chosen.
    :param sync_mode: when `mode` is 'exactly' this used to indicate how the
                      sync has to be done
                      http://www.rabbitmq.com./ha.html#eager-synchronisation
    """

    if cmp_pkgrevno('rabbitmq-server', '3.0.0') < 0:
        log(("Mirroring queues cannot be enabled, only supported "
             "in rabbitmq-server >= 3.0"), level='WARN')
        log(("More information at http://www.rabbitmq.com/blog/"
             "2012/11/19/breaking-things-with-rabbitmq-3-0"), level='INFO')
        return

    if mode == 'all':
        value = '{"ha-mode": "all"}'
    elif mode == 'exactly':
        value = '{"ha-mode":"exactly","ha-params":%s,"ha-sync-mode":"%s"}' \
                % (params, sync_mode)
    elif mode == 'nodes':
        value = '{"ha-mode":"nodes","ha-params":[%s]}' % ",".join(params)
    else:
        raise RabbitmqError(("Unknown mode '%s', known modes: "
                             "all, exactly, nodes"))

    log("Setting HA policy to vhost '%s'" % vhost, level='INFO')
    set_policy(vhost, 'HA', '^(?!amq\.).*', value)


def clear_ha_mode(vhost, name='HA', force=False):
    """
    Clear policy from the `vhost` by `name`
    """
    if cmp_pkgrevno('rabbitmq-server', '3.0.0') < 0:
        log(("Mirroring queues not supported "
             "in rabbitmq-server >= 3.0"), level='WARN')
        log(("More information at http://www.rabbitmq.com/blog/"
             "2012/11/19/breaking-things-with-rabbitmq-3-0"), level='INFO')
        return

    log("Clearing '%s' policy from vhost '%s'" % (name, vhost), level='INFO')
    try:
        subprocess.check_call([RABBITMQ_CTL, 'clear_policy', '-p', vhost,
                               name])
    except subprocess.CalledProcessError as ex:
        if not force:
            raise ex


def set_all_mirroring_queues(enable):
    """
    :param enable: if True then enable mirroring queue for all the vhosts,
                   otherwise the HA policy is removed
    """
    if cmp_pkgrevno('rabbitmq-server', '3.0.0') < 0:
        log(("Mirroring queues not supported "
             "in rabbitmq-server >= 3.0"), level='WARN')
        log(("More information at http://www.rabbitmq.com/blog/"
             "2012/11/19/breaking-things-with-rabbitmq-3-0"), level='INFO')
        return

    for vhost in list_vhosts():
        if enable:
            set_ha_mode(vhost, 'all')
        else:
            clear_ha_mode(vhost, force=True)


def service(action):
    cmd = ['service', 'rabbitmq-server', action]
    subprocess.check_call(cmd)


def cluster_with():
    log('Clustering with new node')
    if cmp_pkgrevno('rabbitmq-server', '3.0.1') >= 0:
        cluster_cmd = 'join_cluster'
    else:
        cluster_cmd = 'cluster'
    out = subprocess.check_output([RABBITMQ_CTL, 'cluster_status'])
    log('cluster status is %s' % str(out))

    # check if node is already clustered
    total_nodes = 1
    running_nodes = []
    m = re.search("\{running_nodes,\[(.*?)\]\}", out.strip(), re.DOTALL)
    if m is not None:
        running_nodes = m.group(1).split(',')
        running_nodes = [x.replace("'", '') for x in running_nodes]
        total_nodes = len(running_nodes)

    if total_nodes > 1:
        log('Node is already clustered, skipping')
        return False

    # check all peers and try to cluster with them
    available_nodes = []
    for r_id in relation_ids('cluster'):
        for unit in related_units(r_id):
            if config('prefer-ipv6'):
                address = relation_get('hostname',
                                       rid=r_id, unit=unit)
            else:
                address = relation_get('private-address',
                                       rid=r_id, unit=unit)
            if address is not None:
                try:
                    node = get_hostname(address, fqdn=False)
                except:
                    log('Cannot resolve hostname for {} '
                        'using DNS servers'.format(address), level='WARNING')
                    log('Falling back to use socket.gethostname()',
                        level='WARNING')
                    # If the private-address is not resolvable using DNS
                    # then use the current hostname
                    node = socket.gethostname()

                available_nodes.append(node)

    if len(available_nodes) == 0:
        log('No nodes available to cluster with')
        return False

    # iterate over all the nodes, join to the first available
    num_tries = 0
    for node in available_nodes:
        log('Clustering with remote rabbit host (%s).' % node)
        if node in running_nodes:
            log('Host already clustered with %s.' % node)
            return False

        try:
            cmd = [RABBITMQ_CTL, 'stop_app']
            subprocess.check_call(cmd)
            cmd = [RABBITMQ_CTL, cluster_cmd, 'rabbit@%s' % node]
            subprocess.check_call(cmd)
            cmd = [RABBITMQ_CTL, 'start_app']
            subprocess.check_call(cmd)
            log('Host clustered with %s.' % node)
            return True
        except:
            log('Failed to cluster with %s.' % node)
        # continue to the next node
        num_tries += 1
        if num_tries > config('max-cluster-tries'):
            log('Max tries number exhausted, exiting', level=ERROR)
            raise

    return False


def break_cluster():
    try:
        cmd = [RABBITMQ_CTL, 'stop_app']
        subprocess.check_call(cmd)
        cmd = [RABBITMQ_CTL, 'reset']
        subprocess.check_call(cmd)
        cmd = [RABBITMQ_CTL, 'start_app']
        subprocess.check_call(cmd)
        log('Cluster successfully broken.')
    except:
        # error, no nodes available for clustering
        log('Error breaking rabbit cluster', level=ERROR)
        raise


def update_rmq_env_conf(hostname=None, ipv6=False):
    """Update or append environment config.

    rabbitmq.conf.d is not present on all releases, so use or create
    rabbitmq-env.conf instead.
    """

    keyvals = {}
    if ipv6:
        keyvals['RABBITMQ_SERVER_START_ARGS'] = "'-proto_dist inet6_tcp'"

    if hostname:
        keyvals['RABBITMQ_NODENAME'] = hostname

    out = []
    keys_found = []
    if os.path.exists(ENV_CONF):
        for line in open(ENV_CONF).readlines():
            for key, val in keyvals.items():
                if line.strip().startswith(key):
                    keys_found.append(key)
                    line = '%s=%s' % (key, val)

            out.append(line)

    for key, val in keyvals.items():
        log('Updating %s, %s=%s' % (ENV_CONF, key, val))
        if key not in keys_found:
            out.append('%s=%s' % (key, val))

    with open(ENV_CONF, 'wb') as conf:
        conf.write('\n'.join(out))
        # Ensure newline at EOF
        conf.write('\n')


def get_node_name():
    if not os.path.exists(ENV_CONF):
        return None
    env_conf = open(ENV_CONF, 'r').readlines()
    node_name = None
    for l in env_conf:
        if l.startswith('RABBITMQ_NODENAME'):
            node_name = l.split('=')[1].strip()
    return node_name


def _manage_plugin(plugin, action):
    os.environ['HOME'] = '/root'
    _rabbitmq_plugins = \
        glob.glob('/usr/lib/rabbitmq/lib/rabbitmq_server-*'
                  '/sbin/rabbitmq-plugins')[0]
    subprocess.check_call([_rabbitmq_plugins, action, plugin])


def enable_plugin(plugin):
    _manage_plugin(plugin, 'enable')


def disable_plugin(plugin):
    _manage_plugin(plugin, 'disable')

ssl_key_file = "/etc/rabbitmq/rabbit-server-privkey.pem"
ssl_cert_file = "/etc/rabbitmq/rabbit-server-cert.pem"
ssl_ca_file = "/etc/rabbitmq/rabbit-server-ca.pem"


def enable_ssl(ssl_key, ssl_cert, ssl_port,
               ssl_ca=None, ssl_only=False, ssl_client=None):
    uid = pwd.getpwnam("root").pw_uid
    gid = grp.getgrnam("rabbitmq").gr_gid

    for contents, path in (
            (ssl_key, ssl_key_file),
            (ssl_cert, ssl_cert_file),
            (ssl_ca, ssl_ca_file)):
        if not contents:
            continue
        with open(path, 'w') as fh:
            fh.write(contents)
        os.chmod(path, 0o640)
        os.chown(path, uid, gid)

    data = {
        "ssl_port": ssl_port,
        "ssl_cert_file": ssl_cert_file,
        "ssl_key_file": ssl_key_file,
        "ssl_client": ssl_client,
        "ssl_ca_file": "",
        "ssl_only": ssl_only}

    if ssl_ca:
        data["ssl_ca_file"] = ssl_ca_file

    render(os.path.basename(RABBITMQ_CONF), RABBITMQ_CONF, data, perms=0o644)


def execute(cmd, die=False, echo=False):
    """ Executes a command

    if die=True, script will exit(1) if command does not return 0
    if echo=True, output of command will be printed to stdout

    returns a tuple: (stdout, stderr, return code)
    """
    p = subprocess.Popen(cmd.split(" "),
                         stdout=subprocess.PIPE,
                         stdin=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    stdout = ""
    stderr = ""

    def print_line(l):
        if echo:
            print l.strip('\n')
            sys.stdout.flush()

    for l in iter(p.stdout.readline, ''):
        print_line(l)
        stdout += l
    for l in iter(p.stderr.readline, ''):
        print_line(l)
        stderr += l

    p.communicate()
    rc = p.returncode

    if die and rc != 0:
        log("command %s return non-zero." % cmd, level=ERROR)
    return (stdout, stderr, rc)


def get_rabbit_password_on_disk(username, password=None, local=False):
    ''' Retrieve, generate or store a rabbit password for
    the provided username on disk'''
    if local:
        _passwd_file = _local_named_passwd.format(service_name(), username)
    else:
        _passwd_file = _named_passwd.format(service_name(), username)

    _password = None
    if os.path.exists(_passwd_file):
        with open(_passwd_file, 'r') as passwd:
            _password = passwd.read().strip()
    else:
        mkdir(os.path.dirname(_passwd_file), owner=RABBIT_USER,
              group=RABBIT_USER, perms=0o775)
        os.chmod(os.path.dirname(_passwd_file), 0o775)
        _password = password or pwgen(length=64)
        write_file(_passwd_file, _password, owner=RABBIT_USER,
                   group=RABBIT_USER, perms=0o660)

    return _password


def migrate_passwords_to_peer_relation():
    '''Migrate any passwords storage on disk to cluster peer relation'''
    for f in glob.glob('/var/lib/charm/{}/*.passwd'.format(service_name())):
        _key = os.path.basename(f)
        with open(f, 'r') as passwd:
            _value = passwd.read().strip()
        try:
            peer_store(_key, _value)
            os.unlink(f)
        except ValueError:
            # NOTE cluster relation not yet ready - skip for now
            pass


def get_rabbit_password(username, password=None, local=False):
    ''' Retrieve, generate or store a rabbit password for
    the provided username using peer relation cluster'''
    if local:
        return get_rabbit_password_on_disk(username, password, local)
    else:
        migrate_passwords_to_peer_relation()
        _key = '{}.passwd'.format(username)
        try:
            _password = peer_retrieve(_key)
            if _password is None:
                _password = password or pwgen(length=64)
                peer_store(_key, _password)
        except ValueError:
            # cluster relation is not yet started, use on-disk
            _password = get_rabbit_password_on_disk(username, password)
        return _password


def bind_ipv6_interface():
    out = "RABBITMQ_SERVER_START_ARGS='-proto_dist inet6_tcp'\n"
    with open(ENV_CONF, 'wb') as conf:
        conf.write(out)


def update_hosts_file(map):
    """Rabbitmq does not currently like ipv6 addresses so we need to use dns
    names instead. In order to make them resolvable we ensure they are  in
    /etc/hosts.

    """
    with open(HOSTS_FILE, 'r') as hosts:
        lines = hosts.readlines()

    log("Updating hosts file with: %s (current: %s)" % (map, lines),
        level=INFO)

    newlines = []
    for ip, hostname in map.items():
        if not ip or not hostname:
            continue

        keepers = []
        for line in lines:
            _line = line.split()
            if len(line) < 2 or not (_line[0] == ip or hostname in _line[1:]):
                keepers.append(line)
            else:
                log("Removing line '%s' from hosts file" % (line))

        lines = keepers
        newlines.append("%s %s\n" % (ip, hostname))

    lines += newlines

    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        with open(tmpfile.name, 'w') as hosts:
            for line in lines:
                hosts.write(line)

    os.rename(tmpfile.name, HOSTS_FILE)
    os.chmod(HOSTS_FILE, 0o644)


def assert_charm_supports_ipv6():
    """Check whether we are able to support charms ipv6."""
    if lsb_release()['DISTRIB_CODENAME'].lower() < "trusty":
        raise Exception("IPv6 is not supported in the charms for Ubuntu "
                        "versions less than Trusty 14.04")


def restart_map():
    '''Determine the correct resource map to be passed to
    charmhelpers.core.restart_on_change() based on the services configured.

    :returns: dict: A dictionary mapping config file to lists of services
                    that should be restarted when file changes.
    '''
    _map = []
    for f, ctxt in CONFIG_FILES.iteritems():
        svcs = []
        for svc in ctxt['services']:
            svcs.append(svc)
        if svcs:
            _map.append((f, svcs))
    return OrderedDict(_map)


def services():
    ''' Returns a list of services associate with this charm '''
    _services = []
    for v in restart_map().values():
        _services = _services + v
    return list(set(_services))
