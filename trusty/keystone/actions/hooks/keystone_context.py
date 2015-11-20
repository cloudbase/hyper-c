import hashlib
import os

from base64 import b64decode

from charmhelpers.core.host import (
    mkdir,
    write_file,
    service_restart,
)

from charmhelpers.contrib.openstack import context

from charmhelpers.contrib.hahelpers.cluster import (
    determine_apache_port,
    determine_api_port,
)

from charmhelpers.core.hookenv import (
    config,
    log,
    DEBUG,
    INFO,
)

from charmhelpers.core.strutils import (
    bool_from_string,
)

from charmhelpers.contrib.hahelpers.apache import install_ca_cert

CA_CERT_PATH = '/usr/local/share/ca-certificates/keystone_juju_ca_cert.crt'


def is_cert_provided_in_config():
    ca = config('ssl_ca')
    cert = config('ssl_cert')
    key = config('ssl_key')
    return bool(ca and cert and key)


class ApacheSSLContext(context.ApacheSSLContext):

    interfaces = ['https']
    external_ports = []
    service_namespace = 'keystone'

    def __call__(self):
        # late import to work around circular dependency
        from keystone_utils import (
            determine_ports,
            update_hash_from_path,
        )

        ssl_paths = [CA_CERT_PATH,
                     os.path.join('/etc/apache2/ssl/',
                                  self.service_namespace)]

        self.external_ports = determine_ports()
        before = hashlib.sha256()
        for path in ssl_paths:
            update_hash_from_path(before, path)

        ret = super(ApacheSSLContext, self).__call__()

        after = hashlib.sha256()
        for path in ssl_paths:
            update_hash_from_path(after, path)

        # Ensure that apache2 is restarted if these change
        if before.hexdigest() != after.hexdigest():
            service_restart('apache2')

        return ret

    def configure_cert(self, cn):
        from keystone_utils import (
            SSH_USER,
            get_ca,
            ensure_permissions,
            is_ssl_cert_master,
        )

        # Ensure ssl dir exists whether master or not
        ssl_dir = os.path.join('/etc/apache2/ssl/', self.service_namespace)
        perms = 0o755
        mkdir(path=ssl_dir, owner=SSH_USER, group='keystone', perms=perms)
        # Ensure accessible by keystone ssh user and group (for sync)
        ensure_permissions(ssl_dir, user=SSH_USER, group='keystone',
                           perms=perms)

        if not is_cert_provided_in_config() and not is_ssl_cert_master():
            log("Not ssl-cert-master - skipping apache cert config until "
                "master is elected", level=INFO)
            return

        log("Creating apache ssl certs in %s" % (ssl_dir), level=INFO)

        cert = config('ssl_cert')
        key = config('ssl_key')

        if not (cert and key):
            ca = get_ca(user=SSH_USER)
            cert, key = ca.get_cert_and_key(common_name=cn)
        else:
            cert = b64decode(cert)
            key = b64decode(key)

        write_file(path=os.path.join(ssl_dir, 'cert_{}'.format(cn)),
                   content=cert, owner=SSH_USER, group='keystone', perms=0o644)
        write_file(path=os.path.join(ssl_dir, 'key_{}'.format(cn)),
                   content=key, owner=SSH_USER, group='keystone', perms=0o644)

    def configure_ca(self):
        from keystone_utils import (
            SSH_USER,
            get_ca,
            ensure_permissions,
            is_ssl_cert_master,
        )

        if not is_cert_provided_in_config() and not is_ssl_cert_master():
            log("Not ssl-cert-master - skipping apache ca config until "
                "master is elected", level=INFO)
            return

        ca_cert = config('ssl_ca')
        if ca_cert is None:
            ca = get_ca(user=SSH_USER)
            ca_cert = ca.get_ca_bundle()
        else:
            ca_cert = b64decode(ca_cert)

        # Ensure accessible by keystone ssh user and group (unison)
        install_ca_cert(ca_cert)
        ensure_permissions(CA_CERT_PATH, user=SSH_USER, group='keystone',
                           perms=0o0644)

    def canonical_names(self):
        addresses = self.get_network_addresses()
        addrs = []
        for address, endpoint in addresses:
            addrs.append(endpoint)

        return list(set(addrs))


class HAProxyContext(context.HAProxyContext):
    interfaces = []

    def __call__(self):
        '''
        Extends the main charmhelpers HAProxyContext with a port mapping
        specific to this charm.
        Also used to extend nova.conf context with correct api_listening_ports
        '''
        from keystone_utils import api_port
        ctxt = super(HAProxyContext, self).__call__()

        # determine which port api processes should bind to, depending
        # on existence of haproxy + apache frontends
        listen_ports = {}
        listen_ports['admin_port'] = api_port('keystone-admin')
        listen_ports['public_port'] = api_port('keystone-public')

        # Apache ports
        a_admin_port = determine_apache_port(api_port('keystone-admin'),
                                             singlenode_mode=True)
        a_public_port = determine_apache_port(api_port('keystone-public'),
                                              singlenode_mode=True)

        port_mapping = {
            'admin-port': [
                api_port('keystone-admin'), a_admin_port],
            'public-port': [
                api_port('keystone-public'), a_public_port],
        }

        # for haproxy.conf
        ctxt['service_ports'] = port_mapping
        # for keystone.conf
        ctxt['listen_ports'] = listen_ports
        return ctxt


class KeystoneContext(context.OSContextGenerator):
    interfaces = []

    def __call__(self):
        from keystone_utils import (
            api_port, set_admin_token, endpoint_url, resolve_address,
            PUBLIC, ADMIN, PKI_CERTS_DIR, SSH_USER, ensure_permissions,
        )
        ctxt = {}
        ctxt['token'] = set_admin_token(config('admin-token'))
        ctxt['admin_port'] = determine_api_port(api_port('keystone-admin'),
                                                singlenode_mode=True)
        ctxt['public_port'] = determine_api_port(api_port('keystone-public'),
                                                 singlenode_mode=True)

        debug = config('debug')
        ctxt['debug'] = debug and bool_from_string(debug)
        verbose = config('verbose')
        ctxt['verbose'] = verbose and bool_from_string(verbose)
        ctxt['token_expiration'] = config('token-expiration')

        ctxt['identity_backend'] = config('identity-backend')
        ctxt['assignment_backend'] = config('assignment-backend')
        if config('identity-backend') == 'ldap':
            ctxt['ldap_server'] = config('ldap-server')
            ctxt['ldap_user'] = config('ldap-user')
            ctxt['ldap_password'] = config('ldap-password')
            ctxt['ldap_suffix'] = config('ldap-suffix')
            ctxt['ldap_readonly'] = config('ldap-readonly')
            ldap_flags = config('ldap-config-flags')
            if ldap_flags:
                flags = context.config_flags_parser(ldap_flags)
                ctxt['ldap_config_flags'] = flags

        enable_pki = config('enable-pki')
        if enable_pki and bool_from_string(enable_pki):
            ctxt['signing'] = True
            ctxt['token_provider'] = 'pki'

        if 'token_provider' in ctxt:
            log("Configuring PKI token cert paths", level=DEBUG)
            certs = os.path.join(PKI_CERTS_DIR, 'certs')
            privates = os.path.join(PKI_CERTS_DIR, 'privates')
            for path in [PKI_CERTS_DIR, certs, privates]:
                perms = 0o755
                if not os.path.isdir(path):
                    mkdir(path=path, owner=SSH_USER, group='keystone',
                          perms=perms)
                else:
                    # Ensure accessible by ssh user and group (for sync).
                    ensure_permissions(path, user=SSH_USER,
                                       group='keystone', perms=perms)

            signing_paths = {'certfile': os.path.join(certs,
                                                      'signing_cert.pem'),
                             'keyfile': os.path.join(privates,
                                                     'signing_key.pem'),
                             'ca_certs': os.path.join(certs, 'ca.pem'),
                             'ca_key': os.path.join(certs, 'ca_key.pem')}

            for key, val in signing_paths.iteritems():
                ctxt[key] = val

        # Base endpoint URL's which are used in keystone responses
        # to unauthenticated requests to redirect clients to the
        # correct auth URL.
        ctxt['public_endpoint'] = endpoint_url(
            resolve_address(PUBLIC),
            api_port('keystone-public')).rstrip('v2.0')
        ctxt['admin_endpoint'] = endpoint_url(
            resolve_address(ADMIN),
            api_port('keystone-admin')).rstrip('v2.0')
        return ctxt


class KeystoneLoggingContext(context.OSContextGenerator):

    def __call__(self):
        ctxt = {}
        debug = config('debug')
        if debug and bool_from_string(debug):
            ctxt['root_level'] = 'DEBUG'

        return ctxt
