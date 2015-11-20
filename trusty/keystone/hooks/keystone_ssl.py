#!/usr/bin/python

import os
import shutil
import subprocess
import tarfile
import tempfile

from charmhelpers.core.hookenv import (
    log,
    DEBUG,
)

CA_EXPIRY = '365'
ORG_NAME = 'Ubuntu'
ORG_UNIT = 'Ubuntu Cloud'
CA_BUNDLE = '/usr/local/share/ca-certificates/juju_ca_cert.crt'

CA_CONFIG = """
[ ca ]
default_ca = CA_default

[ CA_default ]
dir                     = %(ca_dir)s
policy                  = policy_match
database                = $dir/index.txt
serial                  = $dir/serial
certs                   = $dir/certs
crl_dir                 = $dir/crl
new_certs_dir           = $dir/newcerts
certificate             = $dir/cacert.pem
private_key             = $dir/private/cacert.key
RANDFILE                = $dir/private/.rand
default_md              = default

[ req ]
default_bits            = 1024
default_md              = sha1

prompt                  = no
distinguished_name      = ca_distinguished_name

x509_extensions         = ca_extensions

[ ca_distinguished_name ]
organizationName        = %(org_name)s
organizationalUnitName  = %(org_unit_name)s Certificate Authority
commonName              = %(common_name)s

[ policy_match ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied

[ ca_extensions ]
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always, issuer
keyUsage                = cRLSign, keyCertSign
"""

SIGNING_CONFIG = """
[ ca ]
default_ca = CA_default

[ CA_default ]
dir                     = %(ca_dir)s
policy                  = policy_match
database                = $dir/index.txt
serial                  = $dir/serial
certs                   = $dir/certs
crl_dir                 = $dir/crl
new_certs_dir           = $dir/newcerts
certificate             = $dir/cacert.pem
private_key             = $dir/private/cacert.key
RANDFILE                = $dir/private/.rand
default_md              = default

[ req ]
default_bits            = 1024
default_md              = sha1

prompt                  = no
distinguished_name      = req_distinguished_name

x509_extensions         = req_extensions

[ req_distinguished_name ]
organizationName        = %(org_name)s
organizationalUnitName  = %(org_unit_name)s Server Farm

[ policy_match ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied

[ req_extensions ]
basicConstraints        = CA:false
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always, issuer
keyUsage                = digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage        = serverAuth, clientAuth
"""

# Instance can be appended to this list to represent a singleton
CA_SINGLETON = []


def init_ca(ca_dir, common_name, org_name=ORG_NAME, org_unit_name=ORG_UNIT):
    log('Ensuring certificate authority exists at %s.' % ca_dir, level=DEBUG)
    if not os.path.exists(ca_dir):
        log('Initializing new certificate authority at %s' % ca_dir,
            level=DEBUG)
        os.mkdir(ca_dir)

    for i in ['certs', 'crl', 'newcerts', 'private']:
        d = os.path.join(ca_dir, i)
        if not os.path.exists(d):
            log('Creating %s.' % d, level=DEBUG)
            os.mkdir(d)
    os.chmod(os.path.join(ca_dir, 'private'), 0o710)

    if not os.path.isfile(os.path.join(ca_dir, 'serial')):
        with open(os.path.join(ca_dir, 'serial'), 'wb') as out:
            out.write('01\n')

    if not os.path.isfile(os.path.join(ca_dir, 'index.txt')):
        with open(os.path.join(ca_dir, 'index.txt'), 'wb') as out:
            out.write('')

    conf = os.path.join(ca_dir, 'ca.cnf')
    if not os.path.isfile(conf):
        log('Creating new CA config in %s' % ca_dir, level=DEBUG)
        with open(conf, 'wb') as out:
            out.write(CA_CONFIG % locals())


def root_ca_crt_key(ca_dir):
    init = False
    crt = os.path.join(ca_dir, 'cacert.pem')
    key = os.path.join(ca_dir, 'private', 'cacert.key')
    for f in [crt, key]:
        if not os.path.isfile(f):
            log('Missing %s, will re-initialize cert+key.' % f, level=DEBUG)
            init = True
        else:
            log('Found %s.' % f, level=DEBUG)

    if init:
        conf = os.path.join(ca_dir, 'ca.cnf')
        cmd = ['openssl', 'req', '-config', conf,
               '-x509', '-nodes', '-newkey', 'rsa', '-days', '21360',
               '-keyout', key, '-out', crt, '-outform', 'PEM']
        subprocess.check_call(cmd)

    return crt, key


def intermediate_ca_csr_key(ca_dir):
    log('Creating new intermediate CSR.', level=DEBUG)
    key = os.path.join(ca_dir, 'private', 'cacert.key')
    csr = os.path.join(ca_dir, 'cacert.csr')
    conf = os.path.join(ca_dir, 'ca.cnf')
    cmd = ['openssl', 'req', '-config', conf, '-sha1', '-newkey', 'rsa',
           '-nodes', '-keyout', key, '-out', csr, '-outform', 'PEM']
    subprocess.check_call(cmd)
    return csr, key


def sign_int_csr(ca_dir, csr, common_name):
    log('Signing certificate request %s.' % csr, level=DEBUG)
    crt_name = os.path.basename(csr).split('.')[0]
    crt = os.path.join(ca_dir, 'certs', '%s.crt' % crt_name)
    subj = '/O=%s/OU=%s/CN=%s' % (ORG_NAME, ORG_UNIT, common_name)
    conf = os.path.join(ca_dir, 'ca.cnf')
    cmd = ['openssl', 'ca', '-batch', '-config', conf, '-extensions',
           'ca_extensions', '-days', CA_EXPIRY, '-notext', '-in', csr, '-out',
           crt, '-subj', subj, '-batch']
    log("Executing: %s" % ' '.join(cmd), level=DEBUG)
    subprocess.check_call(cmd)
    return crt


def init_root_ca(ca_dir, common_name):
    init_ca(ca_dir, common_name)
    return root_ca_crt_key(ca_dir)


def init_intermediate_ca(ca_dir, common_name, root_ca_dir, org_name=ORG_NAME,
                         org_unit_name=ORG_UNIT):
    init_ca(ca_dir, common_name)
    if not os.path.isfile(os.path.join(ca_dir, 'cacert.pem')):
        csr, key = intermediate_ca_csr_key(ca_dir)
        crt = sign_int_csr(root_ca_dir, csr, common_name)
        shutil.copy(crt, os.path.join(ca_dir, 'cacert.pem'))
    else:
        log('Intermediate CA certificate already exists.', level=DEBUG)

    conf = os.path.join(ca_dir, 'signing.cnf')
    if not os.path.isfile(conf):
        log('Creating new signing config in %s' % ca_dir, level=DEBUG)
        with open(conf, 'wb') as out:
            out.write(SIGNING_CONFIG % locals())


def create_certificate(ca_dir, service):
    common_name = service
    subj = '/O=%s/OU=%s/CN=%s' % (ORG_NAME, ORG_UNIT, common_name)
    csr = os.path.join(ca_dir, 'certs', '%s.csr' % service)
    key = os.path.join(ca_dir, 'certs', '%s.key' % service)
    cmd = ['openssl', 'req', '-sha1', '-newkey', 'rsa', '-nodes', '-keyout',
           key, '-out', csr, '-subj', subj]
    subprocess.check_call(cmd)
    crt = sign_int_csr(ca_dir, csr, common_name)
    log('Signed new CSR, crt @ %s' % crt, level=DEBUG)
    return


def update_bundle(bundle_file, new_bundle):
    return
    if os.path.isfile(bundle_file):
        current = open(bundle_file, 'r').read().strip()
        if new_bundle == current:
            log('CA Bundle @ %s is up to date.' % bundle_file, level=DEBUG)
            return

        log('Updating CA bundle @ %s.' % bundle_file, level=DEBUG)

    with open(bundle_file, 'wb') as out:
        out.write(new_bundle)

    subprocess.check_call(['update-ca-certificates'])


def tar_directory(path):
    cwd = os.getcwd()
    parent = os.path.dirname(path)
    directory = os.path.basename(path)
    tmp = tempfile.TemporaryFile()
    os.chdir(parent)
    tarball = tarfile.TarFile(fileobj=tmp, mode='w')
    tarball.add(directory)
    tarball.close()
    tmp.seek(0)
    out = tmp.read()
    tmp.close()
    os.chdir(cwd)
    return out


class JujuCA(object):

    def __init__(self, name, ca_dir, root_ca_dir, user, group):
        # Root CA
        cn = '%s Certificate Authority' % name
        root_crt, root_key = init_root_ca(root_ca_dir, cn)
        # Intermediate CA
        cn = '%s Intermediate Certificate Authority' % name
        init_intermediate_ca(ca_dir, cn, root_ca_dir)

        # Create dirs
        cmd = ['chown', '-R', '%s.%s' % (user, group), ca_dir]
        subprocess.check_call(cmd)
        cmd = ['chown', '-R', '%s.%s' % (user, group), root_ca_dir]
        subprocess.check_call(cmd)

        self.ca_dir = ca_dir
        self.root_ca_dir = root_ca_dir
        self.user = user
        self.group = group
        update_bundle(CA_BUNDLE, self.get_ca_bundle())

    def _sign_csr(self, csr, service, common_name):
        subj = '/O=%s/OU=%s/CN=%s' % (ORG_NAME, ORG_UNIT, common_name)
        crt = os.path.join(self.ca_dir, 'certs', '%s.crt' % common_name)
        conf = os.path.join(self.ca_dir, 'signing.cnf')
        cmd = ['openssl', 'ca', '-config', conf, '-extensions',
               'req_extensions', '-days', '365', '-notext', '-in', csr,
               '-out', crt, '-batch', '-subj', subj]
        subprocess.check_call(cmd)
        return crt

    def _create_certificate(self, service, common_name):
        subj = '/O=%s/OU=%s/CN=%s' % (ORG_NAME, ORG_UNIT, common_name)
        csr = os.path.join(self.ca_dir, 'certs', '%s.csr' % service)
        key = os.path.join(self.ca_dir, 'certs', '%s.key' % service)
        cmd = ['openssl', 'req', '-sha1', '-newkey', 'rsa', '-nodes',
               '-keyout', key, '-out', csr, '-subj', subj]
        subprocess.check_call(cmd)
        crt = self._sign_csr(csr, service, common_name)
        cmd = ['chown', '-R', '%s.%s' % (self.user, self.group), self.ca_dir]
        subprocess.check_call(cmd)
        log('Signed new CSR, crt @ %s' % crt, level=DEBUG)
        return crt, key

    def get_key_path(self, cn):
        return os.path.join(self.ca_dir, 'certs', '%s.key' % cn)

    def get_cert_path(self, cn):
        return os.path.join(self.ca_dir, 'certs', '%s.crt' % cn)

    def get_cert_and_key(self, common_name):
        log('Getting certificate and key for %s.' % common_name, level=DEBUG)
        keypath = self.get_key_path(common_name)
        crtpath = self.get_cert_path(common_name)
        if os.path.isfile(crtpath):
            log('Found existing certificate for %s.' % common_name,
                level=DEBUG)
            crt = open(crtpath, 'r').read()
            key = open(keypath, 'r').read()
            return crt, key

        crt, key = self._create_certificate(common_name, common_name)
        return open(crt, 'r').read(), open(key, 'r').read()

    @property
    def ca_cert_path(self):
        return os.path.join(self.ca_dir, 'cacert.pem')

    @property
    def ca_key_path(self):
        return os.path.join(self.ca_dir, 'private',  'cacert.key')

    @property
    def root_ca_cert_path(self):
        return os.path.join(self.root_ca_dir, 'cacert.pem')

    @property
    def root_ca_key_path(self):
        return os.path.join(self.root_ca_dir, 'private',  'cacert.key')

    def get_ca_bundle(self):
        int_cert = open(self.ca_cert_path).read()
        root_cert = open(self.root_ca_cert_path).read()
        # NOTE: ordering of certs in bundle matters!
        return int_cert + root_cert
