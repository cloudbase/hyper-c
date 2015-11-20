#!/usr/bin/python3

# This Amulet test exercises the configuration options for rabbitmq-server.

import amulet
import os
import socket
import ssl
from deploy_common import CA

# The number of seconds to wait for the environment to setup.
seconds = 2700
# Get the directory in this way to load the files from the tests directory.
path = os.path.abspath(os.path.dirname(__file__))

ca = CA()

privateKey = ca.get_key()
certificate = ca.get_cert()

# Create a dictionary of all the configuration values.
rabbit_configuration = {
    'management_plugin': True,
    'ssl_enabled': True,
    'ssl_port': 5999,
    'ssl_key': privateKey,
    'ssl_cert': certificate,
}

d = amulet.Deployment(series='trusty')
# Add the rabbitmq-server charm to the deployment.
d.add('rabbitmq-server')
# Configure all the options on rabbitmq-server.
d.configure('rabbitmq-server', rabbit_configuration)
# Expose the rabbitmq-server.
d.expose('rabbitmq-server')

try:
    # Execute the deployer with the current mapping.
    d.setup(timeout=seconds)
    # Wait for the relation to finish the transations.
    d.sentry.wait(seconds)
except amulet.helpers.TimeoutError:
    message = 'The environment did not setup in %d seconds.' % seconds
    # The SKIP status enables skip or fail the test based on configuration.
    amulet.raise_status(amulet.SKIP, msg=message)
except:
    raise

rabbit_unit = d.sentry.unit['rabbitmq-server/0']
###############################################################################
# Verify that the rabbit service is running on the deployed server.
###############################################################################
# Create the command that checks if the rabbitmq-server service is running.
command = 'rabbitmqctl status'
print(command)
# Execute the command on the deployed service.
output, code = rabbit_unit.run(command)
print(output)
# Check the return code for the success and failure of this test.
if (code != 0):
    message = 'The ' + command + ' did not return the expected code of 0.'
    amulet.raise_status(amulet.FAIL, msg=message)
else:
    print('The rabbitmq-server is running.')

###############################################################################
# Verify the configuration values.
###############################################################################
# Get the contents of the private key from the rabbitmq-server
contents = rabbit_unit.file_contents('/etc/rabbitmq/rabbit-server-privkey.pem')
# Verify the private key was saved on the rabbitmq server correctly.
if contents != privateKey:
    message = 'The private keys did not match!'
    amulet.raise_status(amulet.FAIL, msg=message)
else:
    print('The private keys was configured properly on the rabbitmq server.')

# Get the contents of the certificate from the rabbitmq-server.
contents = rabbit_unit.file_contents('/etc/rabbitmq/rabbit-server-cert.pem')
# Verify the certificate was saved on the rabbitmq server correctly.
if contents != certificate:
    message = 'The certificates did not match!'
    amulet.raise_status(amulet.FAIL, msg=message)
else:
    print('The certificate was configured properly on the rabbitmq server.')

# Get the public address for rabbitmq-server instance.
rabbit_host = rabbit_unit.info['public-address']

###############################################################################
# Verify that SSL is set up on the non-default port.
###############################################################################
# Get the port for ssl_port instance.
ssl_port = rabbit_configuration['ssl_port']

try:
    # Create a normal socket.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Require a certificate from the server, since a self-signed certificate
    # was used, the ca_certs must be the server certificate file itself.
    ssl_sock = ssl.wrap_socket(s, ca_certs=ca.ca_cert_path(),
                               cert_reqs=ssl.CERT_REQUIRED)
    # Connect to the rabbitmq server using ssl.
    ssl_sock.connect((rabbit_host, ssl_port))
    # Get the certificate.
    certificate = ssl_sock.getpeercert()
    # SSL scoket connected and got the certificate, this passes the ssl test!
    print('Connected to the rabbitmq-server {0}:{1} using ssl!'.format(
          rabbit_host, ssl_port))
except Exception as e:
    message = 'Failed to create an ssl connection to {0}:{1}\n{2}'.format(
              rabbit_host, ssl_port, str(e))
    amulet.raise_status(amulet.FAIL, msg=message)
finally:
    ssl_sock.close()

print('The rabbitmq-server passed the configuration tests.')
