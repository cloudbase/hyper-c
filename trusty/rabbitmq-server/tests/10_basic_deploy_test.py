#!/usr/bin/python3

# This Amulet test performs a basic deploy and checks if rabbitmq is running.

import amulet
import os
import socket
import ssl
from deploy_common import CA

# The number of seconds to wait for the environment to setup.
seconds = 900
# Get the directory in this way to load the files from the tests directory.
path = os.path.abspath(os.path.dirname(__file__))

ca = CA()

# Create a dictionary for the rabbitmq configuration.
rabbitmq_configuration = {
    'ssl_enabled': True,
    'ssl_key': ca.get_key(),
    'ssl_cert': ca.get_cert(),
    'ssl_port': 5671
}

d = amulet.Deployment(series='trusty')
# Add the rabbitmq-server charm to the deployment.
d.add('rabbitmq-server')
# Configure options on the rabbitmq-server.
d.configure('rabbitmq-server', rabbitmq_configuration)
# Expose the server so we can connect.
d.expose('rabbitmq-server')

try:
    # Execute the deployer with the current mapping.
    d.setup(timeout=seconds)
except amulet.helpers.TimeoutError:
    message = 'The environment did not setup in %d seconds.' % seconds
    # The SKIP status enables skip or fail the test based on configuration.
    amulet.raise_status(amulet.SKIP, msg=message)
except:
    raise
print('The rabbitmq-server has been successfully deployed.')

###############################################################################
# Verify that the rabbit service is running on the deployed server.
###############################################################################
rabbitmq_sentry = d.sentry.unit['rabbitmq-server/0']
# Get the public address for rabbitmq-server instance.
server_address = rabbitmq_sentry.info['public-address']
# Create the command that checks if the rabbitmq-server service is running.
command = 'rabbitmqctl status'
print(command)
# Execute the command on the deployed service.
output, code = rabbitmq_sentry.run(command)
print(output)
# Check the return code for the success and failure of this test.
if (code != 0):
    message = 'The ' + command + ' did not return the expected code of 0.'
    amulet.raise_status(amulet.FAIL, msg=message)
else:
    print('The rabbitmq-server is running on %s' % server_address)

###############################################################################
# Test the ssl certificate.
###############################################################################
# Get the port for ssl_port instance.
server_port = rabbitmq_configuration['ssl_port']

print('Testing ssl connection to rabbitmq-server.')
try:
    # Create a normal socket.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Require a certificate from the server, since a self-signed certificate
    # was used, the ca_certs must be the server certificate file itself.
    ssl_sock = ssl.wrap_socket(s, ca_certs=ca.ca_cert_path(),
                               cert_reqs=ssl.CERT_REQUIRED)
    # Connect to the rabbitmq server using ssl.
    ssl_sock.connect((server_address, server_port))
    # Get the certificate.
    certificate = ssl_sock.getpeercert()
    # SSL socket connected and got the certificate, this passes the ssl test!
    print('Connected to the rabbitmq-server {0}:{1} using ssl!'.format(
          server_address, server_port))
except Exception as e:
    message = 'Failed to create an ssl connection to {0}:{1}\n{2}'.format(
              server_address, server_port, str(e))
    amulet.raise_status(amulet.FAIL, msg=message)
finally:
    ssl_sock.close()

print('The rabbitmq-server passed the basic deploy test!')
