#!/usr/bin/python3

# This Amulet test deploys rabbitmq-server, and the related charms.

import amulet
import os
import subprocess
import time

# The number of seconds to wait for the environment to setup.
seconds = 2700
# The number of units to scale rabbitmq-server to.
scale = 2
# The port that amqp traffic is sent on.
amqp_port = '5672'
# The directory to use as a block devie for the ceph
devices = '/srv/osd1'
# The default version of ceph does not support directories as devices.
havana = 'cloud:precise-updates/havana'
# Create a dictionary of configuration values for ceph.
ceph_configuration = {
    'fsid': 'ecbb8960-0e21-11e2-b495-83a88f44db01',
    'monitor-secret': 'AQBomftSyK1LORAAhg71ukxBxN9ml90stexqEw==',
    'osd-devices': devices,
    'source': havana
}
# Create a dictionary of configuration values for cinder.
cinder_configuration = {
    'block-device': 'None'
}
# Create a dictionary of the rabbit configuration values.
rabbit_configuration = {
    'vip': '192.168.77.11',
    'vip_cidr': 19,
    'vip_iface': 'eth0',
    'ha-bindiface': 'eth0',
    'ha-mcastport': 5406,
    'rbd-size': '2G',
    'rbd-name': 'testrabbit1'
}

# The AMQP package is only available for python version 2.x.
python2 = '/usr/bin/python'
if not os.path.isfile(python2):
    error_message = 'Error, python version 2 is required for this test.'
    amulet.raise_status(amulet.FAIL, msg=error_message)

series = 'trusty'
d = amulet.Deployment(series=series)
# Add rabbitmq-server to the deployment.
d.add('rabbitmq-server', units=scale)

# TODO(billy-olsen) - Rework this following set of code to be more in-line
# with how the other openstack services are done. For now, we want to test
# the current branch with the appropriate branches of related charms in
# order to test /next with /next branches and /trunk with /trunk branches.
stable = False


def determine_charm_branches(services):
    if stable:
        for svc in services:
            temp = 'lp:charms/{}'
            svc['location'] = temp.format(svc['name'])
    else:
        for svc in services:
            temp = 'lp:~openstack-charmers/charms/{}/{}/next'
            svc['location'] = temp.format(series, svc['name'])

    return services


def add_services(services):
    """
    Adds services to the deployment. The input is a list of dicts with
    the key of 'name' name for the service name. The branch location
    will be determined automatically.
    """
    services = determine_charm_branches(services)

    for svc in services:
        d.add(svc['name'], charm=svc['location'])


services_to_add = [
    {'name': 'ceph'},
    {'name': 'cinder'},
    {'name': 'hacluster'},
]

# Add the services to the deployment
add_services(services_to_add)

# The ceph charm requires configuration to deploy successfully.
d.configure('ceph', ceph_configuration)
# Configure the cinder charm.
d.configure('cinder', cinder_configuration)
# Configure the rabbit charm.
d.configure('rabbitmq-server', rabbit_configuration)
# Add relation from rabbitmq-server to ceph testing the ceph relation.
d.relate('rabbitmq-server:ceph', 'ceph:client')
# Add relation from rabbitmq-server to cinder testing the amqp relation.
d.relate('rabbitmq-server:amqp', 'cinder:amqp')
# Add relation from rabibtmq-server to hacluster testing the ha relation.
d.relate('rabbitmq-server:ha', 'hacluster:ha')
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
    amulet.raise_status(amulet.FAIL, msg=message)
except:
    raise
print('The environment successfully deployed.')

# Create a counter to make the messages unique.
counter = 1
# Get the directory in this way to load the files from the tests directory.
path = os.path.abspath(os.path.dirname(__file__))
# Create a path to the python test file to call.
amqp_tester = os.path.join(path, 'amqp_tester.py')
if not os.path.isfile(amqp_tester):
    error_message = 'Unable to locate python test file %s' % amqp_tester
    amulet.raise_status(amulet.FAIL, msg=error_message)

# Verify the ceph unit was created.
ceph_unit = d.sentry.unit['ceph/0']
# Verify the cinder unit was created.
cinder_unit = d.sentry.unit['cinder/0']
rabbit_units = []
for n in range(scale):
    # Get each rabbitmq unit that was deployed.
    rabbit_units.append(d.sentry.unit['rabbitmq-server/%d' % n])

# Iterate over every rabbitmq-unit to get the different relations.
for rabbit_unit in rabbit_units:
    ###########################################################################
    # Test Relations
    ###########################################################################
    # Verify the ceph relation was created for the rabbit unit.
    rabbit_relation = rabbit_unit.relation('ceph', 'ceph:client')
    print('rabbit relation to ceph:')
    for key, value in rabbit_relation.items():
        print(key, value)
    # Verify the amqp relation was created for the rabbit unit.
    rabbit_relation = rabbit_unit.relation('amqp', 'cinder:amqp')
    print('rabbit relation to amqp:')
    for key, value in rabbit_relation.items():
        print(key, value)

    # The hacluster charm is a subordinate, since the relation-sentry is also
    # a subordinate charm no sentry is created for the hacluster relation.

    #  Verify the rabbit relation was created with the ceph unit.
    ceph_relation = ceph_unit.relation('client', 'rabbitmq-server:ceph')
    print('ceph relation to rabbitmq-server:')
    for key, value in ceph_relation.items():
        print(key, value)
    # Verify the rabbit relation was created with the cinder unit.
    cinder_relation = cinder_unit.relation('amqp', 'rabbitmq-server:amqp')
    print('cinder relation to rabbitmq-server:')
    for key, value in cinder_relation.items():
        print(key, value)

    ###########################################################################
    # Test AMQP
    ###########################################################################

    # The AMQP python library is only available for python2 at this time.
    # Call out a command to run the python2 code to test the AMQP protocol.

    # Get the public address for rabbitmq-server instance.
    server_address = rabbit_unit.info['public-address']
    # Create a time stamp to help make the AMQP message unique.
    time_stamp = time.strftime('%F %r')
    # Create the message to send on the AMPQ protocol.
    amqp_message = "Message #{0} to send using the AMPQ protocol {1}".format(
        counter, time_stamp)
    # Create the command with arguments that sends the message.
    send_command = [python2, amqp_tester, server_address, amqp_port,
                    amqp_message]
    print(send_command)
    # Call the python command to send the AMQP message to the server.
    output = subprocess.check_output(send_command)
    # Create the command with arguments to receive messages.
    receive_command = [python2, amqp_tester, server_address, amqp_port]
    print(receive_command)
    # Call the python command to receive the AMQP message from the same server.
    output = subprocess.check_output(receive_command)
    # The output is a byte string so convert the message to a byte string.
    if output.find(amqp_message.encode()) == -1:
        print('The AMQP test to {0}:{1} failed.'.format(server_address,
              amqp_port))
        amulet.raise_status(amulet.FAIL, msg=output)
    else:
        print('The AMQP test to {0}:{1} completed successfully.'.format(
            server_address, amqp_port))
    counter += 1

    ###########################################################################
    # Verify that the rabbitmq cluster status is correct.
    ###########################################################################
    # Create the command that checks if the rabbitmq-server service is running.
    command = 'rabbitmqctl cluster_status'
    print(command)
    # Execute the command on the deployed service.
    output, code = rabbit_unit.run(command)
    print(output)
    # Check the return code for the success and failure of this test.
    if (code != 0):
        message = 'The ' + command + ' did not return the expected code of 0.'
        amulet.raise_status(amulet.FAIL, msg=message)
    else:
        print('The rabbitmq-server cluster status is OK.')

###############################################################################
# Test the AMQP messages can be sent from and read from another.
###############################################################################
# Get the public address for rabbitmq-server instance 0.
send_address = rabbit_units[0].info['public-address']
# Create a message to send from instance 0 and read it from instance 1.
amqp_message = "Message #{0} sent from {1} using the AMQP protocol.".format(
               counter, send_address)
counter += 1
# Create the command that sends the message to instance 0.
send_command = [python2, amqp_tester, send_address, amqp_port, amqp_message]
print(send_command)
output = subprocess.check_output(send_command)
# Get the public address for rabbitmq-server instance 1.
receive_address = rabbit_units[1].info['public-address']
# Create the command that receives the message from instance 1.
recieve_command = [python2, amqp_tester, receive_address, amqp_port]
print(recieve_command)
output = subprocess.check_output(receive_command)
# The output is a byte string so convert the message to a byte string.
if output.find(amqp_message.encode()) == -1:
    print(output)
    message = 'Server {0} did not receive the AMQP message "{1}"'.format(
              receive_address, amqp_message)
    amulet.raise_status(amulet.FAIL, msg=message)
else:
    print('Server {0} received the AMQP message sent from {1}'.format(
          receive_address, send_address))

print('The rabbitmq-server charm passed this relations test.')
