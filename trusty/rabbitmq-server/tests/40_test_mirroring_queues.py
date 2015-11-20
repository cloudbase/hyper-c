#!/usr/bin/python
#
# This Amulet test deploys rabbitmq-server
#
# Note: We use python2, because pika doesn't support python3

import amulet
import pika
import telnetlib


# The number of seconds to wait for the environment to setup.
seconds = 2700

d = amulet.Deployment(series="trusty")
# Add the rabbitmq-server charm to the deployment.
d.add('rabbitmq-server', units=2)

# Create a configuration.
configuration = {'mirroring-queues': True,
                 'management_plugin': True}
d.configure('rabbitmq-server', configuration)
d.expose('rabbitmq-server')

try:
    d.setup(timeout=seconds)
    d.sentry.wait(seconds)
except amulet.helpers.TimeoutError:
    message = 'The environment did not setup in %d seconds.' % seconds
    amulet.raise_status(amulet.SKIP, msg=message)
except:
    raise


rabbit_unit = d.sentry.unit['rabbitmq-server/0']
rabbit_unit2 = d.sentry.unit['rabbitmq-server/1']

commands = ['service rabbitmq-server status',
            'rabbitmqctl cluster_status']

for cmd in commands:
    output, code = rabbit_unit.run(cmd)
    message = cmd + ' | exit code: %d.' % code
    print(message)
    print(output)

    if code != 0:
        amulet.raise_status(amulet.FAIL, msg=message)

rabbit_addr1 = rabbit_unit.info["public-address"]
rabbit_port = "5672"
rabbit_url = 'amqp://guest:guest@%s:%s/%%2F' % (rabbit_addr1, rabbit_port)

print('Connecting to %s' % rabbit_url)
conn1 = pika.BlockingConnection(pika.connection.URLParameters(rabbit_url))
channel = conn1.channel()
print('Declaring queue')
channel.queue_declare(queue='hello')
orig_msg = 'Hello World!'
print('Publishing message: %s' % orig_msg)
channel.basic_publish(exchange='',
                      routing_key='hello',
                      body=orig_msg)

print('stopping rabbit in unit 0')
rabbit_unit.run('service rabbitmq-server stop')

print('Consuming message from second unit')
rabbit_addr2 = rabbit_unit2.info["public-address"]
rabbit_url2 = 'amqp://guest:guest@%s:%s/%%2F' % (rabbit_addr2, rabbit_port)
conn2 = pika.BlockingConnection(pika.connection.URLParameters(rabbit_url2))
channel2 = conn2.channel()
method_frame, header_frame, body = channel2.basic_get('hello')

if method_frame:
    print(method_frame, header_frame, body)
    assert body == orig_msg, '%s != %s' % (body, orig_msg)
    channel2.basic_ack(method_frame.delivery_tag)
else:
    raise Exception('No message returned')

# check the management plugin is running
mgmt_port = "15672"
print('Checking management port')
telnetlib.Telnet(rabbit_addr2, mgmt_port)
