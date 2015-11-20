#!/usr/bin/python

# This class uses Python to make AMQP calls to send and receive messages.
# To send an AMQP message call this module with a host, port, and message.
# To receive an AMQP message call this module with a host and port only.

import logging
import pika
import sys


def send(host, port, message, queue='test'):
    """ Send an AMQP message to a host and port."""
    connection = None
    try:
        parameters = pika.ConnectionParameters(host, port)
        connection = pika.BlockingConnection(parameters)

        channel = connection.channel()
        channel.queue_declare(queue)
        channel.basic_publish(exchange='', routing_key=queue, body=message)
        print('Message published to {0}:{1}'.format(host, port))
    except Exception as e:
        print('Unable to send message to {0}:{1}'.format(host, port))
        print(e)
    finally:
        if connection:
            connection.close()


def callback(ch, method, properties, body):
    """ Handle the callback when the channel receives a message. """
    print(body)


def receive(host, port, queue='test'):
    """ Connects to host and port, and consumes AMQP messages. """
    connection = None
    try:
        parameters = pika.ConnectionParameters(host, port)
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()
        channel.queue_declare(queue)
        channel.basic_consume(callback, queue, no_ack=True)
    except Exception as e:
        print('Unable to receive message from {0}:{1}'.format(host, port))
        print(e)
    finally:
        if connection:
            connection.close()

# Needed to disable pika complaining about logging levels not set.
logging.basicConfig(level=logging.ERROR)

if len(sys.argv) == 3:
    host = sys.argv[1]
    port = int(sys.argv[2])
    receive(host, port)
elif len(sys.argv) > 3:
    host = sys.argv[1]
    port = int(sys.argv[2])
    message = ' '.join(sys.argv[3:])
    send(host, port, message)
else:
    print('Not enough arguments, host and port are required.')
