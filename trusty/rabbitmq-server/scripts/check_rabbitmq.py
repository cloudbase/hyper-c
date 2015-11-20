#!/usr/bin/python
#
#       #
#       #  #    #       #  #    #
#       #  #    #       #  #    #
#       #  #    #       #  #    #
# #     #  #    #       #  #    #
# #     #  #    #  #    #  #    #
#  #####    ####    ####    ####

# This file is managed by juju.  Do not make local changes.

# Copyright (C) 2009, 2012 Canonical
# All Rights Reserved
#
# tests RabbitMQ operation

""" test rabbitmq functionality """

import os
import sys
import signal
import socket

try:
    from amqplib import client_0_8 as amqp
except ImportError:
    print "CRITICAL: amqplib not found"
    sys.exit(2)

from optparse import OptionParser

ROUTE_KEY = "test_mq"


def alarm_handler(signum, frame):
    print "TIMEOUT waiting for all queued messages to be delivered"
    os._exit(1)


def get_connection(host_port, user, password, vhost):
    """ connect to the amqp service """
    if options.verbose:
        print "Connection to %s requested" % host_port
    try:
        ret = amqp.Connection(host=host_port, userid=user,
                              password=password, virtual_host=vhost,
                              insist=False)
    except (socket.error, TypeError), e:
        print "ERROR: Could not connect to RabbitMQ server %s:%d" % (
            options.host, options.port)
        if options.verbose:
            print e
            raise
        sys.exit(2)
    except:
        print "ERROR: Unknown error connecting to RabbitMQ server %s:%d" % (
            options.host, options.port)
        if options.verbose:
            raise
        sys.exit(3)
    return ret


def setup_exchange(conn, exchange_name, exchange_type):
    """ create an exchange """
    # see if we already have the exchange
    must_create = False
    chan = conn.channel()
    try:
        chan.exchange_declare(exchange=exchange_name, type=exchange_type,
                              passive=True)
    except (amqp.AMQPConnectionException, amqp.AMQPChannelException), e:
        if e.amqp_reply_code == 404:
            must_create = True
            # amqplib kills the channel on error.... we dispose of it too
            chan.close()
            chan = conn.channel()
        else:
            raise
    # now create the exchange if needed
    if must_create:
        chan.exchange_declare(exchange=exchange_name, type=exchange_type,
                              durable=False, auto_delete=False,)
        if options.verbose:
            print "Created new exchange %s (%s)" % (
                exchange_name, exchange_type)
    else:
        if options.verbose:
            print "Exchange %s (%s) is already declared" % (
                exchange_name, exchange_type)
    chan.close()
    return must_create


class Consumer(object):
    """ message consumer class """
    _quit = False

    def __init__(self, conn, exname):
        self.exname = exname
        self.connection = conn
        self.name = "%s_queue" % exname

    def setup(self):
        """ sets up the queue and links it to the exchange """
        if options.verbose:
            print self.name, "setup"
        chan = self.connection.channel()
        # setup the queue
        chan.queue_declare(queue=self.name, durable=False,
                           exclusive=False, auto_delete=False)
        chan.queue_bind(queue=self.name, exchange=self.exname,
                        routing_key=ROUTE_KEY)
        chan.queue_purge(self.name)
        chan.close()

    def check_end(self, msg):
        """ checks if this is an end request """
        return msg.body.startswith("QUIT")

    def loop(self, timeout=5):
        """ main loop for the consumer client """
        consumer_tag = "callback_%s" % self.name
        chan = self.connection.channel()

        def callback(msg):
            """ callback for message received """
            if options.verbose:
                print "Client %s saw this message: '%s'" % (self.name, msg.body)
            if self.check_end(msg):  # we have been asked to quit
                self._quit = True
        chan.basic_consume(queue=self.name, no_ack=True, callback=callback,
                           consumer_tag=consumer_tag)
        signal.signal(signal.SIGALRM, alarm_handler)
        signal.alarm(timeout)
        while True:
            chan.wait()
            if self._quit:
                break
        # cancel alarm for receive wait
        signal.alarm(0)
        chan.basic_cancel(consumer_tag)
        chan.close()
        return self._quit


def send_message(chan, exname, counter=None, message=None):
    """ publish a message on the exchange """
    if not message:
        message = "This is test message %d" % counter
    msg = amqp.Message(message)
    chan.basic_publish(msg, exchange=exname, routing_key=ROUTE_KEY)
    if options.verbose:
        print "Sent message: %s" % message


def main_loop(conn, exname):
    """ demo code to send/receive a few messages """
    # first, set up a few consumers
    # setup the queue that would collect the messages
    consumer = Consumer(conn, exname)
    consumer.setup()
    # open up our own connection and start sending messages
    chan = conn.channel()
    # loop a few messages
    for i in range(options.messages):
        send_message(chan, exname, i)
    # signal end of test
    send_message(chan, exname, message="QUIT")
    chan.close()

    # loop around for a while waiting for messages to be picked up
    return consumer.loop(timeout=options.timeout)


def main(host, port, exname, extype, user, password, vhost):
    """ setup the connection and the communication channel """
    sys.stdout = os.fdopen(os.dup(1), "w", 0)
    host_port = "%s:%s" % (host, port)
    conn = get_connection(host_port, user, password, vhost)
    chan = conn.channel()
    if setup_exchange(conn, exname, extype):
        if options.verbose:
            print "Created %s exchange of type %s" % (exname, extype)
    else:
        if options.verbose:
            print "Reusing existing exchange %s of type %s" % (exname, extype)
    ret = main_loop(conn, exname)
    chan.close()
    conn.close()
    return ret

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("--host", dest="host",
                      help="RabbitMQ host [default=%default]",
                      metavar="HOST", default="localhost")
    parser.add_option("--port", dest="port", type="int",
                      help="port RabbitMQ is running on [default=%default]",
                      metavar="PORT", default=5672)
    parser.add_option("--exchange", dest="exchange",
                      help="Exchange name to use [default=%default]",
                      default="test_exchange", metavar="EXCHANGE")
    parser.add_option("--type", dest="type",
                      help="EXCHANGE type [default=%default]",
                      metavar="TYPE", default="fanout")
    parser.add_option("-v", "--verbose", default=False, action="store_true",
                      help="verbose run")
    parser.add_option("-m", "--messages", dest="messages", type="int",
                      help="send NUM messages for testing [default=%default]",
                      metavar="NUM", default=10)
    parser.add_option("-t", "--timeout", dest="timeout", type="int",
                      help="wait TIMEOUT sec for loop test [default=%default]",
                      metavar="TIMEOUT", default=5)
    parser.add_option("-u", "--user", dest="user", default="guest",
                      help="RabbitMQ user [default=%default]",
                      metavar="USER")
    parser.add_option("-p", "--password", dest="password", default="guest",
                      help="RabbitMQ password [default=%default]",
                      metavar="PASSWORD")
    parser.add_option("--vhost", dest="vhost", default="/",
                      help="RabbitMQ vhost [default=%default]",
                      metavar="VHOST")

    (options, args) = parser.parse_args()
    if options.verbose:
        print """
Using AMQP setup: host:port=%s:%d exchange_name=%s exchange_type=%s
""" % (options.host, options.port, options.exchange, options.type)
    ret = main(options.host, options.port, options.exchange, options.type,
               options.user, options.password, options.vhost)
    if ret:
        print "Ok: sent and received %d test messages" % options.messages
        sys.exit(0)
    print "ERROR: Could not send/receive test messages"
    sys.exit(3)
