Charm overview
==============

This charm provides Openstack Nova compute for Hyper-V.

Charm usage
===========

    juju deploy nova-hyperv
    juju add-relation nova-hyperv nova-cloud-controller
    juju add-relation nova-hyperv rabbitmq-server
    juju add-relation nova-hyperv glance

Charm config
============

Ideally you will deploy this charm to a machine that has at least 2 network cards. If only one is present, this charm will add that interface to a vmswitch and enable management OS on the bridge itself.

If more then one NIC is present, you will have to specify the data-port using the charm config. When adding a new node, make sure to update the data-port field using:

	juju set nova-hyperv data-port="aa:aa:aa:aa:aa:aa aa:aa:aa:aa:aa:ab"

where aa:aa:aa:aa:aa:ab is the second machine.
