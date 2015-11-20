#!/bin/bash

neutron router-create router
neutron net-create private --provider:network_type vlan --provider:physical_network physnet1 --provider:segmentation_id 3002
neutron subnet-create --gateway 10.10.11.1 --allocation-pool start=10.10.11.10,end=10.10.11.250 --name private --dns-nameserver 10.228.163.3 private 10.10.11.0/24
neutron router-interface-add router private

neutron net-create ext_net -- --router:external=True
neutron subnet-create ext_net --allocation-pool start=10.7.12.100,end=10.7.12.150  --gateway=10.7.1.1 --enable_dhcp=False 10.7.0.0/16

neutron router-gateway-set router ext_net
