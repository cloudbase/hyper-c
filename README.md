This repository contains the following juju charms:

* upstream ubuntu cloud charms (keystone, cinder, nova-cloud-controller, dashboard, etc)
* nova-hyperv charm for nano server 2016
* Active directory juju charm for windows server 2016
* s2d-proxy responsible for creating a wsfc cluster, and enabling storage spaces direct on it
* s2d a subordonate charm to nova-hyperv that signals the proxy it is ready to be clustered (should be split as a normal charm).

This repo also contains a sample bundle (openstack.yaml) that can be used to deploy the whole thing.


## Requirements

* you will need a hacked version of juju-core that has support for Nano server 2016. For your convenience, the binaries have been added to this repository (juju-core.zip).
* juju-deployer from ppa:juju/stable
* nano image, windows server 2016 image uploaded to MaaS as: win2016nano, win2016
* the s2d charm will error out if you do not specify a static address for the cluster

## deploying

```shell
juju-deployer -L -S -c openstack.yaml
```
