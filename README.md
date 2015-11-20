# tokyo-demo

This repository contains all juju charms demoed at the Tokyo OpenStack summit:

* upstream ubuntu cloud charms (keystone, cinder, nova-cloud-controller, dashboard, etc)
* nova-hyperv charm for nano server 2016
* Active directory juju charm for windows server 2016
* s2d-proxy responsible for creating a wsfc cluster, and enabling storage spaces direct on it
* s2d a subordonate charm to nova-hyperv that signals the proxy it is ready to be clustered (should be split as a normal charm).

This repo also contains a sample bundle (openstack.yaml) that can be used to deploy the whole thing.


## Requirements

* you will need a hacked version of juju-core that has support for Nano server 2016. For your convenience, the binaries have been added to this repository (juju-core.zip). This is based on juju core 1.25.0-beta3, so it may break in some cases, but I have found it to be sufficient for testing.
* juju-deployer from ppa:juju/stable
* nano image, windows server 2016 image uploaded to MaaS as: win2016nano, win2016
* the s2d charm will error out if you do not specify a static address for the cluster


## things to watch out for

The nova zip archive available [HERE](https://www.cloudbase.it/downloads/HyperVNovaCompute_Liberty_12_0_0.zip "Nova") might complain about psutil not being there. If that is the case, you might need to unarchive it, navigate to the psutil package, and move the files from inside that folder, one level up.

## deploying

```shell
juju-deployer -L -S -c openstack.yaml
```
