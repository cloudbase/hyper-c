# Overview

This charm deploys a Windows Active Directory forest.
Active Directory (AD) is a directory service that Microsoft developed
for Windows domain networks and is included in most Windows Server
operating systems as a set of processes and services.

An active-directory unit can be deployed on a virtual or baremetal machine,
as long as it meets the minimum Windows Server 2012 (R2) minimum requirements.

No other manual steps are required in order to scale the Active Directory deployment.

Currently, the user must specify the administrator password.
In the future, this will be replaced by a Juju self generated password which will be exposed to the user.

An Active Directory deployment is a core component for various Windows failover,
clustering or live migration scenarios. Hyper-V, Cinder, Exchange, SMB,
Failover-Cluster, Microsoft SQL Server Always On or VDI charms
use Active Directory for centralized user, authentication, network and resource management.

As Active Directory uses Lightweight Directory Access Protocol
(LDAP) versions 2 and 3, Kerberos and DNS protocols, it can easily
interact wit Unix-based services.

The current supported Windows versions for this charm are
Windows Server 2012 and Windows Server 2012 R2.

The Active Directory deployment can scale by adding multiple
Active Directory Domain Controllers, which will be part of the 
same Active Directory forest,basically scaling out your initial
deployment by adding extra Active Directory Controllers.

Co-location of other charms or multiple units of active-directory
on the same node with the active-directory charm is not supported.

# Version

0.3

# CharmHelpers version

0.33

# Usage

How to deploy the charm:

    juju deploy active-directory

How to add a relation with another charm:

    juju add-relation active-directory <another deployed charm>

## Scale out Usage

If another unit is added, another Domain Controller instance will be deployed.

How to add another unit:

    juju add-unit active-directory

## Scale down usage

When a unit is destroyed, an Active Directory controller is demoted and the node will be destroyed.

How to destroy a unit:

    juju destroy-unit active-directory/<unit-number>
