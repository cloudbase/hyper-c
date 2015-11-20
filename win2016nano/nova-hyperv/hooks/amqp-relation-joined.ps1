#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"

try {
    Import-Module -DisableNameChecking CharmHelpers
    Import-Module -Force -DisableNameChecking "$psscriptroot\compute-hooks.psm1"

    $rabbitUser = charm_config -scope 'rabbit-user'
    $rabbitVhost = charm_config -scope 'rabbit-vhost'

    $relation_set = @{
        'username'=$rabbitUser;
        'vhost'=$rabbitVhost
    }

    $rids = relation_ids -reltype "amqp"
    foreach ($rid in $rids){
        $ret = relation_set -relation_id $rid -relation_settings $relation_set
        if ($ret -eq $false){
           Write-JujuError "Failed to set amqp relation" -Fatal $false
        }
    }
}catch{
    juju-log.exe "Failed to run amqp-relation-joined: $_"
    exit 1
}
