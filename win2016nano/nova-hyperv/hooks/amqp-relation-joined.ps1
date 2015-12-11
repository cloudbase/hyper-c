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
        $ret = relation_set -rid $rid -relation_settings $relation_set
        if ($ret -eq $false){
           Write-JujuWarning "Failed to set amqp relation"
        }
    }
}catch{
    Write-JujuLog "Failed to run amqp-relation-joined: $_" -LogLevel ERROR
    exit 1
}
