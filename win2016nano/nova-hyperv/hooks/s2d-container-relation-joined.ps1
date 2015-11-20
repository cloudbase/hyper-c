#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"

try {
    Import-Module -DisableNameChecking CharmHelpers
    Import-Module -Force -DisableNameChecking "$psscriptroot\compute-hooks.psm1"

    $isInDomain = (gcim Win32_ComputerSystem).PartOfDomain
    if($isInDomain){
        $relation_settings = @{"ready"="True";}
    }else{
        $relation_settings = @{"ready"="False";}
    }
    $ret = relation_set -relation_settings $relation_set
}catch{
    juju-log.exe "Failed to run amqp-relation-joined: $_"
    exit 1
}
