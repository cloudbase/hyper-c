#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"

try {
    Import-Module -DisableNameChecking CharmHelpers
    Import-Module -Force -DisableNameChecking "$psscriptroot\compute-hooks.psm1"
    juju-log.exe "Checking domain membership"
    $compSys = gcim Win32_ComputerSystem
    $isInDomain = $compSys.PartOfDomain
    juju-log.exe ("Computer is part of " + $compSys.Domain)
    if($isInDomain){
        $relation_settings = @{"ready"="True";}
    }else{
        $relation_settings = @{"ready"="False";}
    }
    $ret = relation_set -relation_settings $relation_settings
}catch{
    juju-log.exe "Failed to run s2d-relation-changed: $_"
    exit 1
}
