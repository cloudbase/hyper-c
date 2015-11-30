#
# Copyright 2014 Cloudbase Solutions SRL
#
$env:PSModulePath += "C:\Program Files\WindowsPowerShell\Modules;c:\windows\system32\windowspowershell\v1.0\Modules;$env:CHARM_DIR\lib\Modules"
import-module Microsoft.PowerShell.Management
import-module Microsoft.PowerShell.Utility
# we want to exit on error
$ErrorActionPreference = "Stop"
$computername = [System.Net.Dns]::GetHostName()

try {
    Import-Module -DisableNameChecking CharmHelpers

    $isInDomain = (gcim Win32_ComputerSystem).PartOfDomain
    if($isInDomain){
        $relation_settings = @{"ready"="True"; "computername"=$computername;}
    }else{
        $relation_settings = @{"ready"="False"; "computername"=$computername;}
    }
    $ret = relation_set -relation_settings $relation_settings
}catch{
    juju-log.exe "Failed to run amqp-relation-joined: $_"
    exit 1
}
