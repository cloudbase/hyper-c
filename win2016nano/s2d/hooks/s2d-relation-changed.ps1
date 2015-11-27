#
# Copyright 2014 Cloudbase Solutions SRL
#
$env:PSModulePath += "C:\Program Files\WindowsPowerShell\Modules;c:\windows\system32\windowspowershell\v1.0\Modules;$env:CHARM_DIR\lib\Modules"
import-module Microsoft.PowerShell.Management
import-module Microsoft.PowerShell.Utility
# we want to exit on error
$ErrorActionPreference = "Stop"

try {
    Import-Module -DisableNameChecking CharmHelpers
    $modulePath = "$PSScriptRoot\hooks.psm1"
    Import-Module -Force -DisableNameChecking $modulePath

    Run-S2DRelationChanged
}catch{
    juju-log.exe "Failed to run amqp-relation-joined: $_"
    exit 1
}
