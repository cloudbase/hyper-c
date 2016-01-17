#
# Copyright 2014 Cloudbase Solutions SRL
#

$ErrorActionPreference = "Stop"
Import-Module JujuLoging

try{
    Import-Module ComputeHooks
    Start-InstallHook
}catch{
    Write-HookTracebackToLog $_
    exit 1
}
