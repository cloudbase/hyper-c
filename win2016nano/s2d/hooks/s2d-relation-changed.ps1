#
# Copyright 2014 Cloudbase Solutions SRL
#
# we want to exit on error
$ErrorActionPreference = "Stop"
Import-Module JujuLoging

try {
    Import-Module S2DHooks
    
    Start-S2DRelationChangedHook
}catch{
    Write-HookTracebackToLog $_
    exit 1
}
