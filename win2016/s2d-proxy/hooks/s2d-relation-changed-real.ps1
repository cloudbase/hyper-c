#
# Copyright 2016 Cloudbase Solutions Srl
#

$ErrorActionPreference = 'Stop'
Import-Module JujuLoging

try {
    $modulePath = "$PSScriptRoot\hooks.psm1"
    Import-Module -Force -DisableNameChecking $modulePath

    Write-JujuLog "Running : Start-S2DRelationChanged"
    Start-S2DRelationChanged
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
