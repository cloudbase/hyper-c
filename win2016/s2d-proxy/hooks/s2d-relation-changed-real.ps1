# Copyright 2015 Cloudbase Solutions Srl
$ErrorActionPreference = 'Stop'
Import-Module JujuLoger

try {
    $modulePath = "$PSScriptRoot\hooks.psm1"
    Import-Module -Force -DisableNameChecking $modulePath

    Write-JujuLog "Running : Run-S2DRelationChanged"
    Run-S2DRelationChanged
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
