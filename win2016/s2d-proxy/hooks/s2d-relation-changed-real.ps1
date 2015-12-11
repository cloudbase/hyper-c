# Copyright 2015 Cloudbase Solutions Srl
$ErrorActionPreference = 'Stop'

try {
    $modulePath = "$PSScriptRoot\hooks.psm1"
    Import-Module -Force -DisableNameChecking $modulePath
} catch {
    Write-JujuLog "Error while loading modules : $_" -LogLevel ERROR
    exit 1
}


try {
    Write-JujuLog "Running : Run-S2DRelationChanged"
    Run-S2DRelationChanged
} catch {
    Write-JujuLog "Error while running main script : $_" -LogLevel ERROR
    exit 1
}
