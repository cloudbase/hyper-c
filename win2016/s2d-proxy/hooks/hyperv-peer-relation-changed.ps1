#
# Copyright 2014-2015 Cloudbase Solutions Srl
#
$ErrorActionPreference = 'Stop'

try {
    $modulePath = "$PSScriptRoot\hooks.psm1"
    Import-Module -Force -DisableNameChecking $modulePath
    Import-Module -Force -DisableNameChecking CharmHelpers
} catch {
    $trace = $_.Exception | fl -Force
    juju-log.exe "Error while loading modules" -l ERROR
    juju-log.exe $trace -l ERROR
    exit 1
}

try {
    Write-JujuLog -Message "Running: Run-SetKCD"
    Run-SetKCD
} catch {
    $trace = $_.Exception | fl -Force
    Write-JujuLog "Error while running hyperv-peer-relation-changed.ps1" -LogLevel ERROR
    Write-JujuLog $trace -LogLevel ERROR
    exit 1
}