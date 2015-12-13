#
# Copyright 2014 Cloudbase Solutions SRL
#

$ErrorActionPreference = 'Stop'

try {
    $modulePath = "$PSScriptRoot\hooks.psm1"
    Import-Module -Force -DisableNameChecking $modulePath

    Broadcast-Ready
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
