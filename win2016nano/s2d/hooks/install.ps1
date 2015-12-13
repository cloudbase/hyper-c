# Copyright 2015 Cloudbase Solutions Srl
$ErrorActionPreference = 'Stop'

try {
    $modulePath = "$PSScriptRoot\hooks.psm1"
    Import-Module -Force -DisableNameChecking $modulePath

    Clear-AllDisks
} catch {
    Write-HookTracebackToLog $_
    exit 1
}

