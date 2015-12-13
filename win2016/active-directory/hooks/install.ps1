#
# Copyright 2014-2015 Cloudbase Solutions Srl
#
$ErrorActionPreference = 'Stop'

try {
    $modulePath = "$PSScriptRoot\active-directory-common.psm1"
    Import-Module -Force -DisableNameChecking $modulePath

    Run-TimeResync
    Run-InstallHook
} catch {
    Write-HookTracebackToLog $_
    exit 1
}