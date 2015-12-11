#
# Copyright 2014-2015 Cloudbase Solutions Srl
#
$ErrorActionPreference = 'Stop'

try {
    $modulePath = "$PSScriptRoot\active-directory-common.psm1"
    Import-Module -Force -DisableNameChecking $modulePath
} catch {
    Write-JujuLog "Error while loading modules: $_" -LogLevel ERROR
    exit 1
}

try {
    Run-ConfigChangedHook
} catch {
    Write-JujuLog "Error while running main script: $_" -LogLevel ERROR
    exit 1
}
