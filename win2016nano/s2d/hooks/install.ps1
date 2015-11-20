# Copyright 2015 Cloudbase Solutions Srl
$ErrorActionPreference = 'Stop'

try {
    $modulePath = "$PSScriptRoot\hooks.psm1"
    Import-Module -Force -DisableNameChecking $modulePath
} catch {
    juju-log.exe "Error while loading modules: $_.Exception.Message"
    exit 1
}


try {
    Clear-AllDisks
} catch {
    juju-log.exe "Error while running main script: $_.Exception.Message"
    exit 1
}

