#
# Copyright 2014-2015 Cloudbase Solutions Srl
#
$ErrorActionPreference = 'Stop'

try {
    $modulePath = "$PSScriptRoot\hooks.psm1"
    Import-Module -Force -DisableNameChecking $modulePath
} catch {
    juju-log.exe "Error while loading modules: $_"
    exit 1
}

try {
    juju-log.exe "Running: Run-SetKCD"
    Run-SetKCD
} catch {
    juju-log.exe "Error while running main script: $_"
    exit 1
}