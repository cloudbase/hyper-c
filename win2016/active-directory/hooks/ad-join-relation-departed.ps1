#
# Copyright 2014-2015 Cloudbase Solutions Srl
#
$ErrorActionPreference = 'Stop'

try {
    $modulePath = "$PSScriptRoot\active-directory-common.psm1"
    Import-Module -Force -DisableNameChecking $modulePath
} catch {
    juju-log.exe "Error while loading modules: $_"
    exit 1
}

try {
    Run-ADRelationDepartedHook
} catch {
    juju-log.exe "Error while running main script: $_"
    exit 1
}