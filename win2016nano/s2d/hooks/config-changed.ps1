#
# Copyright 2014 Cloudbase Solutions SRL
#
try {
    $modulePath = "$PSScriptRoot\hooks.psm1"
    Import-Module -Force -DisableNameChecking $modulePath
} catch {
    juju-log.exe "Error while loading modules: $_.Exception.Message"
    exit 1
}


try {
    Broadcast-Ready
} catch {
    juju-log.exe "Error while running config-changed: $_"
    exit 1
}
