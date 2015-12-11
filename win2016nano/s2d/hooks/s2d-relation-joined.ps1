#
# Copyright 2014 Cloudbase Solutions SRL
#
try {
    $modulePath = "$PSScriptRoot\hooks.psm1"
    Import-Module -Force -DisableNameChecking $modulePath
} catch {
    Write-JujuLog "Error while loading modules: $_" -LogLevel ERROR
    exit 1
}


try {
    Broadcast-Ready
} catch {
    Write-JujuLog "Error while running s2d-relation-joined: $_" -LogLevel ERROR
    exit 1
}
