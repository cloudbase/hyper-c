#
# Copyright 2014-2016 Cloudbase Solutions SRL
#

$ErrorActionPreference = "Stop"

Import-Module JujuLogging

try {
    Import-Module ComputeHooks

    Stop-Nova
    Stop-Neutron
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
