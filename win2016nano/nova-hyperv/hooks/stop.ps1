#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"
Import-Module JujuLoging

try {
    Import-Module ComputeHooks

    Stop-Service "nova-compute"
    Stop-Neutron
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
