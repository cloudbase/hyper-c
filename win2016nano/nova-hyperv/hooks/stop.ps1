#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"

try {
    Import-Module -DisableNameChecking CharmHelpers
    Import-Module -Force -DisableNameChecking "$psscriptroot\compute-hooks.psm1"

    Stop-Service nova-compute
    Stop-Neutron
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
