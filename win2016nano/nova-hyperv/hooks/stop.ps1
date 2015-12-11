#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"

try {
    Import-Module -DisableNameChecking CharmHelpers
    Import-Module -Force -DisableNameChecking "$psscriptroot\compute-hooks.psm1"
}catch{
    Write-JujuLog "Failed to import modules: $_" -LogLevel ERROR
    exit 1
}

try {
    Stop-Service nova-compute
    Stop-Neutron
} catch {
    Write-JujuLog "Failed to stop services : $_" -LogLevel ERROR
    exit 1
}
