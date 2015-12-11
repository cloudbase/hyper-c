#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"
exit 0
try {
    Import-Module -DisableNameChecking CharmHelpers
    Import-Module -Force -DisableNameChecking "$psscriptroot\compute-hooks.psm1"
}catch{
    Write-JujuLog "Failed to import modules: $_" -LogLevel ERROR
    exit 1
}

try {
    Restart-Nova
    Restart-Neutron
} catch {
    Write-JujuLog "Failed to start services: $_" -LogLevel ERROR
    exit 1
}
