#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"

try {
    Import-Module -Force -DisableNameChecking "$psscriptroot\compute-hooks.psm1"
}catch{
    Write-JujuLog "Failed to import modules: $_" -LogLevel ERROR
    exit 1
}

try {
    Run-ConfigChanged
} catch {
    Write-JujuLog "Failed to run s2d-container-relation-changed: $_" -LogLevel ERROR
    exit 1
}
