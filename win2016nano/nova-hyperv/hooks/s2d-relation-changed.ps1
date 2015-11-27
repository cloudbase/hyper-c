#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"

try {
    Import-Module -Force -DisableNameChecking "$psscriptroot\compute-hooks.psm1"
}catch{
    juju-log.exe "Failed to import modules: $_"
    exit 1
}

try {
    Run-ConfigChanged
} catch {
    juju-log.exe "Failed to run s2d-container-relation-changed: $_"
    exit 1
}