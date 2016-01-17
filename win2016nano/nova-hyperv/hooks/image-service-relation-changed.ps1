#
# Copyright 2016 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"
Import-Module JujuLoging

try {
    Import-Module ComputeHooks

    Start-ConfigChangedHook
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
