#
# Copyright 2014-2016 Cloudbase Solutions SRL
#

$ErrorActionPreference = "Stop"

Import-Module JujuLogging

try {
    Import-Module S2DCharmUtils
    Import-Module ComputeHooks

    Start-S2DRelationJoinedHook
    Start-ConfigChangedHook
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
