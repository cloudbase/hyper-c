#
# Copyright 2014-2016 Cloudbase Solutions SRL
#

$ErrorActionPreference = "Stop"

Import-Module JujuLogging

try {
    Import-Module ADCharmUtils
    Import-Module ComputeHooks
    Import-Module S2DCharmUtils

    if(Start-JoinDomain) {
        Start-ADJoinRelationChangedHook
        Start-ADInfoRelationJoinedHook
        Start-WSFCRelationJoinedHook
        Start-S2DRelationJoinedHook
        Start-ConfigChangedHook
    }
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
