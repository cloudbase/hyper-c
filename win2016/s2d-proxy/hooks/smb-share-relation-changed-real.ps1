#
# Copyright 2016 Cloudbase Solutions Srl
#

$ErrorActionPreference = 'Stop'

Import-Module JujuLogging

try {
    Import-Module S2DProxyHooks

    Write-JujuLog "Running : Start-SMBShareRelationChanged"
    Start-SMBShareRelationChanged
    Write-JujuLog "Running : Start-S2DRelationChanged"
    Start-S2DRelationChanged
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
