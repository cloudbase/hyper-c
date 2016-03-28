#
# Copyright 2016 Cloudbase Solutions Srl
#

$ErrorActionPreference = 'Stop'

Import-Module JujuLogging

try {
    Import-Module S2DProxyHooks

    Write-JujuLog "Running : Start-SMBShareRelationChanged"
    Start-SMBShareRelationChanged
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
