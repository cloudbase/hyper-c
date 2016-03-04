#
# Copyright 2014-2015 Cloudbase Solutions Srl
#
$ErrorActionPreference = 'Stop'
Import-Module JujuLogging

try {
    Import-Module ADHooks
    Start-LeaderElectedHook
} catch {
    Write-HookTracebackToLog $_
    exit 1
}