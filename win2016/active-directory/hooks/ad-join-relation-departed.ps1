#
# Copyright 2014-2015 Cloudbase Solutions Srl
#
$ErrorActionPreference = 'Stop'
Import-Module JujuLoging

try {
    Import-Module ADHooks
    Start-ADRelationDepartedHook
} catch {
    Write-HookTracebackToLog $_
    exit 1
}