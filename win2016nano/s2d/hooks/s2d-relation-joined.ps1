#
# Copyright 2014 Cloudbase Solutions SRL
#
$ErrorActionPreference = 'Stop'
Import-Module JujuLoging

try {
    Import-Module S2DHooks

    Ping-S2DReady
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
