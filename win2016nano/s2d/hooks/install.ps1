# Copyright 2015 Cloudbase Solutions Srl
$ErrorActionPreference = 'Stop'
Import-Module JujuLoging


try {
    Import-Module S2DHooks

    Clear-AllDisks
} catch {
    Write-HookTracebackToLog $_
    exit 1
}

