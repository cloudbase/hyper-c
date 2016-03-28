#
# Copyright 2016 Cloudbase Solutions Srl
#

$ErrorActionPreference = "Stop"

Import-Module JujuLogging

try {
    Import-Module JujuUtils

    $hooksFolder = Join-Path $env:CHARM_DIR "hooks"
    $wrapper = Join-Path $hooksFolder "run-with-ad-credentials.ps1"
    $hook = Join-Path $hooksFolder "smb-share-relation-changed-real.ps1"
    Start-ExternalCommand { & $wrapper $hook }
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
