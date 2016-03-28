#
# Copyright 2016 Cloudbase Solutions Srl
#

$ErrorActionPreference = "Stop"

Import-Module JujuLogging

try {
    Import-Module ADCharmUtils
    Import-Module JujuWindowsUtils
    Import-Module JujuUtils

    Write-JujuLog -Message "Running Join-Domain"
    $done = Start-JoinDomain
    if($done) {
        $ctx = Get-ActiveDirectoryContext
        if(!$ctx["adcredentials"]){
            return
        }
        $creds = $ctx["adcredentials"][0]["pscredentials"]
        Grant-PrivilegesOnDomainUser -Username $ctx["adcredentials"][0]["username"]

        $hooksFolder = Join-Path $env:CHARM_DIR "hooks"
        $wrapper = Join-Path $hooksFolder "run-with-ad-credentials.ps1"
        $hook = Join-Path $hooksFolder "s2d-relation-changed-real.ps1"
        Start-ExecuteWithRetry {
            Start-ExternalCommand { & $wrapper $hook }
        } -RetryInterval 10 -MaxRetryCount 10
    }
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
