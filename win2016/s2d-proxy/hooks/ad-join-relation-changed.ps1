#
# Copyright 2016 Cloudbase Solutions Srl
#

$ErrorActionPreference = "Stop"
Import-Module JujuLoging

try {
    Import-Module S2DUtils
    Import-Module ADCharmUtils

    Write-JujuLog -Message "Running Join-Domain"
    $done = Start-JoinDomain
    if($done) {
        Write-JujuLog -Message "Running relation changed"
        $script = "$psscriptroot\s2d-relation-changed-real.ps1"
        $creds = Get-CimCredentials
        $args = @("-File", "$script")
        $exitCode = Start-ProcessAsUser -Command "$PShome\powershell.exe" -Arguments ($args -Join " ") -Credential $creds -LoadUserProfile $false
        if($exitCode){
            Throw "Failed run $script`: $exitCode"
        }
    }
} catch {
    Write-HookTracebackToLog $_
    exit 1
}

