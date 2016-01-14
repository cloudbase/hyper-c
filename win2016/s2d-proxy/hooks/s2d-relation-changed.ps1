#
# Copyright 2016 Cloudbase Solutions Srl
#

$ErrorActionPreference = "Stop"
Import-Module JujuLoging

try {
    Import-Module ADCharmUtils
    Import-Module S2DUtils

    Write-JujuInfo "Running relation changed"
    $script = "$psscriptroot\s2d-relation-changed-real.ps1"
    $creds = Get-CimCredentials
    if(!$creds){
        Write-JujuWarning "Failed to get Cim credentials. Machine not yet in AD?"
        return $true
    }
    $args = @("-File", "$script")
    Write-JujuInfo "Running $script"
    $exitCode = Start-ProcessAsUser -Command "$PShome\powershell.exe" -Arguments ($args -Join " ") -Credential $creds
    if($exitCode){
        Throw "Failed run $script --> $exitCode"
    }
} catch {
    Write-HookTracebackToLog $_
    exit 1
}

