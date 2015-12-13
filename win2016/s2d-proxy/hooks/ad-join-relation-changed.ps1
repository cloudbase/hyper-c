$ErrorActionPreference = "Stop"

try {
    if ($env:PSModulePath -eq "") {
        $env:PSModulePath = "${env:ProgramFiles}\WindowsPowerShell\Modules;${env:SystemDrive}\windows\system32\windowspowershell\v1.0\Modules;$env:CHARM_DIR\lib\Modules"
        import-module Microsoft.PowerShell.Management
        import-module Microsoft.PowerShell.Utility
    }else{
        $env:PSModulePath += ";$env:CHARM_DIR\lib\Modules"
    }

    $adJoinModulePath = "$psscriptroot\active-directory.psm1"
    $hooksPath = "$psscriptroot\hooks.psm1"
    Import-Module -Force -DisableNameChecking $adJoinModulePath
    Import-Module -Force -DisableNameChecking $hooksPath
    Import-Module -Force -DisableNameChecking CharmHelpers

    Write-JujuLog -Message "Running Join-Domain"
    $done = Juju-JoinDomain 
    if($done) {
        Write-JujuLog -Message "Running relation changed"
        $script = "$psscriptroot\s2d-relation-changed-real.ps1"
        $creds = Get-CimCredentials
        $args = @("-File", "$script")
        $exitCode = Start-ProcessAsUser -Command "$PShome\powershell.exe" -Arguments ($args -Join " ") -Credential $creds
        if($exitCode){
            Throw "Failed run $script`: $exitCode"
        }
    }
} catch {
    Write-HookTracebackToLog $_
    exit 1
}

