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

    juju-log.exe "Running Join-Domain"
    $done = Juju-JoinDomain 
    if($done) {
        juju-log.exe "Running relation changed"
        $script = "$psscriptroot\s2d-relation-changed-real.ps1"
        juju-log.exe "<<<<<<<<<<<<2222222222222222222"
        $creds = Get-CimCredentials
        juju-log.exe "<<<<<<<<<<<<33333333333333333: $creds"
        $args = @("-File", "$script")
        $exitCode = Start-ProcessAsUser -Command "$PShome\powershell.exe" -Arguments ($args -Join " ") -Credential $creds
        if($exitCode){
            Throw "Failed run $script`: $exitCode"
        }
    }
} catch {
    juju-log.exe "Failed to join domain $_"
    exit 1
}

