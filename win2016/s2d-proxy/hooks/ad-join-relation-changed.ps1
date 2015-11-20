$ErrorActionPreference = "Stop"

try {
    $adJoinModulePath = "$psscriptroot\active-directory.psm1"
    $hooksPath = "$psscriptroot\hooks.psm1"
    Import-Module -Force -DisableNameChecking $adJoinModulePath
    Import-Module -Force -DisableNameChecking $hooksPath

    juju-log.exe "Running Join-Domain"
    $done = Juju-JoinDomain 
    if($done) {
        juju-log.exe "Running relation changed"
        Run-S2DRelationChanged
    }
} catch {
    juju-log.exe "Failed to join domain $_.Exception.Message"
    exit 1
}

