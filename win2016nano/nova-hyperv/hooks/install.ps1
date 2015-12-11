#
# Copyright 2014 Cloudbase Solutions SRL
#

$ErrorActionPreference = "Stop"

try {
    Import-Module -Force -DisableNameChecking "$psscriptroot\compute-hooks.psm1"
}catch {
    juju-log.exe "Failed to run install: $_"
    exit 1
}

function Juju-RunInstall {
    Install-JsonModule

    if(!(Is-NanoServer)){
        try {
            Set-MpPreference -DisableRealtimeMonitoring $true
        } catch {
            # No need to error out the hook if this fails.
            Write-JujuWarning "Failed to disable antivirus: $_"
        }
    }
    # Set machine to use high performance settings.
    PowerCfg.exe /S 8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C
    if ($LASTEXITCODE){
        # No need to error out the hook if this fails.
        Write-JujuWarning "Failed to set power scheme. Error code: $LASTEXITCODE"
    }
    Install-Prerequisites
    Run-TimeResync
    Import-CloudbaseCert -NoRestart
    Juju-ConfigureVMSwitch
    $installerPath = Get-NovaInstaller
    Install-Nova -InstallerPath $installerPath
    Check-ServicePrerequisites
    Configure-NeutronAgent
}

try{
    Juju-RunInstall
}catch{
    Write-JujuLog "Failed to run install: $_" -LogLevel ERROR
    exit 1
}
