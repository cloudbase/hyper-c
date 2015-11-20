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

#    Grant-Privilege -User "Administrator" -Grant SeServiceLogonRight
#    $jujuServices = gcim win32_service | Where-Object {$_.Name -like "jujud-*"}
#    foreach($i in $jujuServices){
#        $shouldReboot = $false
#        $user = ".\Administrator"
#        if ($i.StartName -ne $user){
#            juju-log.exe ($i.Name + "has service start name: " + $i.StartName)
#            Change-ServiceLogon -Service $i.Name -UserName ".\Administrator" -Password "P@ssw0rd"
#            $shouldReboot = $true
#        }
#    }
#    if ($shouldReboot){
#        juju-reboot.exe --now
#    }
    PowerCfg.exe /S 8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C
    if ($LASTEXITCODE){
        juju-log.exe "WARNING: Failed to set power scheme. Error code: $LASTEXITCODE"
    }
    juju-log.exe "Prerequisites"
    Install-Prerequisites
    Run-TimeResync
    juju-log.exe "Cloudbase certificate"
    Import-CloudbaseCert -NoRestart
    juju-log.exe "Configure vmswitch"
    Juju-ConfigureVMSwitch
    $installerPath = Get-NovaInstaller
    Juju-Log "Running Nova install"
    Install-Nova -InstallerPath $installerPath
    Juju-Log "Running Check-ServicePrerequisites"
    Check-ServicePrerequisites
    Juju-Log "Running Configure-NeutronAgent"
    Configure-NeutronAgent
}

try{
    juju-log.exe "Starting install"
    Juju-RunInstall
}catch{
    juju-log.exe "Failed to run install: $_"
    exit 1
}
