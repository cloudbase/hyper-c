#
# Copyright 2016 Cloudbase Solutions Srl
#

$ErrorActionPreference = 'Stop'

Import-Module JujuLogging

try {
    Import-Module JujuHooks

    $status = Install-WindowsFeature -Name 'File-Services','Failover-Clustering' -IncludeManagementTools
    if (!$status.Success){
        Throw "Failed to install Windows feature"
    }
    Enable-WindowsOptionalFeature -Online -FeatureName "ActiveDirectory-Powershell" -All
    $netbiosName = Convert-JujuUnitNameToNetbios
    $computername = [System.Net.Dns]::GetHostName()
    $hostnameChanged = Get-CharmState -Namespace "Common" -Key "HostnameChanged"
    if (!($hostnameChanged) -and ($computername -ne $netbiosName)) {
        Write-JujuWarning ("Changing computername from {0} to {1}" -f @($computername, $netbiosName))
        Rename-Computer -NewName $netbiosName
        Set-CharmState -Namespace "Common" -Key "HostnameChanged" -Value "True"
        Invoke-JujuReboot -Now
    }
} catch {
    Write-HookTracebackToLog $_
    exit 1
}

