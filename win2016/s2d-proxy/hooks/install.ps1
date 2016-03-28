#
# Copyright 2016 Cloudbase Solutions Srl
#

$ErrorActionPreference = 'Stop'

Import-Module JujuLogging

try {
    $status = Install-WindowsFeature -Name 'File-Services','Failover-Clustering' -IncludeManagementTools
    if (!$status.Success){
        Throw "Failed to install Windows feature"
    }
    Enable-WindowsOptionalFeature -Online -FeatureName "ActiveDirectory-Powershell" -All
} catch {
    Write-HookTracebackToLog $_
    exit 1
}

