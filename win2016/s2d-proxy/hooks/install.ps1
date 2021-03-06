#
# Copyright 2014-2015 Cloudbase Solutions Srl
#
$ErrorActionPreference = 'Stop'

try {
    $ret = Install-WindowsFeature -Name File-Services, Failover-Clustering -IncludeManagementTools
    if (!$ret.Success){
        Throw "Failed to install windows features"
    }
    Enable-WindowsOptionalFeature -Online -FeatureName "ActiveDirectory-Powershell" -All
} catch {
    Write-HookTracebackToLog $_
    exit 1
}

