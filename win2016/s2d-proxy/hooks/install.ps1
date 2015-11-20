#
# Copyright 2014-2015 Cloudbase Solutions Srl
#
$ErrorActionPreference = 'Stop'

try {
    $ret = Install-WindowsFeature -Name File-Services, Failover-Clustering -IncludeManagementTools
    if (!$ret.Success){
        Throw "Failed to ionstall windows features"
    }
    Enable-WindowsOptionalFeature -Online -FeatureName "ActiveDirectory-Powershell" -All
} catch {
    juju-log.exe "Error while running main script: $_"
    exit 1
}

