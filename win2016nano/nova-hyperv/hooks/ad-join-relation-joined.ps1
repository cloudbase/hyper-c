#
# Copyright 2016 Cloudbase Solutions Srl
#

# we want to exit on error
$ErrorActionPreference = "Stop"
$computername = [System.Net.Dns]::GetHostName()
Import-Module JujuLoging
Import-Module JujuUtils
Import-Module JujuHooks

function Get-AdUserAndGroup {
    $creds = @{
        "nova-hyperv"=@(
            "CN=Domain Admins,CN=Users"
        );
    }
    $ret = Get-MarshaledObject $creds
    return $ret
}

try {
    Import-Module ADCharmUtils

    $adGroup = "CN=Nova,OU=OpenStack"
    $encGr = ConvertTo-Base64 $adGroup
    $adUser = Get-AdUserAndGroup

    $relation_set = @{
        'adusers' = $adUser;
        'computername' = $computername;
        "computerGroup"=$encGr;
    }

    $rids = relation_ids -reltype "ad-join"
    foreach ($rid in $rids){
        $ret = relation_set -relation_id $rid -relation_settings $relation_set
        if ($ret -eq $false){
           Write-JujuWarning "Failed to set ad-join relation"
        }
    }
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
