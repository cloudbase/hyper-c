#
# Copyright 2014-2016 Cloudbase Solutions SRL
#

$ErrorActionPreference = "Stop"

Import-Module JujuLogging
Import-Module JujuUtils
Import-Module JujuHooks

function Get-AdUserAndGroup {
    $adUser = Get-JujuCharmConfig -Scope 'ad-user'
    $creds = @{
        $adUser=@(
            "CN=Domain Admins,CN=Users"
        );
    }
    $ret = Get-MarshaledObject $creds
    return $ret
}

try {
    Import-Module ADCharmUtils

    $group = Get-JujuCharmConfig -Scope 'ad-computer-group'
    $adGroup = "CN=$group,OU=OpenStack"
    $encGr = ConvertTo-Base64 $adGroup
    $adUser = Get-AdUserAndGroup

    $computername = [System.Net.Dns]::GetHostName()
    $relationSettings = @{
        'adusers' = $adUser;
        'computername' = $computername;
        "computerGroup" = $encGr;
    }

    $rids = Get-JujuRelationIds -Relation "ad-join"
    foreach ($rid in $rids){
        $ret = Set-JujuRelation -RelationId $rid -Settings $relationSettings
        if ($ret -eq $false){
           Write-JujuWarning "Failed to set ad-join relation"
        }
    }
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
