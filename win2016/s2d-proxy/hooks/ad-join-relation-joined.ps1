#
# Copyright 2016 Cloudbase Solutions Srl
#

$ErrorActionPreference = "Stop"

Import-Module JujuLogging

function Get-AdUserAndGroup {
    $creds = @{
        "s2duser"=@(
            "CN=Domain Admins,CN=Users"
        )
    }
    $ret = Get-MarshaledObject $creds
    return $ret
}

try {
    Import-Module ADCharmUtils
    Import-Module JujuUtils

    $adUser = Get-AdUserAndGroup
    $computername = [System.Net.Dns]::GetHostName()
    $relation_set = @{
        'adusers' = $adUser;
        'computername' = $computername;
    }

    $rids = Get-JujuRelationIds -Relation "ad-join"
    foreach ($rid in $rids){
        $ret = Set-JujuRelation -RelationID $rid -Settings $relation_set
        if ($ret -eq $false){
           Write-JujuWarning "Failed to set ad-join relation"
        }
    }
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
