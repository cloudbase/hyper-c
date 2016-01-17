#
# Copyright 2016 Cloudbase Solutions Srl
#

# we want to exit on error
$ErrorActionPreference = "Stop"
$computername = [System.Net.Dns]::GetHostName()
Import-Module JujuLoging
Import-Module JujuUtils

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
    
    $adUser = Get-AdUserAndGroup

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
