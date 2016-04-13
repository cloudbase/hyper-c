#
# Copyright 2014-2016 Cloudbase Solutions SRL
#

$ErrorActionPreference = "Stop"

Import-Module JujuLogging
Import-Module JujuUtils
Import-Module JujuHooks

$COMPUTERNAME = [System.Net.Dns]::GetHostName()


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
    $encGr = ConvertTo-Base64 ("CN={0},OU=OpenStack" -f @($group))
    $adUser = Get-AdUserAndGroup

    $relationSettings = @{
        'adusers' = $adUser;
        'computername' = $COMPUTERNAME;
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
