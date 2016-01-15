#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"
$computername = [System.Net.Dns]::GetHostName()

try {
    Import-Module -DisableNameChecking CharmHelpers
    Import-Module -Force -DisableNameChecking "$psscriptroot\active-directory.psm1"

    $adUser = Get-AdUserAndGroup

    $relation_set = @{
        'adusers' = $adUser;
        'computername' = $computername;
    }

    $rids = Get-JujuRelationIds -Relation "ad-join"
    foreach ($rid in $rids){
        Set-JujuRelation -RelationID $rid -Settings $relation_set
    }
} catch {
    Write-HookTracebackToLog $_
    exit 1
}


