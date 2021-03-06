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
