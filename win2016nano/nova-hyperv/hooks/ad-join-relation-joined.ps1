#
# Copyright 2014 Cloudbase Solutions SRL
#

$env:PSModulePath += ";$env:CHARM_DIR\lib\Modules"

# we want to exit on error
$ErrorActionPreference = "Stop"
$computername = [System.Net.Dns]::GetHostName()

try {
    Import-Module -DisableNameChecking CharmHelpers
    Import-Module -Force -DisableNameChecking "$psscriptroot\active-directory.psm1"

    $adUser = Get-AdUserAndGroup

    $relation_set = @{
        'nano-adusers'=$adUser;
        'computername'=$computername;
    }

    $rids = relation_ids -reltype "ad-join"
    foreach ($rid in $rids){
        $ret = relation_set -rid $rid -relation_settings $relation_set
        if ($ret -eq $false){
            Write-JujuWarning "Failed to set ad-join relation"
        }
    }
} catch {
    Write-JujuLog "Failed to run ad-join-relation-joined: $_" -LogLevel ERROR
    exit 1
}


