#
# Copyright 2014 Cloudbase Solutions SRL
#

$env:PSModulePath += ";$env:CHARM_DIR\lib\Modules"

# we want to exit on error
$ErrorActionPreference = "Stop"

try {
    Import-Module -DisableNameChecking CharmHelpers
    Import-Module -Force -DisableNameChecking "$psscriptroot\active-directory.psm1"

    $adUser = Get-AdUserAndGroup

    $relation_set = @{
        'nano-adusers'=$adUser;
        'computername'=$env:computername;
    }

    $rids = relation_ids -reltype "ad-join"
    foreach ($rid in $rids){
        $ret = relation_set -relation_id $rid -relation_settings $relation_set
        if ($ret -eq $false){
            Write-JujuError "Failed to set ad-join relation" -Fatal $false
        }
    }
} catch {
    juju-log.exe "Failed to run ad-join-relation-joined: $_"
    juju-log.exe ($_.Exception|format-list -force)
    exit 1
}


