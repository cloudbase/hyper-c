#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"

try {
    $adJoinModulePath = "$psscriptroot\active-directory.psm1"
    Import-Module -Force -DisableNameChecking $adJoinModulePath

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

    Join-Domain
} catch {
    juju-log.exe "Failed to run ad-join-relation-changed: $_"
    exit 1
}
