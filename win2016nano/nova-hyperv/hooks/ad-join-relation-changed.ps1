#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"
$computername = [System.Net.Dns]::GetHostName()

try {
    $adJoinModulePath = "$psscriptroot\active-directory.psm1"
    Import-Module -Force -DisableNameChecking $adJoinModulePath

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

    Join-Domain
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
