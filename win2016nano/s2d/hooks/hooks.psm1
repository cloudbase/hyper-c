#
# Copyright 2015 Cloudbase Solutions SRL
#

$env:PSModulePath += "C:\Program Files\WindowsPowerShell\Modules;c:\windows\system32\windowspowershell\v1.0\Modules;$env:CHARM_DIR\lib\Modules"
import-module Microsoft.PowerShell.Management
import-module Microsoft.PowerShell.Utility
$ErrorActionPreference = "Stop"

Import-Module -Force -DisableNameChecking CharmHelpers
$computername = [System.Net.Dns]::GetHostName()

function Clear-AllDisks {
    Clear-Disk -Number 1 -RemoveOEM -Confirm:$false
}

function Run-S2DRelationChanged {
    $volumePath = relation_get -attr "volumepath" 
    if(!$volumePath){
        return $false
    }
    $relation_set = @{
        "s2dvolpath"=$volumePath;
    }
    $relations = relation_ids -reltype 's2d-container'
    foreach($rid in $relations){
        $ret = relation_set -relation_id $rid -relation_settings $relation_set
        if ($ret -eq $false){
            Write-JujuWarning "Failed to set s2d relation"
        }
    }
    
}

function Broadcast-Ready {
    $ready = "False"
    $relations = relation_ids -reltype 's2d-container'
    foreach($rid in $relations){
        $related_units = related_units -relid $rid
        foreach($unit in $related_units){
            $ready = relation_get -attr "ready" -rid $rid -unit $unit
            if ($ready -and $ready -eq "True"){
                break
            }
        }
    }
    $relation_set = @{
        "computername"=$computername; 
        "ready"=$ready;
    }

    $rids = relation_ids -reltype "s2d"
    foreach ($rid in $rids){
        $ret = relation_set -relation_id $rid -relation_settings $relation_set
        if ($ret -eq $false){
            Write-JujuWarning "Failed to set s2d relation"
        }
    }

}

Export-ModuleMember -Function *
