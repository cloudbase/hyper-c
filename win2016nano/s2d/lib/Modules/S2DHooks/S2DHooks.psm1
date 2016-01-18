#
# Copyright 2015 Cloudbase Solutions SRL
#

$ErrorActionPreference = "Stop"

$computername = [System.Net.Dns]::GetHostName()

function Clear-AllDisks {
    Get-Disk | Where-Object {
        $_.IsBoot -eq $false -and $_.IsSystem -eq $false
    } | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false -ErrorAction SilentlyContinue
}

function Start-S2DRelationChangedHook {
    $volumePath = Get-JujuRelation -Attribute "volumepath" 
    if(!$volumePath){
        return $false
    }
    $relation_set = @{
        "s2dvolpath"=$volumePath;
    }
    $relations = Get-JujuRelationIds -Relation 's2d-container'
    foreach($rid in $relations){
        Set-JujuRelation -RelationId $rid -Settings $relation_set
    }
    
}

function Ping-S2DReady {
    $ready = $false
    $relations = Get-JujuRelationIds -Relation 's2d-container'
    foreach($rid in $relations){
        $related_units = Get-JujuRelatedUnits -RelationId $rid
        foreach($unit in $related_units){
            $ready = Get-JujuRelation -Attribute "ready" -RelationId $rid -Unit $unit
            if ($ready){
                break
            }
        }
    }
    $relation_set = @{
        "computername"=$computername; 
        "ready"=$ready;
    }

    $rids = Get-JujuRelationIds -Relation "s2d"
    foreach ($rid in $rids){
        Set-JujuRelation -RelationId $rid -Settings $relation_set
    }

}

Export-ModuleMember -Function *
