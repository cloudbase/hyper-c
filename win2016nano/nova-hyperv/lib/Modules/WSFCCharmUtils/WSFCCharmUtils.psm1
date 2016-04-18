Import-Module JujuHooks

$computername = [System.Net.Dns]::GetHostName()

function Get-WSFCContext {
    $key = "clustered-$computername"
    $requiredCtxt = @{
        $key = $null;
        'cluster-name' = $null;
        'cluster-ip' = $null
    }
    $ctxt = Get-JujuRelationContext -Relation "failover-cluster" -RequiredContext $requiredCtxt
    if(!$ctxt.Count) {
        return @{}
    }
    return $ctxt
}

function Set-ClusterableStatus {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int]$Ready=1,
        [Parameter(Mandatory=$false)]
        [string]$Relation
    )
    PROCESS {
        $relation_set = @{
            "computername"=$computername; 
            "ready"=$Ready;
        }
        if($Relation) {
            $rids = Get-JujuRelationIds -Relation $Relation
        } else {
            $rids = Get-JujuRelationId
        }
        foreach ($rid in $rids){
            Write-JujuInfo ("Setting: {0} --> {1}" -f @($relation_set["computername"], $relation_set["ready"]))
            Set-JujuRelation -RelationId $rid -Settings $relation_set
        }
    }
}
