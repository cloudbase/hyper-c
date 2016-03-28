#
# Copyright 2015-2016 Cloudbase Solutions SRL
#

$ErrorActionPreference = "Stop"

Import-Module ADCharmUtils
Import-Module WSFCCharmUtils
Import-Module JujuHooks

function Start-S2DRelationJoinedHook {
    $adCtxt = Get-ActiveDirectoryContext
    if (!$adCtxt.Count) {
        Write-JujuLog "Delaying the S2D relation changed hook until AD context is ready"
        return
    }
    $wsfcCtxt = Get-WSFCContext
    if (!$wsfcCtxt.Count) {
        Write-JujuLog "Delaying the S2D relation changed hook until WSFC context is ready"
        return
    }

    Get-Disk | Where-Object {
        $_.IsBoot -eq $false -and $_.IsSystem -eq $false
    } | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false -ErrorAction SilentlyContinue

    $computername = [System.Net.Dns]::GetHostName()
    $settings = @{
        'ready' = $true;
        'computername' = $computername;
        'joined-cluster-name' = $wsfcCtxt['cluster-name']
    }
    $rids = Get-JujuRelationIds -Relation 's2d'
    foreach ($rid in $rids) {
        $ret = Set-JujuRelation -RelationId $rid -Settings $settings
        if ($ret -ne $true) {
            Write-JujuWarning "Failed to set S2D relation context."
        }
    }
}
