#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"
Import-Module JujuLoging
Import-Module JujuWindowsUtils
Import-Module JujuUtils

$nova_compute = "nova-compute"

function Ping-Subordonate {
    $ready = $false
    $params = Get-ActiveDirectoryContext
    if ($params.Count){
        if ((Confirm-IsInDomain $params['domainName'])) {
            $ready = $true
        }
    }

    $relation_set = @{
        "ready"=$ready;
    }
    $relations = Get-JujuRelationIds -Relation 's2d'
    Write-JujuInfo "Found relations $relations"
    foreach($rid in $relations){
        $ready = Set-JujuRelation -Settings $relation_set -RelationId $rid
    }
}

function Set-NovaUser {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [string]$Password
    )
    $domUser = "$domain\$Username"

    Grant-PrivilegesOnDomainUser -Username $Username
    Set-ServiceLogon -Services $nova_compute -UserName $Username -Password $Password
    return $true
}

try {
    Import-Module ADCharmUtils
    Import-Module ComputeHooks

    $ctx = Get-ActiveDirectoryContext
        if(!$ctx["adcredentials"]){
            return
        }

    if((Start-JoinDomain)){
        $params = Get-ActiveDirectoryContext
        if(!$params["adcredentials"]) {
            return
        }
        Write-JujuInfo ("Creds-->: {0}" -f $params["adcredentials"])
        $username = $params["adcredentials"][0]["username"]
        $pass = $params["adcredentials"][0]["password"]

        Stop-Service $nova_compute
        Write-JujuInfo "Setting nova user"
        Set-NovaUser -Username $username -Password $pass
        Start-ConfigChangedHook
        Ping-Subordonate
    }
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
