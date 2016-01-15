#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"

function Set-ExtraRelationParams {
    $adGroup = "CN=Nova,OU=OpenStack"

    $encGr = ConvertTo-Base64 $adGroup
    $relation_set = @{
        'computerGroup'=$encGr;
    }
    $ret = Set-JujuRelation -Settings $relation_set
    if ($ret -eq $false){
       Write-JujuWarning "Failed to set extra relation params"
    }
}

function Ping-Subordonate {
    $ready = "False"
    $params = Get-ActiveDirectoryContext
    if ($params.Count){
        if ((Confirm-IsInDomain $params['domainName'])) {
            $ready = "True"
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
        [string]$Password,
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )
    $domUser = "$domain\$Username"

    Grant-PrivilegesOnDomainUser -Username $Username -Domain $Domain
    Set-ServiceLogon -Services $nova_compute -UserName $domUser -Password $Password
    return $true
}

try {
    $adJoinModulePath = "$psscriptroot\active-directory.psm1"
    Import-Module -Force -DisableNameChecking $adJoinModulePath

    if((Start-JoinDomain)){
        $params = Get-ActiveDirectoryContext
        $username = "nova-hyperv"
        $pass = $params["my_ad_password"]
        Set-ExtraRelationParams
        Stop-Service $nova_compute
        Write-JujuInfo "Setting nova user"
        Set-NovaUser -Username $username -Password $pass -Domain $params['netbiosname']
        Start-Service $nova_compute
        Ping-Subordonate
    }
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
