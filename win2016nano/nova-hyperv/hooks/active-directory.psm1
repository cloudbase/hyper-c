#
# Copyright 2014 Cloudbase Solutions SRL
#

$env:PSModulePath = "${env:ProgramFiles}\WindowsPowerShell\Modules;${env:SystemDrive}\windows\system32\windowspowershell\v1.0\Modules;$env:CHARM_DIR\lib\Modules"
import-module Microsoft.PowerShell.Management
import-module Microsoft.PowerShell.Utility
$computername = [System.Net.Dns]::GetHostName()

$ErrorActionPreference = 'Stop'
$nova_compute = "nova-compute"

Import-Module -Force -DisableNameChecking CharmHelpers

function Confirm-IsInDomain {
    param(
        [Parameter(Mandatory=$true)]
        [string]$WantedDomain
    )

    $currentDomain = (Get-ManagementObject -Class Win32_ComputerSystem).Domain.ToLower()
    $comparedDomain = ($WantedDomain).ToLower()
    $inDomain = $currentDomain.Equals($comparedDomain)

    return $inDomain
}

function Get-AdUserAndGroup {
    $creds = @{
        "nova-hyperv"=@(
            "CN=Domain Admins,CN=Users"
        )
    }
    $ret = Get-MarshaledObject $creds
    return $ret
}

function Get-MyADCredentials {
    Param (
        [System.Object]$creds
    )
    if (!$creds){
        return $null
    }
    $obj = Get-UnmarshaledObject $creds
    $passwd = $obj["nova-hyperv"]
    return $passwd
}

function Get-ActiveDirectoryContext {
    $blobKey = ("djoin-" + $computername)
    $requiredCtx = @{
        "already-joined" = $null;
        "address" = $null;
        "domainName" = $null;
        "netbiosname" = $null;
        "adcredentials" = $null;
    }

    $optionalContext = @{
        $blobKey = $null;
    }
    $ctx = Get-JujuRelationContext -Relation "ad-join" -RequiredContext $requiredCtx -OptionalContext $optionalContext

    # Required context not found
    if(!$ctx.Count) {
        return @{}
    }
    # A node may be added to an active directory domain outside of Juju, or it may be added by another charm colocated.
    # If another charm adds the computer to AD, we still get back a djoin_blob, but if we manually add a computer, the
    # djoin blob will be empty. That is the reason we make the djoin blob optional.
    if($ctx["already-joined"] -eq $false -and !$ctx[$blobKey]){
        return @{}
    }

    # replace the djoin data key with something less dynamic
    $djoin_data = $ctx[$blobKey]
    $ctx.Remove($blobKey)
    $ctx["djoin_blob"] = $djoin_data

    # Deserialize credential info
    $ctx["my_ad_password"] = Get-MyADCredentials $ctx["adcredentials"]
    $ctx.Remove("adcredentials")
    return $ctx
}

function Grant-PrivilegesOnDomainUser {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )

    $domUser = "$domain\$Username"
    Grant-Privilege $domUser SeServiceLogonRight

    $administratorsGroupSID = "S-1-5-32-544"
    Add-UserToLocalGroup -Username $domUser -GroupSID $administratorsGroupSID
}

function Invoke-Djoin {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$params
    )
    PROCESS {
        Write-JujuInfo "Started Join Domain"

        $networkName = (Get-MainNetadapter)
        Set-DnsClientServerAddress -InterfaceAlias $networkName -ServerAddresses $params["address"]
        $cmd = @("ipconfig", "/flushdns")
        Invoke-JujuCommand -Command $cmd

        if($params["djoin_blob"]){
            $blobFile = Join-Path $env:TMP "djoin-blob.txt"
            Write-FileFromBase64 -File $blobFile -Content $params["djoin_blob"]
            $cmd = @("djoin.exe", "/requestODJ", "/loadfile", $blobFile, "/windowspath", $env:SystemRoot, "/localos")
            Invoke-JujuCommand -Command $cmd
            Invoke-JujuReboot -Now
        }
    }
}

function Start-JoinDomain {
    # Install-WindowsFeatures $WINDOWS_FEATURES 
    $params = Get-ActiveDirectoryContext
    if ($params.Count){
        if (!(Confirm-IsInDomain $params['domainName'])) {
            if (!$params["djoin_blob"] -and $params["already-joined"]) {
                Throw "The domain controller reports that a computer with the same hostname as this unit is already added to the domain, and we did not get any domain join information."
            }
            Invoke-Djoin -params $params
        } else {
            return $true
        }
    }
    Write-JujuInfo "ad-join returned EMPTY"
    return $false
}

Export-ModuleMember -Function *
