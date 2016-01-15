#
# Copyright 2016 Cloudbase Solutions Srl
#

$computername = [System.Net.Dns]::GetHostName()

$ErrorActionPreference = 'Stop'
$nova_compute = "nova-compute"

$global:cimCreds = $null

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

function Grant-PrivilegesOnDomainUser {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Username
    )

    Grant-Privilege $Username SeServiceLogonRight

    $administratorsGroupSID = "S-1-5-32-544"
    Add-UserToLocalGroup -Username $Username -GroupSID $administratorsGroupSID
}

function Get-NewCimSession {
    Param(
        [Parameter(Mandatory=$true)]
        [array]$Nodes
    )

    foreach ($node in $nodes){
        try {
            Write-JujuInfo "Creating new CIM session on node $node"
            $session = New-CimSession -ComputerName $node
            return $session
        } catch {
            Write-JujuWarning "Failed to get CIM session on $node`: $_"
            continue
        }
    }
    Throw "Failed to get a CIM session on any of the provided nodes: $Nodes"
}

function Get-AdUserAndGroup {
    $creds = @{
        "s2duser"=@(
            "CN=Domain Admins,CN=Users"
        )
    }
    $ret = Get-MarshaledObject $creds
    return $ret
}

function Get-MyADCredentials {
    Param (
        [Parameter(Mandatory=$false)]
        [System.Object]$Credentials,
        [Parameter(Mandatory=$false)]
        [string]$Domain
    )
    if (!$Credentials){
        return $null
    }
    if(!$Domain){
        $Domain = "."
    }
    $obj = Get-UnmarshaledObject $Credentials
    $creds = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
    foreach($i in $obj.keys){
        $usr = $Domain + "\" + $i
        $clearPasswd = $obj[$i]
        $encPasswd = ConvertTo-SecureString -AsPlainText -Force $clearPasswd
        $pscreds = [System.Management.Automation.PSCredential](New-Object System.Management.Automation.PSCredential($usr, $encPasswd))
        $c = @{
            "pscredentials"=$pscreds;
            "password"=$clearPasswd;
            "username"=$usr;
        }
        $creds.Add($c)
    }
    return $creds
}

function Get-ActiveDirectoryContext {
    PROCESS {
        $blobKey = ("djoin-" + $computername)
        $requiredCtx = @{
            "already-joined" = $null;
            "address" = $null;
            "domainName" = $null;
            "netbiosname" = $null;
        }

        $optionalContext = @{
            $blobKey = $null;
            "adcredentials" = $null;
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
        if($ctx["adcredentials"]) {
            [array]$ctx["adcredentials"] = Get-MyADCredentials -Credentials $ctx["adcredentials"] -Domain $ctx["netbiosname"]
        }
        return $ctx
    }
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

