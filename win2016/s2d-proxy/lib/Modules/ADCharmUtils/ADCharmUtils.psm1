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
        [string]$Username,
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )

    $domUser = "$domain\$Username"
    Grant-Privilege $domUser SeServiceLogonRight

    $administratorsGroupSID = "S-1-5-32-544"
    Add-UserToLocalGroup -Username $domUser -GroupSID $administratorsGroupSID
}

function Get-CimCredentials {
    if($global:cimCreds){
        return $global:cimCreds
    }
    Write-JujuInfo "Fetching active directory context"
    $ctx = Get-ActiveDirectoryContext
    if(!$ctx) {
        return $false
    }
    Write-JujuInfo "Granting privileges on s2duser"
    Grant-PrivilegesOnDomainUser -Username "s2duser" -Domain $ctx["netbiosname"] | Out-Null

    $clearPass = $ctx["my_ad_password"]
    Write-JujuInfo "Converting string to SecureString"
    $passwd = ConvertTo-SecureString -AsPlainText -Force $clearPass
    $usr = ($ctx["netbiosname"] + "\s2duser")
    $c = [System.Management.Automation.PSCredential](New-Object System.Management.Automation.PSCredential($usr, $passwd))
    Set-Variable -Scope Global -Name cimCreds -Value $c
    Write-JujuInfo ("Returning: " + $c.GetType().FullName)
    return $c
}

function Get-NewCimSession {
    Param(
        [Parameter(Mandatory=$true)]
        [array]$Nodes
    )

    $creds = Get-CimCredentials
    if(!$creds){
        Throw "Failed to get CIM credentials"
    }
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
        [System.Object]$creds
    )
    if (!$creds){
        return $null
    }
    $obj = Get-UnmarshaledObject $creds
    $passwd = $obj["s2duser"]
    return $passwd
}

function Get-ActiveDirectoryContext {
    $ctx = @{
        "ip_address" = $null;
        "ad_domain" = $null;
        "my_ad_password" = $null;
        "djoin_blob" = $null;
        "netbiosname" = $null;
    }

    $blobKey = ("djoin-" + $computername)
    $relations = relation_ids -reltype "ad-join"
    foreach($rid in $relations){
        $related_units = related_units -relid $rid
        Write-JujuInfo "Found related units: $related_units"
        if($related_units){
            foreach($unit in $related_units){
                $already_joined = Get-JujuRelation -Attribute "already-joined" -RelationID $rid -unit $unit
                $ctx["ip_address"] = Get-JujuRelation -Attribute "address" -RelationID $rid -unit $unit
                $ctx["ad_domain"] = Get-JujuRelation -Attribute "domainName" -RelationID $rid -unit $unit
                $ctx["netbiosname"] = Get-JujuRelation -Attribute "netbiosname" -RelationID $rid -unit $unit
                $ctx["djoin_blob"] = Get-JujuRelation -Attribute $blobKey -RelationID $rid -unit $unit
                $creds = Get-JujuRelation -Attribute "adcredentials" -RelationID $rid -unit $unit
                $ctx["my_ad_password"] = Get-MyADCredentials $creds
                if($already_joined){
                    $ctx.Remove("djoin_blob")
                    $ctx["partial"] = $true
                }
                $ctxComplete = Confirm-ContextComplete -Context $ctx
                if ($ctxComplete){
                    break
                }
            }
        }
    }

    $ctxComplete = Confirm-ContextComplete -Context $ctx
    if (!$ctxComplete){
        return @{}
    }
    return $ctx
}

function Invoke-Djoin {    
    Write-JujuInfo "Started Join Domain"
    $networkName = (Get-MainNetadapter)
    Set-DnsClientServerAddress -InterfaceAlias $networkName -ServerAddresses $params["ip_address"]
    $cmd = @("ipconfig", "/flushdns")
    Invoke-JujuCommand -Command $cmd

    $params = Get-ActiveDirectoryContext
    if($params["djoin_blob"]){
        $blobFile = Join-Path $env:TMP "djoin-blob.txt"
        Write-FileFromBase64 -File $blobFile -Content $params["djoin_blob"]
        $cmd = @("djoin.exe", "/requestODJ", "/loadfile", $blobFile, "/windowspath", $env:SystemRoot, "/localos")
        Invoke-JujuCommand -Command $cmd
        Invoke-JujuReboot -Now
    }
}

function Start-JoinDomain {
    # Install-WindowsFeatures $WINDOWS_FEATURES 
    $params = Get-ActiveDirectoryContext
    if ($params["partial"]){
        Write-JujuInfo "Got partial context"
    }
    if ($params){
        if (!(Confirm-IsInDomain $params['ad_domain'])) {
            if ($params["partial"]) {
                Throw "We only got partial context, and computer is not in desired domain."
            }
            Invoke-Djoin
        }
        Grant-PrivilegesOnDomainUser -Username "s2duser" -Domain $params["netbiosname"]
        return $true
    }
    Write-JujuInfo "ad-join returned EMPTY"
    return $false
}

