#
# Copyright 2014 Cloudbase Solutions SRL
#

$computername = [System.Net.Dns]::GetHostName()

if ($env:PSModulePath -eq "") {
    $env:PSModulePath = "${env:ProgramFiles}\WindowsPowerShell\Modules;${env:SystemDrive}\windows\system32\windowspowershell\v1.0\Modules;$env:CHARM_DIR\lib\Modules"
    import-module Microsoft.PowerShell.Management
    import-module Microsoft.PowerShell.Utility
}else{
    $env:PSModulePath += ";$env:CHARM_DIR\lib\Modules"
}

$ErrorActionPreference = 'Stop'
$nova_compute = "nova-compute"

Import-Module -Force -DisableNameChecking CharmHelpers

function Get-CimCredentials {
    if($cimCreds){
        return $cimCreds
    }
    juju-log.exe "Fetching active directory context"
    $ctx = Get-ActiveDirectoryContext
    if(!$ctx.Count) {
        return $false
    }
    juju-log.exe "Granting privileges on s2duser"
    GrantPrivileges-OnDomainUser -Username "s2duser" -Domain $ctx["netbiosname"]

    $clearPass = $ctx["my_ad_password"]
    juju-log.exe "Converting string to SecureString"
    $passwd = ConvertTo-SecureString -AsPlainText -Force $clearPass
    $usr = ($ctx["netbiosname"] + "\s2duser")
    juju-log.exe "Generating new credential object using $usr and $clearPass"
    $c = New-Object System.Management.Automation.PSCredential($usr, $passwd)
    Set-Variable -Scope Global -Name cimCreds -Value $c
    juju-log.exe "Returning creds"
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
            juju-log.exe "Creating new CIM session on node $node"
            $session = New-CimSession -ComputerName $node
            return $session
        } catch {
            juju-log.exe "Failed to get CIM session on $node`: $_"
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
    $ret = Marshall-Object $creds
    return $ret
}

function Is-InDomain {
    param(
        [Parameter(Mandatory=$true)]
        [string]$WantedDomain
    )

    $currentDomain = (gcim Win32_ComputerSystem).Domain.ToLower()
    $comparedDomain = ($WantedDomain).ToLower()
    $inDomain = $currentDomain.Equals($comparedDomain)
    return $inDomain
}

function Extract-ADCredentials {
    Param (
        [string]$creds
    )
    if (!$creds){
        return $null
    }
    $obj = Unmarshall-Object $creds
    $passwd = $obj."s2duser"
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
        juju-log.exe "Found related units: $related_units"
        if($related_units){
            foreach($unit in $related_units){
                $already_joined = relation_get -attr "already-joined" -rid $rid -unit $unit
                $ctx["ip_address"] = relation_get -attr "address" -rid $rid -unit $unit
                $ctx["ad_domain"] = relation_get -attr "domainName" -rid $rid -unit $unit
                $ctx["netbiosname"] = relation_get -attr "netbiosname" -rid $rid -unit $unit
                $ctx["djoin_blob"] = relation_get -attr $blobKey -rid $rid -unit $unit
                $creds = relation_get -attr "adcredentials" -rid $rid -unit $unit
                $ctx["my_ad_password"] = Extract-ADCredentials $creds
                if($already_joined){
                    $ctx.Remove("djoin_blob")
                    $ctx["partial"] = $true
                }
                $ctxComplete = Check-ContextComplete -ctx $ctx
                if ($ctxComplete){
                    break
                }
            }
        }
    }

    $ctxComplete = Check-ContextComplete -ctx $ctx
    if (!$ctxComplete){
        return @{}
    }
    return $ctx
}

function Is-GroupMember {
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Group,
		[Parameter(Mandatory=$true)]
        [string]$Username
	)
	$members = net localgroup $Group | 
		where {$_ -AND $_ -notmatch "command completed successfully"} | 
		select -skip 4
    foreach ($i in $members){
		if ($Username -eq $i){
			return $true
		}
	}
	return $false
}

function GrantPrivileges-OnDomainUser {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )

    $domUser = "$domain\$Username"
    Grant-Privilege $domUser SeServiceLogonRight

    $administratorsGroupSID = "S-1-5-32-544"
    $adminGroup = Convert-SIDToFriendlyName $administratorsGroupSID

    juju-log.exe "Checking if $Username is in $adminGroup"
    $isMember = Is-GroupMember -Group $adminGroup -Username $Username
    if (!$isMember){
        juju-log.exe "Adding $domUser to group $adminGroup"
        net localgroup $adminGroup $domUser /add 2>&1 | Out-Null
    }
}

function Set-JujudUser {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [string]$Password,
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )
    GrantPrivileges-OnDomainUser -Username $Username -Domain $Domain

    $jujuServices = gcim win32_service | Where-Object {$_.Name -like "jujud-*"}
    foreach($i in $jujuServices){
        if ($i.StartName -ne $domUser){
            juju-log.exe ($i.Name + "has service start name: " + $i.StartName)
            Change-ServiceLogon -Service $i.Name -UserName $domUser -Password $Password
            $shouldReboot = $true
        }
    }
    if ($shouldReboot){
        juju-reboot.exe --now
    }
    return $true
}

function Invoke-Djoin {    
    Juju-Log "Started Join Domain"
    $networkName = (Get-MainNetadapter)
    Set-DnsClientServerAddress -InterfaceAlias $networkName -ServerAddresses $params["ip_address"]
    ipconfig /flushdns
    if($LASTEXITCODE){
        Throw "Failed to flush dns"
    }

    $params = Get-ActiveDirectoryContext
    if($params["djoin_blob"]){
        $blobFile = Join-Path $env:TMP "djoin-blob.txt"
        WriteFile-FromBase64 $blobFile $params["djoin_blob"]
        djoin.exe /requestODJ /loadfile $blobFile /windowspath $env:SystemRoot /localos
        if($LASTEXITCODE){
            Throw "Failed to join domain: $LASTEXITCODE"
        }
        juju-reboot.exe --now
    }
}

function Juju-JoinDomain {
    # Install-WindowsFeatures $WINDOWS_FEATURES 
    $params = Get-ActiveDirectoryContext
    if ($params["partial"]){
        Juju-Log "Got partial context"
    }
    if ($params.Count){
        if (!(Is-InDomain $params['ad_domain'])) {
            if ($params["partial"]) {
                Throw "We only got partial context, and computer is not in desired domain."
            }
            Invoke-Djoin
        }
        GrantPrivileges-OnDomainUser -Username "s2duser" -Domain $params["netbiosname"]
        return $true
    }
    Juju-Log "ad-join returned EMPTY"
    return $false
}

Export-ModuleMember -Function *


