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
        if($related_units -ne $Null -and $related_units.Count -gt 0){
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
        } else {
            $already_joined = relation_get -attr "already-joined" -rid $rid
            $ctx["ip_address"] = relation_get -attr "address" -rid $rid
            $ctx["ad_domain"] = relation_get -attr "domainName" -rid $rid
            $ctx["netbiosname"] = relation_get -attr "netbiosname" -rid $rid
            $ctx["djoin_blob"] = relation_get -attr $blobKey -rid $rid
            $creds = relation_get -attr "adcredentials" -rid $rid
            $ctx["my_ad_password"] = Extract-ADCredentials $creds
            if($already_joined){
                $ctx.Remove("djoin_blob")
                $ctx["partial"] = $true
            }
            $ctxComplete = Check-ContextComplete -ctx $ctx
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

function Set-JujudUser {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [string]$Password,
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )
    $domUser = "$domain\$Username"
    Grant-Privilege $domUser SeServiceLogonRight

    $administratorsGroupSID = "S-1-5-32-544"
    $adminGroup = Convert-SIDToFriendlyName $administratorsGroupSID

    $isMember = Is-GroupMember -Group $adminGroup -Username $domUser
    if (!$isMember){
    	net localgroup $adminGroup $domUser /add
    }

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
            return $false
        }else {
            $username = "s2duser"
            $pass = $params["my_ad_password"]
            Juju-Log "Got password $pass from relation"
            Juju-Log "Setting nova user"
            Set-JujudUser -Username $username -Password $pass -Domain $params['netbiosname']
            return $true
        }
    } else {
        Juju-Log "ad-join returned EMPTY"
    }
    return $false
}

Export-ModuleMember -Function *


