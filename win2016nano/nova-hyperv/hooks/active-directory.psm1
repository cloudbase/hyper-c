#
# Copyright 2014 Cloudbase Solutions SRL
#

#if ($env:PSModulePath -eq "") {
$env:PSModulePath = "${env:ProgramFiles}\WindowsPowerShell\Modules;${env:SystemDrive}\windows\system32\windowspowershell\v1.0\Modules;$env:CHARM_DIR\lib\Modules"
import-module Microsoft.PowerShell.Management
import-module Microsoft.PowerShell.Utility
$computername = [System.Net.Dns]::GetHostName()

#}else{
#    $env:PSModulePath += ";$env:CHARM_DIR\lib\Modules"
#}

$ErrorActionPreference = 'Stop'
$nova_compute = "nova-compute"

Import-Module -Force -DisableNameChecking CharmHelpers

function Get-AdUserAndGroup {
    # pipe separated list of groups
    $groups = "CN=Domain Admins,CN=Users"
    $encoded = ConvertTo-Base64 $groups
    $creds = "nova-hyperv=$encoded"
    return $creds
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

function Extract-NovaADCredentials {
    Param (
        $creds
    )
    if (!$creds){
        return $false
    }
    $decoded = ConvertFrom-Base64 $creds
    $users = $decoded.Split("|")
    if(!$users){
        return $false
    }
    foreach ($i in $users){
        $elem = $i.Split("=", 2)
        if($elem.Length -ne 2){
            continue
        }
        $passwd = $elem[1]
        return $passwd
    }
    return $false
}

function Get-RelationParams($type){
    $ctx = @{
        "ad_host" = $null;
        "ip_address" = $null;
        "ad_hostname" = $null;
        "ad_username" = $null;
        "ad_password" = $null;
        "ad_domain" = $null;
        "my_ad_password" = $null;
        "djoin_blob" = $null;
        "netbiosname" = $null;
        "context" = $True;
    }

    $blobKey = ("djoin-" + $computername)
    $relations = relation_ids -reltype $type
    foreach($rid in $relations){
        $related_units = related_units -relid $rid
        if($related_units -ne $Null -and $related_units.Count -gt 0){
            foreach($unit in $related_units){
                $ctx["ad_host"] = relation_get -attr "private-address" -rid $rid -unit $unit
                $ctx["ip_address"] = relation_get -attr "address" -rid $rid -unit $unit
                $ctx["ad_hostname"] = relation_get -attr "hostname" -rid $rid -unit $unit
                $ctx["ad_username"] = relation_get -attr "username" -rid $rid -unit $unit
                $ctx["ad_password"] = relation_get -attr "password" -rid $rid -unit $unit
                $ctx["ad_domain"] = relation_get -attr "domainName" -rid $rid -unit $unit
                $ctx["netbiosname"] = relation_get -attr "netbiosname" -rid $rid -unit $unit
                $ctx["djoin_blob"] = relation_get -attr $blobKey -rid $rid -unit $unit
                $creds = relation_get -attr "nano-ad-credentials" -rid $rid -unit $unit
                $ctx["my_ad_password"] = Extract-NovaADCredentials $creds
                $ctxComplete = Check-ContextComplete -ctx $ctx
                if ($ctxComplete){
                    break
                }
            }
        } else {
            $ctx["ad_host"] = relation_get -attr "private-address" -rid $rid 
            $ctx["ip_address"] = relation_get -attr "address" -rid $rid
            $ctx["ad_hostname"] = relation_get -attr "hostname" -rid $rid
            $ctx["ad_username"] = relation_get -attr "username" -rid $rid 
            $ctx["ad_password"] = relation_get -attr "password" -rid $rid 
            $ctx["ad_domain"] = relation_get -attr "domainName" -rid $rid
            $ctx["netbiosname"] = relation_get -attr "netbiosname" -rid $rid
            $ctx["djoin_blob"] = relation_get -attr $blobKey -rid $rid
            $creds = relation_get -attr "nano-ad-credentials" -rid $rid
            $ctx["my_ad_password"] = Extract-NovaADCredentials $creds
            $ctxComplete = Check-ContextComplete -ctx $ctx
        }
    }

    $ctxComplete = Check-ContextComplete -ctx $ctx
    if (!$ctxComplete){
        $ctx["context"] = $False
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
	$ret = New-Object PSObject -Property @{
		Computername = $computername
		Group = $Group
		Members=$members
		}
        foreach ($i in $ret.Members){
		if ($Username -eq $i){
			return $true
		}
	}
	return $false
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
    Grant-Privilege $domUser SeServiceLogonRight
    #TODO: Find group name using SID. This does not currently support i18n
    $isMember = Is-GroupMember -Group "Administrators" -Username $domUser
    if (!$isMember){
    	net localgroup Administrators $domUser /add
    }
    Change-ServiceLogon $nova_compute $domUser $Password
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

    $params = Get-RelationParams('ad-join')
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

function Set-ExtraRelationParams {
    $adGroup = "CN=Nova,OU=OpenStack"

    $encGr = ConvertTo-Base64 $adGroup
    $relation_set = @{
        'computerGroup'=$encGr;
    }
    $ret = relation_set -relation_settings $relation_set
    if ($ret -eq $false){
       Write-JujuError "Failed to set extra relation params" -Fatal $false
    }
}

function Ping-Subordonate {
    $relations = relation_ids -reltype 's2d-container'
    $relation_set = @{
        "ready"="True";
    }
    foreach($rid in $relations){
        $ready = relation_set -relation_settings $relation_set -rid $rid
    }
}

function Join-Domain{
    # Install-WindowsFeatures $WINDOWS_FEATURES 
    $params = Get-RelationParams('ad-join')
    if ($params['context']){
        if (!(Is-InDomain $params['ad_domain'])) {
            Invoke-Djoin
        }else {
            Set-ExtraRelationParams
            $username = "nova-hyperv"
            $pass = $params["my_ad_password"]
            Juju-Log "Got password $pass from relation"
            Stop-Service $nova_compute
            Juju-Log "Setting nova user"
            Set-NovaUser -Username $username -Password $pass -Domain $params['netbiosname']
            Start-Service $nova_compute
            Ping-Subordonate
        }
    } else {
        Juju-Log "ad-join returned EMPTY"
    }
}

Export-ModuleMember -Function *


