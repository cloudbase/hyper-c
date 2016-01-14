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

function Get-AdUserAndGroup {
    $creds = @{
        "nova-hyperv"=@(
            "CN=Domain Admins,CN=Users"
        )
    }
    $ret = Get-MarshaledObject $creds
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

function Extract-NovaADCredentials {
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
    Write-JujuInfo "Started Join Domain"
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
       Write-JujuWarning "Failed to set extra relation params"
    }
}

function Ping-Subordonate {
    $ready = "False"
    $params = Get-RelationParams('ad-join')
    if ($params['context']){
        if ((Is-InDomain $params['ad_domain'])) {
            $ready = "True"
        }
    }

    $relation_set = @{
        "ready"=$ready;
    }
    $relations = relation_ids -reltype 's2d'
    Write-JujuInfo "Found relations $relations"
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
            Stop-Service $nova_compute
            Write-JujuInfo "Setting nova user"
            Set-NovaUser -Username $username -Password $pass -Domain $params['netbiosname']
            Start-Service $nova_compute
            Ping-Subordonate
        }
    } else {
        Write-JujuWarning "ad-join returned EMPTY. Peer not yet ready?"
    }
}

Export-ModuleMember -Function *
