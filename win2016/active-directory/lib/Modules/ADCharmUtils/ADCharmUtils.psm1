#
# Copyright 2014-2015 Cloudbase Solutions Srl
#

function Set-UserRunAsRights {
    Param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $Username
    )
    # TODO: Check if we actually need all these...
    $privileges = @(
        "SeServiceLogonRight",
        "SeTakeOwnershipPrivilege",
        "SeSyncAgentPrivilege",
        "SeSecurityPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeRestorePrivilege",
        "SeShutdownPrivilege",
        "SeMachineAccountPrivilege",
        "SeTcbPrivilege",
        "SeInteractiveLogonRight",
        "SeBatchLogonRight",
        "SeNetworkLogonRight",
        "SeBackupPrivilege",
        "SeCreateTokenPrivilege",
        "SeCreatePermanentPrivilege",
        "SeCreatePagefilePrivilege",
        "SeSystemEnvironmentPrivilege",
        "SeProfileSingleProcessPrivilege",
        "SeCreateSymbolicLinkPrivilege")

    $allPrivillegesCount = $privileges.Count
    $allPrivillegesInstalled = 0
    foreach ($privilege in $privileges) {
        Grant-Privilege -User $Username -Grant $privilege
    }
    return $true
}

function Connect-ToADController {
    Param(
        [parameter(Mandatory=$true)]
        [HashTable]$ADParams,
        [string]$localAdminUsername="localadmin"
    )
    Write-JujuLog "Joining active directory domain..."
    $netbiosName = Convert-JujuUnitNameToNetbios
    $shouldReboot = $false
    if ($computername -ne $netbiosName) {
        Rename-Computer -NewName $netbiosName
        $shouldReboot = $true
    }
    if($shouldReboot){
        Invoke-JujuReboot -Now
    }

    $localAdminPassword = Get-RandomString -Length 20 -Weak
    New-LocalAdmin $localAdminUsername $localAdminPassword
    $passwordSecure = ConvertTo-SecureString -String $localAdminPassword -AsPlainText -Force
    $localCredential = New-Object PSCredential($localAdminUsername, $passwordSecure)
    $adCredential = Get-ADCredential $ADParams
    $networkName = Get-MainNetadapter
    Start-ExecuteWithRetry -Command {
        Join-Domain $ADParams["ad_domain"] `
                    $ADParams["ip_address"] `
                    $localCredential `
                    $adCredential `
                    $networkName
    } -MaxRetryCount 5 -RetryInterval 10
    Remove-WindowsUser $localAdminUsername
    Write-JujuLog "Finished joining active directory domain."
}

function Join-Domain {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FQDN,
        [Parameter(Mandatory=$true)]
        [string]$DomainCtrlIP,
        [Parameter(Mandatory=$true)]
        $LocalCredential,
        [Parameter(Mandatory=$true)]
        $ADCredential,
        [Parameter(Mandatory=$true)]
        $netAdapterName
    )

    $nameservers = Get-PrimaryAdapterDNSServers
    $new = @()
    if (!($DomainCtrlIP -in $nameservers)) {
        $new += $DomainCtrlIP
        $new += $nameservers
        $nameservers = $new
    }
    Set-DnsClientServerAddress -InterfaceAlias $netAdapterName `
            -ServerAddresses $nameservers

    Add-Computer -LocalCredential $LocalCredential `
                 -Credential $ADCredential `
                 -Domain $FQDN
}

function Get-DomainName {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FQDN
    )

    $fqdnParts = $FQDN.split(".")
    $domainNameParts = $fqdnParts[0..($fqdnParts.Length - 2)]
    $domainName = $domainNameParts -join '.'

    return $domainName
}

function Get-ADCredential {
    param(
        [Parameter(Mandatory=$true)]
        $ADParams
    )

    $adminUsername = $ADParams["ad_username"]
    $adminPassword = $ADParams["ad_password"]
    $domain = $ADParams["ad_domain"]
    $passwordSecure = ConvertTo-SecureString $adminPassword -AsPlainText -Force
    $adCredential = New-Object PSCredential("$adminUsername@$domain",
                                             $passwordSecure)

    return $adCredential
}

function Confirm-IsInDomain {
    param(
        [Parameter(Mandatory=$true)]
        [string]$WantedDomain
    )

    $currentDomain = (Get-WmiObject -Class `
                          Win32_ComputerSystem).Domain.ToLower()
    $comparedDomain = ($WantedDomain).ToLower()
    $inDomain = $currentDomain.Equals($comparedDomain)

    return $inDomain
}

function Get-ADGroupWrapper {
    param($SearchBase,
        $Credential,
        $Server)

    $cmd = Get-Command -Name "Get-ADGroup" -ErrorAction SilentlyContinue

    if ($cmd) {
        return (Get-ADGroup -Filter * -SearchBase $SearchBase -Credential $Credential -Server $Server)
    }
}

function Disconnect-FromADDomain {
    Param($ADParams)

    Write-JujuLog "Leaving AD domain..."

    $localAdminPassword = Get-RandomString -Length 20 -Weak
    $localAdminUsername = "adminlocal"
    New-LocalAdmin $localAdminUsername $localAdminPassword
    $passwordSecure = ConvertTo-SecureString -String $localAdminPassword -asPlainText -Force
    $localCredential = New-Object PSCredential($localAdminUsername, $passwordSecure)

    $adCredential = Get-ADCredential $ADParams
    Remove-Computer -LocalCredential $localCredential `
                    -UnJoinDomainCredential $adCredential `
                    -Force `
                    -Confirm:$false

    Remove-WindowsUser $localAdminUsername
    $networkName = (Get-MainNetadapter)
    Set-DnsClientServerAddress -InterfaceAlias $networkName -ResetServerAddresses

    Write-JujuLog "Finished leaving AD domain..."
    Invoke-JujuReboot -Now
}

New-Alias -Name ConnectTo-ADController -Value Connect-ToADController
New-Alias -name Is-InDomain -Value Confirm-IsInDomain
New-Alias -Name Leave-ADDomain -Value Disconnect-FromADDomain