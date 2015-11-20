#
# Copyright 2014-2015 Cloudbase Solutions Srl
#

$utilsModulePath = Join-Path $PSScriptRoot "Utils.psm1"
Import-Module -Force -DisableNameChecking $utilsModulePath
$jujuModulePath = Join-Path $PSScriptRoot "Juju.psm1"
Import-Module -Force -DisableNameChecking $jujuModulePath
$windowsModulePath = Join-Path $PSScriptRoot "Windows.psm1"
Import-Module -Force -DisableNameChecking $windowsModulePath
$carbonModulePath = Join-Path $PSScriptRoot "Carbon.psm1"
Import-Module -Force -DisableNameChecking $carbonModulePath

function ConnectTo-ADController {
    Param(
        [parameter(Mandatory=$true)]
        [HashTable]$ADParams,
        [string]$localAdminUsername="localadmin"
    )
    Write-JujuLog "Joining active directory domain..."
    Rename-Hostname
    $localAdminPassword = Generate-StrongPassword
    Create-LocalAdmin $localAdminUsername $localAdminPassword
    $passwordSecure = ConvertTo-SecureString -String $localAdminPassword `
        -AsPlainText -Force
    $localCredential = New-Object `
        PSCredential($localAdminUsername, $passwordSecure)
    $adCredential = Get-ADCredential $ADParams
    $networkName = Get-MainNetadapter
    ExecuteWith-Retry -Command {
        Join-Domain $ADParams["ad_domain"] `
                    $ADParams["ip_address"] `
                    $localCredential `
                    $adCredential `
                    $networkName
    } -MaxRetryCount 5 -RetryInterval 10
    Delete-WindowsUser $localAdminUsername
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
    if (!($DomainCtrlIP -in $nameservers)) {
        $nameservers = ,$DomainCtrlIP + $nameservers
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
    $domain = Get-DomainName $ADParams["ad_domain"]
    $passwordSecure = ConvertTo-SecureString $adminPassword -AsPlainText -Force
    $adCredential = New-Object PSCredential("$domain\$adminUsername",
                                             $passwordSecure)

    return $adCredential
}

function Is-InDomain {
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

function Create-ADUsers {
    param(
        [Parameter(Mandatory=$true)]
        $UsersToAdd,
        [Parameter(Mandatory=$true)]
        [string]$AdminUsername,
        [Parameter(Mandatory=$true)]
        $AdminPassword,
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        [Parameter(Mandatory=$true)]
        [string]$DCName,
        [Parameter(Mandatory=$true)]
        [string]$MachineName
    )

    $dcsecpassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
    $dccreds = New-Object System.Management.Automation.PSCredential("$Domain\$AdminUsername", $dcsecpassword)
    $session = New-PSSession -ComputerName $DCName -Credential $dccreds
    Import-PSSession -AllowClobber -Session $session -CommandName New-ADUser, Get-ADUser, Set-ADAccountPassword

    foreach($user in $UsersToAdd){
        $username = $user['Name']
        $password = $user['Password']
        $alreadyUser = $False
        try{
            $alreadyUser = (Get-ADUser $username) -ne $Null
        }
        catch{
            $alreadyUser = $False
        }

        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        if($alreadyUser -eq $False){
            $Description = "AD user"
            New-ADUser -Name $username -AccountPassword $securePassword -Description $Description -Enabled $True

            $User = [ADSI]("WinNT://$Domain/$username")
            $Group = [ADSI]("WinNT://$MachineName/Administrators")
            $Group.PSBase.Invoke("Add",$User.PSBase.Path)
        }
        else{
            Write-JujuLog "User already addded"
            Set-ADAccountPassword -NewPassword $securePassword -Identity $username
        }
    }

    $session | Remove-PSSession
}

function Leave-ADDomain {
    Param($ADParams)

    Write-JujuLog "Leaving AD domain..."

    $localAdminPassword = Generate-StrongPassword
    $localAdminUsername = "adminlocal"
    Create-LocalAdmin $localAdminUsername $localAdminPassword
    $passwordSecure = ConvertTo-SecureString `
                          -String $localAdminPassword -asPlainText -Force
    $localCredential = New-Object PSCredential($localAdminUsername, `
                                               $passwordSecure)

    $adCredential = Get-ADCredential $ADParams
    Remove-Computer -LocalCredential $localCredential `
                    -UnJoinDomainCredential $adCredential `
                    -Force `
                    -Confirm:$false

    Delete-WindowsUser $localAdminUsername
    $networkName = (Get-MainNetadapter)
    Set-DnsClientServerAddress -InterfaceAlias $networkName `
        -ResetServerAddresses

    Write-JujuLog "Finished leaving AD domain..."
    ExitFrom-JujuHook -WithReboot
}

Export-ModuleMember -Function *
