#
# Copyright 2014-2015 Cloudbase Solutions Srl
#
$ErrorActionPreference = 'Stop'
$computername = [System.Net.Dns]::GetHostName()

$charmHelpers = Join-Path $PSScriptRoot "Modules\CharmHelpers"
Import-Module -Force -DisableNameChecking $charmHelpers

$WINDOWS_FEATURES = @( 'AD-Domain-Services',
                       'RSAT-AD-Tools',
                       'RSAT-AD-Powershell',
                       'RSAT-ADDS',
                       'RSAT-ADDS-Tools',
                       'RSAT-AD-AdminCenter',
                       'DNS',
                       'RSAT-DNS-Server' )

$ADUserSection = "ADCharmUsers"


function Set-JujuStatus {
    Param(
        [Parameter(Mandatory=$true)]
        [ValidatePattern("^\w+$")]
        [ValidateSet("maintenance", "blocked", "waiting", "active")]
        [string]$Status=$null
    )

    $cmd = @("status-set.exe", $Status)
    try {
        if ((Get-JujuStatus) -ne $Status) {
            return Execute-Command -Cmd $cmd
        }
    } catch {
        return $false
    }
}

function Get-JujuStatus {
    $cmd = @("status-get.exe", "--format=json")
    try {
        $result = Execute-Command -Cmd $cmd | ConvertFrom-Json
    } catch {
        return $false
    }

    if ($result) {
        return $result["status"]
    }
}

function Run-TimeResync {
    Param()
    tzutil.exe /s "UTC" 
    if ($LastExitCode){
        Throw "Failed to set timezone"
    }
    Write-JujuLog "Synchronizing time..."
    try {
        Start-Service "w32time"
        Execute-ExternalCommand {
            w32tm.exe /config /manualpeerlist:time.windows.com /syncfromflags:manual /update
        }
    } catch {
        Write-JujuError "Failed to synchronize time..." -Fatal $false
    }
    Write-JujuLog "Finished synchronizing time."
}

function CreateNew-ADUser {
    Param(
        [parameter(Mandatory=$true)]
        [string]$Username
    )

    Write-JujuLog "Creating AD user..."
    $dn = (Get-ADDomain).DistinguishedName
    if (!$dn) {
        Write-JujuError "Could not get DistinguishedName."
    }
    $passwd = Generate-StrongPassword
    $secPass = ConvertTo-SecureString -AsPlainText $passwd -Force
    $adPath = "CN=Users," + $dn

    $usr = New-ADUser -SamAccountName $Username `
                      -Name $Username `
                      -AccountPassword $secPass `
                      -Enabled $true `
                      -PasswordNeverExpires $true `
                      -Path $adPath `
                      -PassThru

    Write-JujuLog "Finished creating AD user."
    return @($usr, $passwd)
}

function Check-Membership {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string]$GroupSID,
        [Parameter(Mandatory=$false)]
        [string]$Domain
    )

    if (!$Domain) {
        $Domain = $computername
    }
    $group = Get-CimInstance -ClassName Win32_Group  `
                -Filter "SID = '$GroupSID'"
    $ret = Get-CimAssociatedInstance -InputObject $group `
        -ResultClassName Win32_UserAccount | Where-Object `
        { $_.Name -eq $User -and $_.Domain -eq $Domain}
    return $ret
}

function GetOrCreate-ADUser {
    Param(
        [parameter(Mandatory=$true)]
        [string]$Username
    )
    $keyName = ("ad-" + $Username)
    Write-JujuLog "Getting/creating AD user..."
    try {
        $usr = Get-ADUser -Identity $Username
    } catch {
        $usr = $null
    }
    if ($usr) {
        $cachedPass = GetBlob-FromLeader -Name $keyName
        if(!$cachedPass){
            Throw "Failed to get cached password for user $Username"
        }
        Write-JujuLog "Finished getting/creating AD user..."
        return @($usr, $cachedPass)
    } else {
        $details = CreateNew-ADUser $Username
        SetBlob-ToLeader -Name $keyName -Blob $details[1]

        Write-JujuLog "Finished getting/creating AD user..."
        return $details
    }
}

#Creates an Active Directory Organizational Unit
function CreateNew-ADOU {
    Param(
        [parameter(Mandatory=$true)]
        [string]$OUName,
        [parameter(Mandatory=$true)]
        [string]$Path
    )

    Write-JujuLog "Creating Organizational Unit..."
    $Path = $Path.trim(",")
    Write-JujuLog "OU: $OUName ; Path: $Path"
    $tmp = "OU=" + $OUName + "," + $Path
    $ou = Get-ADOrganizationalUnit -Filter {DistinguishedName -eq $tmp}
    if (!$ou) {
        Write-JujuLog "$OUName --> $Path"
        $ou = New-ADOrganizationalUnit -Name $OUName -Path $Path
    }
    Write-JujuLog "Finished creating Organizational Unit."
    return $ou
}

#Creates an Active Directory Group
function CreateNew-ADGroup {
    Param(
        [parameter(Mandatory=$true)]
        [string]$Group
    )

    Write-JujuLog "Creating Active Directory Group $Group ..."
    #Sanitize the group, in case there are extra " in it
    $Group = $Group.Replace('"',"")
    $dn = (Get-ADDomain).DistinguishedName
    $grpDN = $Group + "," + $dn
    $ou = $null
    $grpSplit = $Group.Split(",")
    [array]::Reverse($grpSplit)
    $tmp = ""
    foreach ($i in $grpSplit){
        $s = $i.Split("=")
        $adType = $s[0].replace('"', "")
        $adTypeValue= $s[1].replace('"', "")
        if ($adType -eq "OU") {
            Write-JujuLog "Creating $s[1]"
            $ou = CreateNew-ADOU $adTypeValue ($tmp + "," + $dn)
        } elseif ($adType -eq "CN") {
            $groupName = $adTypeValue
        }
    }
    
    if ($ou) {
        $containerDn = $ou
    } else {
        $containerDn = $dn
    }

    Write-JujuLog "Looking for $groupName"
    try {
        $grp = Get-ADGroup -Identity $groupName
    } catch {
        Write-JujuLog "AD Group $groupName does not exist."
    }
    if ($grp) {
        Write-JujuLog "Active Directory Group $groupName already exists. Skipping."
        return $grp
    }

    $group = New-ADGroup -GroupScope DomainLocal -GroupCategory Security `
             -PassThru -Name $groupName -Path $containerDn
    Write-JujuLog "Finished creating Active Directory Group $Group ."
    return $group
}

function AssignUserTo-Groups {
    Param(
        [parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User,
        [parameter(Mandatory=$true)]
        [array]$Groups
    )

    foreach ($i in $Groups) {
        Write-JujuLog "Assigning user $User to group $i"
        $grp = CreateNew-ADGroup $i
        Add-ADGroupMember $grp $User
    }
}

function Create-ADUsersFromRelation {
    Param (
        [parameter(Mandatory=$true)]
        $Users
    )

    Write-JujuLog "Users to be created: $Users"
    $creds = @{}
    
    foreach($i in $Users.psobject.properties) {
        Write-JujuLog "Creating AD user $i."
        $groups = $i.Value
        $details = GetOrCreate-ADUser $i.Name
        $usr = $details[0]
        $pass = $details[1]
        $creds[$i.Name] = $details[1]
        if($groups.length -ne 0){
            AssignUserTo-Groups $details[0] $groups
        }
    }

    return $creds
}

function AddTo-ComputerADGroup {
    Param (
        [parameter(Mandatory=$true)]
        [string]$ComputerName,
        [parameter(Mandatory=$true)]
        [string]$Group
    )

    Write-JujuLog "Adding computer $ComputerName to AD GROUP $Group..."
    $group = CreateNew-ADGroup $Group
    $adhost = Get-ADComputer $ComputerName
    Add-ADGroupMember $group $adhost
    Write-JujuLog "Finished adding computer $ComputerName to AD GROUP $Group."
}

function Convert-SIDToFriendlyName {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
    $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
    $name = $objUser.Value
    $n = $name.Split("\")
    if ($n.length -gt 1){
        return $n[1]
    }
    return $n[0]
}

function Normalize-User {
    Param(
     [Parameter(Mandatory=$true)]
     [string]$User
    )

    $splitUser = $User.Split("\")
    if ($splitUser.length -eq 2) {
        if ($splitUser[0] -eq ".") {
            $domain = $computername
        } else {
            $domain = $splitUser[0]
        }
        $u = $splitUser[1]
    } else {
        $domain = $computername
        $u = $User
    }
    return @($domain, $u)
}

function AddTo-LocalGroup {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [Parameter(Mandatory=$true)]
        [string]$GroupSID
    )

    $usrSplit = Normalize-User -User $Username
    $domain = $usrSplit[0]
    $user = $usrSplit[1]

    $isMember = Check-Membership -User $Username -Group $GroupSID
    $groupName = Convert-SIDToFriendlyName -SID $GroupSID

    if (!$isMember) {
        $objUser = [ADSI]("WinNT://$domain/$user")
        $objGroup = [ADSI]("WinNT://$computername/$groupName")
        try {
            $objGroup.PSBase.Invoke("Add",$objUser.PSBase.Path)
        } catch {
            Write-JujuLog "$_"
            Write-JujuLog "Failed to add user $Username to group $groupName"
        }
    }

    return $true
}

function Add-UserToDomainAdmins {
     Param(
        [Parameter(Mandatory=$true)]
        [string]$AdminUsername,
        [Parameter(Mandatory=$true)]
        $AdminPassword,
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        [Parameter(Mandatory=$true)]
        [string]$DCName,
        [Parameter(Mandatory=$true)]
        [string]$userToAdd
    )

    $dcsecpassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
    $dccreds = New-Object System.Management.Automation.PSCredential("$Domain\$AdminUsername", $dcsecpassword)
    $domainSID = (Get-ADDomain -Credential $dccreds -Identity $Domain).DomainSid.Value
    # "Administrators", "Domain Admin", "Schema admin", "Enterprise admin" group SID
    $sids = @("S-1-5-32-544", "$domainSID-512", "$domainSID-518", "$domainSID-519")
    foreach ($sid in $sids) {
        $domainGroupName = Convert-SIDToFriendlyName -SID $sid
        Write-JujuLog $domainGroupName
        Add-ADGroupMember -Members $userToAdd -Identity $domainGroupName `
            -Credential $dccreds -Server $DCName
    }
}

function Get-StrippedUsername {
    Param(
        [parameter(Mandatory=$true)]
        [string]$ShortUsername
    )

    $hostName = Execute-ExternalCommand -Command {
        HOSTNAME.EXE
    } -ErrorMessage "Failed to get hostname"

    $username = $ShortUsername + "-" + $hostName
    if($username.Length -gt 20){
        return $username.Substring(0, 20)
    } else {
        return $username
    }
}

function Change-ServicesLogons {
    Param(
        [parameter(Mandatory=$true)]
        [HashTable]$ADparams
    )

    $domain = Get-DomainName $ADparams["ad_domain"]
    $jujuUsername = Get-StrippedUsername "juju"
    $cbsinitUsername = Get-StrippedUsername "cbs"
    $cbsUserPassword = Generate-StrongPassword
    $jujuUserPassword = Generate-StrongPassword
    $usersToAdd = @( @{"Name"=$cbsinitUsername;"Password" = $cbsUserPassword},
                     @{"Name"=$jujuUsername;"Password" = $jujuUserPassword} )
    Create-ServicesUsers $usersToAdd $ADparams
    Change-CBSServicesLogon "$domain\$jujuUsername" "$domain\$cbsinitUsername" `
        $jujuUserPassword $cbsUserPassword
}

function Change-CBSServicesLogon {
    Param(
        [parameter(Mandatory=$true)]
        [string]$jujuUser,
        [parameter(Mandatory=$true)]
        [string]$cbsUser,
        [string]$jujuPass,
        [string]$cbsPass
    )
    $jujuServices = Get-WmiObject Win32_Service | Where {$_.Name -Match 'juju'}
    if ($jujuServices) {
        Change-ServiceLogon $jujuServices $jujuUser $jujuPass
    }
    $cbsServices = Get-WmiObject Win32_Service | Where {$_.Name -Match 'cloudbase'}
    if ($cbsServices) {
        Change-ServiceLogon $cbsServices $cbsUser $cbsPass
    }

    $rights = ":(OI)(CI)(M)"
    $cbsRights = $cbsUser + $rights
    $jujuRights = $jujuUser + $rights
    $cbsFolder = Join-Path ${env:ProgramFiles(x86)} "Cloudbase Solutions"
    $jujuFolder = Join-Path $env:SystemDrive "Juju"
    if((Test-Path $cbsFolder) -and $cbsPass) {
        Execute-ExternalCommand -Command {
            icacls $cbsFolder /grant $cbsRights
        } -ErrorMessage "Failed to set permissions for $cbsFolder ."
    }
    if((Test-Path $jujuFolder) -and $jujuPass) {
        Execute-ExternalCommand -Command {
            icacls $jujuFolder /grant $jujuRights
        } -ErrorMessage "Failed to set permissions for $jujuFolder ."
    }
}

function Create-ServicesUsers {
    Param(
        [parameter(Mandatory=$true)]
        [array]$UsersToAdd,
        [parameter(Mandatory=$true)]
        [HashTable]$ADparams
    )

    Write-JujuLog "Creating AD Users for active-directory DC...."

    $machineName = $computername
    $domain = Get-DomainName $ADparams["ad_domain"]
    $adminUsername = $ADparams["ad_username"]
    $adminPassword = $ADparams["ad_password"]
    $dcName = $ADparams["ad_hostname"]
    $administratorsGroupSID = "S-1-5-32-544"
    $isLocalAdmin = Check-Membership $adminUsername $administratorsGroupSID $domain
    $administratorsGroupName = Convert-SIDToFriendlyName $administratorsGroupSID
    if(!$isLocalAdmin) {
        Write-JujuLog "Adding user to local admins."
        net.exe localgroup $administratorsGroupName ("$domain\$adminUsername") /add
    }

    $defaultAdminPassword = Get-JujuCharmConfig -Scope "default-administrator-password"
    $defaultAdmin = Get-DefaultLocalAdministrator
    ExecuteWith-Retry {
        Create-ADUsers $UsersToAdd $defaultAdmin $defaultAdminPassword $domain $dcName `
            $machineName
    } -RetryInterval 10 -MaxRetryCount 3
    foreach ($userToAdd in $UsersToAdd) {
        Write-JujuLog "Adding user admin rights..."
        $userName = $userToAdd["Name"]
        Add-UserToDomainAdmins $defaultAdmin $defaultAdminPassword $domain `
            $dcName $userName
        net.exe localgroup $administratorsGroupName ("$domain\$userName") /add
        Set-UserRunAsRights "$domain\$userName"
    }
    Write-JujuLog "Finished creating AD Users for active-directory DC."
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
    $dccreds = `
        New-Object System.Management.Automation.PSCredential("$Domain\$AdminUsername", $dcsecpassword)

    foreach($user in $UsersToAdd){
        $username = $user['Name']
        $password = $user['Password']
        $alreadyUser = $False
        try {
            $alreadyUser = (Get-ADUser $username -Credential $dccreds) -ne $Null
        } catch {
            Write-JujuError "Could not get ad user" -Fatal $false
        }

        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        if ($alreadyUser -eq $False) {
            $Description = "AD user"
            Write-JujuLog "Create new user"
            New-ADUser -Name $username -AccountPassword $securePassword `
                -Description $Description -Enabled $True -Credential $dccreds
        } else {
            Write-JujuLog "User already addded"
            Set-ADAccountPassword -NewPassword $securePassword `
                -Identity $username -Credential $dccreds
        }
    }
}

function Get-ADRelationMap {
    Param()

    return @{
        "ad_host" = "private-address";
        "ip_address" = "address";
        "ad_hostname" = "hostname";
        "ad_username" = "username";
        "ad_password" = "password";
        "ad_domain" = "domainName";
    }
}

function Get-RelationParams {
    Param($Type)

    switch ($Type) {
        'add-controller' {
            return (Get-JujuRelationParams $Type (Get-ADRelationMap))
        }
        default {
            throw "Unsupported relation."
        }
    }
}

function Is-Leader {
    return $true
    $cmd = @("is-leader.exe", "--format=json")
    try {
        return Execute-Command -Cmd $cmd | ConvertFrom-Json
    } catch {
        Write-JujuError "Failed to run is-leader.exe" -Fatal $true
    }

}

function Get-ActiveDirectoryFirewallContext {
    # https://technet.microsoft.com/en-us/library/dd772723(v=ws.10).aspx
    $basePorts = @{
        "TCP" = @(389, 636, 88, 53, 464, 5985, 5986, 3389);
        "UDP" = @(389, 88, 53, 464, 3389)
    }

    $openAllPorts = Get-JujuCharmConfig -Scope "open-all-active-directory-ports"
    if (!$openAllPorts -or ($openAllPorts -eq "False")) {
        return $basePorts
    }
    $basePorts["TCP"] += @(3269, 3268, 445, 25, 135, 5722, 9389, 139)
    $basePorts["UDP"] += @(445, 123, 138, 137)
    return $basePorts
}

function Prepare-ADInstall {
    Write-JujuLog "Preparing AD install..."

    Rename-Hostname
    $shouldReboot = Install-Certificate
    if ($shouldReboot) {
        ExitFrom-JujuHook -WithReboot
    }
    try {
        Install-WindowsFeatures $WINDOWS_FEATURES
    } catch {
        Write-JujuError "Failed to install Windows features." -Fatal $true
    }

    Write-JujuLog "Finished preparing AD install."
}

function Get-DefaultLocalAdministrator {
    $administratorsGroupSID = "S-1-5-32-544"
    $group = Get-CimInstance -ClassName Win32_Group  `
                -Filter "SID = '$administratorsGroupSID'"
    $localAdministrator = Get-CimAssociatedInstance -InputObject $group `
        -ResultClassName Win32_UserAccount | Where-Object `
        { $_.SID.StartsWith("S-1-5-21") -and $_.SID.EndsWith("-500") }
    if ($localAdministrator) {
        return $localAdministrator.Name
    } else {
        Write-JujuError "Failed to get default local administrator"
    }
}

function Install-ADForest {
    Param()

    Write-JujuLog "Installing Forest..."

    $fullDomainName = Get-JujuCharmConfig -Scope 'domain-name'
    $defaultDomainUser = Get-JujuCharmConfig -Scope 'default-domain-user'
    $defaultAdministratorPassword = `
        Get-JujuCharmConfig -Scope 'default-administrator-password'
    $defaultDomainUserPassword = `
        Get-JujuCharmConfig -Scope 'default-domain-user-password'
    $localAdministrator = Get-DefaultLocalAdministrator
    $domainName = Get-DomainName $fullDomainName
    if (Is-DomainInstalled $fullDomainName) {
        Write-JujuLog "AD is already installed."
        $dcName = $computername
        Add-UserToDomainAdmins $localAdministrator $defaultAdministratorPassword $domainName `
            $dcName $defaultDomainUser
        return
    }
    if (Is-InDomain $fullDomainName) {
        Write-JujuLog "Machine cannot reinstall the forest."
        return $false
    }

    if ($defaultAdministratorPassword) {
        Write-JujuLog "Setting default administrator password."
        Add-WindowsUser $localAdministrator $defaultAdministratorPassword
    }

    ExecuteWith-Retry -Command {
        Create-LocalAdmin $defaultDomainUser $defaultDomainUserPassword
    } -MaxRetryCount 5 -RetryInterval 10

    $safeModePassword = Get-JujuCharmConfig -Scope 'safe-mode-password'
    $safeModePasswordSecure = ConvertTo-SecureString `
        -String $safeModePassword -AsPlainText -Force

    $forestInstalled = ExecuteWith-Retry {
        try {
            Install-ADDSForest -DomainName $fullDomainName `
               -DomainNetbiosName $domainName `
               -SafeModeAdministratorPassword $safeModePasswordSecure `
               -InstallDns -Force -NoRebootOnCompletion
        } catch {
            $domainAlreadyInUse = $_.Exception.Message -match "already in use"
            if (!$domainAlreadyInUse) {
                Write-JujuError -Fatal $true "Failed to install forest: $_"
            }
            Write-JujuError -Fatal $false "Domain already in use. Skipping..."
            return $false
        }
        return $true
    } -MaxRetryCount 3 -RetryInterval 30

    if (!$forestInstalled) {
        return
    }
    Set-CharmState "ADController" "IsInstalled" "True"
    Write-JujuLog "Finished installing Forest..."
    ExitFrom-JujuHook -WithReboot
}

function Add-DNSForwarders {
    $nameservers = Get-PrimaryAdapterDNSServers
    $nameservers = $nameservers | Where-Object { $_ -ne "127.0.0.1" }
    Write-JujuLog "Nameservers are: $nameservers"
    if (!$nameservers) {
        Write-JujuLog "No nameservers to add."
        return
    }
    ExecuteWith-Retry {
        $hostname = $computername
        Execute-ExternalCommand {
            dnscmd.exe $hostname /resetforwarders $nameservers
        }
    } -MaxRetryCount 3 -RetryInterval 30
}

function Main-Slave {
    Param($ADParams)

    Write-JujuLog "Executing main slave..."
    if (!(Is-InDomain $ADParams['ad_domain'])) {
        ConnectTo-ADController $ADParams
        ExitFrom-JujuHook -WithReboot
    }
    $domain = Get-DomainName $ADParams["ad_domain"]
    ExecuteWith-Retry {
        Change-ServicesLogons $ADParams
    } -MaxRetryCount 20 -RetryInterval 30


    $safeModePassword = Get-JujuCharmConfig -Scope "safe-mode-password"
    $safeModePasswordSecure = ConvertTo-SecureString $safeModePassword `
        -AsPlainText -Force

    $adminPassword = Get-JujuCharmConfig -Scope "default-administrator-password"
    $dcsecpassword = ConvertTo-SecureString $adminPassword -AsPlainText -Force
    $domain = Get-DomainName $ADParams["ad_domain"]
    $adminUsername = Get-DefaultLocalAdministrator
    $adCredential = `
        New-Object System.Management.Automation.PSCredential("$domain\$adminUsername", $dcsecpassword)

    Add-DNSForwarders
    ExecuteWith-Retry {
        Install-ADDSDomainController -NoGlobalCatalog:$false `
            -InstallDns:$true -CreateDnsDelegation:$false `
            -CriticalReplicationOnly:$false -DomainName $domain `
            -SafeModeAdministratorPassword:$safeModePasswordSecure `
            -NoRebootOnCompletion:$true -Credential $adCredential -Force
    } -MaxRetryCount 3 -RetryInterval 30
    Set-CharmState "ADController" "IsInstalled" "True"

    ExitFrom-JujuHook -WithReboot
}

function Is-DomainInstalled {
    Param(
        [string]$fullDomainName
    )

    $isAdControllerInstalled = (Get-CharmState "ADController" "IsInstalled") -eq "True"
    if (!$isAdControllerInstalled) {
        return $false
    }
    $runningServiceCode = ExecuteWith-Retry {
        Add-Type -Assemblyname System.ServiceProcess
        return [System.ServiceProcess.ServiceControllerStatus]::GetValues("System.ServiceProcess.ServiceControllerStatus")[3]
    } -MaxRetryCount 3 -RetryInterval 30
    $isForestInstalled = $true
    try {
        $services = $("ADWS","NTDS")
        ExecuteWith-Retry {
            foreach ($service in $services) {
                $status = (Get-Service $service).Status
                if (!($status.Equals($runningServiceCode))) {
                    Write-JujuError "Service $service is not running." -Fatal $true
                } else {
                    Write-JujuLog "Service $service is running with status $status."
                }
            }
        } -MaxRetryCount 4 -RetryInterval 30
        $forestName = (Get-ADForest).Name
        if ($forestName -eq $fullDomainName) {
            Write-JujuLog "AD Domain already installed."
        } else {
            Write-JujuLog "Forest name: $forestName"
            Write-JujuLog "AD Domain not installed."
            $isForestInstalled = $false
        }
    } catch {
        Write-JujuLog "Failed to check if AD Domain is installed."
        Write-JujuLog "$_"
        $isForestInstalled = $false
    }
    return ($isForestInstalled)
}

function Set-AdminOnlyACL {
    Param(
        [string]$Path
    )

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    # Disable inheritance from parent
    $acl.SetAccessRuleProtection($true,$true)

    $fsRights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
    $aceType =[System.Security.AccessControl.AccessControlType]::Allow

    # BUILTIN\Administrators, NT AUTHORITY\SYSTEM
    # Avoid using account names as they might change based on the locale
    foreach($sid in @("S-1-5-32-544", "S-1-5-18"))
    {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $account = $sidObj.Translate( [System.Security.Principal.NTAccount])
        $ace = New-Object System.Security.AccessControl.FileSystemAccessRule (
            $account, $fsRights, $inheritanceFlags, $propagationFlags, $aceType)
        $acl.AddAccessRule($ace)
    }

    Set-ACL $Path $acl
}

function Generate-FQDN {
    Param()

    $unit_name = Get-JujuUnitName
    $domain_name = charm_config -scope "domain-name"
    $fqdn = $unit_name + "." + $domain_name
    return $fqdn
}

function Create-CA {
    Param()

    $base_dir="C:\OpenSSL-Win32\"
    $ca_dir="$base_dir\CA"

    if (!(Test-Path $ca_dir)) {
        New-Item -ItemType Directory -Path $ca_dir
    }
    Set-AdminOnlyACL $ca_dir

    $private_dir = "$ca_dir\private"
    $certs_dir = "$ca_dir\certs"
    $crl_dir = "$ca_dir\crl"
    if (!(Test-Path $private_dir)) {
        New-Item -ItemType Directory -Path $private_dir
    }
    if (!(Test-Path $certs_dir)) {
        New-Item -ItemType Directory -Path $certs_dir
    }
    if (!(Test-Path $crl_dir)) {
        New-Item -ItemType Directory -Path $crl_dir
    }

    if (!(Test-Path "$ca_dir\index.txt")){
        [System.IO.File]::WriteAllText("$ca_dir\index.txt", "")
    }

    if(!(Test-Path "$ca_dir\serial")){
        [System.IO.File]::WriteAllText("$ca_dir\serial", "01`n")
    }

    if ((Test-Path "$private_dir\ca.key") `
        -and (Test-Path "$certs_dir\cert.pem") `
        -and (Test-Path "$private_dir\cert.key")) {
        return @{
            "ca"="$certs_dir\ca.pem";
            "cert"="$certs_dir\cert.pem";
            "key"="$private_dir\cert.key";
        }
    }

    $ca_conf_file="ca.cnf"
    $openssl_conf_file="openssl.cnf"
    Copy-Item $env:CHARM_DIR\files\configs\* $ca_dir

    $ENV:OPENSSL_CONF="$ca_dir\ca.cnf"
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -out $certs_dir\ca.pem -outform PEM -keyout $private_dir\ca.key
    if ($LastExitCode) {
        throw "openssl failed to create CA certificate"
    }

    $ENV:OPENSSL_CONF="$ca_dir\openssl.cnf"
    $fqdn = Generate-FQDN
    openssl req -newkey rsa:2048 -nodes -sha1 -keyout $private_dir\cert.key -keyform PEM -out $certs_dir\cert.req -outform PEM -subj "/C=US/ST=Washington/L=Seattle/emailAddress=nota@realone.com/organizationName=IT/CN=$fqdn"
    if ($LastExitCode) {
        throw "openssl failed to create server certificate request"
    }

    $ENV:OPENSSL_CONF="$ca_dir\ca.cnf"
    openssl ca -batch -notext -in $certs_dir\cert.req -out $certs_dir\cert.pem -extensions v3_req_server
    if ($LastExitCode) {
        throw "openssl CA failed to sign server certificate request"
    }

    $ret = @{
        "ca"="$certs_dir\ca.pem";
        "cert"="$certs_dir\cert.pem";
        "key"="$private_dir\cert.key";
    }

    return $ret
}

function Import-CA {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ca
    )

    if (!(Test-Path $ca)) {
        Throw "$ca was not found"
    }
    # Import CA certificate
    $cacert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ca)
    $castore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $castore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $castore.Add($cacert)
}

function Import-Certificate {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$cert_file,
        [Parameter(Mandatory=$true)]
        [string]$key_file
    )

    if (!(Test-Path $cert_file) -or !(Test-Path $key_file)) {
        Throw "$cert_file or $key_file not found"
    }

    $password = charm_config -scope 'password'
    # Import server certificate
    $pfx = Join-Path $env:TEMP cert.pfx

    Execute-ExternalCommand {
        openssl.exe pkcs12 -export -in $cert_file -inkey $key_file -out $pfx -password pass:$password
    }

    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $pfx, $password,
        ([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet))

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Add($cert)
    Remove-Item $pfx
}

# EXPORTED FUNCTIONS

function Set-Availability {
    Param(
        [string]$rid="ad-join"
    )
    Write-JujuLog "Setting active-directory relation data..."
    $fullDomainName = Get-JujuCharmConfig -Scope 'domain-name'
    if (!(Is-DomainInstalled $fullDomainName)) {
        Write-JujuLog "This machine is not yet AD Controller. Skipping..."
        return
    }

    $privateAddress = Get-JujuUnitPrivateIP
    $user = Get-JujuCharmConfig -Scope 'default-domain-user'
    $password = Get-JujuCharmConfig -Scope 'default-domain-user-password'
    $domainInfo = Get-ADDomain

    $relation_set = @{
        'address' = $privateAddress;
        'hostname' = $computername;
        'username' = $user;
        'password' = $password;
        'domainName' = $fullDomainName;
        'suffix' = $domainInfo.DistinguishedName;
        'netbiosname' = $domainInfo.NetBIOSName;
    }
    if ($rid) {
        $rids = Get-JujuRelationIds $rid
        foreach ($r in $rids) {
            Set-JujuRelation -Relation_Settings $relation_set `
                -Relation_Id $r
            if ($ret -eq $false) {
                Write-JujuError "Failed to set active-directory relation." `
                    -Fatal $false
            }
        }
    }

    Write-JujuLog "Finished setting active-directory relation data."
}

function Win-Peer {
    Param()

    Write-JujuLog "Running peer relation..."
    $resumeInstall = (Get-CharmState "AD" "InstallingSlave") -eq "True"
    $fullDomainName = Get-JujuCharmConfig -Scope 'domain-name'
    if (!(Is-DomainInstalled $fullDomainName) -or $resumeInstall) {
        Write-JujuLog "This machine is not yet AD Controller."
        $ADParams = Get-RelationParams 'add-controller'
        if (!$ADParams['context']) {
            Write-JujuError -Fatal $false "Ad context not ready"
        } else {
            if((Get-CharmState "ADController" "IsInstalled") -ne "True") {
                Set-CharmState "AD" "InstallingSlave" "True"
                Main-Slave $ADParams
            } else {
                $dns = Get-PrimaryAdapterDNSServers
                Write-JujuLog "$dns"
                if ($dns -contains $ADParams['ip_address']) {
                    $dns = $dns | Where-Object {$_ -ne $ADParams['ip_address']}
                    if ($dns) {
                        Set-DnsClientServerAddress `
                            -InterfaceAlias (Get-MainNetadapter) `
                            -ServerAddresses $dns
                    }
                }
                Set-CharmState "AD" "InstallingSlave" "False"
            }
        }
    }
    if ((Get-CharmState "AD" "RunningLeaderElectedHook") -eq "True") {
        $peerRelationsNotSet = $true
    }
    $isDomainInstalled = Is-DomainInstalled $fullDomainName
    if (((Is-Leader) -or $peerRelationsNotSet) -and $isDomainInstalled) {
        Write-JujuLog "Setting relations..."
        Set-Availability 'add-controller'
        Set-Availability 'ad-join'
        Set-CharmState "AD" "RunningLeaderElectedHook" "False"
    }

    if ($isDomainInstalled) {
        Finish-Install
    }
    Write-JujuLog "Finished running peer relation."
}

function Finish-Install {
    $nameservers = Get-PrimaryAdapterDNSServers
    $netadapter = Get-MainNetadapter

    if ($nameservers) {
        if (!("127.0.0.1" -in $nameservers)) {
            $nameservers = ,"127.0.0.1" + $nameservers
        }
        Set-DnsClientServerAddress -InterfaceAlias $netadapter `
            -ServerAddresses $nameservers
    }
    Add-DNSForwarders
    Open-DCPorts
    Set-JujuStatus -Status "active"
}

function Uninstall-ActiveDomainController {
    $hostname = $computername
    $fullDomainName = Get-JujuCharmConfig -Scope 'domain-name'
    $user = Get-DefaultLocalAdministrator
    $password = Get-JujuCharmConfig -Scope 'default-administrator-password'
    $uninstallPassword = Get-JujuCharmConfig -Scope 'uninstall-password'
    $domain = Get-DomainName $fullDomainName
    $passwordSecure = ConvertTo-SecureString $password -AsPlainText -Force
    $uninstallPasswordSecure = `
        ConvertTo-SecureString $password -AsPlainText -Force
    $adCredential = New-Object -TypeName PSCredential -ArgumentList `
                       @("$domain\$user", $passwordSecure)
    Execute-ExternalCommand {
        repadmin.exe /syncall
    }
    $domainControllers = (Get-ADDomainController `
        -Filter {Enabled -eq $true}).Name
    if (!($domainControllers -contains $hostname)) {
        Write-JujuLog "This unit is not a domain Controller."
        return
    }
    if ($domainControllers.Count -eq 1) {
        Write-JujuLog "Trying to remove the last domain controller."
        ExecuteWith-Retry -Command {
            param($adCredential, $passwordSecure)
            Uninstall-ADDSDomainController -Credential $adCredential `
                -LocalAdministratorPassword:$uninstallPasswordSecure `
                -NoRebootOnCompletion:$true -Force `
                -IgnoreLastDCInDomainMismatch `
                -IgnoreLastDnsServerForZone -LastDomainControllerInDomain `
                -RemoveApplicationPartitions
        } -MaxRetryCount 2 -RetryInterval 30 `
          -ArgumentList @($adCredential, $passwordSecure)
    } else {
        Write-JujuLog "Trying to remove the domain controller."
        ExecuteWith-Retry -Command {
            param($adCredential, $passwordSecure)
            Uninstall-ADDSDomainController -Credential $adCredential `
                -LocalAdministratorPassword:$passwordSecure `
                -NoRebootOnCompletion:$true -Force `
                -IgnoreLastDCInDomainMismatch `
                -IgnoreLastDnsServerForZone -RemoveApplicationPartitions
        } -MaxRetryCount 2 -RetryInterval 30 `
          -ArgumentList @($adCredential, $passwordSecure)
    }
}

function Destroy-ADDomain {
    Param()

    Write-JujuLog "Started destroying AD Domain..."
    $hostname = $computername

    $fullDomainName = Get-JujuCharmConfig -Scope 'domain-name'
    if (!(Is-DomainInstalled $fullDomainName)) {
        Write-JujuLog "The machine is not part of the domain."
        return
    }
    Close-DCPorts
    Change-CBSServicesLogon "$hostname\LocalSystem" `
        "$hostname\LocalSystem" $null $null
    Write-JujuLog "Syncing AD domain controllers before demotion..."

    try {
        ExecuteWith-Retry -Command {
            Uninstall-ActiveDomainController
        } -MaxRetryCount 3 -RetryInterval 30
        ExitFrom-JujuHook -WithReboot
        Set-CharmState "ADController" "IsInstalled" "False"
    } catch {
        Write-JujuError "Failed to uninstall AD controller" -Fatal $false
    }
}

function Install-Certificate {
    Param()
    Write-JujuLog "Installing certificate..."

    if ((Get-CharmState "AD" "CertificateInstalled") -eq "True") {
        Write-JujuLog "Certificate already installed. Skipping..."
        return $false
    }

    $ENV:PATH+=";$env:CHARM_DIR\files\openssl"
    $cas = (Get-ChildItem "Cert:\LocalMachine\Root").Subject
    foreach ($i in $cas) {
        if ($i.StartsWith("O=Cloudbase")) {
            $hasCertifiedAuthority = $true
            break
        }
    }

    $fqdn = Generate-FQDN

    $certs = (Get-ChildItem "Cert:\LocalMachine\My").Subject
    foreach ($i in $certs) {
        if ($i.Contains("CN=$fqdn")) {
            $hasCertificate = $true
        }
    }
    if ($hasCertificate -and $hasCertifiedAuthority) {
        Write-JujuLog "Certificate already exists. Skipping..."
        return $false
    }

    $certificateFile = Create-CA
    Import-CA -ca $certificateFile.ca
    Import-Certificate -cert $certificateFile.cert -key $certificateFile.key
    Set-CharmState "AD" "CertificateInstalled" "True"
    Write-JujuLog "Finished installing certificate."
    return $true
}

function Open-DCPorts {
    Param()

    try {
        $firewallContext = Get-ActiveDirectoryFirewallContext
        foreach ($protocol in $firewallContext.Keys) {
            foreach ($port in $firewallContext[$protocol]) {
                Open-JujuPort "$port/$protocol"
                $ruleNameOutbound = "Allow Outbound Port $port/$protocol"
                $ruleNameInbound = "Allow Inbound Port $port/$protocol"
                if (!(Get-NetFirewallRule $ruleNameOutbound `
                        -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName $ruleNameOutbound `
                        -Name $ruleNameOutbound `
                        -Direction Outbound -LocalPort $port `
                        -Protocol $protocol -Action Allow
                }
                if (!(Get-NetFirewallRule $ruleNameInbound `
                        -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName $ruleNameInbound `
                        -Name $ruleNameInbound `
                        -Direction Inbound -LocalPort $port `
                        -Protocol $protocol -Action Allow
                }
            }
        }
    } catch {
        Write-JujuLog "$_"
        Write-JujuError "Failed to open DC ports."
    }
}

function Close-DCPorts {
    Param()

    try {
        $firewallContext = Get-ActiveDirectoryFirewallContext
        foreach ($protocol in $firewallContext.Keys) {
            foreach ($port in $firewallContext[$protocol]) {
                Close-JujuPort "$port/$protocol"
            }
        }
    } catch {
        Write-JujuLog "Failed to close DC ports."
    }
}

function Update-DC {
    Win-Peer
}

function Parse-ADUsersFromNano {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$credentials
    )

    $ret = New-Object PSObject
    $c = $credentials.Split("|")
    foreach ($i in $c){
        $elem = $i.Split("=", 2)
        $user = $elem[0]
        $groupsDec = ConvertFrom-Base64 $elem[1]
        $groupArr = $groupsDec.Split("|")
        $ret | Add-Member $user $groupArr
    }
    return $ret
}


function GetBlob-FromLeader {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    $blob = Get-LeaderData -Attr $Name
    if($blob -ne "Nil"){
        return $blob
    }
}

function SetBlob-ToLeader {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [string]$Blob
    )

    $ret = Set-LeaderData @{$Name=$Blob;}
    if (!$ret){
        Throw "Failed to set djoin blob for $node"
    }
}

function RemoveBlob-FromLeader {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    $ret = Set-LeaderData @{$Name="Nil";}
    if (!$ret){
        Throw "Failed to set djoin blob for $node"
    }
}

function Create-DjoinData {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$computername
    )
    $blobName = ("djoin-" + $computername)

    if(!(Is-Leader)){
        Write-JujuLog "Not the leader. Exiting..."
        return $false
    }
    $fullDomainName = Get-JujuCharmConfig -Scope 'domain-name'
    if(!(Is-DomainInstalled $fullDomainName)){
        Write-JujuLog "Forest is not fully installed. Skipping."
        return $false
    }

    $blob = GetBlob-FromLeader -Name $blobName
    if($blob){
        return $blob
    }

    $storage = Join-Path $env:TEMP "blobs"
    if(!(Test-Path $storage)){
        mkdir $storage 2>&1 | out-null
    }
    $blobFile = Join-Path $storage ($computername + ".txt")

    if((Test-Path $blobFile)){
        $c = ConvertFile-ToBase64 $blobFile
        $blob = GetBlob-FromLeader -Name $blobName
        if($blob -and $blob -ne $c){
            # Stale local blob file
            $ret = rm -Force $blobFile
            return $blob
        }
        $ret = SetBlob-ToLeader -Name $blobName -Blob $c
        return $c
    }

    $domain = Get-JujuCharmConfig -Scope 'domain-name'
    djoin.exe /provision /domain $domain /machine $computername /savefile $blobFile 2>&1 | out-null
    if($LastExitCode){
        if((Test-Path $blobFile)){
            $ret = rm -Force $blobFile
        }
        Throw "Error provisioning machine: $LastExitCode"
    }
    $blob = ConvertFile-ToBase64 $blobFile
    $ret = SetBlob-ToLeader -Name $blobName -Blob $blob
    $ret = rm -Force $blobFile
    return $blob
}

function Encode-NanoCredentials {
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$creds
    )
    $ret = ""
    foreach($i in $creds.GetEnumerator()){
        if($ret.Length -eq 0){
            $ret += ($i.Name + "=" + $i.Value)
        }else{
            $ret += ("|" + $i.Name + "=" + $i.Value)
        }
    }
    return (ConvertTo-Base64 $ret)
}

function Set-ADUserAvailability {
    $settings = @{}
    $isLeader = Is-Leader
    if (!$isLeader) {
        Write-JujuLog "I am not leader. Will not continue."
        return
    }
    $settings = @{}
    $adUsersEnc = Get-JujuRelation -Attr "adusers"
    $nanoAdUsersEnc = Get-JujuRelation -Attr "nano-adusers"
    $computerGroupEnc = Get-JujuRelation -Attr "computerGroup"

    if ($computerGroupEnc) {
        $computerGroup = ConvertFrom-Base64 $computerGroupEnc
    }
    $compName = Get-JujuRelation -Attr "computername"

    if ($compName){
        try {
            $isInAD = Get-ADComputer $compName
        } catch {
            $isInAD = $false
        }
        if(!$isInAD){
            $djoinKey = ("djoin-" + $compName)
            $blob = Create-DjoinData $compName
            if($blob){
                $settings[$djoinKey] = $blob
            }
        }else {
            $settings["already-joined"] = $true
        }
    } 

    if ($nanoAdUsersEnc){
        $adUsers = Parse-ADUsersFromNano $nanoAdUsersEnc
        $creds = Create-ADUsersFromRelation $adUsers
        if ($creds){
            $encCreds = Encode-NanoCredentials $creds
            $settings["nano-ad-credentials"] = $encCreds
        }
    } elseif ($adUsersEnc) {
        $adUsers = Unmarshall-Object $adUsersEnc
        $creds = Create-ADUsersFromRelation $adUsers
        $encCreds = Marshall-Object $creds
        $settings["adcredentials"] = $encCreds
    }
    
    if($settings.Count -gt 0){
        Set-JujuRelation -relation_settings $settings    
    }
    if ($computerGroup -and $compName) {
        AddTo-ComputerADGroup $compName $computerGroup
    }
    Write-JujuLog "Finished setting AD user relation."
}

function Run-ADRelationDepartedHook {
    $compName = Get-JujuRelation -Attr "computername"
    $blobName = ("djoin-" + $compName)
    if ($compName){
        $blob = GetBlob-FromLeader -Name $blobName
        if(!$blob){
            return $true
        }
        try {
            $isInDomain = Get-ADComputer $compName -ErrorAction SilentlyContinue
        }catch{
            $isInDomain = $false
        }
        if($isInDomain){
            Remove-ADComputer $compName -Confirm:$false
        }
        RemoveBlob-FromLeader -Name $blobName
        $storage = Join-Path $env:TEMP "blobs"
        $blobFile = Join-Path $storage ($compName + ".txt")
        if((Test-Path $blobFile)){
            rm -Force $blobFile
        }
    }
    return $true
}

function Run-InstallHook {
    Write-JujuLog "Running install hook..."
    Prepare-ADInstall
    Run-LeaderElectedHook
    Write-JujuLog "Finished running install hook."
}

function Run-ConfigChangedHook {
    Write-JujuLog "Running config-changed hook..."
    Write-JujuLog "Finished running config-changed hook."
}

function Run-StartHook {
    Write-JujuLog "Running start hook..."
    Write-JujuLog "Finished running start hook."
}

function Run-StopHook {
    Write-JujuLog "Running stop hook..."
    Destroy-ADDomain
    Close-DCPorts
    Write-JujuLog "Finished running stop hook."
}

function Run-UpgradeCharmHook {
    Write-JujuLog "Running upgrade-charm hook..."
    Update-DC
    Write-JujuLog "Finished running upgrade-charm hook."
}

function Run-LeaderElectedHook {
    Write-JujuLog "Running leader elected hook..."
    try {
        $isLeader = Is-Leader
    } catch {
        Write-JujuError "Failed to get leader." -Fatal $false
        return $false
    }

    $isFormerLeader = $false
    $leaderHostname = Get-LeaderData -Attr "active-leader"
    Write-JujuLog "Leader hostname: $leaderHostname"
    if (!$leaderHostname -or ($leaderHostname -eq $computername)) {
        Write-JujuLog "This unit is the first or former leader"
        $isFormerLeader = $true
    }
    $alreadyRunningLeaderElected = (Get-CharmState "AD" "RunningLeaderElectedHook") -eq "True"
    if ($isLeader) {
        Set-LeaderData @{"active-leader"=($computername);}
    }
    if (($isLeader -and $isFormerLeader) -or $alreadyRunningLeaderElected) {
        Write-JujuLog "This unit should resume running the hook."
        Set-CharmState "AD" "RunningLeaderElectedHook" "True"
        ExecuteWith-Retry {
            Install-ADForest
        } -MaxRetryCount 30 -RetryInterval 30
    } else {
        Write-JujuLog "This unit should not resume running the hook. Skipping..."
    }
    if ($isLeader) {
        Set-Availability 'ad-join'
        Set-Availability 'add-controller'
    }
    Finish-Install
    Write-JujuLog "Finished running leader elected hook."
}

function Run-LeaderSettingsChangedHook {
    Write-JujuLog "Running leader settings changed hook..."
    Write-JujuLog "Finished running leader settings changed hook."
}

function Run-ADRelationChangedHook {
    Write-JujuLog "Running AD relation changed hook..."

    $isLeader = Is-Leader
    if (!$isLeader) {
        Write-JujuLog "I am not leader. Will not continue."
        return
    }
    Set-ADUserAvailability
    Write-JujuLog "Finished running AD relation changed hook."
}

function Run-ADRelationJoinedHook {
    Write-JujuLog "Running AD relation joined hook..."
    $isLeader = Is-Leader
    if (!$isLeader) {
        Write-JujuLog "I am not leader. Will not continue."
        return
    }
    Set-Availability 'ad-join'
    Write-JujuLog "Finished running AD relation joined hook."
}

function Run-AddControllerRelationJoinedHook {
    Write-JujuLog "Running add-controller relation joined hook..."
    Win-Peer
    Write-JujuLog "Finished running add-controller relation joined hook."
}

function Run-AddControllerRelationChangedHook {
    Write-JujuLog "Running add-controller relation changed hook..."
    Win-Peer
    Write-JujuLog "Finished running add-controller relation changed hook."
}

function Run-SetKCD {
    $name = relation_get -attr "$computername"
    $charm_dir = charm_dir

    $relations = relation_ids -reltype 'hyperv-peer'
    $peers = @()
    foreach($rid in $relations){
        $related_units = related_units -relid $rid
        foreach($unit in $related_units){
            $name = relation_get -attr "computername" -rid $rid -unit $unit
            $ready = Get-ADComputer $name -ErrorAction SilentlyContinue
            if($ready){ 
                $peers += $private_address
            }
        }
    }

    foreach($i in $peers){
        if($i -eq $name){
            continue
        }
        & $charm_dir\hooks\Set-KCD.ps1 $name $i -ServiceType "Microsoft Virtual System Migration Service"
        & $charm_dir\hooks\Set-KCD.ps1 $name $i -ServiceType cifs
        & $charm_dir\hooks\Set-KCD.ps1 $i $name -ServiceType "Microsoft Virtual System Migration Service"
        & $charm_dir\hooks\Set-KCD.ps1 $i $name -ServiceType cifs
    }
    return $true
}

Export-ModuleMember -Function Run-ADRelationJoinedHook
Export-ModuleMember -Function Run-ADRelationChangedHook

Export-ModuleMember -Function Run-AddControllerRelationJoinedHook
Export-ModuleMember -Function Run-AddControllerRelationChangedHook

Export-ModuleMember -Function Run-InstallHook
Export-ModuleMember -Function Run-ConfigChangedHook
Export-ModuleMember -Function Run-StartHook
Export-ModuleMember -Function Run-StopHook
Export-ModuleMember -Function Run-UpgradeCharmHook

Export-ModuleMember -Function Run-LeaderElectedHook
Export-ModuleMember -Function Run-LeaderSettingsChangedHook

Export-ModuleMember -Function Run-ADRelationDepartedHook
Export-ModuleMember -Function Run-TimeResync
Export-ModuleMember -Function Run-SetKCD
