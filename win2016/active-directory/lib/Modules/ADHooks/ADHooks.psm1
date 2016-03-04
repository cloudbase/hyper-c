#
# Copyright 2014-2015 Cloudbase Solutions Srl
#
$ErrorActionPreference = 'Stop'
$computername = [System.Net.Dns]::GetHostName()

# Charm Helpers
Import-Module JujuLogging
Import-Module JujuHooks
Import-Module JujuUtils
Import-Module JujuWindowsUtils

Import-Module ADCharmUtils

$WINDOWS_FEATURES = @( 'AD-Domain-Services',
                       'RSAT-AD-Tools',
                       'RSAT-AD-Powershell',
                       'RSAT-ADDS',
                       'RSAT-ADDS-Tools',
                       'RSAT-AD-AdminCenter',
                       'DNS',
                       'RSAT-DNS-Server' )

$ADUserSection = "ADCharmUsers"

function Set-RequiredPrivileges {
    $me = whoami
    Grant-Privilege -User $me -Grant SeBatchLogonRight
    Grant-Privilege -User $me -Grant SeServiceLogonRight
    Grant-Privilege -User $me -Grant SeAssignPrimaryTokenPrivilege
}


function Start-TimeResync {
    Write-JujuInfo "Synchronizing time..."
    $ts = @("tzutil.exe", "/s", "UTC")
    Invoke-JujuCommand -Command $ts | Out-Null

    try {
        Start-Service "w32time"
        $manualTS = @("w32tm.exe", "/config", "/manualpeerlist:time.windows.com", "/syncfromflags:manual", "/update")
        Invoke-JujuCommand -Command $manualTS | Out-Null
    } catch {
        # not a fatal error
        Write-JujuErr "Failed to synchronize time: $_"
    }
}

function CreateNew-ADUser {
    Param(
        [parameter(Mandatory=$true)]
        [string]$Username
    )

    Write-JujuInfo "Creating AD user..."
    $dn = (Get-ADDomain).DistinguishedName
    if (!$dn) {
        Throw "Could not get DistinguishedName."
    }
    $passwd = Get-RandomString -Length 10 -Weak
    $secPass = ConvertTo-SecureString -AsPlainText $passwd -Force
    $adPath = "CN=Users," + $dn

    $usr = New-ADUser -SamAccountName $Username `
                      -Name $Username `
                      -AccountPassword $secPass `
                      -Enabled $true `
                      -PasswordNeverExpires $true `
                      -Path $adPath `
                      -PassThru

    Write-JujuInfo "Finished creating AD user."
    return @($usr, $passwd)
}

function GetOrCreate-ADUser {
    Param(
        [parameter(Mandatory=$true)]
        [string]$Username
    )
    $keyName = ("ad-" + $Username)
    Write-JujuInfo "Getting/creating AD user..."
    try {
        $usr = Get-ADUser -Identity $Username
    } catch {
        $usr = $null
    }
    if ($usr) {
        $cachedPass = GetBlob-FromLeader -Name $keyName
        if(!$cachedPass){
#            $cachedPass = Get-RandomString -Weak
#            Set-ADAccountPassword -Identity $Username -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $cachedPass -Force)
#            SetBlob-ToLeader -Name $keyName -Blob $cachedPass
            Throw "Failed to get cached password for user $Username"
        }
        return @($usr, $cachedPass)
    } 
    Write-JujuInfo "Creating new AD user: $Username"
    $details = CreateNew-ADUser $Username
    SetBlob-ToLeader -Name $keyName -Blob $details[1]
    return $details
}

#Creates an Active Directory Organizational Unit
function CreateNew-ADOU {
    Param(
        [parameter(Mandatory=$true)]
        [string]$OUName,
        [parameter(Mandatory=$true)]
        [string]$Path
    )

    Write-JujuInfo "Creating Organizational Unit..."
    $Path = $Path.trim(",")
    $tmp = "OU=" + $OUName + "," + $Path
    $ou = Get-ADOrganizationalUnit -Filter {DistinguishedName -eq $tmp}
    if (!$ou) {
        $ou = New-ADOrganizationalUnit -Name $OUName -Path $Path
    }
    return $ou
}

#Creates an Active Directory Group
function CreateNew-ADGroup {
    Param(
        [parameter(Mandatory=$true)]
        [string]$Group
    )

    Write-JujuInfo "Creating Active Directory Group $Group ..."
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
            Write-JujuInfo ("Creating {0}" -f $s[1])
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

    Write-JujuInfo "Looking for $groupName"
    if(!$groupName){
        return $false
    }
    try {
        $grp = Get-ADGroup -Identity $groupName
        return $grp
    } catch {
        Write-JujuWarning "AD Group $groupName does not exist."
    }

    Write-JujuInfo "Creating new group: $groupName"
    $group = New-ADGroup -GroupScope DomainLocal -GroupCategory Security `
             -PassThru -Name $groupName -Path $containerDn
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
        Write-JujuInfo "Assigning user $User to group $i"
        $grp = CreateNew-ADGroup $i
        if(!$grp){
            Write-JujuErr "Could not create group $i"
            return $false
        }
        Add-ADGroupMember $grp $User
    }
}

function Create-ADUsersFromRelation {
    Param (
        [parameter(Mandatory=$true)]
        [hashtable]$Users
    )

    Write-JujuInfo "Users to be created: $Users"
    $creds = @{}
    
    foreach($i in $Users.GetEnumerator()) {
        Write-JujuInfo "Creating AD user $i."
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

    Write-JujuInfo "Adding computer $ComputerName to AD GROUP $Group"
    $group = CreateNew-ADGroup $Group
    $adhost = Get-ADComputer $ComputerName
    Add-ADGroupMember $group $adhost
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

    $isMember = Get-UserGroupMembership -Username $Username -GroupSID $GroupSID
    $groupName = Get-GroupNameFromSID -SID $GroupSID

    if (!$isMember) {
        $objUser = [ADSI]("WinNT://$domain/$user")
        $objGroup = [ADSI]("WinNT://$computername/$groupName")
        try {
            $objGroup.PSBase.Invoke("Add",$objUser.PSBase.Path)
        } catch {
            # the -Fatal flag is deprecated.
            Write-JujuError "Failed to add user $Username to group $groupName" -Fatal $false
            Throw
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
        $domainGroupName = Get-GroupNameFromSID -SID $sid
        Add-ADGroupMember -Members $userToAdd -Identity $domainGroupName `
            -Credential $dccreds -Server $DCName
    }
}

function Get-StrippedUsername {
    Param(
        [parameter(Mandatory=$true)]
        [string]$ShortUsername
    )
    $username = $ShortUsername + "-" + $computername
    if($username.Length -gt 20){
        return $username.Substring(0, 20)
    } else {
        return $username
    }
}

function Create-ServicesUsers {
    Param(
        [parameter(Mandatory=$true)]
        [array]$UsersToAdd,
        [parameter(Mandatory=$true)]
        [HashTable]$ADparams
    )

    Write-JujuInfo "Creating AD Users for active-directory DC"

    $machineName = $computername
    $domain = Get-DomainName $ADparams['domainName']
    $adminUsername = $ADparams["username"]
    $adminPassword = $ADparams["password"]
    $dcName = $ADparams["private-address"]
    $administratorsGroupSID = "S-1-5-32-544"
    $isLocalAdmin = Get-UserGroupMembership -Username $adminUsername -GroupSID $administratorsGroupSID
    $administratorsGroupName = Get-GroupNameFromSID -SID $administratorsGroupSID

    if(!$isLocalAdmin) {
        Write-JujuInfo "Adding user $adminUsername to $administratorsGroupName"
        $admUsr = "$domain\$adminUsername"
        $cmd = @("net.exe", "localgroup", "$administratorsGroupName", "$admUsr", "/add")
        Invoke-JujuCommand -Command $cmd | Out-Null
    }

    $defaultAdminPassword = Get-JujuCharmConfig -Scope "default-administrator-password"
    $defaultAdmin = Get-AdministratorAccount

    Start-ExecuteWithRetry {
        Create-ADUsers $UsersToAdd $defaultAdmin $defaultAdminPassword $domain $dcName $machineName
    } -RetryInterval 10 -MaxRetryCount 3

    foreach ($userToAdd in $UsersToAdd) {
        Write-JujuInfo "Adding user admin rights"
        $userName = $userToAdd["Name"]
        Add-UserToDomainAdmins $defaultAdmin $defaultAdminPassword $domain `
            $dcName $userName
        $u = "$domain\$userName"
        $cmd = @("net.exe", "localgroup", $administratorsGroupName, $u, "/add")
        Invoke-JujuCom`mand -Command $cmd
        Set-UserRunAsRights "$domain\$userName"
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

    foreach($user in $UsersToAdd){
        $username = $user['Name']
        $password = $user['Password']
        $alreadyUser = (Get-ADUser $username -Credential $dccreds -ErrorAction SilentlyContinue) -ne $Null

        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        if (!$alreadyUser) {
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
    return @{
        "ad_host" = "private-address";
        "ip_address" = "address";
        "ad_hostname" = "hostname";
        "ad_username" = "username";
        "ad_password" = "password";
        'ad_domain' = "domainName";
    }
}

function Get-PeerContext {
    $required = @{
        "private-address"=$null;
        "address"=$null;
        "hostname"=$null;
        "username"=$null;
        "password"=$null;
        "domainName"=$null;
    }

    $ctx = Get-JujuRelationContext -RequiredContext $required -Relation "add-controller"
    if(!$ctx.Count) {
        return @{}
    }
    return $ctx
}

function Get-RelationParams {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string]$Type
    )
    PROCESS {
        switch ($Type) {
            'add-controller' {
                return (Get-JujuRelationParams $Type (Get-ADRelationMap))
            }
            default {
                throw "Unsupported relation."
            }
        }
    }
}

function Get-ActiveDirectoryFirewallContext {
    # https://technet.microsoft.com/en-us/library/dd772723(v=ws.10).aspx
    $basePorts = @{
        "TCP" = @(389, 636, 88, 53, 464, 5985, 5986, 3389);
        "UDP" = @(389, 88, 53, 464, 3389)
    }

    $openAllPorts = Get-JujuCharmConfig -Scope "open-all-active-directory-ports"
    if (!$openAllPorts) {
        return $basePorts
    }
    $basePorts["TCP"] += @(3269, 3268, 445, 25, 135, 5722, 9389, 139)
    $basePorts["UDP"] += @(445, 123, 138, 137)
    return $basePorts
}

function Prepare-ADInstall {
    Write-JujuLog "Preparing AD install..."

    $netbiosName = Convert-JujuUnitNameToNetbios
    $shouldReboot = $false
    if ($computername -ne $netbiosName) {
        Write-JujuWarning ("Changing computername from {0} to {1}" -f @($computername, $netbiosName))
        Rename-Computer -NewName $netbiosName
        $shouldReboot = $true
    }
    if((Install-Certificate)) {
        $shouldReboot = $true
    }
    if ($shouldReboot) {
        Invoke-JujuReboot -Now
    }
    try {
        Install-WindowsFeatures $WINDOWS_FEATURES
    } catch {
        Write-JujuError "Failed to install Windows features." -Fatal $true
    }

    Write-JujuLog "Finished preparing AD install."
}

function Install-ADForest {
    Param()

    Write-JujuLog "Installing Forest..."

    $fullDomainName = Get-JujuCharmConfig -Scope 'domain-name'
    $defaultDomainUser = Get-JujuCharmConfig -Scope 'default-domain-user'
    $defaultAdministratorPassword = Get-JujuCharmConfig -Scope 'default-administrator-password'
    $defaultDomainUserPassword = Get-JujuCharmConfig -Scope 'default-domain-user-password'
    $localAdministrator = Get-AdministratorAccount
    $domainName = Get-DomainName $fullDomainName

    if (Is-DomainInstalled $fullDomainName) {
        Write-JujuLog "AD is already installed."
        $dcName = $computername
        Add-UserToDomainAdmins $localAdministrator $defaultAdministratorPassword $domainName $dcName $defaultDomainUser
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

    Start-ExecuteWithRetry -Command {
        New-LocalAdmin -Username $defaultDomainUser -Password $defaultDomainUserPassword
    } -MaxRetryCount 5 -RetryInterval 10

    $safeModePassword = Get-JujuCharmConfig -Scope 'safe-mode-password'
    $safeModePasswordSecure = ConvertTo-SecureString -String $safeModePassword -AsPlainText -Force

    $forestInstalled = Start-ExecuteWithRetry {
        try {
            Install-ADDSForest -DomainName $fullDomainName `
               -DomainNetbiosName $domainName `
               -SafeModeAdministratorPassword $safeModePasswordSecure `
               -InstallDns -Force -NoRebootOnCompletion
        } catch {
            $domainAlreadyInUse = $_.Exception.Message -match "already in use"
            if (!$domainAlreadyInUse) {
                Write-JujuErr "Failed to install forest: $_"
                Throw
            }
            Write-JujuErr "Domain already in use. Skipping..."
            return $false
        }
        return $true
    } -MaxRetryCount 3 -RetryInterval 30

    if (!$forestInstalled) {
        return
    }
    Set-CharmState -Namespace "ADController" -Key "IsInstalled" -Value $true
    Write-JujuLog "Finished installing Forest..."
    Invoke-JujuReboot -Now
}

function Add-DNSForwarders {
    $nameservers = Get-PrimaryAdapterDNSServers | Where-Object { $_ -ne "127.0.0.1" }
    Write-JujuLog "Nameservers are: $nameservers"

    if (!$nameservers) {
        Write-JujuLog "No nameservers to add."
        return
    }

    Start-ExecuteWithRetry {
        $hostname = $computername
        foreach($i in $nameservers) {
            $cmd = @("dnscmd.exe", $hostname, "/resetforwarders", $i)
            Invoke-JujuCommand -Command $cmd | Out-Null
        }
    } -MaxRetryCount 3 -RetryInterval 30
}

function Main-Slave {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$ADParams
    )
    PROCESS {
        Write-JujuLog "Executing main slave..."
        if (!(Is-InDomain $ADParams['domainName'])) {
            ConnectTo-ADController $ADParams
            $services = (Get-Service "jujud-*").Name
            foreach($i in $services) {
                Set-ServiceLogon -Services $i
            }
            Invoke-JujuReboot -Now
        }
        $domain = Get-DomainName $ADParams['domainName']

        $safeModePassword = Get-JujuCharmConfig -Scope "safe-mode-password"
        $safeModePasswordSecure = ConvertTo-SecureString $safeModePassword -AsPlainText -Force

        $adminPassword = Get-JujuCharmConfig -Scope "default-administrator-password"
        $dcsecpassword = ConvertTo-SecureString $adminPassword -AsPlainText -Force
        $domain = Get-DomainName $ADParams['domainName']
        $adminUsername = Get-AdministratorAccount
        $adCredential = New-Object System.Management.Automation.PSCredential("$domain\$adminUsername", $dcsecpassword)

        Add-DNSForwarders
        Start-ExecuteWithRetry {
            Install-ADDSDomainController -NoGlobalCatalog:$false `
                -InstallDns:$true -CreateDnsDelegation:$false `
                -CriticalReplicationOnly:$false -DomainName $domain `
                -SafeModeAdministratorPassword:$safeModePasswordSecure `
                -NoRebootOnCompletion:$true -Credential $adCredential -Force
        } -MaxRetryCount 3 -RetryInterval 30
        Set-CharmState -Namespace "ADController" -Key "IsInstalled" -Value $true

        Invoke-JujuReboot -Now
    }
}

function Is-DomainInstalled {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$fullDomainName
    )

    $isAdControllerInstalled = (Get-CharmState -Namespace "ADController" -Key "IsInstalled")
    if (!$isAdControllerInstalled) {
        return $false
    }
    $runningServiceCode = Start-ExecuteWithRetry {
        Add-Type -Assemblyname System.ServiceProcess
        return [System.ServiceProcess.ServiceControllerStatus]::GetValues("System.ServiceProcess.ServiceControllerStatus")[3]
    } -MaxRetryCount 3 -RetryInterval 30
    $isForestInstalled = $true
    try {
        $services = $("ADWS","NTDS")
        Start-ExecuteWithRetry {
            foreach ($service in $services) {
                $status = (Get-Service $service).Status
                if (!($status.Equals($runningServiceCode))) {
                    Throw "Service $service is not running."
                }
            }
        } -MaxRetryCount 4 -RetryInterval 30
        $forestName = (Get-ADForest).Name
        if ($forestName -ne $fullDomainName) {
            Write-JujuLog "Forest name: $forestName"
            Write-JujuLog "AD Domain not installed."
            $isForestInstalled = $false
        }
    } catch {
        Write-JujuErr "Failed to check if AD Domain is installed: $_"
        $isForestInstalled = $false
    }
    return $isForestInstalled
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

function Create-CA {
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
    $cmd = @("openssl", "req", "-x509", "-nodes", "-days", "3650", "-newkey", "rsa:2048",
             "-out", "$certs_dir\ca.pem", "-outform", "PEM", "-keyout", "$private_dir\ca.key")

    $ErrorActionPreference = "SilentlyContinue"
    Invoke-JujuCommand -Command $cmd | Out-Null

    $ENV:OPENSSL_CONF="$ca_dir\openssl.cnf"
    $fqdn = $computername

    $cmd = @(
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-sha1", "-keyout", "$private_dir\cert.key", "-keyform",
        "PEM", "-out", "$certs_dir\cert.req", "-outform", "PEM",
        "-subj", "/C=US/ST=Washington/L=Seattle/emailAddress=nota@realone.com/organizationName=IT/CN=$fqdn")
    Invoke-JujuCommand -Command $cmd | Out-Null

    $ENV:OPENSSL_CONF="$ca_dir\ca.cnf"
    $cmd = @(
        "openssl", "ca", "-batch", "-notext", "-in",
        "$certs_dir\cert.req", "-out", "$certs_dir\cert.pem",
        "-extensions", "v3_req_server")
    Invoke-JujuCommand -Command $cmd | Out-Null

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

    $password = Get-RandomString -Length 10 -Weak
    # Import server certificate
    $pfx = Join-Path $env:TEMP cert.pfx
    if((Test-Path $pfx)){
        rm -Force $pfx
    }

    $cmd = @(
        "openssl.exe", "pkcs12", "-export", "-in",
        "$cert_file", "-inkey", $key_file, "-out",
        $pfx, "-password", "pass:$password")
    Invoke-JujuCommand -Command $cmd | Out-Null

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
                Write-JujuErr "Failed to set active-directory relation."
            }
        }
    }

    Write-JujuLog "Finished setting active-directory relation data."
}

function Win-Peer {
    Write-JujuLog "Running peer relation..."
    $resumeInstall = (Get-CharmState -Namespace "AD" -Key "InstallingSlave")
    $fullDomainName = Get-JujuCharmConfig -Scope 'domain-name'
    if (!(Is-DomainInstalled $fullDomainName) -or $resumeInstall) {
        Write-JujuLog "This machine is not yet AD Controller."
        $ADParams = Get-PeerContext
        if ($ADParams.Count) {
            if(!(Get-CharmState -Namespace "ADController" -Key "IsInstalled")) {
                Set-CharmState -Namespace "AD" -Key "InstallingSlave" -Value $true 
                Main-Slave $ADParams
            } else {
                $dns = Get-PrimaryAdapterDNSServers
                if ($dns -contains $ADParams['ip_address']) {
                    $dns = $dns | Where-Object {$_ -ne $ADParams['ip_address']}
                    if ($dns) {
                        Set-DnsClientServerAddress `
                            -InterfaceAlias (Get-MainNetadapter) `
                            -ServerAddresses $dns
                    }
                }
                Set-CharmState -Namespace "AD" -Key "InstallingSlave" -Value $false
            }
        }
    }
    if ((Get-CharmState -Namespace "AD" -Key "RunningLeaderElectedHook")) {
        $peerRelationsNotSet = $true
    }
    $isDomainInstalled = Is-DomainInstalled $fullDomainName
    if (((Confirm-Leader) -or $peerRelationsNotSet) -and $isDomainInstalled) {
        Write-JujuInfo "Setting relations..."
        Set-Availability 'add-controller'
        Set-Availability 'ad-join'
        Set-CharmState -Namespace "AD" -Key "RunningLeaderElectedHook" -Value $false
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
    $domainInfo = Get-ADDomain

    $user = Get-AdministratorAccount
    $password = Get-JujuCharmConfig -Scope 'default-administrator-password'
    $uninstallPassword = Get-JujuCharmConfig -Scope 'uninstall-password'
    $netbiosName = $domainInfo.NetBIOSName
    $passwordSecure = ConvertTo-SecureString $password -AsPlainText -Force
    $uninstallPasswordSecure = ConvertTo-SecureString $password -AsPlainText -Force
    $adCredential = New-Object -TypeName PSCredential -ArgumentList @("$netbiosName\$user", $passwordSecure)

    $cmd = @("repadmin.exe", "/syncall")
    Invoke-JujuCommand -Command $cmd | Out-Null

    $domainControllers = (Get-ADDomainController -Filter {Enabled -eq $true}).Name
    if (!($domainControllers -contains $hostname)) {
        Write-JujuLog "This unit is not a domain Controller."
        return
    }

    if ($domainControllers.Count -eq 1) {
        Write-JujuInfo "Trying to remove the last domain controller."
        Start-ExecuteWithRetry -Command {
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
    Write-JujuLog "Started destroying AD Domain..."
    $fullDomainName = Get-JujuCharmConfig -Scope 'domain-name'
    if (!(Is-DomainInstalled $fullDomainName)) {
        Write-JujuLog "The machine is not part of the domain."
        return
    }
    Close-DCPorts
    Write-JujuLog "Syncing AD domain controllers before demotion..."

    Start-ExecuteWithRetry -Command {
        Uninstall-ActiveDomainController
    } -MaxRetryCount 3 -RetryInterval 30
    Set-CharmState -Namespace "ADController" -Key "IsInstalled" -Value $false
    Invoke-JujuReboot -Now
}

function Install-Certificate {
    Write-JujuLog "Installing certificate..."

    if ((Get-CharmState -Namespace "AD" -Key "CertificateInstalled")) {
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

    $fqdn = $computername

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
    Set-CharmState -Namespace "AD" -Key "CertificateInstalled" -Value $true
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
    if((Confirm-Leader)) {
        Set-LeaderData @{$Name=$Blob;}
    }
}

function RemoveBlob-FromLeader {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    if((Confirm-Leader)) {
        Set-LeaderData @{$Name="Nil";}
    }
}

function Create-DjoinData {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$computername
    )
    $blobName = ("djoin-" + $computername)

    if(!(Confirm-Leader)){
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
        $c = Convert-FileToBase64 $blobFile
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
    $cmd = @("djoin.exe", "/provision", "/domain", $domain, "/machine", $computername, "/savefile", $blobFile)
    try {
        Invoke-JujuCommand -Command $cmd | Out-Null
        $blob = Convert-FileToBase64 $blobFile
        SetBlob-ToLeader -Name $blobName -Blob $blob | Out-Null
    } finally {
        rm -Force $blobFile | out-null
    }
    return $blob
}

function Set-ADUserAvailability {
    $isLeader = Confirm-Leader
    if (!$isLeader) {
        Write-JujuLog "I am not leader. Will not continue."
        return
    }
    $settings = @{}
    $adUsersEnc = Get-JujuRelation -Attr "adusers"
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
        $djoinKey = ("djoin-" + $compName)
        if(!$isInAD){
            $blob = Create-DjoinData $compName
            if(!$blob){
                Throw "Failed to generate domain join information"
            }
            $settings[$djoinKey] = $blob
            $settings["already-joined"] = $false
        }else {
            $blob = GetBlob-FromLeader -Name $djoinKey
            if($blob){
                # a blob has already been generated. we send it again
                $settings[$djoinKey] = $blob
            } else {
                # This computer is already part of this domain, but there is no djoin blob
                # associated with this machine. This may happen id the computer is manually added
                # we send a flag to let it know, not to expect a djoin-blob
                $settings["already-joined"] = $true
            }
        }
    } 

    if ($adUsersEnc) {
        $adUsers = Get-UnmarshaledObject $adUsersEnc
        $creds = Create-ADUsersFromRelation $adUsers
        $encCreds = Get-MarshaledObject $creds
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

function Start-ADRelationDepartedHook {
    $compName = Get-JujuRelation -Attr "computername"
    $blobName = ("djoin-" + $compName)
    if ($compName){
        $blob = GetBlob-FromLeader -Name $blobName
        if(!$blob){
            return $true
        }
        try {
            $computerObject = Get-ADComputer $compName -ErrorAction SilentlyContinue
        }catch{
            $computerObject = $false
        }
        if($computerObject){
            Write-JujuWarning "Removing $compName form AD"
            $computerObject | Remove-ADObject -Recursive -Confirm:$false
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

function Start-InstallHook {
    Write-JujuLog "Running install hook..."
    Prepare-ADInstall
    Run-LeaderElectedHook
    Write-JujuLog "Finished running install hook."
}

function Start-StopHook {
    Write-JujuLog "Running stop hook..."
    Destroy-ADDomain
    Close-DCPorts
    Write-JujuLog "Finished running stop hook."
}

function Start-UpgradeCharmHook {
    Write-JujuLog "Running upgrade-charm hook..."
    Win-Peer
    Write-JujuLog "Finished running upgrade-charm hook."
}

function Start-LeaderElectedHook {
    Write-JujuLog "Running leader elected hook..."
    $isLeader = Confirm-Leader

    $isFormerLeader = $false
    $leaderHostname = Get-LeaderData -Attr "active-leader"
    Write-JujuLog "Leader hostname: $leaderHostname"
    if (!$leaderHostname -or ($leaderHostname -eq $computername)) {
        Write-JujuLog "This unit is the first or former leader"
        $isFormerLeader = $true
    }
    $alreadyRunningLeaderElected = (Get-CharmState -Namespace "AD" -Key "RunningLeaderElectedHook")
    if ($isLeader) {
        Set-LeaderData @{"active-leader"=($computername);}
    }
    if (($isLeader -and $isFormerLeader) -or $alreadyRunningLeaderElected) {
        Write-JujuLog "Resuming hook run."
        Set-CharmState -Namespace "AD" -Key "RunningLeaderElectedHook" -Value $true
        Start-ExecuteWithRetry {
            Install-ADForest
        } -MaxRetryCount 30 -RetryInterval 30
    }
    if ($isLeader) {
        Set-Availability 'ad-join'
        Set-Availability 'add-controller'
    }
    Finish-Install
    Write-JujuLog "Finished running leader elected hook."
}

function Start-ADRelationChangedHook {
    Write-JujuLog "Running AD relation changed hook..."

    $isLeader = Confirm-Leader
    if (!$isLeader) {
        Write-JujuLog "I am not leader. Will not continue."
        return
    }
    Set-ADUserAvailability
    Write-JujuLog "Finished running AD relation changed hook."
}

function Start-ADRelationJoinedHook {
    Write-JujuLog "Running AD relation joined hook..."
    $isLeader = Confirm-Leader
    if (!$isLeader) {
        Write-JujuLog "I am not leader. Will not continue."
        return
    }
    Set-Availability 'ad-join'
    Write-JujuLog "Finished running AD relation joined hook."
}

function Start-AddControllerRelationJoinedHook {
    Write-JujuLog "Running add-controller relation joined hook..."
    Win-Peer
    Write-JujuLog "Finished running add-controller relation joined hook."
}

function Start-AddControllerRelationChangedHook {
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

New-Alias -Name Run-TimeResync -Value Start-TimeResync
New-Alias -Name Run-InstallHook -Value Start-InstallHook
New-Alias -Name Run-StopHook -Value Start-StopHook
New-Alias -Name Run-UpgradeCharmHook -Value Start-UpgradeCharmHook
New-Alias -Name Run-LeaderElectedHook -Value Start-LeaderElectedHook
New-Alias -Name Run-ADRelationChangedHook -Value Start-ADRelationChangedHook
New-Alias -Name Run-AddControllerRelationJoinedHook -Value Start-AddControllerRelationJoinedHook
New-Alias -Name Run-AddControllerRelationChangedHook -Value Start-AddControllerRelationChangedHook
New-Alias -Name Run-ADRelationJoinedHook -Value Start-ADRelationJoinedHook
New-Alias -Name Run-ADRelationDepartedHook -Value Start-ADRelationDepartedHook

Export-ModuleMember -Function *