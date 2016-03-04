# Copyright 2014-2015 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

Import-Module JujuHelper
Import-Module JujuLogging
Import-Module JujuHooks
Import-Module JujuUtils

$moduleHome = Split-Path -Parent $MyInvocation.MyCommand.Path
$administratorsGroupSID = "S-1-5-32-544"
$computername = [System.Net.Dns]::GetHostName()

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

function Get-ServerLevelKey {
    <#
    .SYNOPSIS
    Returns the path to the registry location where information about the server levels is stored
    #>
    PROCESS {
        return "HKLM:Software\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels"
    }
}

function Get-IsNanoServer {
    <#
    .SYNOPSIS
    Return a boolean value of $true if we are running on a Nano server version.
    #>
    PROCESS {
        $serverLevelKey = Get-ServerLevelKey
        if (!(Test-Path $serverLevelKey)){
            # We are most likely running on a workstation version
            return $false
        }
        $serverLevels = Get-ItemProperty $serverLevelKey
        return ($serverLevels.NanoServer -eq 1)
    }
}

function Grant-Privilege {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string]$Grant
    )
    BEGIN {
        $privBin = (get-command SetUserAccountRights.exe -ErrorAction SilentlyContinue).source
        if(!$privBin) {
            $privBin = Join-Path (Join-Path $moduleHome "Bin") "SetUserAccountRights.exe"
            Write-JujuWarning "Failed to find SetUserAccountRights.exe in PATH. Trying with: $privBin"
        }
        if(!(Test-Path $privBin)) {
            Throw "Cound not find SetUserAccountRights.exe on the system."
        }
    }
    PROCESS {
        #Write-JujuInfo "Running: $privBin -g $User -v $Grant"
        $cmd = @($privBin, "-g", "$User", "-v", $Grant)
        Invoke-JujuCommand -Command $cmd | Out-Null
    }
}

function Start-ProcessRedirect {
    <#
    .SYNOPSIS
    A helper function that allows executing a process with more advanced process diagnostics. It returns a System.Diagnostics.Proces
    that gives you access to ExitCode, Stdout/StdErr.
    .PARAMETER Filename
    The executable to run
    .PARAMETER Arguments
    Arguments to pass to the executable
    .PARAMETER Domain
    Optionally, the process can be run as a domain user. This option allows you to specify the domain on which to run the command.
    .PARAMETER Username
    The username under which to run the command.
    .PARAMETER Password
    A SecureString encoded password.

    .EXAMPLE
    $p = Start-ProcessRedirect -Filename (Join-Path $PSHome powershell.exe) -Arguments @("-File", "C:\amazingPowershellScript.ps1")
    $p.ExitCode
    0
    $p.StandardOutput.ReadToEnd()
    whoami sais: desktop-dj170ar\JohnDoe
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Filename,
        [Parameter(Mandatory=$false)]
        [array]$Arguments,
        [Parameter(Mandatory=$false)]
        [array]$Domain,
        [Parameter(Mandatory=$false)]
        [array]$Username,
        [Parameter(Mandatory=$false)]
        [Alias("SecPassword")]
        [System.Security.SecureString]$Password
    )
    PROCESS {
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $Filename
        if ($Domain -ne $null) {
            $pinfo.Username = $Username
            $pinfo.Password = $Password
            $pinfo.Domain = $Domain
        }
        $pinfo.CreateNoWindow = $true
        $pinfo.RedirectStandardError = $true
        $pinfo.RedirectStandardOutput = $true
        $pinfo.UseShellExecute = $false
        $pinfo.LoadUserProfile = $true
        if($Arguments){
            $pinfo.Arguments = $Arguments
        }
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $pinfo
        $p.Start() | Out-Null
        $p.WaitForExit()
        return $p
    }
}

function Get-ComponentIsInstalled {
    <#
    .SYNOPSIS
    This commandlet checks if a program is installed and returns a boolean value. Exact product names must be used, wildcards are not accepted.
    .PARAMETER Name
    The name of the product to check for

    .NOTES
    This commandlet is not supported on Nano server
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    BEGIN {
        if((Get-IsNanoServer)) {
            # TODO: Should we throw or just print a warning?
            # if the user expects this to work on nano, it may lead to
            # faulty code due to bad assumptions
            Throw "This commandlet is not supported on Nano server"
        }
    }
    PROCESS {
        $products = Get-ManagementObject -Class Win32_Product
        $component = $products | Where-Object { $_.Name -eq $Name}

        return ($component -ne $null)
    }
}

function Set-ServiceLogon {
    <#
    .SYNOPSIS
    This function accepts a service or an array of services and sets the user under which the service should run.
    .PARAMETER Services
    An array of services to change startup user on. The values of the array can be a String, ManagementObject (returned by Get-WmiObject) or CimInstance (Returned by Get-CimInstance)
    .PARAMETER UserName
    The local or domain user to set as. Defaults to LocalSystem.
    .PARAMETER Password
    The password for the account.

    .NOTES
    The selected user account must have SeServiceLogonRight privilege.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        [array]$Services,
        [Parameter(Mandatory=$true)]
        [string]$UserName="LocalSystem",
        [Parameter(Mandatory=$false)]
        [string]$Password=""
    )
    PROCESS {
        foreach ($i in $Services){
            switch($i.GetType().FullName){
                "System.String" {
                    $svc = Get-ManagementObject -Class Win32_Service -Filter ("Name='{0}'" -f $i)
                    if(!$svc){
                        Throw ("Service named {0} could not be found" -f @($i))
                    }
                    Set-ServiceLogon -Services $svc -UserName $UserName -Password $Password
                }
                "System.Management.ManagementObject" {
                    if ($i.CreationClassName -ne "Win32_Service"){
                        Throw ("Invalid management object {0}. Expected: {1}" -f @($i.CreationClassName, "Win32_Service"))
                    }
                    $i.Change($null,$null,$null,$null,$null,$null,$UserName,$Password)
                }
                "Microsoft.Management.Infrastructure.CimInstance" {
                    if ($i.CreationClassName -ne "Win32_Service"){
                        Throw ("Invalid management object {0}. Expected: {1}" -f @($i.CreationClassName, "Win32_Service"))
                    }
                    $ret = Invoke-CimMethod -CimInstance $i `
                                            -MethodName "Change" `
                                            -Arguments @{"StartName"=$UserName;"StartPassword"=$Password;}
                    if ($ret.ReturnValue){
                        Throw "Failed to set service credentials: $ret"
                    }
                }
                default {
                    Throw ("Invalid service type {0}" -f $i.GetType().Name)
                }
            }
        }
    }
}

function Get-ServiceIsRunning {
    <#
    .SYNOPSIS
    Checks if a service is running and returns a boolean value.
    .PARAMETER ServiceName
    The service name to check
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )
    PROCESS {
        $service = Get-Service $ServiceName
        if ($service) {
            return ($service.Status -eq 'Running')
        } 
        return $false
    }
}

function Install-Msi {
    <#
    .SYNOPSIS
    Installs a MSI in unattended mode. If install fails an exception is thrown.
    .PARAMETER Installer
    Full path to the MSI installer
    .PARAMETER LogFilePath
    The path to the install log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Alias("MsiFilePath")]
        [string]$Installer,
        [Parameter(Mandatory=$false)]
        [string]$LogFilePath
    )
    PROCESS {
        $args = @(
            "/i",
            $Installer,
            "/q"
            )

        if($LogFilePath){
            $parent = Split-Path $LogFilePath -Parent
            if(!(Test-Path $parent)){
                New-Item -ItemType Directory $parent
            }
            $args += @("/l*v", $LogFilePath)
        }

        if (!(Test-Path $Installer)){
            Throw "Could not find MSI installer at $Installer"
        }
        $p = Start-Process -FilePath "msiexec" -Wait -PassThru -ArgumentList $args
        if ($p.ExitCode -ne 0) {
            Throw "Failed to install MSI package."
        }
    }
}

function Expand-ZipArchive {
    <#
    .SYNOPSIS
    Helper function to unzip a file. This function should work on all modern windows versions, including Windows Server Nano.
    .PARAMETER ZipFile
    The path to the zip archive
    .PARAMETER Destination
    The destination folder into which to unarchive the zipfile.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ZipFile,
        [Parameter(Mandatory=$false)]
        [string]$Destination
    )
    PROCESS {
        $normZipPath = (Resolve-Path $ZipFile).Path
        if(!$Destination){
            $Destination = $PWD.Path
        }
        try {
            # This will work on PowerShell >= 5.0 (default on Windows 10/Windows Server 2016).
            Expand-Archive -Path $normZipPath -DestinationPath $Destination
        } catch [System.Management.Automation.CommandNotFoundException] {
            try {
                # Try without loading system.io.compression.filesystem. This will work by default on Nano
                [System.IO.Compression.ZipFile]::ExtractToDirectory($normZipPath, $Destination)
            }catch [System.Management.Automation.RuntimeException] {
                # Load system.io.compression.filesystem. This will work on the full version of Windows Server
                Add-Type -assembly "system.io.compression.filesystem"
                [System.IO.Compression.ZipFile]::ExtractToDirectory($normZipPath, $Destination)
            }
        }
    }
}

function Install-WindowsFeatures {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [array]$Features
    )
    PROCESS {
        $rebootNeeded = $false
        foreach ($feature in $Features) {
            $state = Start-ExecuteWithRetry -Command {
                Install-WindowsFeature -Name $feature -ErrorAction Stop
            }
            if ($state.Success -eq $true) {
                if ($state.RestartNeeded -eq 'Yes') {
                    $rebootNeeded = $true
                }
            } else {
                throw "Install failed for feature $feature"
            }
        }
        if ($rebootNeeded) {
            Invoke-JujuReboot -Now
        }
    }
}

function Get-AccountObjectByName {
    <#
    .SYNOPSIS
    Returns a CimInstance or a ManagementObject containing the Win32_Account representation of the requested username.
    .PARAMETER Username
    User name to lookup.
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$Username
    )
    PROCESS {
        $u = Get-ManagementObject -Class "Win32_Account" `
                                  -Filter ("Name='{0}'" -f $Username)
        if (!$u) {
            Throw [System.Management.Automation.ItemNotFoundException] "User not found: $Username"
        }
        return $u
    }
}

function Get-GroupObjectByName {
    <#
    .SYNOPSIS
    Returns a CimInstance or a ManagementObject containing the Win32_Group representation of the requested group name.
    .PARAMETER GroupName
    Group name to lookup.
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$GroupName
    )
    PROCESS {
        $g = Get-ManagementObject -Class "Win32_Group" `
                                  -Filter ("Name='{0}'" -f $GroupName)
        if (!$g) {
            Throw "Group not found: $GroupName"
        }
        return $g
    }
}

function Get-AccountObjectBySID {
    <#
    .SYNOPSIS
    This will return a Win32_UserAccount object. If running on a system with powershell >= 4, this will be a CimInstance.
    Systems running powershell <= 3 will return a ManagementObject.
    .PARAMETER SID
    The SID of the user we want to find
    .PARAMETER Exact
    This is $true by default. If set to $false, the query will use the 'LIKE' operator instead of '=' when filtering for users.
    .NOTES
    If $Exact is $false, multiple account objects may be returned.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SID,
        [Parameter(Mandatory=$false)]
        [switch]$Exact=$true
    )
    PROCESS {
        $modifier = " LIKE "
        if ($Exact){
            $modifier = "="
        }
        $query = ("SID{0}'{1}'" -f @($modifier, $SID))
        $s = Get-ManagementObject -Class Win32_UserAccount -Filter $query
        if(!$s){
            Throw "SID not found: $SID"
        }
        return $s
    }
}

function Get-GroupObjectBySID {
    <#
    .SYNOPSIS
    This will return a win32_group object. If running on a system with powershell >= 4, this will be a CimInstance.
    Systems running powershell <= 3 will return a ManagementObject.
    .PARAMETER SID
    The SID of the user we want to find
    .PARAMETER Exact
    This is $true by default. If set to $false, the query will use the 'LIKE' operator instead of '='.
    .NOTES
    If $Exact is $false, multiple win32_account objects may be returned.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SID,
        [Parameter(Mandatory=$false)]
        [switch]$Exact=$true
    )
    PROCESS {
        $modifier = " LIKE "
        if ($Exact){
            $modifier = "="
        }
        $query = ("SID{0}'{1}'" -f @($modifier, $SID))
        $s = Get-ManagementObject -Class Win32_Group -Filter $query
        if(!$s){
            Throw "SID not found: $SID"
        }
        return $s
    }
}

function Get-AccountNameFromSID {
    <#
    .SYNOPSIS
    This function exists for compatibility. Please use Get-AccountObjectBySID.
    .PARAMETER SID
    The SID of the user we want to find
    .PARAMETER Exact
    This is $true by default. If set to $false, the query will use the 'LIKE' operator instead of '='.
    .NOTES
    If $Exact is $false, multiple account objects may be returned.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SID,
        [Parameter(Mandatory=$false)]
        [switch]$Exact=$true
    )
    PROCESS {
        # Get-AccountObjectBySID will throw an exception if an account is not found
        return (Get-AccountObjectBySID -SID $SID -Exact:$Exact).Name
    }
}

function Get-GroupNameFromSID {
    <#
    .SYNOPSIS
    This function exists for compatibility. Please use Get-GroupObjectBySID.
    .PARAMETER SID
    The SID of the group we want to find
    .PARAMETER Exact
    This is $true by default. If set to $false, the query will use the 'LIKE' operator instead of '='.
    .NOTES
    If $Exact is $false, multiple win32_group objects may be returned.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SID,
        [Parameter(Mandatory=$false)]
        [switch]$Exact=$true
    )
    PROCESS {
        return (Get-GroupObjectBySID -SID $SID -Exact:$Exact).Name
    }
}

function Get-AdministratorAccount {
    <#
    .SYNOPSIS
    Helper function to return the local Administrator account name. This works with internationalized versions of Windows.
    #>
    PROCESS {
        $SID = "S-1-5-21-%-500"
        return Get-AccountNameFromSID -SID $SID -Exact:$false
    }
}

function Get-AdministratorsGroup {
    <#
    .SYNOPSIS
    Helper function to get the local Administrators group. This works with internationalized versions of Windows.
    #>
    PROCESS {
        return Get-GroupNameFromSID -SID $administratorsGroupSID
    }
}

function Confirm-IsMemberOfGroup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$GroupSID,
        [Parameter(Mandatory=$true)]
        [string]$Username
    )
    PROCESS {
        $inDomain = (Get-ManagementObject -Class Win32_ComputerSystem).PartOfDomain
        if($inDomain){
            $domainName = (Get-ManagementObject -Class Win32_NTDomain).DomainName
            $myDomain = [Environment]::UserDomainName
            if($domainName -eq $myDomain) {
                return (Get-UserGroupMembership -Username $Username -GroupSID $GroupSID)
            }
        }
        $name = Get-GroupNameFromSID -SID $GroupSID
        return Get-LocalUserGroupMembership -Group $name -Username $Username
    }
}

function Get-LocalUserGroupMembership {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Group,
        [Parameter(Mandatory=$true)]
        [string]$Username
    )
    PROCESS {
        $cmd = @("net.exe", "localgroup", $Group)
        $ret = Invoke-JujuCommand -Command $cmd
        $members =  $ret | where {$_ -AND $_ -notmatch "command completed successfully"} | select -skip 4
        foreach ($i in $members){
            if ($Username -eq $i){
                return $true
            }
        }
        return $false
    }
}

function Get-UserGroupMembership {
    <#
    .SYNOPSIS
    Checks whether or not a user is part of a particular group. If running under a local user, domain users will not be visible.
    .PARAMETER Username
    The username to verify
    .PARAMETER GroupSID
    The SID of the group we want to check if the user is part of.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [Alias("User")]
        [string]$Username,
        [Parameter(Mandatory=$true)]
        [string]$GroupSID
    )
    PROCESS {
        $group = Get-GroupObjectBySID -SID $GroupSID
        if($Username.Contains('@')) {
            $data = $Username.Split('@')
            $Username = $data[0]
            $Domain = $data[1]
        } elseif ($Username.Contains('\')) {
            $data = $Username.Split('\')
            $Username = $data[1]
            $Domain = $data[0]
        }
        $scriptBlock =  { $_.Name -eq $Username }
        if($Domain) {
            $scriptBlock = { $_.Name -eq $Username -and $_.Domain -eq $Domain}
        }
        switch($group.GetType().FullName){
            "Microsoft.Management.Infrastructure.CimInstance" {
                $ret = Get-CimAssociatedInstance -InputObject $group `
                                                 -ResultClassName Win32_UserAccount | Where-Object $scriptBlock
            }
            "System.Management.ManagementObject" {
                $ret = $group.GetRelated("Win32_UserAccount") | Where-Object $scriptBlock
            }
            default {
                Throw ("Invalid group object type {0}" -f $group.GetType().FullName)
            }
        }   
        return ($ret -ne $null)
    }
}

function New-LocalAdmin {
    <#
    .SYNOPSIS
    Create a local user account and add it to the local Administrators group. This works with internationalized versions of Windows as well.
    .PARAMETER Username
    The user name of the new user
    .PARAMETER Password
    The password the user will authenticate with
    .NOTES
    This commandlet creates an administrator user that never expires, and which is not required to reset the password on first logon.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Alias("LocalAdminUsername")]
        [string]$Username,
        [Parameter(Mandatory=$true)]
        [Alias("LocalAdminPassword")]
        [string]$Password
    )
    PROCESS {
        Add-WindowsUser $Username $Password | Out-Null
        Add-UserToLocalGroup -Username $Username -GroupSID $administratorsGroupSID
    }
}

function Add-UserToLocalGroup {
    <#
    .SYNOPSIS
    Add a user to a localgroup
    .PARAMETER Username
    The username to add
    .PARAMETER GroupSID
    The SID of the group to add the user to
    .PARAMETER GroupName
    The name of the group to add the user to
    .NOTES
    GroupSID and GroupName are mutually exclusive
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [Parameter(Mandatory=$false)]
        [string]$GroupSID,
        [Parameter(Mandatory=$false)]
        [string]$GroupName
    )
    PROCESS {
        if(!$GroupSID) {
            if(!$GroupName) {
                Throw "Neither GroupSID, nor GroupName have been specified"
            }
        }
        if($GroupName -and $GroupSID){
            Throw "The -GroupName and -GroupSID options are mutually exclusive"
        }
        if($GroupSID){
            $GroupName = Get-GroupNameFromSID $GroupSID
        }
        if($GroupName) {
            $GroupSID = (Get-GroupObjectByName $GroupName).SID
        }
        $isInGroup = Confirm-IsMemberOfGroup -User $Username -Group $GroupSID
        if($isInGroup){
            return
        }
        $cmd = @("net.exe", "localgroup", $GroupName, $Username, "/add")
        Invoke-JujuCommand -Command $cmd | Out-Null
    }
}

function Add-WindowsUser {
    <#
    .SYNOPSIS
    Creates a new local Windows account.
    .PARAMETER Username
    The user name of the new user
    .PARAMETER Password
    The password the user will authenticate with
    .NOTES
    This commandlet creates a local user that never expires, and which is not required to reset the password on first logon.
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$Username,
        [parameter(Mandatory=$true)]
        [string]$Password
    )
    PROCESS {
        try {
            $exists = Get-AccountObjectByName $Username
        } catch [System.Management.Automation.ItemNotFoundException] {
            $exists = $false
        }
        $cmd = @("net.exe", "user", $Username)
        if (!$exists) {
            $cmd += @($Password, "/add", "/expires:never", "/active:yes")
        } else {
            $cmd += $Password
        }
        Invoke-JujuCommand -Command $cmd | Out-Null
    }
}

function Remove-WindowsUser {
    <#
    .SYNOPSIS
    Delete a local Windows user.
    .PARAMETER Username
    The user we want to delete
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$Username
    )
    PROCESS {
        try {
            $userExists = Get-AccountObjectByName $Username
        } catch [System.Management.Automation.ItemNotFoundException] {
            return
        }
        if ($userExists) {
            $cmd = @("net.exe", "user", $Username, "/delete")
            Invoke-JujuCommand -Command $cmd | Out-Null
        }
    }
}

function Open-Ports {
    <#
    .SYNOPSIS
    Helper function that opens IaaS provider firewall as well as local firewall ports.
    .PARAMETER Ports
    A hashtable containing ports that should be open both in the IaaS provider firewall (ie: security groups in OpenStack) and in the local firewall.
    .PARAMETER Fatal
    Deprecated option. Is set to $true by default and will be removed in the future. All errors opening ports should fail.

    .EXAMPLE

    $ports = @{
        "tcp" = @(1024, 587, 465);
        "udp" = @(69, 139);
    }

    Open-Ports -Ports $ports
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [hashtable]$Ports,
        [Parameter(Mandatory=$false)]
        [Obsolete("This parameter is obsolete and will be removed in the future.")]
        [bool]$Fatal=$true
    )
    PROCESS {
        $directions = @("Inbound", "Outbound")
        foreach ($protocol in $ports.Keys) {
            foreach ($port in $ports[$protocol]) {
                # due to bug https://bugs.launchpad.net/juju-core/+bug/1427770,
                # there is no way to get the ports opened by other units on
                # the same node, thus we can have collisions
                Open-JujuPort -Port "$port/$protocol" -Fatal $Fatal
                foreach ($direction in $directions) {
                    $ruleName = "Allow $direction Port $port/$protocol"
                    if (!(Get-NetFirewallRule $ruleName `
                            -ErrorAction SilentlyContinue)) {
                        New-NetFirewallRule -DisplayName $ruleName `
                            -Name $ruleName `
                            -Direction $direction -LocalPort $port `
                            -Protocol $protocol -Action Allow
                    }
                }
            }
        }
    }
}

function Import-Certificate() {
    <#
    .SYNOPSIS
    Imports a x509 certificate in the chosen certificate store.
    .PARAMETER CertificatePath
    Path to x509 certificate
    .PARAMETER StoreLocation
    x509 store location
    .PARAMETER StoreName
    The name of the store to import into
    .EXAMPLE
    # Path to certificate folder
    $filesDir = Join-Path (Get-JujuCharmDir) "files"
    $crt = Join-Path $filesDir "Cloudbase_signing.cer"
    Import-Certificate $crt -StoreLocation LocalMachine -StoreName TrustedPublisher
    #>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string]$CertificatePath,

        [parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation,

        [parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.StoreName]$StoreName
    )
    PROCESS
    {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            $StoreName, $StoreLocation)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $CertificatePath)
        $store.Add($cert)
    }
}

function Set-PowerProfile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("PowerSave", "Balanced", "Performance")]
        [string]$PowerProfile
    )
    PROCESS {
        $guids = @{
            "PowerSave"="a1841308-3541-4fab-bc81-f71556f20b4a";
            "Balanced"="381b4222-f694-41f0-9685-ff5bb260df2e";
            "Performance"="8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";
        }
        $cmd = @("PowerCfg.exe", "/S", $guids[$PowerProfile])
        Invoke-JujuCommand -Command $cmd | Out-Null
    }
}

function Get-IniFileValue {
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Key,

        [parameter()]
        [string]$Section = "DEFAULT",

        [parameter()]
        [string]$Default = $null,

        [parameter(Mandatory=$true)]
        [string]$Path
    )
    process {
        $api = [Cloudbase.PSUtils.Win32IniApi](New-Object "Cloudbase.PSUtils.Win32IniApi")
        return $api.GetIniValue($Section, $Key, $Default, $Path)
    }
}

function Set-IniFileValue {
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Key,

        [parameter()]
        [string]$Section = "DEFAULT",

        [parameter(Mandatory=$true)]
        [string]$Value,

        [parameter(Mandatory=$true)]
        [string]$Path
    )
    process {
        $api = [Cloudbase.PSUtils.Win32IniApi](New-Object "Cloudbase.PSUtils.Win32IniApi")
        $api.SetIniValue($Section, $Key, $Value, $Path)
    }
}

function Remove-IniFileValue {
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Key,

        [parameter()]
        [string]$Section = "DEFAULT",

        [parameter(Mandatory=$true)]
        [string]$Path
    )
    process {
        $api = [Cloudbase.PSUtils.Win32IniApi](New-Object "Cloudbase.PSUtils.Win32IniApi")
        $api.SetIniValue($Section, $Key, $null, $Path)
    }
}


function Start-ProcessAsUser {
    <#
    .SYNOPSIS
    Starts a process under a user defined by the credentials given as a parameter.
    This command is similar to Linux "su", making possible to run a command under
    different Windows users, for example a user which is a domain administrator.
    .DESCRIPTION
    It uses a wrapper of advapi32.dll functionality,
    [PSCloudbase.ProcessManager]::RunProcess, which is defined as native C++ code
    in the same file.
    .PARAMETER Command
    The executable file path.
    .PARAMETER Arguments
    The arguments that will be sent to the process.
    .PARAMETER Credential
    The credential under which the newly spawned process will run. A credential can
    be created by instantiating System.Management.Automation.PSCredential class.
    .PARAMETER LoadUserProfile
    Whether to load the user profile in case the process needs it.
    .EXAMPLE
    $exitCode = Start-ProcessAsUser -Command "$PShome\powershell.exe" -Arguments @("script.ps1", "arg1", "arg2") -Credential $credential
    .Notes
    The user under which this command is run must have the appropriate privilleges
    and to be a local administrator in order to be able to execute the command
    successfully.
    #>
    [CmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [String]$Command,
        [parameter()]
        [array]$Arguments,
        [parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        [parameter()]
        [bool]$LoadUserProfile = $true,
        [ValidateSet("InteractiveLogon", "NetworkLogon", "BatchLogon", "ServiceLogon")]
        [string]$LogonType="ServiceLogon"
    )

    Process
    {
        $nc = $Credential.GetNetworkCredential()
        $domain = "."
        if($nc.Domain)
        {
            $domain = $nc.Domain
        }
        $logonTypes = @{
            "InteractiveLogon" = 2;
            "NetworkLogon" = 3;
            "BatchLogon" = 4;
            "ServiceLogon" = 5;
        }

        $l = $logonTypes[$LogonType]

        return [Cloudbase.PSUtils.ProcessManager]::RunProcess(
            $nc.UserName, $nc.Password, $domain, $Command, $Arguments,
            $LoadUserProfile, $l)
    }
}

# Backwards compatible aliases
New-Alias -Name Is-ComponentInstalled -Value Get-ComponentIsInstalled
New-Alias -Name Change-ServiceLogon -Value Set-ServiceLogon
New-Alias -Name Is-ServiceAlive -Value Get-ServiceIsRunning
New-Alias -Name Get-WindowsUser -Value Get-AccountObjectByName
New-Alias -Name Get-WindowsGroup -Value Get-GroupObjectByName
New-Alias -Name Convert-SIDToFriendlyName -Value Get-AccountNameFromSID
New-Alias -Name Check-Membership -Value Get-UserGroupMembership
New-Alias -Name Create-LocalAdmin -Value New-LocalAdmin
New-Alias -Name Delete-WindowsUser -Value Remove-WindowsUser

Export-ModuleMember -Function * -Alias *
