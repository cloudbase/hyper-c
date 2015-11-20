#
# Copyright 2014-2015 Cloudbase Solutions Srl
#

$utilsModulePath = Join-Path $PSScriptRoot "utils.psm1"
Import-Module -Force -DisableNameChecking $utilsModulePath
$jujuModulePath = Join-Path $PSScriptRoot "juju.psm1"
Import-Module -Force -DisableNameChecking $jujuModulePath

function Start-ProcessRedirect {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Filename,
        [Parameter(Mandatory=$true)]
        [array]$Arguments,
        [Parameter(Mandatory=$false)]
        [array]$Domain,
        [Parameter(Mandatory=$false)]
        [array]$Username,
        [Parameter(Mandatory=$false)]
        $SecPassword
    )

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $Filename
    if ($Domain -ne $null) {
        $pinfo.Username = $Username
        $pinfo.Password = $secPassword
        $pinfo.Domain = $Domain
    }
    $pinfo.CreateNoWindow = $true
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.LoadUserProfile = $true
    $pinfo.Arguments = $Arguments
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit()

    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    Write-JujuLog "stdout: $stdout"
    Write-JujuLog "stderr: $stderr"

    return $p
}

function Is-ComponentInstalled {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    $component = Get-WmiObject -Class Win32_Product | `
                     Where-Object { $_.Name -eq $Name}

    return ($component -ne $null)
}

function Get-JujuUnitName {
    $jujuUnitNameNumber = (Get-JujuLocalUnit).split('/')
    $jujuUnitName = ($jujuUnitNameNumber[0]).ToString()
    $jujuUnitNumber = ($jujuUnitNameNumber[1]).ToString()
    if (!$jujuUnitName -or !$jujuUnitNumber) {
        Write-JujuError "Failed to get unit name and number" -Fatal $true
    }
    $maxUnitNameLength = 15 - ($jujuUnitName.Length + $jujuUnitNumber.Length)
    if ($maxUnitNameLength -lt 0) {
        $jujuUnitName = $jujuUnitName.substring(0, ($jujuUnitName.Length + $maxUnitNameLength))
    }
    $newHostname = $jujuUnitName + $jujuUnitNumber
    return $newHostname
}


function Rename-Hostname {
    $newHostname = Get-JujuUnitName
    if ($env:computername -ne $newHostname) {
        Rename-Computer -NewName $newHostname
        ExitFrom-JujuHook -WithReboot
    }
}

function Change-ServiceLogon {
    param(
        [Parameter(Mandatory=$true)]
        $Services,
        [Parameter(Mandatory=$true)]
        [string]$UserName,
        [Parameter(Mandatory=$false)]
        $Password
    )

    $Services | ForEach-Object { $_.Change($null,$null,$null,$null,$null,$null,$UserName,$Password) }
}

function Is-ServiceAlive {
    param(
        [Parameter(Mandatory=$true)]
        [string]$serviceName)

    $service = Get-Service $serviceName
    if ($service -and $service.Status -eq 'Running') {
        Write-JujuLog "Service $serviceName is alive."
        return $true
    } else {
        Write-JujuLog "Service $serviceName is dead."
        return $false
    }
}

function Install-Msi {
    param(
        [Parameter(Mandatory=$true)]
        [string]$MsiFilePath,
        [Parameter(Mandatory=$true)]
        [string]$LogFilePath
        )

    $args = @(
        "/i",
        $MsiFilePath,
        "/l*v",
        $LogFilePath
        )

    $p = Start-Process -FilePath "msiexec" -Wait -PassThru -ArgumentList $args
    if ($p.ExitCode -ne 0) {
        Write-JujuLog "Failed to install MSI package."
        Throw "Failed to install MSI package."
    } else {
        Write-JujuLog "Succesfully installed MSI package."
    }

}

function Get-IPv4Subnet {
    param(
        [Parameter(Mandatory=$true)]
        $IP,
        [Parameter(Mandatory=$true)]
        $Netmask
    )

    $class = 32
    $netmaskClassDelimiter = "255"
    $netmaskSplit = $Netmask -split "[.]"
    $ipSplit = $IP -split "[.]"
    for ($i = 0; $i -lt 4; $i++) {
        if ($netmaskSplit[$i] -ne $netmaskClassDelimiter) {
            $class -= 8
            $ipSplit[$i] = "0"
        }
    }

    $fullSubnet = ($ipSplit -join ".") + "/" + $class
    return $fullSubnet
}

function Install-WindowsFeatures {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Features
    )

    $rebootNeeded = $false
    foreach ($feature in $Features) {
        $state = ExecuteWith-Retry -Command {
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

    if ($rebootNeeded -eq $true) {
        ExitFrom-JujuHook -WithReboot
    }
}

function Get-CharmStateFullKeyPath () {
    return ((Get-CharmStateKeyDir) + (Get-CharmStateKeyName))
}

function Get-CharmStateKeyDir () {
    return "HKLM:\SOFTWARE\Wow6432Node\"
}

function Get-CharmStateKeyName () {
    return "Juju-Charms"
}

function Set-CharmState {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CharmName,
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [Parameter(Mandatory=$true)]
        [string]$Val
    )

    $keyPath = Get-CharmStateFullKeyPath
    $keyDirExists = Test-Path -Path $keyPath
    if ($keyDirExists -eq $false) {
        $keyDir = Get-CharmStateKeyDir
        $keyName = Get-CharmStateKeyName
        New-Item -Path $keyDir -Name $keyName
    }

    $fullKey = ($CharmName + $Key)
    $property = New-ItemProperty -Path $keyPath `
                                 -Name $fullKey `
                                 -Value $Val `
                                 -PropertyType String `
                                 -ErrorAction SilentlyContinue

    if ($property -eq $null) {
        Set-ItemProperty -Path $keyPath -Name $fullKey -Value $Val
    }
}

function Get-CharmState {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CharmName,
        [Parameter(Mandatory=$true)]
        [string]$Key
    )

    $keyPath = Get-CharmStateFullKeyPath
    $fullKey = ($CharmName + $Key)
    $property = Get-ItemProperty -Path $keyPath `
                                 -Name $fullKey `
                                 -ErrorAction SilentlyContinue

    if ($property -ne $null) {
        $state = Select-Object -InputObject $property -ExpandProperty $fullKey
        return $state
    } else {
        return $null
    }
}

function Get-WindowsUser {
    Param(
        [parameter(Mandatory=$true)]
        [string]$Username
    )

    $existentUser = Get-WmiObject -Class "Win32_Account" `
                                  -Filter "Name = '$Username'"
    if ($existentUser -eq $null) {
        Write-JujuLog "User not found."
    }

    return $existentUser
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

function Check-Membership {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string]$GroupSID
    )

    $group = Get-CimInstance -ClassName Win32_Group  `
                -Filter "SID = '$GroupSID'"
    $ret = Get-CimAssociatedInstance -InputObject $group `
          -ResultClassName Win32_UserAccount | Where-Object `
                                               { $_.Name -eq $User }
    return $ret
}

function Create-LocalAdmin {
    param(
        [Parameter(Mandatory=$true)]
        [string]$LocalAdminUsername,
        [Parameter(Mandatory=$true)]
        [string]$LocalAdminPassword
    )

    Add-WindowsUser $LocalAdminUsername $LocalAdminPassword

    $administratorsGroupSID = "S-1-5-32-544"
    $isLocalAdmin = Check-Membership $LocalAdminUsername $administratorsGroupSID
    $groupName = Convert-SIDToFriendlyName -SID $administratorsGroupSID
    if (!$isLocalAdmin) {
        Execute-ExternalCommand -Command {
            net.exe localgroup $groupName $LocalAdminUsername /add
        } -ErrorMessage "Failed to add user to local admins group."
    } else {
        Juju-Log "User is already in the administrators group."
    }
}

function Add-WindowsUser {
    param(
        [parameter(Mandatory=$true)]
        [string]$Username,
        [parameter(Mandatory=$true)]
        [string]$Password
    )

    $existentUser = Get-WindowsUser $Username
    if ($existentUser -eq $null) {
        $computer = [ADSI]"WinNT://$env:computername"
        $user = $computer.Create("User", $Username)
        $user.SetPassword($Password)
        $user.SetInfo()
        $user.FullName = $Username
        $user.SetInfo()
        # UserFlags = Logon script | Normal user | No pass expiration
        $user.UserFlags = 1 + 512 + 65536
        $user.SetInfo()
    } else {
        Execute-ExternalCommand -Command {
            $computername = hostname.exe
            $user = [ADSI] "WinNT://$computerName/$Username,User"
            $user.SetPassword($Password)
        } -ErrorMessage "Failed to update user password."
    }
}

function Delete-WindowsUser {
    param(
        [parameter(Mandatory=$true)]
        [string]$Username
    )

    Execute-ExternalCommand -Command {
        NET.EXE USER $Username '/DELETE'
    } -ErrorMessage "Failed to delete user."
}

Export-ModuleMember -Function *
