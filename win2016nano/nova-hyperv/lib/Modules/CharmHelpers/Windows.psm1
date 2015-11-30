#ps1_sysnative

# Copyright 2014 Cloudbase Solutions Srl
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

$utilsModulePath = Join-Path $PSScriptRoot "utils.psm1"
Import-Module -Force -DisableNameChecking $utilsModulePath
$jujuModulePath = Join-Path $PSScriptRoot "juju.psm1"
Import-Module -Force -DisableNameChecking $jujuModulePath
$computername = [System.Net.Dns]::GetHostName()

function Get-JsonParser {
    $json = [System.Reflection.Assembly]::Load("JSON.Silverlight4")
    $jsp = $json.GetTypes() | ? name -match jsonparser
    return $jsp
}

function Grant-Privilege {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string]$Grant
    )
    $files = Join-Path $env:CHARM_DIR "files"
    $privBin = Join-Path $files "SetUserAccountRights.exe"
    juju-log.exe "Running:  $privBin -g $User -v $Grant"
    & $privBin -g $User -v $Grant
    if ($LASTEXITCODE){
        Throw "SetUserAccountRights.exe: exited with status $LASTEXITCODE"
    }
}

function Import-Certificate()
{
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
                     Where-Object { $_.Name -Match $Name}

    return ($component -ne $null)
}

function Rename-Hostname {
    $jujuUnitName = ${env:JUJU_UNIT_NAME}.split('/')
    if ($jujuUnitName[0].Length -ge 15) {
        $jujuName = $jujuUnitName[0].substring(0, 12)
    } else {
        $jujuName = $jujuUnitName[0]
    }
    $newHostname = $jujuName + $jujuUnitName[1]

    if ($computername -ne $newHostname) {
        Rename-Computer -NewName $newHostname
        ExitFrom-JujuHook -WithReboot
    }
}

function Change-ServiceLogon {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Service,
        [Parameter(Mandatory=$true)]
        [string]$UserName,
        [Parameter(Mandatory=$false)]
        [string]$Password
    )
    juju-log.exe "Setting $UserName on $Service with $Password"
    $svc = gcim Win32_Service | Where-Object {$_.Name -eq $Service }
    if (!$svc) {
        Throw "Could not find $Service"
    }
    $ret = Invoke-CimMethod -CimInstance $svc -MethodName "Change" -Arguments @{StartName=$UserName;StartPassword=$Password}
    if ($ret.ReturnValue){
        Throw "Failed to set service credentials: $ret"
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

function Get-CharmStateKeyPath () {
    return "HKLM:\SOFTWARE\Wow6432Node\Juju-Charms"
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

    $keyPath = Get-CharmStateKeyPath
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

    $keyPath = Get-CharmStateKeyPath
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

function Create-LocalAdmin {
    param(
        [Parameter(Mandatory=$true)]
        [string]$LocalAdminUsername,
        [Parameter(Mandatory=$true)]
        [string]$LocalAdminPassword
    )

    $existentUser = Get-WmiObject -Class Win32_Account `
                                  -Filter "Name = '$LocalAdminUsername'"
    if ($existentUser -eq $null) {
        $computer = [ADSI]"WinNT://$computername"
        $localAdmin = $computer.Create("User", $LocalAdminUsername)
        $localAdmin.SetPassword($LocalAdminPassword)
        $localAdmin.SetInfo()
        $LocalAdmin.FullName = $LocalAdminUsername
        $LocalAdmin.SetInfo()
        # UserFlags = Logon script | Normal user | No pass expiration
        $LocalAdmin.UserFlags = 1 + 512 + 65536
        $LocalAdmin.SetInfo()
    } else {
        Execute-ExternalCommand -Command {
            net.exe user $LocalAdminUsername $LocalAdminPassword
        } -ErrorMessage "Failed to create new user"
    }

    $localAdmins = Execute-ExternalCommand -Command {
        net.exe localgroup Administrators
    } -ErrorMessage "Failed to get local administrators"

    # Assign user to local admins groups if he isn't there
    $isLocalAdmin = ($localAdmins -match $LocalAdminUsername) -ne 0
    if ($isLocalAdmin -eq $false) {
        Execute-ExternalCommand -Command {
            net.exe localgroup Administrators $LocalAdminUsername /add
        } -ErrorMessage "Failed to add user to local admins group"
    }
}

function Add-WindowsUser {
    param(
        [parameter(Mandatory=$true)]
        [string]$Username,
        [parameter(Mandatory=$true)]
        [string]$Password
    )

    Execute-ExternalCommand -Command {
        NET.EXE USER $Username $Password '/ADD'
    } -ErrorMessage "Failed to create new user"
}

function Delete-WindowsUser {
    param(
        [parameter(Mandatory=$true)]
        [string]$Username
    )

    Execute-ExternalCommand -Command {
        NET.EXE USER $Username '/DELETE'
    } -ErrorMessage "Failed to create new user"
}

function Create-Service {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [string]$User,
        [Parameter(Mandatory=$false)]
        [string]$Pass
    )

    if($user -and $Pass){
        $secpasswd = ConvertTo-SecureString $Pass -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($User, $secpasswd)
    }

    if ($cred){
        New-Service -Name $Name -BinaryPathName $Path -DisplayName $Name -Description $Description  -Credential $cred -Confirm:$false
    }else{
        New-Service -Name $Name -BinaryPathName $Path -DisplayName $Name -Description $Description -Confirm:$false
    }

}

Export-ModuleMember -Function *
