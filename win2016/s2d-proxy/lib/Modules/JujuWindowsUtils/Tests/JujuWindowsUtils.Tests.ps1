$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleHome = Split-Path -Parent $here
$moduleRoot = Split-Path -Parent $moduleHome

$modulePath = ${env:PSModulePath}.Split(";")
if(!($moduleRoot -in $modulePath)){
    $env:PSModulePath += ";$moduleRoot"
}

$savedEnv = [System.Environment]::GetEnvironmentVariables()

Import-Module JujuWindowsUtils

function Clear-Environment {
    $current = [System.Environment]::GetEnvironmentVariables()
    foreach($i in $savedEnv.GetEnumerator()) {
        [System.Environment]::SetEnvironmentVariable($i.Name, $i.Value, "Process")
    }
    $current = [System.Environment]::GetEnvironmentVariables()
    foreach ($i in $current.GetEnumerator()){
        if(!$savedEnv[$i.Name]){
            [System.Environment]::SetEnvironmentVariable($i.Name, $null, "Process")
        }
    }
}

Describe "Test Get-IsNanoServer" {
    Mock Get-ServerLevelKey -ModuleName JujuWindowsUtils { return "HKCU:\Software\Juju-Charms"}
    AfterEach {
        $CharmStateKey = "HKCU:\Software\Juju-Charms"
        if($CharmStateKey -and (Test-Path $CharmStateKey)) {
            Remove-Item $CharmStateKey -Recurse -Force
        }
    }
    Context "Running on a server build" {
        BeforeEach {
            $CharmStateKey = "HKCU:\Software\Juju-Charms"
            if($CharmStateKey -and (Test-Path $CharmStateKey)) {
                Remove-Item $CharmStateKey -Recurse -Force
            }
            $keyDir = Split-Path -Parent $CharmStateKey
            $keyName = Split-Path -Leaf $CharmStateKey
            New-Item -Path $keyDir -Name $keyName | Out-Null
        }
        It "Should return True" {
            New-ItemProperty -Path "HKCU:\Software\Juju-Charms" -Name NanoServer -Value 1 -PropertyType Dword
            Get-IsNanoServer | Should Be $true
        }
        It "Should return False" {
            New-ItemProperty -Path "HKCU:\Software\Juju-Charms" -Name NanoServer -Value 0 -PropertyType Dword
            Get-IsNanoServer | Should Be $false
        }
    }
    Context "Running on a desktop build" {
        It "Should be false" {
            Get-IsNanoServer | Should Be $false
        }
    }
}

Describe "Test Start-ProcessRedirect" {}

Describe "Test Get-ComponentIsInstalled" {}

Describe "Test Set-ServiceLogon" {}

Describe "Test Get-ServiceIsRunning" {}

Describe "Test Install-Msi" {}

Describe "Test Expand-ZipArchive" {}

Describe "Test Install-WindowsFeatures" {
    # This is missing on a desktop Windows workstation
    function Install-WindowsFeature { }

    Mock Invoke-JujuReboot -ModuleName JujuWindowsUtils { }

    Context "Windows features are enabled for Nano" {
        Mock Get-IsNanoServer -ModuleName JujuWindowsUtils { return $true }
        Mock Get-WindowsOptionalFeature -ModuleName JujuWindowsUtils {
            return @{
                'State' = 'Enabled';
                'RestartNeeded' = $true
            }
        }
        It "should install features and do a reboot" {
            $fakeFeatures = @('NanoFeature_1', 'NanoFeature_2')
            Install-WindowsFeatures -Features $fakeFeatures | Should BeNullOrEmpty
            Assert-MockCalled Get-IsNanoServer -Exactly 2 -ModuleName JujuWindowsUtils
            Assert-MockCalled Get-WindowsOptionalFeature -Exactly 2 -ModuleName JujuWindowsUtils
            Assert-MockCalled Invoke-JujuReboot -Exactly 1 -ModuleName JujuWindowsUtils
        }
    }

    Context "Windows features are installed for regular Windows Server" {
        Mock Get-IsNanoServer -ModuleName JujuWindowsUtils { return $false }
        Mock Install-WindowsFeature -ModuleName JujuWindowsUtils {
            return @{
                'Success' = $true;
                'RestartNeeded' = $false
            }
        }
        It "should install features and without a reboot" {
            $fakeFeatures = @('WindowsFeature_1', 'WindowsFeature_2')
            Install-WindowsFeatures -Features $fakeFeatures | Should BeNullOrEmpty
            Assert-MockCalled Get-IsNanoServer -Exactly 2 -ModuleName JujuWindowsUtils
            Assert-MockCalled Install-WindowsFeature -Exactly 2 -ModuleName JujuWindowsUtils
            Assert-MockCalled Invoke-JujuReboot -Exactly 0 -ModuleName JujuWindowsUtils
        }
    }

    Context "Windows feature failed to install on regular Windows Server" {
        Mock Get-IsNanoServer -ModuleName JujuWindowsUtils { return $false }
        Mock Install-WindowsFeature -ModuleName JujuWindowsUtils {
            return @{
                'Success' = $false;
                'RestartNeeded' = $true
            }
        }
        It "should install features and without a reboot" {
            $fakeFeatures = @('WindowsFeature_1')
            { Install-WindowsFeatures -Features $fakeFeatures } | Should Throw
            Assert-MockCalled Get-IsNanoServer -Exactly 1 -ModuleName JujuWindowsUtils
            Assert-MockCalled Install-WindowsFeature -Exactly 1 -ModuleName JujuWindowsUtils
            Assert-MockCalled Invoke-JujuReboot -Exactly 0 -ModuleName JujuWindowsUtils
        }
    }
}

Describe "Test Get-AccountObjectByName" {}

Describe "Test Get-GroupObjectByName" {}

Describe "Test Get-AccountObjectBySID" {}

Describe "Test Get-GroupObjectBySID" {}

Describe "Test Get-AccountNameFromSID" {}

Describe "Test Get-GroupNameFromSID" {}

Describe "Test Get-AdministratorAccount" {}

Describe "Test Get-AdministratorsGroup" {}

Describe "Test Get-UserGroupMembership" {}

Describe "Test New-LocalAdmin" {}

Describe "Test Add-WindowsUser" {}

Describe "Test Remove-WindowsUser" {}

Describe "Test Open-Ports" {}

Describe "Test Import-Certificate" {}

Describe "Test Grant-Privilege" {}