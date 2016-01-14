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

Describe "Test Install-WindowsFeatures" {}

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