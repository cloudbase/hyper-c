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

$moduleName = "windows"
$modulePath = Resolve-Path "..\windows.psm1"
Import-Module $modulePath -DisableNameChecking

InModuleScope $moduleName {
    # Needed for Pester unit tests due to the mocking limitation
    function juju-log.exe () {
        return $true
    }

    $isWinServer = (Get-WmiObject -class Win32_OperatingSystem).Caption -match `
             "Microsoft Windows Server"
    if ($isWinServer -eq $false) {
        function Get-WindowsFeature ($Name) {
            return $true
        }
        function Install-WindowsFeature ($Name) {
            return $true
        }
    }

    Describe "Start-Process-Redirect" {
        Context "Parameters are null" {
            Mock juju-log.exe { return 0 } -Verifiable
            Mock New-Object { return 0 } `
                    -Verifiable -ParameterFilter `
                    { $TypeName -eq "System.Diagnostics.ProcessStartInfo" }
            Mock New-Object { return 0 } `
                    -Verifiable -ParameterFilter `
                    { $TypeName -eq "System.Diagnostics.Process" }
            Mock Out-Null {} -Verifiable

            It "should throw" {
                { Start-Process-Redirect $null $null } | Should Throw
            }

            It "should call New-Object ProcessStartInfo zero times" {
                Assert-MockCalled New-Object -Exactly 0
            }

            It "should call New-Object Process zero times" {
                Assert-MockCalled New-Object -Exactly 0
            }

            It "should call Out-Null zero times" {
                Assert-MockCalled Out-Null -Exactly 0
            }

            It "should call juju-log.exe zero times" {
                Assert-MockCalled juju-log.exe -Exactly 0
            }
        }

        Context "Parameter filename is null" {
            Mock juju-log.exe { return 0 } -Verifiable
            Mock New-Object { return 0 } `
                    -Verifiable -ParameterFilter `
                    { $TypeName -eq "System.Diagnostics.ProcessStartInfo" }
            Mock New-Object { return 0 } `
                    -Verifiable -ParameterFilter `
                    { $TypeName -eq "System.Diagnostics.Process" }
            Mock Out-Null { } -Verifiable

            It "should throw" {
                { Start-Process-Redirect $null "arg" } | Should Throw
            }

            It "should call New-Object ProcessStartInfo zero times" {
                Assert-MockCalled New-Object -Exactly 0
            }

            It "should call New-Object Process zero times" {
                Assert-MockCalled New-Object -Exactly 0
            }

            It "should call Out-Null zero times" {
                Assert-MockCalled Out-Null -Exactly 0
            }

            It "should call juju-log.exe zero times" {
                Assert-MockCalled juju-log.exe -Exactly 0
            }
        }

        Context "Parameter arguments is null" {
            Mock juju-log.exe { return 0 } -Verifiable
            Mock New-Object { return 0 } `
                    -Verifiable -ParameterFilter `
                    { $TypeName -eq "System.Diagnostics.ProcessStartInfo" }
            Mock New-Object { return 0 } `
                    -Verifiable -ParameterFilter `
                    { $TypeName -eq "System.Diagnostics.Process" }
            Mock Out-Null {} -Verifiable

            It "should throw" {
                { Start-Process-Redirect "filename" $null } | Should Throw
            }

            It "should call New-Object ProcessStartInfo zero times" {
                Assert-MockCalled New-Object -Exactly 0
            }

            It "should call New-Object Process zero times" {
                Assert-MockCalled New-Object -Exactly 0
            }

            It "should call Out-Null zero times" {
                Assert-MockCalled Out-Null -Exactly 0
            }

            It "should call juju-log.exe zero times" {
                Assert-MockCalled juju-log.exe -Exactly 0
            }
        }

        Context "Only parameters filename and arguments are passed" {
            $fakePinfoObj = New-Object –TypeName PSObject
            $fakeProperties = @("FileName",
                              "Username",
                              "Password",
                              "Domain",
                              "CreateNoWindow",
                              "RedirectStandardError",
                              "RedirectStandardOutput",
                              "UseShellExecute",
                              "LoadUserProfile",
                              "Arguments")
            Add-FakeObjProperties ([ref]$fakePinfoObj) $fakeProperties $null

            $fakeProcessObj = New-Object -TypeName PSObject
            $fakeProperties = @("StartInfo")
            $fakeMethods = @("Start",
                           "WaitForExit")
            Add-FakeObjProperties ([ref]$fakeProcessObj) $fakeProperties $null
            Add-FakeObjMethods ([ref]$fakeProcessObj) $fakeMethods
            $fakeStdOutObj = New-Object -TypeName PSObject
            Add-FakeObjMethod ([ref]$fakeStdOutObj) "ReadToEnd" 
            Add-FakeObjProperty `
                ([ref]$fakeProcessObj) "StandardOutput" $fakeStdOutObj
            $fakeStdErrObj = New-Object -TypeName PSObject
            Add-FakeObjMethod ([ref]$fakeStdErrObj) "ReadToEnd"
            Add-FakeObjProperty `
                ([ref]$fakeProcessObj) "StandardError" $fakeStdErrObj

            Mock Write-JujuLog { return 0 } -Verifiable
            Mock New-Object { return $fakePinfoObj } `
                    -Verifiable -ParameterFilter `
                    { $TypeName -eq "System.Diagnostics.ProcessStartInfo" }
            Mock New-Object { return $fakeProcessObj } `
                    -Verifiable -ParameterFilter `
                    { $TypeName -eq "System.Diagnostics.Process" }
            Mock Out-Null { } -Verifiable

            $fakeFileName = "fakeFileName"
            $fakeArgs = @("arg1", "arg2")
            $ret = Start-ProcessRedirect $fakeFileName $fakeArgs

            It "should not be null" {
                $ret | Should Not BeNullOrEmpty
            }

            It "should call New-Object ProcessStartInfo one time" {
                Assert-MockCalled New-Object `
                    -Exactly 1 -ParameterFilter `
                    { $TypeName -eq "System.Diagnostics.ProcessStartInfo" }
            }

            It "should call New-Object Process one time" {
                Assert-MockCalled New-Object `
                    -Exactly 1 -ParameterFilter `
                    { $TypeName -eq "System.Diagnostics.Process" }
            }

            It "should call Out-Null one time" {
                Assert-MockCalled Out-Null -Exactly 1
            }

            It "should call Write-JujuLog two times" {
                Assert-MockCalled Write-JujuLog -Exactly 2
            }
        }

        Context "Not-null parameters are passed" {
            $fakePinfoObj = New-Object –TypeName PSObject
            $fakeProperties = @("FileName",
                              "Username",
                              "Password",
                              "Domain",
                              "CreateNoWindow",
                              "RedirectStandardError",
                              "RedirectStandardOutput",
                              "UseShellExecute",
                              "LoadUserProfile",
                              "Arguments")
            Add-FakeObjProperties ([ref]$fakePinfoObj) $fakeProperties $null

            $fakeProcessObj = New-Object -TypeName PSObject
            $fakeProperties = @("StartInfo")
            $fakeMethods = @("Start",
                           "WaitForExit")
            Add-FakeObjProperties ([ref]$fakeProcessObj) $fakeProperties $null
            Add-FakeObjMethods ([ref]$fakeProcessObj) $fakeMethods
            $fakeStdOutObj = New-Object -TypeName PSObject
            Add-FakeObjMethod ([ref]$fakeStdOutObj) "ReadToEnd" 
            Add-FakeObjProperty `
                ([ref]$fakeProcessObj) "StandardOutput" $fakeStdOutObj
            $fakeStdErrObj = New-Object -TypeName PSObject
            Add-FakeObjMethod ([ref]$fakeStdErrObj) "ReadToEnd"
            Add-FakeObjProperty `
                ([ref]$fakeProcessObj) "StandardError" $fakeStdErrObj

            Mock Write-JujuLog { return 0 } -Verifiable
            Mock New-Object { return $fakePinfoObj } `
                    -Verifiable -ParameterFilter `
                    { $TypeName -eq "System.Diagnostics.ProcessStartInfo" }
            Mock New-Object { return $fakeProcessObj } `
                    -Verifiable -ParameterFilter `
                    { $TypeName -eq "System.Diagnostics.Process" }
            Mock Out-Null { } -Verifiable

            $fakeFileName = "fakeFileName"
            $fakeArgs = @("arg1", "arg2")
            $fakeDomain = "fakeDomain"
            $fakeUser = "fakeUser"
            $fakePassword = "fakePassword"

            $ret = (Start-ProcessRedirect `
                       $fakeFileName $fakeArgs $fakeDomain $fakeUser $fakeUser)

            It "should succeed" {
                $ret | Should Not BeNullOrEmpty
            }

            It "should call New-Object ProcessStartInfo one time" {
                Assert-MockCalled New-Object `
                    -Exactly 1 -ParameterFilter `
                    { $TypeName -eq "System.Diagnostics.ProcessStartInfo" }
            }

            It "should call New-Object Process one time" {
                Assert-MockCalled New-Object `
                    -Exactly 1 -ParameterFilter `
                    { $TypeName -eq "System.Diagnostics.Process" }
            }

            It "should call Out-Null one time" {
                Assert-MockCalled Out-Null -Exactly 1
            }

            It "should call Write-JujuLog two times" {
                Assert-MockCalled Write-JujuLog -Exactly 2
            }
        }
    }

    Describe "Is-Component-Installed" {
        Context "Name parameter is null" {
            Mock Get-WmiObject { return 0 } -Verifiable `
                     -ParameterFilter { $Class -eq "Win32_Product" }

            It "should throw" {
                { Is-Component-Installed $null } | Should Throw
            }

            It "should call Get-WmiObject zero times" {
                Assert-MockCalled Get-WmiObject `
                    -Exactly 0 -ParameterFilter { $Class -eq "Win32_Product" }
            }
        }

        Context "Component is installed" {
            $fakeWmiObj = New-Object PSObject
            Add-FakeObjProperty ([ref]$fakeWmiObj) "Name" "fakeName"

            Mock Get-WmiObject { return $fakeWmiObj } -Verifiable `
                     -ParameterFilter { $Class -eq "Win32_Product" }

            $fakeName = "fakeName"
            $ret = Is-ComponentInstalled $fakeName

            It "should be true" {
                $ret | Should Be $true
            }

            It "should call Get-WmiObject one time" {
                Assert-MockCalled Get-WmiObject `
                    -Exactly 1 -ParameterFilter { $Class -eq "Win32_Product" }
            }
        }

        Context "Component is not installed" {
            $fakeWmiObj = New-Object PSObject
            Add-FakeObjProperty ([ref]$fakeWmiObj) "Name" "fakeName"

            Mock Get-WmiObject { $fakeWmiObj } -Verifiable `
                     -ParameterFilter { $Class -eq "Win32_Product" }

            $anotherfakeName = "anotherFakeName"
            $ret = Is-ComponentInstalled $anotherfakeName

            It "should be false" {
                $ret | Should Be $false
            }

            It "should call Get-WmiObject one time" {
                Assert-MockCalled Get-WmiObject `
                    -Exactly 1 -ParameterFilter { $Class -eq "Win32_Product" }
            }
        }
    }
}

Remove-Module $moduleName
