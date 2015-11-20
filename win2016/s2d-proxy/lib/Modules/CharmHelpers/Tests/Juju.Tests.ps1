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

$moduleName = "juju"
$modulePath = Resolve-Path "..\juju.psm1"
Import-Module $modulePath -DisableNameChecking

InModuleScope $moduleName {
    # Empty function declaration of juju executables used in the current
    # module. It is needed for unit tests due to the Pester's mocking
    # limitation
    function juju-log.exe () {
        return $true
    }

    Describe "Write-JujuError" {
        $errorMessage = "err"
        $fatal = $false

        Context "Null params are given" {
            It "should fail with null params" {
                { Write-JujuError $null $null } | Should Throw
            }
        }

        Context "Non bool fatal param is given" {
            It "should fail" {
                Assert-VerifiableMocks
                { Write-JujuError $errorMessage $null } | Should Throw
            }
        }

        Context "Params are given" {
            Mock juju-log.exe { return 0 } -Verifiable

            It "should fail only with default fatal param" {
                { Write-JujuError $errorMessage } | Should Throw
                Assert-VerifiableMocks
            }
            It "should succeed with both args" {
                { Write-JujuError $errorMessage $fatal } | Should Not Throw
                Assert-VerifiableMocks
            }
        }
    }

    Describe "Check if juju context is complete" {

        Context "Incorrect argument" {
            It "should fail due to mandatory param" {
                $ctx = $null
                { Check-ContextComplete $ctx} | Should Throw
            }
            It "should fail due to incorrect param" {
                $ctx = @()
                { Check-ContextComplete $ctx} | Should Throw
            }
        }

        Context "Correct arguments" {
            It "should return false" {
                $ctx = @{"key" = $null}
                (Check-ContextComplete $ctx) | Should Be $false
            }
            It "should return true" {
                $ctx = @{"key" = "value"}
                (Check-ContextComplete $ctx) | Should Be $true
            }
        }
    }

    Describe "Juju environment variables" {
        Context "Charm dir check" {
            $charmDirMock = "dir_mock"
            $varName = "CHARM_DIR"
            $prevValue = Prepare-MockEnvVariable $varName $charmDirMock
            It "should get the charm dir" {
                $charmDir = Get-JujuCharmDir
                $charmDir | Should Be $charmDirMock
            }
            Restore-EnvironmentVariable $varName $prevValue
        }

        Context "Is in relation" {
            It "should return true" {
                $a ="red"
                Mock Get-JujuRelationType { $a } -Verifiable
                $isInRelation = Has-JujuRelation
                $isInRelation | Should Be $true
                Assert-VerifiableMocks
            }

            It "should return false" {
                Mock Get-JujuRelationType { return $null } -Verifiable
                $isInRelation = Has-JujuRelation
                $isInRelation | Should Be $false
                Assert-VerifiableMocks
            }
        }

        Context "Charm relation type" {
            $relIdMock = "rel_type"
            $varName = "JUJU_RELATION_ID"
            $prevValue = Prepare-MockEnvVariable $varName $relIdMock
            It "should get the relation id" {
                $relId = Get-JujuRelationId
                $relId | Should Be $relIdMock
            }
            Restore-EnvironmentVariable $varName $prevValue
        }

        Context "Charm local unit" {
            $localUnitMock = "Get-JujuLocalUnit"
            $varName = "JUJU_UNIT_NAME"
            $prevValue = Prepare-MockEnvVariable $varName $localUnitMock
            It "should get the local unit" {
                $localUnit = Get-JujuLocalUnit
                $localUnit | Should Be $localUnitMock
            }
            Restore-EnvironmentVariable $varName $prevValue
        }

        Context "Charm remote unit" {
            $remoteUnitMock = "Get-JujuRemoteUnit"
            $varName = "JUJU_REMOTE_UNIT"
            $prevValue = Prepare-MockEnvVariable $varName $remoteUnitMock
            It "should get the remote unit" {
                $remoteUnit = Get-JujuRemoteUnit
                $remoteUnit | Should Be $remoteUnitMock
            }
            Restore-EnvironmentVariable $varName $prevValue
        }

        Context "Get service name" {
            It "should resturn the service name" {
                $mockLocalUnit = 'win-ad-controller/0'
                $mockServiceName = 'win-ad-controller'
                Mock Get-JujuLocalUnit { return $mockServiceName } -Verifiable

                $serviceName = Get-JujuServiceName
                $serviceName | Should Be $mockServiceName
                Assert-VerifiableMocks
            }
        }

        Context "Check if is master unit" {
            It "should return master unit" {
                $mockLocalUnit = 'win-ad-controller/0'
                Mock Get-JujuLocalUnit { return $mockLocalUnit } -Verifiable

                $isMasterUnit = Is-JujuMasterUnit
                $isMasterUnit | Should Be $true
                Assert-VerifiableMocks
            }

            It "should not return master unit" {
                $mockLocalUnit = 'win-ad-controller/1'
                Mock Get-JujuLocalUnit { return $mockLocalUnit } -Verifiable

                $isMasterUnit = Is-JujuMasterUnit
                $isMasterUnit | Should Be $false
                Assert-VerifiableMocks
            }
        }
    }

    # Execute-Command method is not well implemented
    # as Invoke-Command returns the output+return code of the scriptblock
    Describe "Run powershell command" {
        Context "Incorrect arguments" {
            It "should fail with null arg" {
                { Execute-Command $null} | Should Throw
            }
        }

        Context "Correct arguments" {
            $lastexitcodeCpy = $lastexitcode
            $lastexitcode = 0
            It "should succeed" {
                $fakeScript = { "fake script" }
                $fakeCommand = 'ifconfig'
                $fakeResult = "result"
                Mock Invoke-Command { return $fakeResult } -Verifiable
                Mock Invoke-StaticMethod { return $fakeScript } -Verifiable `
                    -ParameterFilter { 
                        ($Type -eq "ScriptBlock") -and ($Name -eq "Create") 
                    }
                $result = Execute-Command $fakeCommand
                $result | Should Be $fakeResult
                Assert-VerifiableMocks
            }

            It "should fail" {
                $fakeScript = { "fake script" }
                $fakeCommand = 'ifconfig'
                $fakeResult = "result"
                Mock Invoke-Command { return 0 } -Verifiable
                Mock Invoke-StaticMethod { return $fakeScript } -Verifiable `
                    -ParameterFilter { 
                        ($Type -eq "ScriptBlock") -and ($Name -eq "Create") 
                    }
                $result = Execute-Command $fakeResult
                $result | Should Be $false
                Assert-VerifiableMocks
            }

            $lastexitcode = $lastexitcodeCpy
        }
    }

    Describe "Charm configuration" {
        Context "Correct json output" {
            $fakeExecuteCommandResult = "{ 'a' : 'b' }"
            $fakeJsonOutput = "{ 'a' : 'b' }"
            Mock Execute-Command { return $fakeExecuteCommandResult } -Verifiable
            Mock ConvertFrom-Json { return $fakeJsonOutput } -Verifiable

            It "should succeed" {
                $result = Get-JujuCharmConfig
                $result | Should Be $fakeJsonOutput
                Assert-VerifiableMocks
             }
        }

        Context "Failed Execute-Command" {
            Mock Execute-Command { Throw } -Verifiable

            It "should fail" {
                { Get-JujuCharmConfig } | Should Throw
                Assert-VerifiableMocks
             }
        }

        Context "Convert from json fail" {
            $fakeExecuteCommandResult = "{ 'a' : 'b' }"
            $fakeJsonOutput = "{ 'a' : fail"
            Mock Execute-Command { return $fakeExecuteCommandResult } -Verifiable
            Mock ConvertFrom-Json { Throw } -Verifiable

            It "should fail" {
                { Get-JujuCharmConfig } | Should Throw
                Assert-VerifiableMocks
             }
        }

        Context "Null result" {
            $fakeExecuteCommandResult = $null
            Mock Execute-Command { return $fakeExecuteCommandResult } -Verifiable

            It "should fail" {
                $result = Get-JujuCharmConfig
                $result | Should Be $fakeExecuteCommandResult
                Assert-VerifiableMocks
             }
        }
    }

    Describe "Charm relation get" {
        $fakeRid = "1"
        $fakeAttr = "attr"
        $fakeUnit = "attr"
        $fakeCmd = @("relation-get.exe",
                   "--format=json",
                   "-r",
                   $fakeRid,
                   $fakeAttr,
                   $fakeUnit)

        Context "error with json" {
            $fakeResult = "fake result"
            Mock Execute-Command { return $fakeResult } -Verifiable
            Mock ConvertFrom-Json { throw } -Verifiable

            $result = Get-JujuRelation -Rid $fakeRid -Attr $fakeAttr -Unit $fakeUnit

            It "should call Execute-Command" {
                Assert-MockCalled Execute-Command -ParameterFilter `
                { Compare-Objects $cmd $fakeCmd }
            }

            It "should return succesfully" {
                $result | Should Be $false
            }

            It "should verify method calls" {
                Assert-VerifiableMocks
            }
        }

        Context "null json" {
            $fakeResult = $null
            Mock Execute-Command { return $fakeResult } -Verifiable

            $result = Get-JujuRelation -Rid $fakeRid -Attr $fakeAttr -Unit $fakeUnit

            It "should call Execute-Command" {
                Assert-MockCalled Execute-Command -ParameterFilter `
                { Compare-Objects $cmd $fakeCmd }
            }

            It "should return succesfully" {
                $result | Should Be $fakeResult
            }

            It "should verify method calls" {
                Assert-VerifiableMocks
            }
        }

        Context "succesfully executed" {
            $fakeResult = "fake result"
            Mock Execute-Command { return $fakeResult } -Verifiable
            Mock ConvertFrom-Json { return $fakeResult } -Verifiable

            $result = Get-JujuRelation -Rid $fakeRid -Attr $fakeAttr -Unit $fakeUnit

            It "should call Execute-Command" {
                Assert-MockCalled Execute-Command -ParameterFilter `
                { Compare-Objects $cmd $fakeCmd }
            }

            It "should return succesfully" {
                $result | Should Be $fakeResult
            }

            It "should verify method calls" {
                Assert-VerifiableMocks
            }
        }
    }

    Describe "test charm relation set" {
        Context "With non null variables" {
            $fakeRelationId = "fake relation id"
            $fakeRelationSettings = @{"relation-setting"="relt"}
            $fakeCmd = @("relation-set.exe",
                       "-r",
                       $fakeRelationId,
                       "relation-setting='relt'")
            Mock Execute-Command { return $fakeResult } -Verifiable

            $result = Set-JujuRelation $fakeRelationId $fakeRelationSettings

            It "should succeed" {
                $result | Should Be $fakeResult
            }

            It "should check runcommand" {
                Assert-MockCalled Execute-Command -ParameterFilter `
                { Compare-Objects $cmd $fakeCmd }
            }
        }
    }

    Describe "Test relation ids" {
        Context "Non null param" {
            $fakeRelType = "fakereltype"
            $fakeCmd = @("relation-ids.exe",
                       "--format=json",
                       $fakeRelType)

            $fakeResult = "fakreresult"
            $fakeFromJSON = "fakejson"
            Mock Execute-Command { return $fakeFromJSON } -Verifiable
            Mock ConvertFrom-Json { return $fakeResult } -Verifiable

            $result = Get-JujuRelationIds $fakeRelType

            It "should verify result" {
                $result | Should Be $fakeResult
            }

            It "should verify mocks called" {
                Assert-VerifiableMocks
            }

            It "should verify mocks called with" {
                Assert-MockCalled Execute-Command -ParameterFilter `
                    { Compare-Objects $cmd $fakeCmd }
            }
        }

        Context "Null param" {
            $fakeRelType = $null

            $fakeResult = $false
            Mock Get-JujuRelationType { return $fakeRelType } -Verifiable

            $result = Get-JujuRelationIds $fakeRelType

            It "should verify result" {
                $result | Should Be $fakeResult
            }

            It "should verify mocks called" {
                Assert-VerifiableMocks
            }
        }

        Context "Try catch Execute-Command" {
            $fakeRelType = "fakereltype"
            $fakeCmd = @("relation-ids.exe",
                       "--format=json",
                       $fakeRelType)

            $fakeResult = $false
            Mock Execute-Command { Throw } -Verifiable

            $result = Get-JujuRelationIds $fakeRelType

            It "should verify result" {
                $result | Should Be $false
            }

            It "should verify mocks called" {
                Assert-VerifiableMocks
            }

            It "should verify mocks called with" {
                Assert-MockCalled Execute-Command -ParameterFilter `
                    { Compare-Objects $cmd $fakeCmd }
            }
        }

        Context "Try catch convert-from json" {
            $fakeRelType = "fakereltype"
            $fakeCmd = @("relation-ids.exe",
                       "--format=json",
                       $fakeRelType)

            $fakeResult = $false
            Mock Execute-Command { return $fakeResult } -Verifiable
            Mock ConvertFrom-Json{ Throw } -Verifiable
            $result = Get-JujuRelationIds $fakeRelType

            It "should verify result" {
                $result | Should Be $false
            }

            It "should verify mocks called" {
                Assert-VerifiableMocks
            }

            It "should verify mocks called with" {
                Assert-MockCalled Execute-Command -ParameterFilter `
                    { Compare-Objects $cmd $fakeCmd }
                Assert-MockCalled ConvertFrom-Json -ParameterFilter `
                    { Compare-Objects $InputObject $fakeResult }
            }
        }

        Context "Null param" {
            $fakeRelType = $null

            $fakeResult = $false
            Mock Get-JujuRelationType { return $fakeRelType } -Verifiable

            $result = Get-JujuRelationIds $fakeRelType

            It "should verify result" {
                $result | Should Be $fakeResult
            }

            It "should verify mocks called" {
                Assert-VerifiableMocks
            }
        }
    }

    Describe "Get-PrimaryAdapterDNSServers" {
        Context "success" {
            $fakeNetAdapter = "fakeNetAdapter"
            $fakeDnsServers = "fakeDnsServers"
            $fakeDnsClient = New-Object -TypeName PSObject
            Add-FakeObjProperty -obj ([ref]$fakeDnsClient) `
                 -name "ServerAddresses" -value $fakeDnsServers

            Mock Get-MainNetadapter { return $true } -Verifiable
            Mock Get-DnsClientServerAddress { return $fakeDnsClient } `
                 -Verifiable

            $result = Get-PrimaryAdapterDNSServers

            It "should check result is correct" {
                $result | Should Be $fakeDnsServers
            }

            It "should check commands called" {
                Assert-MockCalled Get-MainNetadapter -Exactly 1
                Assert-MockCalled Get-DnsClientServerAddress -Exactly 1
            }
        }
    }

    Describe "Is-JujuPortRangeOpen" {
        Context "port is open" {
            $fakePort = "50"
            $fakeOpenedPorts = "$fakePort/tcp"
            $fakeOpenedPortsJSON = @($fakeOpenedPorts)

            Mock Execute-Command { return $fakeOpenedPorts } -Verifiable
            Mock ConvertFrom-Json { return $fakeOpenedPortsJSON } -Verifiable

            $result = Is-JujuPortRangeOpen $fakePort

            It "should check result is correct" {
                $result | Should Be $true
            }

            It "should check commands called" {
                Assert-MockCalled Execute-Command -Exactly 1
                Assert-MockCalled ConvertFrom-Json -Exactly 1
            }
        }

        Context "fail execute command" {
            $fakePort = "50"
            $fakeOpenedPorts = "$fakePort/tcp"
            $fakeOpenedPortsJSON = @($fakeOpenedPorts)

            Mock Execute-Command { throw } -Verifiable
            Mock ConvertFrom-Json { return $fakeOpenedPortsJSON } -Verifiable

            $result = Is-JujuPortRangeOpen $fakePort

            It "should check result is correct" {
                $result | Should Be $false
            }

            It "should check commands called" {
                Assert-MockCalled Execute-Command -Exactly 1
                Assert-MockCalled ConvertFrom-Json -Exactly 0
            }
        }

        Context "fail json conversion" {
            $fakePort = "50"
            $fakeOpenedPorts = "$fakePort/tcp"
            $fakeOpenedPortsJSON = @($fakeOpenedPorts)

            Mock Execute-Command { return $fakeOpenedPorts } -Verifiable
            Mock ConvertFrom-Json { throw } -Verifiable

            $result = Is-JujuPortRangeOpen $fakePort

            It "should check result is correct" {
                $result | Should Be $false
            }

            It "should check commands called" {
                Assert-MockCalled Execute-Command -Exactly 1
                Assert-MockCalled ConvertFrom-Json -Exactly 1
            }
        }

        Context "port is closed" {
            $fakePort = "50"
            $fakeOpenedPorts = "51"
            $fakeOpenedPortsJSON = @($fakeOpenedPorts)

            Mock Execute-Command { return $fakeOpenedPorts } -Verifiable
            Mock ConvertFrom-Json { return $fakeOpenedPortsJSON } -Verifiable

            $result = Is-JujuPortRangeOpen $fakePort

            It "should check result is correct" {
                $result | Should Be $false
            }

            It "should check commands called" {
                Assert-MockCalled Execute-Command -Exactly 1
                Assert-MockCalled ConvertFrom-Json -Exactly 1
            }
        }
    }

    Describe "Open-JujuPort" {
        Context "already opened port" {
            $fakePort = "fakePort"

            Mock Is-JujuPortRangeOpen { return $true } -Verifiable
            Mock Execute-Command { return } -Verifiable
            Mock Write-JujuError { return } -Verifiable
            Mock Write-JujuLog { return } -Verifiable

            Open-JujuPort $fakePort

            It "should check commands called" {
                Assert-MockCalled Is-JujuPortRangeOpen -Exactly 1
                Assert-MockCalled Execute-Command -Exactly 0
                Assert-MockCalled Write-JujuError -Exactly 0
                Assert-MockCalled Write-JujuLog -Exactly 1
            }
        }

        Context "succes opening port" {
            $fakePort = "fakePort"

            Mock Is-JujuPortRangeOpen { return $false } -Verifiable
            Mock Execute-Command { return } -Verifiable
            Mock Write-JujuError { return } -Verifiable
            Mock Write-JujuLog { return } -Verifiable

            Open-JujuPort $fakePort

            It "should check commands called" {
                Assert-MockCalled Is-JujuPortRangeOpen -Exactly 1
                Assert-MockCalled Execute-Command -Exactly 1
                Assert-MockCalled Write-JujuError -Exactly 0
                Assert-MockCalled Write-JujuLog -Exactly 1
            }
        }
    }

    Describe "Close-JujuPort" {
        Context "already closed port" {
            $fakePort = "fakePort"

            Mock Is-JujuPortRangeOpen { return $false } -Verifiable
            Mock Execute-Command { return } -Verifiable
            Mock Write-JujuError { return } -Verifiable
            Mock Write-JujuLog { return } -Verifiable

            Close-JujuPort $fakePort

            It "should check commands called" {
                Assert-MockCalled Is-JujuPortRangeOpen -Exactly 1
                Assert-MockCalled Execute-Command -Exactly 0
                Assert-MockCalled Write-JujuError -Exactly 0
                Assert-MockCalled Write-JujuLog -Exactly 1
            }
        }

        Context "succes closing port" {
            $fakePort = "fakePort"

            Mock Is-JujuPortRangeOpen { return $true } -Verifiable
            Mock Execute-Command { return } -Verifiable
            Mock Write-JujuError { return } -Verifiable
            Mock Write-JujuLog { return } -Verifiable

            Close-JujuPort $fakePort

            It "should check commands called" {
                Assert-MockCalled Is-JujuPortRangeOpen -Exactly 1
                Assert-MockCalled Execute-Command -Exactly 1
                Assert-MockCalled Write-JujuError -Exactly 0
                Assert-MockCalled Write-JujuLog -Exactly 1
            }
        }
    }

}

Remove-Module $moduleName