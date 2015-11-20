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

$moduleName = "carbon"
$modulePath = Resolve-Path "..\carbon.psm1"
Import-Module $modulePath -DisableNameChecking

InModuleScope $moduleName {
    Describe "Test generate strong password" {
        Context "with no errors" {
            $fakePassword = "Passw0rd"
            $fakeresult = "Passw0rd^"

            Mock Get-RandomPassword { return $fakePassword } -Verifiable

            $result = Generate-StrongPassword

            It "should verify result" {
                $result | Should Be $fakeResult
            }

            It "should verify mocks called" {
                Assert-VerifiableMocks
            }

            It "should verify mocks called with" {
                Assert-MockCalled Get-RandomPassword -ParameterFilter `
                    { Compare-Objects $Length 15 }
            }
        }
    }

}

Remove-Module $moduleName