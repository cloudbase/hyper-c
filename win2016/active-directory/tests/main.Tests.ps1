#
# Copyright 2014-2015 Cloudbase Solutions Srl
#

$modulePath = (Resolve-Path "..\hooks\active-directory-common.psm1").Path
$moduleName = $modulePath.Split('\')[-1].Split('.')[0]
Import-Module $modulePath -Force -DisableNameChecking

InModuleScope $moduleName {

    Describe "Run-TimeResync" {
        Context "On success" {
            Mock w32tm.exe { } -Verifiable

            Mock Write-JujuLog { return } -Verifiable
            Run-TimeResync

            It "should call all methods" {
                Assert-VerifiableMocks
            }
        }
    }

    Describe "CreateNew-ADUser" {
        #Define AD Methods if there non-existent, so that mocking can work.
        if (!(Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) {
            function Get-ADDomain {
                return
            }
        }

        if (!(Get-Command New-ADUser -ErrorAction SilentlyContinue)) {
            function New-ADUser {
                return
            }
        }

        Context "On success" {
            $fakeDomain = New-Object -TypeName PSObject
            Add-FakeObjProperty -obj ([ref]$fakeDomain) `
                 -name "DistinguishedName" -value "fakeName"
            $fakePassword = "fakePassword"
            $fakeSecureString = "fakeSecureString"
            $fakeUser = "fakeUser"
            $fakeResult = @($fakeUser, $fakePassword)

            Mock Write-JujuLog { return } -Verifiable
            Mock Get-ADDomain { return $fakeDomain } -Verifiable
            Mock New-ADUser { return $fakeUser } -Verifiable
            Mock Generate-StrongPassword { return $fakePassword } -Verifiable
            Mock ConvertTo-SecureString { return $fakeSecureString } `
                 -Verifiable

            $result = CreateNew-ADUser $fakeUser

            It "verify result" {
                Compare-Arrays $result $fakeResult | Should Be $true
            }

            It "should call all methods" {
                Assert-VerifiableMocks
            }
        }

        Context "On fail fetting distinguished name" {
            $fakeDomain = New-Object -TypeName PSObject
            Add-FakeObjProperty -obj ([ref]$fakeDomain) `
                 -name "DistinguishedName" -value $null
            $fakeUser = "fakeUser"
            $fakeResult = @($fakeUser, $fakePassword)

            Mock Write-JujuLog { return } -Verifiable
            Mock Get-ADDomain { return $fakeDomain } -Verifiable
            Mock Write-JujuError { return } -Verifiable

            CreateNew-ADUser $fakeUser

            It "should call all methods" {
                Assert-VerifiableMocks
            }
        }
    }


    Describe "CreateNew-ADUser" {
        #Define AD Methods if there non-existent, so that mocking can work.
        if (!(Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
            function Get-ADUser  {
                return
            }
        }

        Context "On create success" {
            $fakeUser = "fakeUser"
            $fakePass = "fakePass"
            $fakeDecodedPass= "fakeDecodedPass"
            $fakeResult = @($fakeUser, $fakeDecodedPass)

            Mock Write-JujuLog { return } -Verifiable
            Mock Get-ADUser { return $fakeUser } -Verifiable
            Mock Get-CharmState { return $fakePass } -Verifiable
            Mock Decrypt-String { return $fakeDecodedPass } -Verifiable

            $result = GetOrCreate-ADUser $fakeUser

            It "verify result" {
                Compare-Arrays $result $fakeResult | Should Be $true
            }

            It "should call all methods" {
                Assert-VerifiableMocks
            }
        }

        Context "On get success" {
            $fakePassword = "fakePassword"
            $fakeSecureString = "fakeSecureString"
            $fakeUser = "fakeUser"
            $fakeEncString = "fakeEncString"
            $fakeResult = @($fakeUser, $fakePassword)

            Mock Write-JujuLog { return } -Verifiable
            Mock Get-ADUser { return $null } -Verifiable
            Mock CreateNew-ADUser { return $fakeResult } -Verifiable
            Mock Encrypt-String { return $fakeEncString } -Verifiable
            Mock Set-CharmState { return } -Verifiable

            $result = GetOrCreate-ADUser -Username $fakeUser

            It "verify result" {
                Compare-Arrays $result $fakeResult | Should Be $true
            }

            It "should call all methods" {
                Assert-VerifiableMocks
            }
        }
    }

    Describe "Install-Certificate" {
        Context "On new certificate" {
            $fakeFQDN="fakeFQDN"
            $fakeCert = New-Object -TypeName PSObject
            Add-FakeObjProperty -obj ([ref]$fakeCert) `
                 -name "Subject" -value "O=Cloudbase"
            Add-FakeObjProperty -obj ([ref]$fakeCert) `
                 -name "ca" -value "fakeCA"
            Add-FakeObjProperty -obj ([ref]$fakeCert) `
                 -name "key" -value "fakeKey"
            Add-FakeObjProperty -obj ([ref]$fakeCert) `
                 -name "cert" -value "fakeCert"

            Mock Write-JujuLog { return } -Verifiable
            Mock Get-CharmState { return } -Verifiable
            Mock Get-ChildItem { return $fakeCert } -Verifiable
            Mock Generate-FQDN { return $fakeFQDN } -Verifiable
            Mock Create-CA { return $fakeCert } -Verifiable
            Mock Import-CA { return $fakeFQDN } -Verifiable
            Mock Import-Certificate { return $fakeFQDN } -Verifiable

            $result = Install-Certificate

            It "should return correctly" {
                $result | Should Be $true
            }

            It "should call all methods" {
                Assert-VerifiableMocks
            }
        }

        Context "On existent certificate" {
            $fakeFQDN="fakeFQDN"
            $fakeCert = New-Object -TypeName PSObject
            Add-FakeObjProperty -obj ([ref]$fakeCert) `
                 -name "Subject" -value "O=CloudbaseCN=$fakeFQDN"

            Mock Write-JujuLog { return } -Verifiable
            Mock Get-CharmState { return } -Verifiable
            Mock Get-ChildItem { return $fakeCert } -Verifiable
            Mock Generate-FQDN { return $fakeFQDN } -Verifiable

            $result = Install-Certificate

            It "should return correctly" {
                $result | Should Be $false
            }

            It "should call all methods" {
                Assert-VerifiableMocks
            }
        }
    }

    Describe "Open-DCPorts" {
        Context "On success" {
            Mock Open-JujuPort { } -Verifiable

            Open-DCPorts

            It "should call all methods" {
                Assert-VerifiableMocks
            }
        }
    }

    Describe "Update-DC" {
        Context "On success with reboot" {
            Mock Run-TimeResync { } -Verifiable
            Mock Win-Peer { return $true } -Verifiable

            Update-DC

            It "should call all methods" {
                Assert-VerifiableMocks
            }
        }
    }

}

Remove-Module $moduleName
