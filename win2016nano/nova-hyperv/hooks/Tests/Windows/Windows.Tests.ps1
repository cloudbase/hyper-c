$moduleBasePath = "..\..\Modules\CharmHelpers\"
$binPath = "..\..\Bin\"
$moduleNameBasic = ((Split-Path `
                   -Leaf $MyInvocation.MyCommand.Path).Split(".")[0])
$moduleName = $moduleNameBasic + ".psm1"
$moduleNamePs1 = $moduleNameBasic + ".ps1"
$modulePath = Join-Path $moduleBasePath $moduleName
$moduleCpy = Join-Path $env:Temp $moduleNamePs1

if ((Test-Path $modulePath) -eq $false) {
    return
} else {
    Copy-Item $modulePath $moduleCpy -Force
    Copy-Item ($moduleBasePath + "\*.psm1") ($env:Temp + "\") -Force
    . $moduleCpy
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
        Mock New-Object { return 0 } `
                -Verifiable -ParameterFilter `
                { $TypeName -eq "System.Diagnostics.ProcessStartInfo" }
        Mock New-Object { return 0 } `
                -Verifiable -ParameterFilter `
                { $TypeName -eq "System.Diagnostics.Process" }
        Mock Out-Null {} -Verifiable
        Mock juju-log.exe { return 0 } -Verifiable

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
        Mock New-Object { return 0 } `
                -Verifiable -ParameterFilter `
                { $TypeName -eq "System.Diagnostics.ProcessStartInfo" }
        Mock New-Object { return 0 } `
                -Verifiable -ParameterFilter `
                { $TypeName -eq "System.Diagnostics.Process" }
        Mock Out-Null { } -Verifiable
        Mock juju-log.exe { return 0 } -Verifiable

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
        Mock New-Object { return 0 } `
                -Verifiable -ParameterFilter `
                { $TypeName -eq "System.Diagnostics.ProcessStartInfo" }
        Mock New-Object { return 0 } `
                -Verifiable -ParameterFilter `
                { $TypeName -eq "System.Diagnostics.Process" }
        Mock Out-Null {} -Verifiable
        Mock juju-log.exe { return 0 } -Verifiable

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

        Mock New-Object { return $fakePinfoObj } `
                -Verifiable -ParameterFilter `
                { $TypeName -eq "System.Diagnostics.ProcessStartInfo" }
        Mock New-Object { return $fakeProcessObj } `
                -Verifiable -ParameterFilter `
                { $TypeName -eq "System.Diagnostics.Process" }
        Mock Out-Null { } -Verifiable
        Mock juju-log.exe { return 0 } -Verifiable

        $fakeFileName = "fakeFileName"
        $fakeArgs = @("arg1", "arg2")
        $ret = Start-Process-Redirect $fakeFileName $fakeArgs

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

        It "should call juju-log.exe two times" {
            Assert-MockCalled juju-log.exe -Exactly 2
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

        Mock New-Object { return $fakePinfoObj } `
                -Verifiable -ParameterFilter `
                { $TypeName -eq "System.Diagnostics.ProcessStartInfo" }
        Mock New-Object { return $fakeProcessObj } `
                -Verifiable -ParameterFilter `
                { $TypeName -eq "System.Diagnostics.Process" }
        Mock Out-Null { } -Verifiable
        Mock juju-log.exe { return 0 } -Verifiable

        $fakeFileName = "fakeFileName"
        $fakeArgs = @("arg1", "arg2")
        $fakeDomain = "fakeDomain"
        $fakeUser = "fakeUser"
        $fakePassword = "fakePassword"
        $ret = (Start-Process-Redirect `
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

        It "should call juju-log.exe two times" {
            Assert-MockCalled juju-log.exe -Exactly 2
        }
    }
}

Describe "Get-FeatureAvailable" {
    Context "Feature name is null" {
        Mock Get-WindowsFeature { return 0 } -Verifiable

        It "should throw" {
            { Get-FeatureAvailable $null }
        }

        It "should call Get-WindowsFeature zero times" {
            Assert-MockCalled Get-WindowsFeature -Exactly 0
        }
    }

    Context "Feature is Available" {
        $fakeObj = New-Object PSObject
        Add-FakeObjProperty ([ref]$fakeObj) "InstallState" "Available"

        Mock Get-WindowsFeature { return $fakeObj } -Verifiable

        $fakeFeature = "fakeFeature"
        $ret = Get-FeatureAvailable $fakeFeature

        It "should be true" {
            $ret | Should Be $true
        }

        It "should call Get-WindowsFeature one time" {
            Assert-MockCalled Get-WindowsFeature -Exactly 1 `
                -ParameterFilter { $Name.CompareTo($fakeFeature) -eq 0 }
        }
    }

    Context "Feature is not Available" {
        $fakeObj = New-Object PSObject
        Add-FakeObjProperty ([ref]$fakeObj) "InstallState" "Removed"

        Mock Get-WindowsFeature { return $fakeObj } -Verifiable

        $fakeFeature = "fakeFeature"
        $ret = Get-FeatureAvailable $fakeFeature

        It "should be false" {
            $ret | Should Be $false
        }

        It "should call Get-WindowsFeature one time" {
            Assert-MockCalled Get-WindowsFeature -Exactly 1 `
                -ParameterFilter { $Name.CompareTo($fakeFeature) -eq 0 }
        }
    }
}

Describe "Get-FeatureInstall" {
    Context "Feature name is null" {
        Mock Get-WindowsFeature { return 0 } -Verifiable

        It "should throw" {
            { Get-FeatureInstall $null }
        }

        It "should call Get-WindowsFeature zero times" {
            Assert-MockCalled Get-WindowsFeature -Exactly 0
        }
    }

    Context "Feature state is Installed" {
        $fakeObj = New-Object PSObject
        Add-FakeObjProperty ([ref]$fakeObj) "InstallState" "Installed"

        Mock Get-WindowsFeature { return $fakeObj } -Verifiable

        $fakeFeature = "fakeFeature"
        $ret = Get-FeatureInstall $fakeFeature

        It "should be true" {
            $ret | Should Be $true
        }

        It "should call Get-WindowsFeature one time" {
            Assert-MockCalled Get-WindowsFeature -Exactly 1 `
                -ParameterFilter { $Name.CompareTo($fakeFeature) -eq 0 }
        }
    }

    Context "Feature state is InstallPending" {
        $fakeObj = New-Object PSObject
        Add-FakeObjProperty ([ref]$fakeObj) "InstallState" "InstallPending"

        Mock Get-WindowsFeature { return $fakeObj } -Verifiable

        $fakeFeature = "fakeFeature"
        $ret = Get-FeatureInstall $fakeFeature

        It "should be true" {
            $ret | Should Be $true
        }

        It "should call Get-WindowsFeature one time" {
            Assert-MockCalled Get-WindowsFeature -Exactly 1 `
                -ParameterFilter { $Name.CompareTo($fakeFeature) -eq 0 }
        }
    }

    Context "Feature state is not Installed or InstallPending" {
        $fakeObj = New-Object PSObject
        Add-FakeObjProperty ([ref]$fakeObj) "InstallState" "Removed"

        Mock Get-WindowsFeature { return $fakeObj } -Verifiable

        $fakeFeature = "fakeFeature"
        $ret = Get-FeatureInstall $fakeFeature

        It "should be false" {
            $ret | Should Be $false
        }

        It "should call Get-WindowsFeature one time" {
            Assert-MockCalled Get-WindowsFeature -Exactly 1 `
                -ParameterFilter { $Name.CompareTo($fakeFeature) -eq 0 }
        }
    }
}

Describe "Install-WindowsFeatures" {
    Context "Features parameter is null" {
        Mock Get-FeatureAvailable { return 0 } -Verifiable
        Mock Get-FeatureInstall { return 0 } -Verifiable
        Mock juju-log.exe { return 0 } -Verifiable

        It "should throw" {
            { Install-WindowsFeatures $null } | Should Throw
        }

        It "should call Get-FeatureAvailable zero times" {
            Assert-MockCalled Get-FeatureAvailable -Exactly 0
        }

        It "should call Get-FeatureInstall zero times" {
            Assert-MockCalled Get-FeatureInstall -Exactly 0
        }

        It "should call juju-log.exe zero times"{
            Assert-MockCalled juju-log.exe -Exactly 0
        }
    }

    Context "Two available feature are installed and restart is needed" {
        Mock Get-FeatureAvailable { return $true } -Verifiable
        Mock Get-FeatureInstall { return $true } -Verifiable
        Mock Install-WindowsFeature { return @{"RestartNeeded"="Yes"} } `
            -Verifiable
        Mock juju-log.exe { return 0 } -Verifiable

        $fakeFeatures = @("feature1", "feature2")
        $ret = Install-WindowsFeatures $fakeFeatures
        $expectedRet = @{ "InstalledFeatures" = 2;
                          "Reboot" = $true }
        $areEqual = Compare-HashTables $ret $expectedRet

        It "should true" {
            $areEqual | Should Be $true
        }

        It "should call Get-FeatureAvailable two times" {
           Assert-MockCalled Get-FeatureAvailable `
                -Exactly 2 -ParameterFilter `
                    {($FeatureName.CompareTo("feature1") -eq 0) `
                    -or ($FeatureName.CompareTo("feature2") -eq 0)}
        }

        It "should call Get-FeatureInstall two times" {
            Assert-MockCalled Get-FeatureInstall `
                -Exactly 2 -ParameterFilter `
                    {($FeatureName.CompareTo("feature1") -eq 0) `
                    -or ($FeatureName.CompareTo("feature2") -eq 0)}
        }

        It "should call Install-WindowsFeature two times" {
            Assert-MockCalled Install-WindowsFeature `
                -Exactly 2 -ParameterFilter `
                    {($Name.CompareTo("feature1") -eq 0) `
                    -or ($Name.CompareTo("feature2") -eq 0)}
        }

        It "should call juju-log.exe zero times" {
            Assert-MockCalled juju-log.exe -Exactly 0
        }
    }

    Context "Available features don't install and restart isn't needed" {
        Mock Get-FeatureAvailable { return $true } -Verifiable
        Mock Get-FeatureInstall { return $false } -Verifiable
        Mock Install-WindowsFeature { return @{"RestartNeeded"="No"} } `
            -Verifiable
        Mock juju-log.exe { return 0 } -Verifiable

        $fakeFeatures = @("feature1", "feature2")
        $ret = Install-WindowsFeatures $fakeFeatures
        $expectedRet = @{ "InstalledFeatures" = 0;
                          "Reboot" = $false }
        $areEqual = Compare-HashTables $ret $expectedRet

        It "should be false" {
            $areEqual | Should Be $false
        }

        It "should call Get-FeatureAvailable two times" {
           Assert-MockCalled Get-FeatureAvailable `
                -Exactly 2 -ParameterFilter `
                    {($FeatureName.CompareTo("feature1") -eq 0) `
                    -or ($FeatureName.CompareTo("feature2") -eq 0)}
        }

        It "should call Get-FeatureInstall two times" {
            Assert-MockCalled Get-FeatureInstall `
                -Exactly 2 -ParameterFilter `
                    {($FeatureName.CompareTo("feature1") -eq 0) `
                    -or ($FeatureName.CompareTo("feature2") -eq 0)}
        }

        It "should call Install-WindowsFeature two times" {
            Assert-MockCalled Install-WindowsFeature `
                -Exactly 2 -ParameterFilter `
                    {($Name.CompareTo("feature1") -eq 0) `
                    -or ($Name.CompareTo("feature2") -eq 0)}
        }

        It "should call juju-log.exe two times" {
            Assert-MockCalled juju-log.exe -Exactly 2
        }
    }

    Context "Features are unavailable and restart isn't needed" {
        Mock Get-FeatureAvailable { return $false } -Verifiable
        Mock Get-FeatureInstall { return $false } -Verifiable
        Mock Install-WindowsFeature { return @{"RestartNeeded"="No"} } `
            -Verifiable
        Mock juju-log.exe { return 0 } -Verifiable

        $fakeFeatures = @("feature1", "feature2")
        $ret = Install-WindowsFeatures $fakeFeatures
        $expectedRet = @{ "InstalledFeatures" = 0;
                          "Reboot" = $false }
        $areEqual = Compare-HashTables $ret $expectedRet

        It "should be false" {
            $areEqual | Should Be $false
        }

        It "should call Get-FeatureAvailable two times" {
           Assert-MockCalled Get-FeatureAvailable `
                -Exactly 2 -ParameterFilter `
                    {($FeatureName.CompareTo("feature1") -eq 0) `
                    -or ($FeatureName.CompareTo("feature2") -eq 0)}
        }

        It "should call Get-FeatureInstall two times" {
            Assert-MockCalled Get-FeatureInstall `
                -Exactly 2 -ParameterFilter `
                    {($FeatureName.CompareTo("feature1") -eq 0) `
                    -or ($FeatureName.CompareTo("feature2") -eq 0)}
        }

        It "should call Install-WindowsFeature zero times" {
            Assert-MockCalled Install-WindowsFeature `
                -Exactly 0 -ParameterFilter `
                    {($Name.CompareTo("feature1") -eq 0) `
                    -or ($Name.CompareTo("feature2") -eq 0)}
        }

        It "should call juju-log.exe two times" {
            Assert-MockCalled juju-log.exe -Exactly 2
        }
    }
}

Describe "install_windows_features" {
    Context "Features parameter is null" {
        Mock Install-WindowsFeatures { return 0 } -Verifiable

        It "should throw" {
            { install_windows_features $null } | Should Throw
        }

        It "should call Install-WindowsFeatures zero times" {
            Assert-MockCalled Install-WindowsFeatures -Exactly 0
        }
    }

    Context "Features installation fail" {
        Mock Install-WindowsFeatures { Throw } -Verifiable

        $fakeFeatures = @("feature1", "feature2")

        It "should throw" {
            { install_windows_features $fakeFeatures } | Should Throw
        }

        It "should call Install-WindowsFeatures one time" {
            Assert-MockCalled Install-WindowsFeatures -Exactly 1 `
                -ParameterFilter { Compare-Arrays $Features $fakeFeatures }
        }
    }

    Context "Two available features get installed" {
        Mock Install-WindowsFeatures { return @{"InstalledFeatures" = 2} } `
            -Verifiable

        $fakeFeatures = @("feature1", "feature2")
        $ret = install_windows_features $fakeFeatures

        It "should be two" {
            $ret | Should be 2
        }

        It "should call Install-WindowsFeatures one time" {
            Assert-MockCalled Install-WindowsFeatures -Exactly 1 `
                -ParameterFilter { Compare-Arrays $Features $fakeFeatures }
        }
    }
}

Describe "get_available_windows_features" {
    Context "Features parameter is null" {
        Mock Get-WindowsFeature { return 0 } -Verifiable

        It "should throw" {
            { get_available_windows_features $null } | Should Throw
        }

        It "should call Get-WindowsFeature zero times" {
            Assert-MockCalled Get-WindowsFeature -Exactly 0
        }
    }

    Context "Two Available features" {
        $fakeObj = New-Object -TypeName PSObject
        Add-FakeObjProperty ([ref]$fakeObj) "InstallState" "Available"

        Mock Get-WindowsFeature { return $fakeObj } -Verifiable

        $fakeFeatures = @("feature1", "feature2")
        $ret = get_available_windows_features $fakeFeatures

        It "should be two" {
            $ret | Should Be 2
        }

        It "should call Get-WindowsFeature two times" {
            Assert-MockCalled Get-WindowsFeature `
                -Exactly 2 -ParameterFilter {$Name -eq "feature1" `
                                            -or $Name -eq "feature2"}
        }
    }

    Context "Two InstallPending features" {
        $fakeObj = New-Object -TypeName PSObject
        Add-FakeObjProperty ([ref]$fakeObj) "InstallState" "InstallPending"

        Mock Get-WindowsFeature { return $fakeObj } -Verifiable

        $fakeFeatures = @("feature1", "feature2")
        $ret = get_available_windows_features $fakeFeatures

        It "should be two" {
            $ret | Should Be 2
        }

        It "should call Get-WindowsFeature two times" {
            Assert-MockCalled Get-WindowsFeature `
                -Exactly 2 -ParameterFilter {$Name -eq "feature1" `
                                            -or $Name -eq "feature2"}
        }
    }

    Context "Two features are not InstallPending or Available" {
        $fakeObj = New-Object -TypeName PSObject
        Add-FakeObjProperty ([ref]$fakeObj) "InstallState" "Removed"

        Mock Get-WindowsFeature { return $fakeObj } -Verifiable

        $fakeFeatures = @("feature1", "feature2")
        $ret = get_available_windows_features $fakeFeatures

        It "should be two" {
            $ret | Should Be 0
        }

        It "should call Get-WindowsFeature two times" {
            Assert-MockCalled Get-WindowsFeature `
                -Exactly 2 -ParameterFilter {$Name -eq "feature1" `
                                            -or $Name -eq "feature2"}
        }
    }
}

Describe "Install-Windows-Features" {
    Context "Features parameter is null" {
        Mock install_windows_features { return 0 } -Verifiable

        It "should throw" {
            { Install-Windows-Features $null | Should Throw }
        }

        It "should call install_windows_features zero times" {
            Assert-MockCalled install_windows_features -Exactly 0
        }
    }

    Context "Install two available windows features" {
        Mock install_windows_features { return 2 } -Verifiable

        $fakeFeatures = @("feat1", "feat2")
        $ret = Install-Windows-Features $fakeFeatures

        It "should be 2" {
            $ret | Should Be 2
        }

        It "should call install_windows_features one time" {
            Assert-MockCalled install_windows_features `
                -Exactly 1 `
                -ParameterFilter { Compare-Arrays $Features $fakeFeatures }
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
        $ret = Is-Component-Installed $fakeName

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
        $ret = Is-Component-Installed $anotherfakeName

        It "should be false" {
            $ret | Should Be $false
        }

        It "should call Get-WmiObject one time" {
            Assert-MockCalled Get-WmiObject `
                -Exactly 1 -ParameterFilter { $Class -eq "Win32_Product" }
        }
    }
}

Describe "Set-Dns" {
    Context "Both params are null" {
        Mock Set-DnsClientServerAddress { return 0 } -Verifiable

        It "should throw" {
            { Set-Dns $null $null } | Should Throw
        }

        It "should call Set-DnsClientServerAddress zero times" {
            Assert-MockCalled Set-DnsClientServerAddress -Exactly 0
        }
    }

    Context "Interace parameter is null" {
        Mock Set-DnsClientServerAddress { return 0 } -Verifiable

        $fakeDnsIp = "x.x.x.x"

        It "should throw" {
            { Set-Dns $null $fakeDnsIp } | Should Throw
        }

        It "should call Set-DnsClientServerAddress zero times" {
            Assert-MockCalled Set-DnsClientServerAddress -Exactly 0
        }
    }

    Context "DNS IPs parameter is null" {
        Mock Set-DnsClientServerAddress { return 0 } -Verifiable

        $fakeInterface = "fakeInterface"

        It "should throw" {
            { Set-Dns $fakeInterface $null } | Should Throw
        }

        It "should call Set-DnsClientServerAddress zero times" {
            Assert-MockCalled Set-DnsClientServerAddress -Exactly 0
        }
    }

    Context "Set one DNS IP" {
        $fakeInterface = "fakeInterface"
        $fakeDnsIp = "x.x.x.x"

        Mock Set-DnsClientServerAddress { return 0 } -Verifiable

        It "should not throw" {
            { Set-Dns $fakeInterface $fakeDnsIp } | Should Not Throw
        }

        It "should call Set-DnsClientServerAddress one time" {
            Assert-MockCalled Set-DnsClientServerAddress `
            -Exactly 1 -ParameterFilter `
                {($fakeInterface.CompareTo([string]$InterfaceAlias) -eq 0) `
                -and ( Compare-Arrays ([array]$fakeDnsIp) $ServerAddresses )}
        }
    }

    Context "Set more DNS IPs" {
        $fakeInterface = "fakeInterface"
        $fakeDnsIps = @("x.x.x.x", "y.y.y.y")

        Mock Set-DnsClientServerAddress { return 0 } -Verifiable

        It "should not throw" {
            { Set-Dns $fakeInterface $fakeDnsIps } | Should Not Throw
        }

        It "should call Set-DnsClientServerAddress one time" {
            Assert-MockCalled Set-DnsClientServerAddress `
            -Exactly 1 -ParameterFilter `
                {($fakeInterface.CompareTo([string]$InterfaceAlias) -eq 0) `
                -and ( Compare-Arrays ([array]$fakeDnsIps) $ServerAddresses )}
        }
    }
}

Describe "Is-In-Domain" {
    Context "WantedDomain parameter is null" {
        Mock Get-WmiObject { return 0 } -Verifiable `
                 -ParameterFilter { $Class -eq "Win32_ComputerSystem" }

        It "should throw" {
            { Is-In-Domain $null } | Should Throw
        }

        It "should call Get-WmiObject zero times" {
            Assert-MockCalled Get-WmiObject -Exactly 0 `
                -ParameterFilter { $Class -eq "Win32_ComputerSystem" }
        }
    }

    Context "It is in domain" {
        $fakeWmiObj = New-Object PSObject
        Add-FakeObjProperty ([ref]$fakeWmiObj) "Domain" "fakedomain.local"

        Mock Get-WmiObject { return $fakeWmiObj } -Verifiable `
                 -ParameterFilter { $Class -eq "Win32_ComputerSystem" }

        $fakeDomain = "fakedomain.local"
        $ret = Is-In-Domain $fakeDomain

        It "should be true" {
            $ret | Should Be $true
        }

        It "should call Get-WmiObject one time" {
            Assert-MockCalled Get-WmiObject -Exactly 1 `
                -ParameterFilter { $Class -eq "Win32_ComputerSystem" }
        }
    }

    Context "It is not in domain" {
        $fakeWmiObj = New-Object PSObject
        Add-FakeObjProperty ([ref]$fakeWmiObj) "Domain" "fakedomain.local"

        Mock Get-WmiObject { return $fakeWmiObj } -Verifiable `
                 -ParameterFilter { $Class -eq "Win32_ComputerSystem" }

        $anotherFakeDomain = "anotherfakedomain.local"
        $ret = Is-In-Domain $anotherFakeDomain

        It "should be false" {
            $ret | Should Be $false
        }

        It "should call Get-WmiObject one time" {
            Assert-MockCalled Get-WmiObject -Exactly 1 `
                -ParameterFilter { $Class -eq "Win32_ComputerSystem" }
        }
    }
}

Describe "Get-NetAdapterName" {
    Context "Network adapter name is returned" {
        $fakeObj = New-Object PSObject
        Add-FakeObjProperty ([ref]$fakeObj) "Name" "fakeAdapterName"

        Mock Get-NetAdapter { return $fakeObj } -Verifiable

        $ret = Get-NetAdapterName

        It "should be fakeAdapterName" {
            $ret | Should Be "fakeAdapterName"
        }

        It "should call Get-NetAdapter one time" {
            Assert-MockCalled Get-NetAdapter -Exactly 1
        }
    }

    Context "Get-NetAdapter throws an exception" {
        Mock Get-NetAdapter { Throw } -Verifiable

        It "should throw" {
            { Get-NetAdapterName } | Should Throw
        }

        It "should call Get-NetAdapter one time" {
            Assert-MockCalled Get-NetAdapter -Exactly 1
        }
    }
}

Describe "Get-Default-Ethernet-Network-Name" {
    Context "No Second parameter is given" {
        $fakeNetAdapter = New-Object PSObject
        Add-FakeObjProperty ([ref]$fakeNetAdapter) "Name" "Ethernet0"
        $fakeNetAdapter1 = New-Object PSObject
        Add-FakeObjProperty ([ref]$fakeNetAdapter1) "Name" "Ethernet1"
        $fakeAdapters = @($fakeNetAdapter, $fakeNetAdapter1)
        $fakeAdapterName = "fakeAdapterName"

        Mock Get-NetAdapter { return $fakeAdapters } -Verifiable
        Mock Get-NetAdapterName { return $fakeAdapterName } -Verifiable

        $ret = (Get-Default-Ethernet-Network-Name)

        It "should be a primary adapter (Ethernet0 or Management0)" {
            $ret | Should Be "Ethernet0"
        }

        It "should call Get-NetAdapter one time" {
            Assert-MockCalled Get-NetAdapter -Exactly 1
        }

        It "should call Get-NetAdapterName zero times" {
            Assert-MockCalled Get-NetAdapterName -Exactly 0
        }
    }

    Context "Second parameter takes value Primary" {
        $fakeNetAdapter = New-Object PSObject
        Add-FakeObjProperty ([ref]$fakeNetAdapter) "Name" "Management0"
        $fakeNetAdapter1 = New-Object PSObject
        Add-FakeObjProperty ([ref]$fakeNetAdapter1) "Name" "Ethernet1"
        $fakeAdapters = @($fakeNetAdapter, $fakeNetAdapter1)
        $fakeAdapterName = "fakeAdapterName"

        Mock Get-NetAdapter { return $fakeAdapters } -Verifiable
        Mock Get-NetAdapterName { return $fakeAdapterName } -Verifiable

        $ret = (Get-Default-Ethernet-Network-Name "Primary")

        It "should be a primary adapter (Ethernet0 or Management0)" {
            $ret | Should Be "Management0"
        }

        It "should call Get-NetAdapter one time" {
            Assert-MockCalled Get-NetAdapter -Exactly 1
        }

        It "should call Get-NetAdapterName zero times" {
            Assert-MockCalled Get-NetAdapterName -Exactly 0
        }
    }

    Context "Second parameter takes value other than Primary" {
        $fakeNetAdapter1 = New-Object PSObject
        Add-FakeObjProperty ([ref]$fakeNetAdapter1) "Name" "Ethernet0"
        $fakeNetAdapter2 = New-Object PSObject
        Add-FakeObjProperty ([ref]$fakeNetAdapter2) "Name" "SecondAdapter"
        $fakeAdapters = @($fakeNetAdapter1, $fakeNetAdapter2)
        $fakeAdapterName = "fakeAdapterName"

        Mock Get-NetAdapter { return $fakeAdapters } -Verifiable
        Mock Get-NetAdapterName { return $fakeAdapterName } -Verifiable

        $ret = (Get-Default-Ethernet-Network-Name "Second")

        It "should be a secondary adapter" {
            $ret | Should Be "SecondAdapter"
        }

        It "should call Get-NetAdapter one time" {
            Assert-MockCalled Get-NetAdapter -Exactly 1
        }

        It "should call Get-NetAdapterName zero times" {
            Assert-MockCalled Get-NetAdapterName -Exactly 0
        }
    }

    Context "Interface is not found" {
        $fakeAdapterName = "fakeAdapterName"

        Mock Get-NetAdapter { Throw } -Verifiable
        Mock Get-NetAdapterName { return $fakeAdapterName }

        $ret = (Get-Default-Ethernet-Network-Name "Second")

        It "should be fakeAdapterName" {
            $ret | Should Be "fakeAdapterName"
        }

        It "should call Get-NetAdapter one time" {
            Assert-MockCalled Get-NetAdapter -Exactly 1
        }

        It "should call Get-NetAdapterName one time" {
            Assert-MockCalled Get-NetAdapterName -Exactly 1
        }
    }
}

Describe "Get-Ethernet-Network-Name" {
    Context "Ethernet0 primary interface is returned" {
        Mock Get-Default-Ethernet-Network-Name { return "Ethernet0" } `
            -Verifiable

        $ret = Get-Ethernet-Network-Name

        It "should be Ethernet0" {
            $ret | Should Be "Ethernet0"
        }

        It "should call Get-Default-Ethernet-Network-Name one time" {
            Assert-MockCalled Get-Default-Ethernet-Network-Name -Exactly 1 `
                -ParameterFilter { $Second -eq "Primary" }
        }
    }

    Context "Management0 primary interface is returned" {
        Mock Get-Default-Ethernet-Network-Name { return "Management0" } `
            -Verifiable

        $ret = Get-Ethernet-Network-Name

        It "should be Management0" {
            $ret | Should Be "Management0"
        }

        It "should call Get-Default-Ethernet-Network-Name one time" {
            Assert-MockCalled Get-Default-Ethernet-Network-Name -Exactly 1 `
                -ParameterFilter { $Second -eq "Primary" }
        }
    }
}

Describe "Get-Second-Ethernet-Network-Name" {
    Context "Secondary interface is returned" {
        $fakeAdapterName = "SecondEthernet"
        Mock Get-Default-Ethernet-Network-Name { return $fakeAdapterName } `
            -Verifiable

        $ret = Get-Second-Ethernet-Network-Name

        It "should be SecondEthernet" {
            $ret | Should Be "SecondEthernet"
        }

        It "should call Get-Default-Ethernet-Network-Name one time" {
            Assert-MockCalled Get-Default-Ethernet-Network-Name -Exactly 1 `
                -ParameterFilter { $Second -eq "Second" }
        }
    }
}
