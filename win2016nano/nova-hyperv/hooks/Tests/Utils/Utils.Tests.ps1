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

Describe "ExecuteWith-RetryPSCommand" {
    Context "Null command" {
        Mock Invoke-Command { Throw } -Verifiable
        Mock Start-Sleep { return 0 } -Verifiable

        It "should throw" {
            { ExecuteWith-RetryPSCommand } | Should Throw
        }

        It "should call Invoke-Command zero times" {
            Assert-MockCalled Invoke-Command -Exactly 0
        }

        It "should call Start-Sleep three times" {
            Assert-MockCalled Start-Sleep -Exactly 3
        }
    }

    Context "Fake command" {
        $fakeScriptBlock = { fake command }

        Mock Invoke-Command { Throw } -Verifiable
        Mock Start-Sleep { return 0 } -Verifiable

        It "should throw" {
            { ExecuteWith-RetryPSCommand $fakeScriptBlock } | Should Throw
        }

        It "should call Invoke-Command four times" {
            Assert-MockCalled Invoke-Command `
                -Exactly 4 -ParameterFilter `
                { Compare-ScriptBlocks $ScriptBlock $fakeScriptBlock }
        }

        It "should call Start-Sleep three times" {
            Assert-MockCalled Start-Sleep -Exactly 3
        }
    }

    Context "Command is not of ScriptBlock type" {
        $fakeScriptBlock = "fake command"

        Mock Invoke-Command { Throw } -Verifiable
        Mock Start-Sleep { return 0 } -Verifiable

        It "should throw" {
            { ExecRetry $fakeScriptBlock } | Should Throw
        }

        It "should call Invoke-Command zero times" {
            Assert-MockCalled Invoke-Command -Exactly 0
        }

        It "should call Start-Sleep zero times" {
            Assert-MockCalled Start-Sleep -Exactly 0
        }
    }

    Context "Command is valid" {
        $fakeScriptBlock = { "fake-command" }

        Mock Invoke-Command { return 0 } -Verifiable
        Mock Start-Sleep { return 0 } -Verifiable

        It "should throw" {
            { ExecRetry $fakeScriptBlock } | Should Not Throw
        }

        It "should call Invoke-Command one time" {
            Assert-MockCalled Invoke-Command `
                -Exactly 1 -ParameterFilter `
                { Compare-ScriptBlocks $fakeScriptBlock $ScriptBlock }
        }

        It "should call Start-Sleep zero times" {
            Assert-MockCalled Start-Sleep -Exactly 0
        }
    }

    Context "Command is not valid" {
        $fakeScriptBlock = { "fake-command" }

        Mock Invoke-Command { Throw } -Verifiable
        Mock Start-Sleep { return 0 } -Verifiable

        It "should throw" {
            { ExecRetry $fakeScriptBlock } | Should Throw
        }

        It "should call Invoke-Command four times" {
            Assert-MockCalled Invoke-Command `
                -Exactly 4 -ParameterFilter `
                { Compare-ScriptBlocks $fakeScriptBlock $ScriptBlock }
        }

        It "should call Start-Sleep three times" {
            Assert-MockCalled Start-Sleep -Exactly 3
        }
    }

    Context "Not-int MaxRetryCount parameter" {
        $fakeCmd = { "fake cmd" }
        $fakeRetryCount = "three"

        Mock Invoke-Command { return 0 } -Verifiable
        Mock Start-Sleep { return 0 } -Verifiable

        It "should throw" {
            { ExecRetry $fakeCmd $fakeRetryCount } | Should Throw
        }

        It "should call Invoke-Command zero times" {
            Assert-MockCalled Invoke-Command -Exactly 0
        }

        It "should call Start-Sleep zero times" {
            Assert-MockCalled Start-Sleep -Exactly 0
        }
    }

    Context "Not-int RetryInterval parameter" {
        $fakeCmd = { "fake cmd" }
        $fakeRetryInterval = "three"

        Mock Invoke-Command { return 0 } -Verifiable
        Mock Start-Sleep { return 0 } -Verifiable

        It "should throw" {
            { ExecRetry $cmd 4 $fakeRetryInterval } | Should Throw
        }

        It "should call Invoke-Command zero times" {
            Assert-MockCalled Invoke-Command -Exactly 0
        }

        It "should call Start-Sleep zero times" {
            Assert-MockCalled Start-Sleep -Exactly 0
        }
    }

    Context "Negative RetryInterval parameter" {
        $fakeCmd = { "fake cmd" }

        Mock Invoke-Command { Throw } -Verifiable
        Mock Start-Sleep { Throw } -Verifiable

        It "should throw" {
            { ExecRetry $fakeCmd 3 -3 } | Should Throw
        }

        It "should call Invoke-Command one time" {
            Assert-MockCalled Invoke-Command `
                -Exactly 1 -ParameterFilter `
                { Compare-ScriptBlocks $ScriptBlock $fakeCmd }
        }

        It "should call Start-Sleep zero times" {
            Assert-MockCalled Start-Sleep -Exactly 0
        }
    }
}

Describe "Test Exit from Juju" {
    Context "Exit with reboot" {
        $rebootValue = 1001
        $varName = "JUJU_MUST_REBOOT"
        $prevValue = Prepare-MockEnvVariable $varName $rebootValue
        Mock Exit-Basic { return } -Verifiable `
            -ParameterFilter { $ExitCode -eq $rebootValue}

        It "should succeed" {
            { ExitFrom-JujuHook -WithReboot $true } | Should Not Throw
        }

        It "should verify method calls" {
            Assert-MockCalled Exit-Basic -Exactly 1 -ParameterFilter `
                { $ExitCode -eq $rebootValue }
        }

        Restore-EnvironmentVariable $varName $null
    }

    Context "Exit with no reboot" {
        $fakeExitCode = 0
        Mock Exit-Basic { return } -Verifiable `
            -ParameterFilter { $ExitCode -eq $fakeExitCode }

        It "should succeed" {
            { ExitFrom-JujuHook -WithReboot $false } | Should Not Throw
        }

        It "should verify method calls" {
            Assert-MockCalled Exit-Basic -Exactly 1 -ParameterFilter `
                { $ExitCode -eq $fakeExitCode }
        }
    }
}