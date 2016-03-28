$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleHome = Split-Path -Parent $here

Import-Module $moduleHome\JujuHelper.psm1

Describe 'Calling Invoke-JujuCommand' {
    $workspace = Join-Path $env:TMP ("temp#" + ("{0:d5}" -f (Get-Random)).Substring(0,5))
    BeforeEach {
        if((Test-Path $workspace)){
            rm -Recurse -Force $workspace
        }
        mkdir $workspace
    }
    AfterEach {
        if((Test-Path $workspace)){
            rm -Recurse -Force $workspace
        }
    }
    It 'Should create a directory using cmd' {
        $d = Join-Path $workspace "test"
        $cmd = @("cmd.exe","/c", "mkdir", $d)
        $result = Invoke-JujuCommand -Command $cmd
        $result | Should Not BeNullOrEmpty
        Test-Path $d | Should Be $true
    }

    It "Should throw an exception calling native command" {
        $cmd = @("cmd.exe", "/c", "nonexistingcommand")
        { Invoke-JujuCommand -Command $cmd } | Should Throw
    }

    It "Should create a directory using powershell function" {
        $d = Join-Path $workspace "test"
        $cmd = @("mkdir", $d)
        (Invoke-JujuCommand -Command $cmd) | Should Not BeNullOrEmpty
        Test-Path $d | Should Be $true
    }

    It "Should throw an exception using powershell commands" {
        $d = Join-Path $workspace ("temp#" + ("{0:d5}" -f (Get-Random)).Substring(0,5))
        { mkdir $d } | Should Not Throw
        $cmd = @("mkdir", $d)
        { Invoke-JujuCommand -Command $cmd -ErrorAction Stop} | Should Throw
    }

    It "Should throw on non existent powershell commandlet" {
        $cmd = @("boguscommandlet")
        { Invoke-JujuCommand -Command $cmd -ErrorAction Stop} | Should Throw
    }
}