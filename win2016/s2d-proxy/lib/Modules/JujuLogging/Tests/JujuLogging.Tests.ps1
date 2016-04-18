$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleHome = Split-Path -Parent $here
$moduleRoot = Split-Path -Parent $moduleHome

$modulePath = ${env:PSModulePath}.Split(";")
if(!($moduleRoot -in $modulePath)){
    $env:PSModulePath += ";$moduleRoot"
}

$savedEnv = [System.Environment]::GetEnvironmentVariables()

Import-Module JujuLogging

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

Describe "Test Get-CallStack" {
    It "Should parse ErrorRecord" {
        $err = $null
        try { nonexistingcommand } catch { $err = $_ }
        $r = Get-CallStack $err
        $r | Should Not BeNullOrEmpty
        $r.Count | Should Be 3
        $r[0] | Should Not BeNullOrEmpty
        $r[1] | Should Not BeNullOrEmpty
        $r[2] | Should Not BeNullOrEmpty
    }
    It "Should throw an exception" {
        { Get-CallStack "bogus" } | Should Throw
    }
}

Describe "Test Write-HookTracebackToLog" {
    Mock Get-CallStack -Verifiable -ModuleName JujuLogging {
        return @("first", "second", "third")
    }
    Mock Write-JujuLog -Verifiable -ModuleName JujuLogging {
        Param(
            [Parameter(Mandatory=$true)]
            [string]$Message,
            [ValidateSet("TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")]
            [string]$LogLevel="INFO"
        )
        if($LogLevel -ne "ERROR"){
            Throw "wrong log level"
        }
    }
    It "Should write traceback to log" {
        $err = $null
        try { nonexistingcommand } catch { $err = $_ }
        Write-HookTracebackToLog  -ErrorRecord $err -LogLevel "ERROR"
        Assert-MockCalled Write-JujuLog -Times 4 -ModuleName JujuLogging
        Assert-MockCalled Get-CallStack -Times 1 -ModuleName JujuLogging
    }
}