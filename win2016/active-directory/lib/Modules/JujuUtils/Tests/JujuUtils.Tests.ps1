$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleHome = Split-Path -Parent $here
$moduleRoot = Split-Path -Parent $moduleHome

$modulePath = ${env:PSModulePath}.Split(";")
if(!($moduleRoot -in $modulePath)){
    $env:PSModulePath += ";$moduleRoot"
}

$savedEnv = [System.Environment]::GetEnvironmentVariables()

Import-Module JujuUtils

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

Describe "Test Convert-FileToBase64" {
    BeforeEach {
        $p = Join-Path $env:TMP "PesterTesting"
        if((Test-Path $p)) {
            rm -Recurse -Force $p
        }
        mkdir $p
    }
    AfterEach {
        $p = Join-Path $env:TMP "PesterTesting"
        if((Test-Path $p)) {
            rm -Recurse -Force $p
        }
        Clear-Environment
    }
    It "Should convert file contents to base64" {
        $p = Join-Path $env:TMP "PesterTesting"
        $file = Join-Path $p "sample.txt"
        { Set-Content $file "hello world" } | Should Not Throw
        Convert-FileToBase64 -File $file | Should Be "aGVsbG8gd29ybGQNCg=="
    }
    It "Should throw an exception" {
        $p = Join-Path $env:TMP "PesterTesting"
        $file = Join-Path $p "sample.txt"
        { Convert-FileToBase64 -File $file } | Should Throw
    }
    It "Should throw an exception (File too large)" {
        $p = Join-Path $env:TMP "PesterTesting"
        $file = Join-Path $p "sample.txt"
        { [System.IO.file]::writeallbytes($file ,$(New-Object Byte[] $(1025KB))) } | Should Not Throw
        { Convert-FileToBase64 -File $file } | Should Throw
    }
    It "Should convert large file using -Force flag" {
        $p = Join-Path $env:TMP "PesterTesting"
        $file = Join-Path $p "sample.txt"
        { [System.IO.file]::writeallbytes($file ,$(New-Object Byte[] $(1025KB))) } | Should Not Throw
        { Convert-FileToBase64 -File $file -Force} | Should Not Throw
        Convert-FileToBase64 -File $file -Force | Should Be (("A" * 1399467) + "=")
    }
}

Describe "Test Write-FileFromBase64" {
    BeforeEach {
        $p = Join-Path $env:TMP "PesterTesting"
        if((Test-Path $p)) {
            rm -Recurse -Force $p
        }
        mkdir $p
    }
    AfterEach {
        $p = Join-Path $env:TMP "PesterTesting"
        if((Test-Path $p)) {
            rm -Recurse -Force $p
        }
        Clear-Environment
    }
    It "Should write file from base64" {
        $c = "aGVsbG8gd29ybGQNCg=="
        $p = Join-Path $env:TMP "PesterTesting"
        $file = Join-Path $p "sample.txt"
        Write-FileFromBase64 -File $file -Content $c | Should BeNullOrEmpty
        Get-Content $file | Should Be "hello world"
    }
    It "Should throw an exception on invalid base64" {
        $p = Join-Path $env:TMP "PesterTesting"
        $file = Join-Path $p "sample.txt"
        { Write-FileFromBase64 -File $file -Content "bogus" } | Should Throw
    }
}

Describe "Test ConvertTo-Base64" {
    It "Should convert string to base64" {
        $sample = "hello world"
        ConvertTo-Base64 -Content $sample | Should Be "aABlAGwAbABvACAAdwBvAHIAbABkAA=="
    }
    It "Should work with unicode as well" {
        $sample = "ățș"
        ConvertTo-Base64 -Content $sample | Should Be "xACSAcgAOiDIACIh"
    }
}

Describe "Test ConvertFrom-Base64" {
    It "Should convert base64 to string" {
        $sample = "aABlAGwAbABvACAAdwBvAHIAbABkAA=="
        ConvertFrom-Base64 -Content $sample | Should Be "hello world"
    }
    It "Should work with unicode as well" {
        $sample = "xACSAcgAOiDIACIh"
        ConvertFrom-Base64 -Content $sample | Should Be "ățș"
    }
}

Describe "Test Get-EncryptedString" {
    It "Should return an encrypted string" {
        $txt = "hello world"
        $r = Get-EncryptedString -Content $txt
        $r | Should Not BeNullOrEmpty
        $c = ConvertTo-SecureString $r
        $dec = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($c)
        $ret = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($dec)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($dec)
        $ret | Should Be $txt 
    }
}

Describe "Test Get-DecryptedString" {
    It "Should decrypt the string" {
        $txt = "hello world"
        $enc = ConvertTo-SecureString -Force -AsPlainText $txt | ConvertFrom-SecureString
        (Get-DecryptedString $enc) | Should Be $txt
    }
}

Describe "Test Get-UserPath" {
    It "Should return user path" {
        Get-UserPath | Should Be ([System.Environment]::GetEnvironmentVariable("PATH", "User"))
    }
}

Describe "Test Get-SystemPath" {
    It "Should return system path" {
        Get-SystemPath | Should Be ([System.Environment]::GetEnvironmentVariable("PATH", "Machine"))
    }
}

Describe "Test Compare-ScriptBlocks" {
    It "Should return True" {
        Compare-ScriptBlocks { Write-Output "test" } { Write-Output "test" } | Should Be $true
    }
    It "Should return False" {
        Compare-ScriptBlocks { Write-Output "test" } { Write-Output "test2" } | Should Be $false
    }
    It "Should throw an exception (invalid data types)" {
        { Compare-ScriptBlocks { Write-Output "test" } "a" }| Should Throw
        { Compare-ScriptBlocks "a" { Write-Output "test" } }| Should Throw
        { Compare-ScriptBlocks "b" "a" }| Should Throw
    }
}

Describe "Test Compare-Arrays" {
    It "Should return True" {
        Compare-Arrays @(1,2,3) @(1,2,3) | Should Be $true
    }
    It "Should return False" {
        Compare-Arrays @(1,2,3) @(1,2,4) | Should Be $false
    }
}

Describe "Test Compare-HashTables" {
    It "Should return True" {
        Compare-HashTables @{"a"=1;} @{"a"=1;} | Should Be $true
    }
    It "Should return False" {
        Compare-HashTables @{"a"=1;} @{"b"=1;} | Should Be $false
    }
    It "Should return False (nested hashtables)" {
        Compare-HashTables @{"a"=@{"a"=1;};} @{"a"=@{"a"=1;};} | Should Be $false
    }
}

Describe "Test Start-ExternalCommand" {
    AfterEach {
        Clear-Environment
    }
    It "Should Write-Output 1" {
        Start-ExternalCommand -ScriptBlock { Write-Output "test" } | Should Be "test"
    }
    It "Should throw an exception on non zero exit status" {
        { Start-ExternalCommand -ScriptBlock { nonexistingcommand } }| Should Throw
    }
    It "Should return 1 using cmd" {
        Start-ExternalCommand -ScriptBlock { cmd.exe /c echo 1 } | Should Be 1
    }
    It "Should throw on cmd non zero exit status" {
        { Start-ExternalCommand -ScriptBlock { cmd.exe /c "nonexisting > NUL 2>&1" } } | Should Throw
    }
}

Describe "Test Start-ExecuteWithRetry" {
    AfterEach {
        Clear-Environment
    }
    Mock Write-HookTracebackToLog -Verifiable -ModuleName JujuUtils {
        Param (
            [Parameter(Mandatory=$true)]
            [System.Management.Automation.ErrorRecord]$ErrorRecord,
            [string]$LogLevel="ERROR"
        )
        if($LogLevel -ne "WARNING"){
            Throw "invalid status"
        }
    }
    Mock Start-Sleep -Verifiable -ModuleName JujuUtils { return }
    Context "should throw error" {
        It "Should retry 3 times, give up and throw" {
            { Start-ExecuteWithRetry -ScriptBlock {nonexistingcommand} -MaxRetryCount 3 } | Should Throw
            Assert-MockCalled Start-Sleep -Times 3 -ModuleName JujuUtils
            Assert-MockCalled Write-HookTracebackToLog -Times 3 -ModuleName JujuUtils
        }
    }
    Context "Should Work" {
        It "Should succeed on the first go" {
            { Start-ExecuteWithRetry -ScriptBlock { Write-Output 1 } -MaxRetryCount 4 } | Should Not Throw
            Assert-MockCalled Start-Sleep -Times 0 -ModuleName JujuUtils
            Assert-MockCalled Write-HookTracebackToLog -Times 0 -ModuleName JujuUtils
        }
    }
    Context "Should retry 5 times, succeed at last try" {
        Mock Write-Output -Verifiable {
            $r = $env:PesterTestingData
            if ([int]$r -le 4){
                $env:PesterTestingData = ([int]$r + 1)
                Throw "not yet"
            }
            $env:PesterTestingData = ([int]$r + 1)
        }
        It "Should work on the 5th go" {
            $env:PesterTestingData = 0
            { Start-ExecuteWithRetry -ScriptBlock { Write-Output 1 } -MaxRetryCount 5 } | Should Not Throw
            Assert-MockCalled Start-Sleep -Times 4 -ModuleName JujuUtils
            Assert-MockCalled Write-HookTracebackToLog -Times 4 -ModuleName JujuUtils
            Assert-MockCalled Write-Output -Times 5
        }

    }
}

Describe "Test Test-FileIntegrity" {
    BeforeEach {
        $p = Join-Path $env:TMP "PesterTesting"
        if((Test-Path $p)) {
            rm -Recurse -Force $p
        }
        mkdir $p
    }
    AfterEach {
        $p = Join-Path $env:TMP "PesterTesting"
        if((Test-Path $p)) {
            rm -Recurse -Force $p
        }
    }
    It "Should return True" {
        $p = Join-Path $env:TMP "PesterTesting"
        $file = Join-Path $p "test-file.txt"
        Set-Content $file "Hello World"
        $md5 = (Get-FileHash -Algorithm MD5 -Path $file).Hash
        { Test-FileIntegrity -Algorithm MD5 -ExpectedHash $md5 -File $file} | Should Not Throw
        (Test-FileIntegrity -Algorithm MD5 -ExpectedHash $md5 -File $file) | Should Be $true
    }

    It "Should throw an exception" {
        $p = Join-Path $env:TMP "PesterTesting"
        $file = Join-Path $p "test-file.txt"
        Set-Content $file "Hello World"
        $md5 = (Get-FileHash -Algorithm MD5 -Path $file).Hash
        { Test-FileIntegrity -Algorithm MD5 -ExpectedHash "bogus" -File $file} | Should Throw
        ($md5 -eq "bogus") | Should Be $false
    }
}

Describe "Test Get-SanePath" {
    AfterEach {
        Clear-Environment
    }
    It "Should deduplicate path" {
        $p = $env:PATH
        $env:PATH = $env:PATH + ";" + $env:PATH
        ($p -eq $env:PATH) | Should be $false
        $x = Get-SanePath
        $x.Split(";") | Should Be $p.Split(";")
        $x.Split(";").Count | Should Not Be $env:PATH.Split(';').Count
    } 
}

Describe "Test Add-ToUserPath" {
    AfterEach {
        Clear-Environment
    }
    Mock setx -ModuleName JujuUtils -Verifiable {
        return
    }
    Mock Start-ExternalCommand -Verifiable -ModuleName JujuUtils {
        return
    }
    Context "adds one path" {
        It "Should call setx once" {
            Add-ToUserPath -Path $env:TMP | Should BeNullOrEmpty
            ($env:TMP -in $env:PATH.Split(';')) | Should Be $true
            Assert-MockCalled Start-ExternalCommand -Times 1 -ModuleName JujuUtils
        }
    }
    Context "Adds existing path" {
        It "Should return if path already set" {
            $env:PATH += ";$env:TMP"
            Add-ToUserPath -Path $env:TMP | Should BeNullOrEmpty
            Assert-MockCalled Start-ExternalCommand -Times 0 -ModuleName JujuUtils
        }
    }
}

Describe "Test Get-MarshaledObject" {
    It "Should return a base64 encoded string" {
        $obj = @{"Hello"="world";}
        $r = Get-MarshaledObject -Object $obj
        $r | Should Be "SABlAGwAbABvADoAIAB3AG8AcgBsAGQADQAKAA=="
        (ConvertFrom-Base64 $r) | Should Be "Hello: world`r`n"
    }
}

Describe "Test Get-UnmarshaledObject" {
    It "Should return a PSCustomObject" {
        $sample = "SABlAGwAbABvADoAIAB3AG8AcgBsAGQADQAKAA=="
        $r = Get-UnmarshaledObject $sample
        $r.GetType() | Should Be "hashtable"
        $r["Hello"] | Should Be "world"
    }
    It "Should throw an exception on bogus data" {
        { Get-UnmarshaledObject "bogus" } | Should Throw
    }
}

Describe "Test Get-CmdStringFromHashtable" {
    It "Should return a '=' separated key/value string" {
        $params = @{
            "firstname"="John";
            "lastname"="Doe";
            "age"="20";
        }
        Get-CmdStringFromHashtable $params | Should Be "age=20 firstname=John lastname=Doe"
    }
}

Describe "Test Get-EscapedQuotedString" {
    It "Should escape single quotes" {
        $sample = "How's it goin'"
        Get-EscapedQuotedString $sample | Should Be "'How''s it goin'''"
    }
}

Describe "Test Get-PSStringParamsFromHashtable" {
    It "Should return powershell commandlet options" {
        $params = @{
            "firstname"="John";
            "lastname"="Doe";
            "age"="20";
        }
        Get-PSStringParamsFromHashtable $params | Should Be "-age 20 -firstname John -lastname Doe"
    }
}

