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

Import-Module JujuLogging

function Convert-FileToBase64{
    <#
    .SYNOPSIS
    This powershell commandlet converts an entire file, byte by byte to base64 and returns the string.

    WARNING: Do not use this to convert large files, as it reads the entire contents of a file
    into memory. This function may be useful to transfer small amounts of data over a relation
    without having to worry about encoding or escaping, preserving at the same time any
    binary info/special
    characters.
    .PARAMETER File
    The path to the file you want to convert. It works for any type of file. Take great care not to
    try and convert large files.
    #>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true)]
        [string]$File,
        [switch]$Force
    )
    PROCESS {
        if(!(Test-Path $File)) {
            Throw "No such file: $File"
        }
        $f = (Get-Item $File)
        if($f.Length -gt 1MB -and !$Force) {
            Throw "File is too big to convert (> 1MB). Use -Force to do it anyway..."
        }
        $ct = [System.IO.File]::ReadAllBytes($File)
        $b64 = [Convert]::ToBase64String($ct)
        return $b64
    }
}

function Write-FileFromBase64 {
    <#
    .SYNOPSIS
    Helper function that converts base64 to bytes and then writes that stream to a file.
    .PARAMETER File
    Destination file to write to.
    .PARAMETER Content
    Base64 encoded string
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$File,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Content
    )
    PROCESS {
        $bytes = [Convert]::FromBase64String($Content)
        [System.IO.File]::WriteAllBytes($File, $bytes)
    }
}

function ConvertTo-Base64 {
    <#
    .SYNOPSIS
    Convert string to its base64 representation
    .PARAMETER Content
    String to be converted to base64
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Content
    )
    PROCESS {
        $x = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Content))
        return $x
    }
}

function ConvertFrom-Base64 {
    <#
    .SYNOPSIS
    Convert base64 back to string
    .PARAMETER Content
    Base64 encoded string
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Content
    )
    PROCESS {
        $x = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($content))
        return $x
    }
}

function Get-EncryptedString {
    <#
    .SYNOPSIS
    This is just a helper function that converts a plain string to a secure string and returns the encrypted
    string representation.
    .PARAMETER Content
    The string you want to encrypt
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Content
    )
    PROCESS {
        $ret = ConvertTo-SecureString -AsPlainText -Force $Content | ConvertFrom-SecureString
        return $ret
    }
}

function Get-DecryptedString {
    <#
    .SYNOPSIS
    Decrypt a securestring back to its plain text representation.
    .PARAMETER Content
    The encrypted content to decrypt.
    .NOTES
    This function is only meant to be used with encrypted strings, not binary.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Content
    )
    PROCESS {
        $c = ConvertTo-SecureString $Content
        $dec = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($c)
        $ret = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($dec)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($dec)
        return $ret
    }
}

function Get-UserPath {
    <#
    .SYNOPSIS
    Returns the $env:PATH variable for the current user.
    #>
    PROCESS {
        return [System.Environment]::GetEnvironmentVariable("PATH", "User")
    }
}

function Get-SystemPath {
    <#
    .SYNOPSIS
    Returns the system wide default $env:PATH.
    #>
    PROCESS {
        return [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
    }
}

function Compare-ScriptBlocks {
    <#
    .SYNOPSIS
    Compare two script blocks
    .PARAMETER ScriptBlock1
    First script block
    .PARAMETER ScriptBlock2
    Second script block
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("scrBlock1")]
        [System.Management.Automation.ScriptBlock]$ScriptBlock1,
        [Parameter(Mandatory=$true)]
        [Alias("scrBlock2")]
        [System.Management.Automation.ScriptBlock]$ScriptBlock2
    )
    PROCESS {
        $sb1 = $ScriptBlock1.ToString()
        $sb2 = $ScriptBlock2.ToString()
        return ($sb1.CompareTo($sb2) -eq 0)
    }
}

function Compare-Arrays {
    <#
    .SYNOPSIS
    Compare two arrays. Returns a boolean value that determines whether or not the arrays are equal.
    .PARAMETER Array1
    First array to compare
    .PARAMETER Array2
    Second array to compare
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("arr1")]
        [System.Object[]]$Array1,
        [Parameter(Mandatory=$true)]
        [Alias("arr2")]
        [System.Object[]]$Array2
    )
    PROCESS {
        return (((Compare-Object $Array1 $Array2).InputObject).Length -eq 0)
    }
}

function Compare-HashTables {
    <#
    .SYNOPSIS
    Compare two arrays. Returns a boolean value that determines whether or not the arrays are equal. This function only works for flat hashtables.
    .PARAMETER Array1
    First array to compare
    .PARAMETER Array2
    Second array to compare
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("tab1")]
        [HashTable]$HashTable1,
        [Parameter(Mandatory=$true)]
        [Alias("tab2")]
        [HashTable]$HashTable2
    )
    PROCESS {
        if ($HashTable1.Count -ne $HashTable2.Count) {
            return $false
        }
        foreach ($i in $HashTable1.Keys) {
            if (($HashTable2.ContainsKey($i) -eq $false) -or ($HashTable1[$i] -ne $HashTable2[$i])) {
                return $false
            }
        }
        return $true
    }
}

function Start-ExternalCommand {
    <#
    .SYNOPSIS
    Helper function to execute a script block and throw an exception in case of error.
    .PARAMETER ScriptBlock
    Script block to execute
    .PARAMETER ArgumentList
    A list of parameters to pass to Invoke-Command
    .PARAMETER ErrorMessage
    Optional error message. This will become part of the exception message we throw in case of an error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Alias("Command")]
        [ScriptBlock]$ScriptBlock,
        [array]$ArgumentList=@(),
        [string]$ErrorMessage
    )
    PROCESS {
        if($LASTEXITCODE){
            # Leftover exit code. Some other process failed, and this
            # function was called before it was resolved.
            # There is no way to determine if the ScriptBlock contains
            # a powershell commandlet or a native application. So we clear out
            # the LASTEXITCODE variable before we execute. By this time, the value of
            # the variable is not to be trusted for error detection anyway.
            $LASTEXITCODE = ""
        }
        $res = Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
        if ($LASTEXITCODE) {
            if(!$ErrorMessage){
                Throw ("Command exited with status: {0}" -f $LASTEXITCODE)
            }
            throw ("{0} (Exit code: $LASTEXITCODE)" -f $ErrorMessage)
        }
        return $res
    }
}

function Start-ExecuteWithRetry {
    <#
    .SYNOPSIS
    In some cases a command may fail several times before it succeeds, be it because of network outage, or a service
    not being ready yet, etc. This is a helper function to allow you to execute a function or binary a number of times
    before actually failing.

    Its important to note, that any powershell commandlet or native command can be executed using this function. The result
    of that command or powershell commandlet will be returned by this function.

    Only the last exception will be thrown, and will be logged with a log level of ERROR.
    .PARAMETER ScriptBlock
    The script block to run.
    .PARAMETER MaxRetryCount
    The number of retries before we throw an exception.
    .PARAMETER RetryInterval
    Number of seconds to sleep between retries.
    .PARAMETER ArgumentList
    Arguments to pass to your wrapped commandlet/command.

    .EXAMPLE
    # If the computer just booted after the machine just joined the domain, and your charm starts running,
    # it may error out until the security policy has been fully applied. In the bellow example we retry 10
    # times and wait 10 seconds between retries before we give up. If successful, $ret will contain the result
    # of Get-ADUser. If it does not, an exception is thrown. 
    $ret = Start-ExecuteWithRetry -ScriptBlock {
        Get-ADUser testuser
    } -MaxRetryCount 10 -RetryInterval 10
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Alias("Command")]
        [ScriptBlock]$ScriptBlock,
        [int]$MaxRetryCount=10,
        [int]$RetryInterval=3,
        [array]$ArgumentList=@()
    )
    PROCESS {
        $currentErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"

        $retryCount = 0
        while ($true) {
            try {
                $res = Invoke-Command -ScriptBlock $ScriptBlock `
                         -ArgumentList $ArgumentList
                $ErrorActionPreference = $currentErrorActionPreference
                return $res
            } catch [System.Exception] {
                $retryCount++
                if ($retryCount -gt $MaxRetryCount) {
                    $ErrorActionPreference = $currentErrorActionPreference
                    throw
                } else {
                    if($_) {
                        Write-HookTracebackToLog $_ -LogLevel WARNING
                    }
                    Start-Sleep $RetryInterval
                }
            }
        }
    }
}

function Get-SanePath {
    <#
    .SYNOPSIS
    There are some situations in which the $env:PATH variable may contain duplicate paths. This function returns
    a sanitized $env:PATH without any duplicates.
    #>
    PROCESS {
        $path = $env:PATH
        $arrayPath = $path.Split(';')
        $arrayPath = $arrayPath | Select-Object -Unique
        $newPath = $arrayPath -join ';'
        return $newPath
    }
}

function Add-ToUserPath {
    <#
    .SYNOPSIS
    Permanently add an additional path to $env:PATH for current user, and also set the current $env:PATH to the new value.
    .PARAMETER Path
    Extra path to add to $env:PATH
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    PROCESS {
        $currentPath = Get-SanePath
        if ($Path -in $env:Path.Split(';')){
            return
        }
        $newPath = $currentPath + ";" + $Path
        Start-ExternalCommand -Command {
            setx PATH $newPath
        } -ErrorMessage "Failed to set user path"
        $env:PATH = $newPath
    }
}

function Get-MarshaledObject {
    <#
    .SYNOPSIS
    Get a base64 encoded representation of a yaml encoded powershell object. "Why?" you might ask. Well, in some cases you
    may need to send more complex information through a relation to another charm. This function allows you to send simple
    powershell objects (hashtables, arrays, etc) as base64 encoded strings. This function first encodes them to yaml, and
    then to base64 encoded strings.

    This also allows us to send the same information to any kind of charm that can unmarshal yaml to a native type (say python).
    .PARAMETER Object

    .NOTES
    ConvertTo-Base64 uses utf-16-le encoding for objects

    .EXAMPLE

    $obj = @{"Hello"="world";}
    Get-MarshaledObject -Object $obj
    ewANAAoAIAAgACAAIAAiAEgAZQBsAGwAbwAiADoAIAAgACIAdwBvAHIAbABkACIADQAKAH0A
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("obj")]
        $Object
    )
    PROCESS {
        $encoded = $Object | ConvertTo-Yaml
        $b64 = ConvertTo-Base64 $encoded
        return $b64
    }
}

function Get-UnmarshaledObject {
    <#
    .SYNOPSIS
    Try to convert a base64 encoded string back to a powershell object.
    .PARAMETER Object
    The base64 encoded representation of the object we want to unmarshal. 
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("obj")]
        [string]$Object
    )
    PROCESS {
        $decode = ConvertFrom-Base64 $Object
        $ret = $decode | ConvertFrom-Yaml
        return $ret
    }
}

function Get-CmdStringFromHashtable {
    <#
    .SYNOPSIS
    Convert a hashtable to a command line key/value string. Values for hashtable keys must be string or int. The result is usually suitable for native commands executed via cmd.exe.
    .PARAMETER Parameters
    hashtable containing command line parameters.

    .EXAMPLE
    $params = @{
        "firstname"="John";
        "lastname"="Doe";
        "age"="20";
    }
    Get-CmdStringFromHashtable $params
    age=20 firstname=John lastname=Doe
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Alias("params")]
        [Hashtable]$Parameters
    )
    PROCESS {
        $args = ""
        foreach($i in $Parameters.GetEnumerator()) {
            $args += $i.key + "=" + $i.value + " "
        }
        return $args.Trim()
    }
}

function Get-EscapedQuotedString {
    [CmdletBinding()]
    param(
        [string]$value
    )
    PROCESS {
        return "'" + $value.Replace("'", "''") + "'"
    }
}

function Get-PSStringParamsFromHashtable {
    <#
    .SYNOPSIS
    Convert a hashtable to a powershell command line options. Values can be any powershell objects.
    .PARAMETER Parameters
    hashtable containing command line parameters.

    .EXAMPLE
    $params = @{
        "firstname"="John";
        "lastname"="Doe";
        "age"="20";
    }
    Get-PSStringParamsFromHashtable $params
    -age 20 -firstname John -lastname Doe
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Hashtable]$params
    )
    PROCESS {
        $args = @()
        foreach($i in $params.GetEnumerator()) {
            $args += @(("-" + $i.key), $i.value)
        }

        return $args -join " "
    }
}

Export-ModuleMember -Function * -Alias *
