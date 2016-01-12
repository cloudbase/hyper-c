$ErrorActionPreference = "Stop"

function Invoke-JujuCommand {
    <#
    .SYNOPSIS
     Invoke-JujuCommand is a helper function that accepts a command as an array and returns the output of
     that command as a string. Any error returned by the command will make it throw an exception. This function
     should be used for launching native commands, not powershell commandlets (although that too is possible).
    .PARAMETER Command
     Array containing the command and its arguments
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("Cmd")]
        [array]$Command
    )
    PROCESS {
        $cmdType = (Get-Command $Command[0]).CommandType
        $ret = & $Command[0] $Command[1..$Command.Length] 2>&1

        if($cmdType -eq "Application" -and $LASTEXITCODE){
            Throw ("Failed to run: " + ($Command -Join " "))
        }
        if($ret -and $ret.Length -gt 0){
            return ($ret -as [string])
        }
        return $false
    }
}

function Invoke-FastWebRequest {
    <#
    .SYNOPSIS
    Invoke-FastWebRequest downloads a file form the web via HTTP. This function will work on all modern windows versions,
    including Windows Server Nano. This function also allows file integrity checks using common hashing algorithms:

    "SHA1", "SHA256", "SHA384", "SHA512", "MACTripleDES", "MD5", "RIPEMD160"

    The hash of the file being downloaded should be specified in the Uri itself. See examples.
    .PARAMETER Uri
    The address from where to fetch the file
    .PARAMETER OutFile
    Destination file
    .PARAMETER SkipIntegrityCheck
    Skip file integrity check even if a valid hash is specified in the Uri.

    .EXAMPLE

    # Download file without file integrity check
    Invoke-FastWebRequest -Uri http://example.com/archive.zip -OutFile (Join-Path $env:TMP archive.zip)

    .EXAMPLE
    # Download file with file integrity check
    Invoke-FastWebRequest -Uri http://example.com/archive.zip#md5=43d89a2f6b8a8918ce3eb76227685276 `
                          -OutFile (Join-Path $env:TMP archive.zip)

    .EXAMPLE
    # Force skip file integrity check
    Invoke-FastWebRequest -Uri http://example.com/archive.zip#md5=43d89a2f6b8a8918ce3eb76227685276 `
                          -OutFile (Join-Path $env:TMP archive.zip) -SkipIntegrityCheck:$true
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=0)]
        [System.Uri]$Uri,
        [Parameter(Position=1)]
        [string]$OutFile,
        [switch]$SkipIntegrityCheck=$false
    )
    PROCESS
    {
        if(!([System.Management.Automation.PSTypeName]'System.Net.Http.HttpClient').Type)
        {
            $assembly = [System.Reflection.Assembly]::LoadWithPartialName("System.Net.Http")
        }

        [Environment]::CurrentDirectory = (pwd).Path

        if(!$OutFile) {
            $OutFile = $Uri.PathAndQuery.Substring($Uri.PathAndQuery.LastIndexOf("/") + 1)
            if(!$OutFile) {
                throw "The ""OutFile"" parameter needs to be specified"
            }
        }

        $client = new-object System.Net.Http.HttpClient
        $task = $client.GetAsync($Uri)
        $task.wait()
        $response = $task.Result
        $status = $response.EnsureSuccessStatusCode()

        $outStream = New-Object IO.FileStream $OutFile, Create, Write, None

        try {
            $task = $response.Content.ReadAsStreamAsync()
            $task.Wait()
            $inStream = $task.Result

            $contentLength = $response.Content.Headers.ContentLength

            $totRead = 0
            $buffer = New-Object Byte[] 1MB
            while (($read = $inStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $totRead += $read
                $outStream.Write($buffer, 0, $read);

                if($contentLength){
                    $percComplete = $totRead * 100 / $contentLength
                    Write-Progress -Activity "Downloading: $Uri" -PercentComplete $percComplete
                }
            }

            if(!$SkipIntegrityCheck) {
                $fragment = $Uri.Fragment.Trim('#')
                if (!$fragment){
                    return
                }
                $details = $fragment.Split("=")
                $algorithm = $details[0]
                $hash = $details[1]
                if($algorithm -in @("SHA1", "SHA256", "SHA384", "SHA512", "MACTripleDES", "MD5", "RIPEMD160")){
                    Test-FileIntegrity -File $OutFile -Algorithm $algorithm -ExpectedHash $hash
                } else {
                    Write-JujuWarning "Hash algorithm $algorithm not recognized. Skipping file integrity check."
                }
            }
        }
        finally {
            $outStream.Close()
        }
    }
}