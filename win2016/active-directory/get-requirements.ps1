#
# Copyright 2014-2015 Cloudbase Solutions Srl
#
$ErrorActionPreference = "Stop"

function Unzip-File {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ZipFile,
        [Parameter(Mandatory=$true)]
        [string]$Destination
    )

    $shellApp = New-Object -ComObject Shell.Application
    $zipFileNs = $shellApp.NameSpace($ZipFile)
    $destinationNS = $shellApp.NameSpace($Destination)
    $destinationNS.CopyHere($zipFileNs.Items(), 0x4)
}

function Download-File {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DownloadLink,
        [Parameter(Mandatory=$true)]
        [string]$DestinationFile
    )

    $webclient = New-Object System.Net.WebClient
    ExecuteWith-Retry -Command {
        $webclient.DownloadFile($DownloadLink, $DestinationFile)
    } -MaxRetryCount 13 -RetryInterval 2
}

function ExecuteWith-Retry {
    param(
        [ScriptBlock]$Command,
        [int]$MaxRetryCount=10,
        [int]$RetryInterval=3,
        [array]$ArgumentList=@()
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    $retryCount = 0
    while ($true) {
        try {
            $res = Invoke-Command -ScriptBlock $Command `
                     -ArgumentList $ArgumentList
            $ErrorActionPreference = $currentErrorActionPreference
            return $res
        } catch [System.Exception] {
            $retryCount++
            if ($retryCount -gt $MaxRetryCount) {
                $ErrorActionPreference = $currentErrorActionPreference
                throw $_.Exception
            } else {
                Write-Error $_.Exception
                Start-Sleep $RetryInterval
            }
        }
    }
}

function Log($message) {
    if ($logEnabled) {
        Write-Host $message
    }
}

function Main() {
    $pesterArchiveRoot = "https://github.com/pester/Pester/archive/"
    $pesterStableCommitId = "3a5e7f5d1bb516f8c18dd3e530ee90e5f12578db"
    $pesterArchive = $pesterArchiveRoot + $pesterStableCommitId + ".zip"

    $tempPesterZip = Join-Path $Env:Temp "pester.zip"
    $pesterModulePath = Join-Path $Env:Temp "Modules"
    $pesterFinalPath = Join-Path $pesterModulePath "Pester"

    if (!(Test-Path $pesterModulePath)) {
        Log "Creating path $pesterModulePath"
        mkdir $pesterModulePath -Force
    }

    Download-File $pesterArchive $tempPesterZip

    Unzip-File $tempPesterZip $pesterModulePath
    Remove-Item -force $tempPesterZip

    if (Test-Path $pesterFinalPath) {
        Log $pesterFinalPath
        Remove-Item -Recurse -Force $pesterFinalPath
    }
    Move-Item -Force (Join-Path $pesterModulePath ("Pester-" + $pesterStableCommitId)) $pesterFinalPath
}

Main
