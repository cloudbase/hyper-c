#
# Copyright 2014-2015 Cloudbase Solutions Srl
#
param($TestModule="CharmMainModule")
$ErrorActionPreference = "Stop"

function Log {
    param($message="")
    Write-Host $message
}

function TestIn-Path {
    param($path=".",
          $pesterFullPath=".\lib\Modules")

    $fullPath = Resolve-Path $path
    $initialPSModulePath = $env:PSModulePath
    $env:PSModulePath = $env:PSModulePath + ";$pesterFullPath"
    $initialExecutionPolicy = Get-ExecutionPolicy
    try {
        Log "Executing tests in the folder $fullPath"
        pushd $fullPath
        Set-ExecutionPolicy Bypass -Scope CurrentUser
        Invoke-Pester
    } catch {
        Log "Tests have failed."
        Log $_.Exception.ToString()
    } finally {
        popd
        Set-ExecutionPolicy $initialExecutionPolicy -Scope CurrentUser
        $env:PSModulePath = $initialPSModulePath
    }
} 

$testTypeCharmHelpersModules = "CharmHelpers"
$charmHelpersTestPath = ".\hooks\Modules\CharmHelpers\Tests"
$charmHelpersPath = ".\hooks\Modules\"
$charmHelpersFullPath = Resolve-Path $charmHelpersPath
$testTypeCharmMainModule = "CharmMainModule"
$mainModuleTestPath = ".\Tests"
$pesterModulePath = Join-Path $Env:Temp "Modules"

if ($TestModule -ne $testTypeCharmHelpersModules -and $TestModule -ne $testTypeCharmMainModule) {
    throw "The test module should be '$testTypeCharmHelpersModules' or '$testTypeCharmMainModule'"
} else {
    if ($TestModule -eq $testTypeCharmHelpersModules) {
        TestIn-Path $charmHelpersTestPath $pesterModulePath
    }
    if ($TestModule -eq $testTypeCharmMainModule) {
        $initialPSModulePath = $env:PSModulePath
        $env:PSModulePath = $env:PSModulePath + ";$charmHelpersFullPath"
        TestIn-Path $mainModuleTestPath $pesterModulePath
        $env:PSModulePath = $initialPSModulePath
    }
}
