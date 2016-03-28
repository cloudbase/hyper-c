#
# Copyright 2016 Cloudbase Solutions Srl
#
Param (
    [Parameter(Mandatory=$true)]
    [string]$Hook
)

$ErrorActionPreference = "Stop"
Import-Module JujuLogging

try {
    Import-Module ADCharmUtils
    Import-Module JujuWindowsUtils

    $ctx = Get-ActiveDirectoryContext
    if(!$ctx["adcredentials"]){
        # Not a fatal error
        Write-JujuWarning "Failed to get credentials. Machine not yet in AD?"
        return
    }
    $args = @("-File", "$Hook")
    Write-JujuInfo "Running $Hook"
    $exitCode = Start-ProcessAsUser -Command "$PShome\powershell.exe" `
                                    -Arguments $args `
                                    -Credential $ctx["adcredentials"][0]["pscredentials"] `
                                    -LoadUserProfile $false
    $LEVEL = "INFO"
    if($exitCode) {
        $LEVEL = "ERROR"
    }
    Write-JujuLog -LogLevel $LEVEL -Message "Script $Hook returned: $exitCode"
    exit $exitCode
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
