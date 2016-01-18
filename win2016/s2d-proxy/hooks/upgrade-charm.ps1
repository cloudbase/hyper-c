# #
# # Copyright 2016 Cloudbase Solutions Srl
# #

# $ErrorActionPreference = "Stop"
# Import-Module JujuLoging

# try {
#     Import-Module ADCharmUtils
#     Import-Module S2DUtils

#     Write-JujuInfo "Running relation changed"
#     $script = "$psscriptroot\s2d-relation-changed-real.ps1"
#     $ctx = Get-ActiveDirectoryContext
#     if(!$ctx["adcredentials"]){
#         Write-JujuWarning "Failed to get credentials. Machine not yet in AD?"
#         return
#     }
#     $args = @("-File", "$script")
#     Write-JujuInfo "Running $script"
#     $exitCode = Start-ProcessAsUser -Command "$PShome\powershell.exe" -Arguments ($args -Join " ") -Credential $ctx["adcredentials"][0]["pscredentials"]
#     if($exitCode){
#         Throw "Failed run $script --> $exitCode"
#     }
# } catch {
#     Write-HookTracebackToLog $_
#     exit 1
# }

