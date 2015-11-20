$moduleBasePath = "..\..\Modules\CharmHelpers\"
$binPath = "..\..\Bin\"
$moduleNameBasic = ((Split-Path `
                   -Leaf $MyInvocation.MyCommand.Path).Split(".")[0])
$moduleName = $moduleNameBasic + ".psm1"
$moduleNamePs1 = $moduleNameBasic + ".ps1"
$modulePath = Join-Path $moduleBasePath $moduleName
$moduleCpy = Join-Path $env:Temp $moduleNamePs1

if ((Test-Path $modulePath) -eq $false){
    return
}
else{
    Copy-Item $modulePath $moduleCpy -Force
    . $moduleCpy
}