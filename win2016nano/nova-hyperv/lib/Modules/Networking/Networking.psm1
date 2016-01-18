$ErrorActionPreference = "Stop"

function Invoke-DHCPRenew {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Microsoft.Management.Infrastructure.CimInstance]$NetAdapter
    )
    PROCESS {
        if($NetAdapter.CreationClassName -ne "MSFT_NetAdapter"){
            Throw ("Invalid object class: {0}" -f $NetAdapter.CreationClassName)
        }
        $ifIndex = $NetAdapter.ifIndex

        $interface = Get-CimInstance -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $ifIndex}
        if($interface.IPEnabled -eq $false) {
            Throw "IP subsystem not enabled on this interface"
        } 
        if ($interface.DHCPEnabled -eq $false) {
            Throw "Interface not configured for DHCP"
        }
        $code = Invoke-CimMethod -CimInstance $interface -MethodName "RenewDHCPLease"
        return $code.ReturnValue
    }
}

function Invoke-DHCPRelease {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Microsoft.Management.Infrastructure.CimInstance]$NetAdapter
    )
    PROCESS {
        if($NetAdapter.CreationClassName -ne "MSFT_NetAdapter"){
            Throw ("Invalid object class: {0}" -f $NetAdapter.CreationClassName)
        }
        $ifIndex = $NetAdapter.ifIndex

        $interface = Get-CimInstance -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $ifIndex}
        if($interface.IPEnabled -eq $false) {
            return 0
        } 
        if ($interface.DHCPEnabled -eq $false) {
            Throw "Interface not configured for DHCP"
        }
        $code = Invoke-CimMethod -CimInstance $interface -MethodName "ReleaseDHCPLease"
        return $code.ReturnValue
    }
}

Export-ModuleMember -Function * -Alias *