# Copyright 2016 Cloudbase Solutions Srl
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