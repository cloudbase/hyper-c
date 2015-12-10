#ps1_sysnative

# Copyright 2014 Cloudbase Solutions Srl
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

$utilsModulePath = Join-Path $PSScriptRoot "utils.psm1"
Import-Module -Force -DisableNameChecking $utilsModulePath

function Write-JujuError {
    param( 
        [parameter(Mandatory=$true)]
        [string]$Msg,
        [bool]$Fatal=$true
    )

    juju-log.exe $Msg
    if ($Fatal) {
        Throw $Msg
    }
}

function Restart-Service {
    param(
        [parameter(Mandatory=$true)]
        [string]$ServiceName
    )

    try {
        Stop-Service $ServiceName
        Start-Service $ServiceName
    } catch {
        Write-JujuError -Msg "Failed to restart $ServiceName" -Fatal $false
    }
}

function Check-ContextComplete {
    param(
        [parameter(Mandatory=$true)]
        [Hashtable]$Ctx
    )

    foreach ($i in $Ctx.GetEnumerator()) {
        if (!$i.Value) {
            return $false
        }
    }
    return $true
}

function Get-JujuCharmDir {
    return ${env:CHARM_DIR}
}

function Has-JujuRelation {
    if (Get-JujuRelationType){
        return $true
    }
    return $false
}

function Get-JujuRelationType {
    return ${env:JUJU_RELATION}
}

function Get-JujuRelationId {
    return ${env:JUJU_RELATION_ID}
}

function Get-JujuLocalUnit {
    return ${env:JUJU_UNIT_NAME}
}

function Get-JujuRemoteUnit {
    return ${env:JUJU_REMOTE_UNIT}
}

function Get-JujuServiceName {
    return (Get-JujuLocalUnit).Split("/")[0]
}

function Is-JujuMasterUnit {
    return ((Get-JujuLocalUnit).Split("/")[1] -eq '0')
}

function RunCommand {
    param(
        [parameter(Mandatory=$true)]
        [array]$Cmd
    )

    $ret = & $Cmd[0] $Cmd[1..$Cmd.Length]
    if($LASTEXITCODE){
        Throw ("Failed to run: " + ($Cmd -Join " "))
    }
    if($ret -and $ret.Length -gt 0){
        return ($ret -as [string])
    }
    return $false
}

function Get-JujuCharmConfig {
    param(
        [string]$Scope=$null
    )
    $jsp = Get-JsonParser

    $cmd = @("config-get.exe", "--format=json")
    #if ($Scope -ne $null){
    #    $cmd += $Scope
    #}
    $ret = RunCommand $cmd
    if ($ret) {
        $data = $jsp::FromJson($ret)
        if ($Scope -ne $null -and $Scope -ne ""){
            return $data.$Scope
        }
        return $data
    }
    return $ret
}

function Get-JujuRelation {
    param(
        [string]$Attr=$null,
        [string]$Unit=$null,
        [string]$Rid=$null
    )
    $jsp = Get-JsonParser
    $cmd = @("relation-get.exe", "--format=json")
    if ($Rid) {
        $cmd += "-r"
        $cmd += $Rid
    }
    $cmd += '-'
    if ($Unit) {
        $cmd += $Unit
    }
    $ret = RunCommand $cmd
    if ($ret) {
        $data = $jsp::FromJson($ret)
        if($Attr) {
            return $data.$Attr
        }
        return $jsp::FromJson($ret)
    }
    return $ret
}

function Set-JujuRelation {
    param(
        [string]$Relation_Id=$null,
        [Hashtable]$Relation_Settings=@{}
    )

    $cmd = @("relation-set.exe")
    if ($Relation_Id) {
        $cmd += "-r"
        $cmd += $Relation_Id
    }
    foreach ($i in $Relation_Settings.GetEnumerator()) {
       $cmd += $i.Name + "=" + $i.Value
    }
    return RunCommand $cmd
}

function Get-JujuRelationIds {
    param(
        [string]$RelType=$null
    )

    $jsp = Get-JsonParser
    $cmd = @("relation-ids.exe", "--format=json")
    if ($RelType) {
        $relationType = $RelType
    }else{
        $relationType = Get-JujuRelationType
    }
    if ($relationType) {
        $cmd += $relationType
        $ret = RunCommand -Cmd $cmd
        return ($jsp::FromJson($ret)).array0
    }
    return $false
}

function Get-JujuRelatedUnits {
    param(
        [string]$RelId=$null
    )
    
    $jsp = Get-JsonParser
    $cmd = @("relation-list.exe", "--format=json")
    if ($RelId) {
        $relationId = $RelId
    } else {
        $relationId = Get-JujuRelationId
    }

    if ($relationId){
        $cmd += "-r" 
        $cmd += $relationId
    }
    $ret = RunCommand $cmd
    if ($ret) {
        return ($jsp::FromJson($ret)).array0
    }
    return $ret
}

function Get-JujuRelationForUnit {
    param(
        [string]$Unit=$null,
        [string]$Rid=$null
    )

    if ($Unit){
        $unitName = $Unit
    }else{
        $unitName = Get-JujuRemoteUnit
    }
    $relation = Get-JujuRelation -Unit $unitName -Rid $Rid
    foreach ($i in $relation.GetEnumerator()) {
        if ($i.Name.EndsWith("-list")) {
            $relation[$i.Name] = $relation[$i.Name].Split()
        }
    }
    $relation['__unit__'] = $unitName
    return $relation
}

# Get relations of a specific relation ID
function Get-JujuRelationForId {
    param(
        [string]$RelId=$null
    )

    $relationData = @()
    if ($RelId) {
        $relationId = $RelId
    }else{
        $relationId = Get-JujuRelationIds
    }
    $relatedUnits = Get-JujuRelatedUnits -RelId $relationId
    foreach ($i in $relatedUnits) {
        $unitData = Get-JujuRelationForUnit -Unit $i -RelId $relationId
        $unitData['__relid__'] = $relationId
        $relationData += $unitData
    }
    return $relationData
}

function Get-JujuRelationsOfType {
    param(
        [string]$RelType=$null
    )

    $relation_data = @()
    if ($RelType) {
        $relationType = $RelType
    } else {
        $relationType = Get-JujuRelationType
    }
    $relationIds = Get-JujuRelationIds $relationType
    foreach ($i in $relationIds) {
        $relForId = Get-JujuRelationsForId $i
        foreach ($j in $relForId) {
            $j['__relid__'] = $i
            $relationData += $j
        }
    }
    return $relationData
}

# Determine whether a relation is established by checking for
# presence of key(s).  If a list of keys is provided, they
# must all be present for the relation to be identified as made
function Is-JujuRelationCreated {
    param(
        [parameter(Mandatory=$true)]
        [string]$Relation,
        [string]$Keys='private-address'
    )

    $keysArr = @()
    if ($Keys.GetType().Name -eq "string") {
        $keysArr += $Keys
    } else {
        $keysArr = $Keys
    }
    $relationIds = Get-JujuRelationIds -RelType $Relation
    foreach ($i in $relationIds) {
        $relatedU = Get-JujuRelatedUnits -RelId $i
        foreach ($j in $relatedU) {
            $temp = @{}
            foreach ($k in $keysArr) {
                $temp[$k] = Get-JujuRelation -Attr $k -Unit $j -Rid $i
            }
            foreach ($val in $temp.GetEnumerator()) {
                if ($val.Value -eq $false) {
                    return $false
                }
            }
        }
    }
    return $true
}

function Get-JujuUnit {
    param(
        [parameter(Mandatory=$true)]
        [string]$Attr
    )

    $jsp = Get-JsonParser
    $cmd = @("unit-get.exe", "--format=json", $Attr)
    $ret = RunCommand $cmd
    return $ret.Trim('"')
    #return $jsp::FromJson($ret)
}

function Validate-IP {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ip
    )
    return ($ip -as [ipaddress]) -as [bool]
}

function Get-JujuUnitPrivateIP {
    $addr = Get-JujuUnit -Attr "private-address"
    if((Validate-IP $addr)){
        return $addr
    }
    $ip = ExecuteWith-Retry {
        ipconfig /flushdns | Out-Null
        if($LASTEXITCODE){
            juju-log.exe "failed to flush dns"
            Throw "Failed to flush DNS"
        }
        $ip = ([system.net.dns]::GetHostAddresses($addr))[0].ipaddresstostring
        return $ip 
    }
    if(!$ip){
        Throw "Could not get private address"
    }
    juju-log.exe ">>> Returning $ip"
    return $ip
}

function Get-JujuRelationParams {
    param(
        [parameter(Mandatory=$true)]
        [string]$type,
        [parameter(Mandatory=$true)]
        [Hashtable]$relationMap
    )

    $ctx = @{ "context" = $true }
    $relations = Get-JujuRelationIds -reltype $type
    foreach($rid in $relations){
        $related_units = Get-JujuRelatedUnits -relid $rid
        if (($related_units -ne $null) -and ($related_units.Count -gt 0)) {
            foreach ($unit in $related_units) {
                foreach ($key in $relationMap.Keys) {
                    $ctx[$key] = Get-JujuRelation -attr $relationMap[$key] -rid $rid -unit $unit
                }
                $ctx["context"] = Check-ContextComplete -ctx $ctx
                if ($ctx["context"]) {
                    return $ctx
                }
            }
        }
        else{
            foreach ($key in $relationMap.Keys) {
                $ctx[$key] = Get-JujuRelation -attr $relationMap[$key] -rid $rid
            }
            $ctx["context"] = Check-ContextComplete -ctx $ctx
            if ($ctx["context"]){
                return $ctx
            }
        }
    }

    return $ctx
}

function Write-JujuLog {
    param(
        [Parameter(Mandatory=$true)]
        $Message
    )

    juju-log.exe $Message
}

function Execute-JujuReboot {
    param(
        [switch]$Now
    )

    if ($Now -eq $true) {
        juju-reboot.exe --now
    } else {
        juju-reboot.exe
    }
}

#Python/Bash like function aliases


function charm_dir {
    return Get-JujuCharmDir
}

function in_relation_hook {
    return Has-JujuRelation
}

function relation_type {
    return Get-JujuRelationType
}

function relation_id {
    return Get-JujuRelationId
}

function local_unit {
    return Get-JujuLocalUnit
}

function remote_unit {
    return Get-JujuRemoteUnit
}

function service_name {
    return Get-JujuServiceName
}

function is_master_unit {
    return Is-JujuMasterUnit
}

function charm_config {
    param(
        [string]$Scope=$null
    )

    return Get-JujuCharmConfig -Scope $Scope
}

function relation_get {
    param(
        [string]$Attr=$null,
        [string]$Unit=$null,
        [string]$Rid=$null
    )

    return Get-JujuRelation -Attr $Attr -Unit $Unit -Rid $Rid
}

function relation_set {
    param(
        [string]$rid=$null,
        [Hashtable]$relation_settings=@{}
    )

    return Set-JujuRelation -Relation_Id $rid `
                            -Relation_Settings $Relation_Settings
}

function relation_ids {
    param(
        [string]$RelType=$null
    )

    return Get-JujuRelationIds -RelType $RelType
}

function related_units {
    param(
        [string]$RelId=$null
    )

    return Get-JujuRelatedUnits -RelId $RelId
}

function relation_for_unit {
    param(
        [string]$Unit=$null,
        [string]$Rid=$null
    )

    return Get-JujuRelationForUnit -Unit $Unit -Rid $Rid
}

function relations_for_id {
    param(
        [string]$RelId=$null
    )

    return Get-JujuRelationsForId -RelId $RelId
}

function relations_of_type {
    param(
        [string]$RelType=$null
    )

    return Get-JujuRelationsOfType -RelType $RelType
}

function is_relation_made {
    param(
        [parameter(Mandatory=$true)]
        [string]$Relation,
        [string]$Keys='private-address'
    )

    return Is-JujuRelationCreated -Relation $Relation -Keys $Keys
}

function unit_get {
    param(
        [parameter(Mandatory=$true)]
        [string]$Attr
    )

    return Get-JujuUnit -Attr $Attr
}

function unit_private_ip {
    return Get-JujuUnitPrivateIP
}


function Get-MainNetadapter {
    $unit_ip = unit_private_ip
    if (!$unit_ip) {
        Throw "Failed to get unit IP"
    }

    $iface = Get-NetIPAddress | Where-Object `
        { $_.IPAddress -match $unit_ip -and $_.AddressFamily -eq "IPv4" }
    if ($iface) {
        $ifaceAlias = $iface.InterfaceAlias
        if ($ifaceAlias) {
            return $ifaceAlias
        } else {
            Throw "Interface alias is null."
        }
    } else {
        Throw "Failed to find primary interface."
    }
}

Export-ModuleMember -Function *
