$utilsModulePath = Join-Path $PSScriptRoot "utils.psm1"
Import-Module -Force -DisableNameChecking $utilsModulePath

function Juju-Error {
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
        Juju-Error -Msg "Failed to restart $ServiceName" -Fatal $false
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

function charm_dir {
    return ${env:CHARM_DIR}
}

function in_relation_hook {
    if (relation_type){
        return $true
    }
    return $false
}

function relation_type {
    return ${env:JUJU_RELATION}
}

function relation_id {
    return ${env:JUJU_RELATION_ID}
}

function local_unit {
    return ${env:JUJU_UNIT_NAME}
}

function remote_unit {
    return ${env:JUJU_REMOTE_UNIT}
}

function service_name {
    return (local_unit).Split("/")[0]
}

function is_master_unit {
    return ((local_unit).Split("/")[1] -eq '0')
}

function RunCommand {
    param(
        [parameter(Mandatory=$true)]
        [array]$Cmd
    )

    $cmdJoined = $Cmd -join " "
    $newCmd = "`$retval = $cmdJoined; if(`$? -eq `$false){return `$false} " + `
                 "; return `$retval"
    $scriptBlock = Invoke-StaticMethod -Type "ScriptBlock" -Name "Create" `
                     -Params $newCmd
    $ret = Invoke-Command -ScriptBlock $scriptBlock
    if ($ret) {
        return $ret
    }
    return $false
}

function charm_config {
    param(
        [string]$Scope=$null
    )

    $cmd = @("config-get.exe", "--format=json")
    if ($Scope -ne $null){
        $cmd += $Scope
    }
    $ret = RunCommand $cmd
    if ($ret) {
        try {
            return $ret | ConvertFrom-Json
        } catch {
            return $false
        }
    }
    return $ret
}

function relation_get {
    param(
        [string]$Attr=$null,
        [string]$Unit=$null,
        [string]$Rid=$null
    )

    $cmd = @("relation-get.exe", "--format=json")
    if ($Rid) {
        $cmd += "-r"
        $cmd += $Rid
    }
    if ($Attr) {
        $cmd += $Attr
    } else {
        $cmd += '-'
    }
    if ($Unit) {
        $cmd += $Unit
    }
    $ret = RunCommand $cmd
    if ($ret) {
        try {
            return $ret | ConvertFrom-Json
        } catch {
            return $false
        }
    }
    return $ret
}

function relation_set {
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

function relation_ids {
    param(
        [string]$RelType=$null
    )

    $cmd = @("relation-ids.exe", "--format=json")
    if ($RelType) {
        $relationType = $RelType
    }else{
        $relationType = relation_type
    }
    if ($relationType) {
        $cmd += $relationType
        try {
            return RunCommand -Cmd $cmd | ConvertFrom-Json
        } catch {
            return $false
        }
    }
    return $false
}

function related_units {
    param(
        [string]$RelId=$null
    )

    $cmd = @("relation-list.exe", "--format=json")
    if ($RelId) {
        $relationId = $RelId
    } else {
        $relationId = relation_id
    }

    if ($relationId){
        $cmd += "-r " 
        $cmd += $relationId
    }
    $ret = RunCommand $cmd
    if ($ret) {
        try{
            return $ret | ConvertFrom-Json
        } catch {
            return $false
        }
    }
    return $ret
}

# Get the json representation of a unit's relation
function relation_for_unit {
    param(
        [string]$Unit=$null,
        [string]$Rid=$null
    )

    if ($Unit){
        $unitName = $Unit
    }else{
        $unitName = remote_unit
    }
    $relation = relation_get -Unit $unitName -Rid $Rid
    foreach ($i in $relation.GetEnumerator()) {
        if ($i.Name.EndsWith("-list")) {
            $relation[$i.Name] = $relation[$i.Name].Split()
        }
    }
    $relation['__unit__'] = $unitName
    return $relation
}

# Get relations of a specific relation ID
function relations_for_id {
    param(
        [string]$RelId=$null
    )

    $relationData = @()
    if ($RelId) {
        $relationId = $RelId
    }else{
        $relationId = relation_ids
    }
    $relatedUnits = related_units -RelId $relationId
    foreach ($i in $relatedUnits) {
        $unitData = relation_for_unit -Unit $i -RelId $relationId
        $unitData['__relid__'] = $relationId
        $relationData += $unitData
    }
    return $relationData
}

# Get relations of a specific type
function relations_of_type {
    param(
        [string]$RelType=$null
    )

    $relation_data = @()
    if ($RelType) {
        $relationType = $RelType
    } else {
        $relationType = relation_type
    }
    $relationIds = relation_ids $relationType
    foreach ($i in $relationIds) {
        $relForId = relations_for_id $i
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
function is_relation_made {
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
    $relationIds = relation_ids -RelType $Relation
    foreach ($i in $relationIds) {
        $relatedU = related_units -RelId $i
        foreach ($j in $relatedU) {
            $temp = @{}
            foreach ($k in $keysArr) {
                $temp[$k] = relation_get -Attr $k -Unit $j -Rid $i
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

# Open a service network port
function open_port {
    param(
        [parameter(Mandatory=$true)]
        [string]$Port,
        [string]$Protocol="TCP"
    )

    $cmd = @("open-port.exe")
    $arg = $Port + "/" + $Protocol
    $cmd += $arg
    return RunCommand $cmd
}

# Close a service network port
function close_port {
    param(
        [parameter(Mandatory=$true)]
        [string]$Port,
        [String]$Protocol="TCP"
    )

    $cmd = @("close-port.exe")
    $arg = $Port + "/" + $Protocol
    $cmd += $arg
    return RunCommand $cmd
}

# Get the unit ID for the remote unit
function unit_get {
    param(
        [parameter(Mandatory=$true)]
        [string]$Attr
    )

    $cmd = @("unit-get.exe", "--format=json", $Attr)
    try {
        return RunCommand $cmd | ConvertFrom-Json
    } catch {
        return $false
    }
}

function unit_private_ip {
    return unit_get -Attr "private-address"
}

function Get-RelationParams {
    param(
        [parameter(Mandatory=$true)]
        [string]$type,
        [parameter(Mandatory=$true)]
        [scriptblock]$script)

    $ctx = @{"context" = $false
            };
    $ctxComplete = $false;
    $relations = relation_ids -reltype $type
    foreach($rid in $relations){
        $related_units = related_units -relid $rid
        if ($related_units -ne $Null -and $related_units.Count -gt 0){
            foreach ($unit in $related_units) {
                $ctx = Invoke-Command -ScriptBlock $script -ArgumentList @($rid,$unit)
                if ($ctx["context"]) {
                    return $ctx
                }
            }
        }
        else{
            $ctx = Invoke-Command -ScriptBlock $script -ArgumentList @($rid)
            if ($ctx["context"]){
                return $ctx
            }
        }
    }

    return $ctx
}

function Get-JujuRelationParams {
    param(
        [parameter(Mandatory=$true)]
        [string]$type,
        [parameter(Mandatory=$true)]
        [Hashtable]$relationMap
    )

    $ctx = @{ "context" = $false }
    $relations = relation_ids -reltype $type
    foreach($rid in $relations){
        $related_units = related_units -relid $rid
        if (($related_units -ne $null) -and ($related_units.Count -gt 0)) {
            foreach ($unit in $related_units) {
                foreach ($key in $relationMap.Keys) {
                    $ctx[$key] = relation_get -attr $relationMap[$key] -rid $rid -unit $unit
                }
                $ctx["context"] = Check-ContextComplete -ctx $ctx
                if ($ctx["context"]) {
                    return $ctx
                }
            }
        }
        else{
            foreach ($key in $relationMap.Keys) {
                $ctx[$key] = relation_get -attr $relationMap[$key] -rid $rid
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

function Make-JujuReboot {
    param(
        [switch]$Now
    )

    if ($Now -eq $true) {
        juju-reboot.exe --now
    } else {
        juju-reboot.exe
    }
}

function ExitFrom-JujuHook {
    param(
        [switch]$WithReboot
    )

    if ($WithReboot -eq $true) {
        Make-JujuReboot -Now
    } else {
        Exit-Basic 0
    }
}


# ALIASES

function Juju-Log {
    param(
        [Parameter(Mandatory=$true)]$arg
    )

    Write-JujuLog $arg
}

Export-ModuleMember -Function *