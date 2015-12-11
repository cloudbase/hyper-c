#
# Copyright 2014-2015 Cloudbase Solutions Srl
#

$utilsModulePath = Join-Path $PSScriptRoot "utils.psm1"
Import-Module -Force -DisableNameChecking $utilsModulePath

function Check-ContextComplete {
    Param(
        [Parameter(Mandatory=$true)]
        [Hashtable]$Ctx
    )

    if ($Ctx.Count -eq 0) {
        return $false
    }
    foreach ($i in $Ctx.GetEnumerator()) {
        if (!$i.Value) {
            juju-log.exe ("Context key " + $i.Key + " is " + $i.Value)
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
    Param(
        [string]$PeerRelationName
    )

    if (!$PeerRelationName) {
        return ((Get-JujuLocalUnit).Split("/")[1] -eq '0')
    }

    $rids = Get-JujuRelationIds -RelType $PeerRelationName
    if (!$rids) {
        # If there are no peer relation ids, then it means the charm has not
        # completed executing the install/config-changed hooks
        # Only the first unit will have the peer relation ids available,
        # which is enough to consider it as master.
        Write-JujuError "ERROR: Cannot retrieve peer relation ids." `
            -Fatal $false
        return $false
    }
    $unitName = (Get-JujuLocalUnit).Split('/')[0]
    $localUnitId = [int](Get-JujuLocalUnit).Split('/')[1]
    $unitsIds = @($localUnitId)
    foreach ($rid in $rids) {
        $units = Get-JujuRelatedUnits -RelId $rid
        if ($units -eq $false) {
            Write-JujuError "ERROR: Cannot retrieve peer units ids."
        }
        if ($units.Count -eq 0) {
            # no peers deployed
            continue
        }
        $unitsIds += $units | % { [int]$_.Split('/')[1] }
    }
    $unitsIds = $unitsIds | Sort-Object
    $jujuMasterUnit = $unitName + "/" + $unitsIds[0]

    return ((Get-JujuLocalUnit) -eq $jujuMasterUnit)
}

function Execute-Command {
    Param(
        [Parameter(Mandatory=$true)]
        [array]$Cmd
    )
    $cmd += "2>&1"
    $cmdJoined = $Cmd -join " "
    $newCmd = "`$retval = $cmdJoined; return `$retval"
    $scriptBlock = Invoke-StaticMethod -Type "ScriptBlock" -Name "Create" `
                     -Params $newCmd
    try {
        $ret = Invoke-Command -ScriptBlock $scriptBlock
    } catch {
        Write-JujuError $_ -Fatal $true
    }

    if ($LastExitCode) {
       Write-JujuError $ret -Fatal $true
    } else {
        return $ret
    }
}

function Get-JujuCharmConfig {
    Param(
        [string]$Scope=$null
    )

    $cmd = @("config-get.exe", "--format=json")
    if ($Scope -ne $null){
        $cmd += $Scope
    }
    try {
        return Execute-Command -Cmd $cmd | ConvertFrom-Json
    } catch {
        Write-JujuError "Charm configuration retrieval failed."
    }
}

function Get-JujuRelation {
    Param(
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
    try {
        return Execute-Command -Cmd $cmd | ConvertFrom-Json
    } catch {
        return $false
    }
}

function Set-JujuRelation {
    Param(
        [string]$Relation_Id=$null,
        [Hashtable]$Relation_Settings=@{}
    )

    $cmd = @("relation-set.exe")
    if ($Relation_Id) {
        $cmd += "-r"
        $cmd += $Relation_Id
    }
    foreach ($i in $Relation_Settings.GetEnumerator()) {
       $cmd += $i.Name + "='" + $i.Value + "'"
    }
    try {
        return Execute-Command $cmd
    } catch {
        return $false
    }

    return $false
}

function Get-JujuRelationIds {
    Param(
        [string]$RelType=$null
    )

    $cmd = @("relation-ids.exe", "--format=json")
    if ($RelType) {
        $relationType = $RelType
    }else{
        $relationType = Get-JujuRelationType
    }
    if ($relationType) {
        $cmd += $relationType
        try {
            return Execute-Command -Cmd $cmd | ConvertFrom-Json
        } catch {
            return $false
        }
    }
    return $false
}

function Get-JujuRelatedUnits {
    Param(
        [string]$RelId=$null
    )

    $cmd = @("relation-list.exe", "--format=json")
    if ($RelId) {
        $relationId = $RelId
    } else {
        $relationId = Get-JujuRelationId
    }

    if ($relationId){
        $cmd += "-r " 
        $cmd += $relationId
    }

    try {
        $ret = Execute-Command $cmd
        return $ret | ConvertFrom-Json
    } catch {
        return $false
    }

    return $false
}

function Get-JujuRelationForUnit {
    Param(
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
    Param(
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
    Param(
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
    Param(
        [Parameter(Mandatory=$true)]
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
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Attr
    )

    $cmd = @("unit-get.exe", "--format=json", $Attr)
    try {
        return Execute-Command $cmd | ConvertFrom-Json
    } catch {
        return $false
    }
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
    return $ip
}

function Get-JujuRelationParams {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$type,
        [Parameter(Mandatory=$true)]
        [Hashtable]$relationMap
    )

    $ctx = @{ }
    $relations = Get-JujuRelationIds -reltype $type
    foreach($rid in $relations){
        $related_units = Get-JujuRelatedUnits -relid $rid
        if (($related_units -ne $null) -and ($related_units.Count -gt 0)) {
            foreach ($unit in $related_units) {
                foreach ($key in $relationMap.Keys) {
                    $ctx[$key] = Get-JujuRelation -attr $relationMap[$key] `
                                 -rid $rid -unit $unit
                }
                $ctx["context"] = $true
                $ctx["context"] = Check-ContextComplete -ctx $ctx
                if ($ctx["context"]) {
                    return $ctx
                }
            }
        } else {
            foreach ($key in $relationMap.Keys) {
                $ctx[$key] = Get-JujuRelation -attr $relationMap[$key] `
                             -rid $rid
            }
        }
    }

    $ctx["context"] = Check-ContextComplete -ctx $ctx
    return $ctx
}

function Write-JujuLog {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")]
        [string]$LogLevel="INFO"
    )

    $cmd = @("juju-log.exe")
    if($LogLevel -eq "DEBUG") {
        $cmd += "--debug"
    }
    $cmd += $Message
    $cmd += @("-l", $LogLevel.ToUpper())
    & $cmd[0] $cmd[1..$cmd.Length]
}

function Write-JujuDebug {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    Write-JujuLog -Message $Message -LogLevel DEBUG
}

function Write-JujuTrace {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    Write-JujuLog -Message $Message -LogLevel TRACE
}

function Write-JujuInfo {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    Write-JujuLog -Message $Message -LogLevel INFO
}

function Write-JujuWarning {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    Write-JujuLog -Message $Message -LogLevel WARNING
}

function Write-JujuCritical {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    Write-JujuLog -Message $Message -LogLevel CRITICAL
}

function Write-JujuError {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Msg,
        [bool]$Fatal=$true
    )

    Write-JujuLog -Message $Msg -LogLevel ERROR
    if ($Fatal) {
        Throw
    }
}

function ExitFrom-JujuHook {
    Param(
        [switch]$WithReboot
    )

    if ($WithReboot -eq $true) {
        Execute-JujuReboot -Now
    } else {
        Exit-Basic 0
    }
}

function Execute-JujuReboot {
    Param(
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
    Param(
        [string]$Scope=$null
    )

    return Get-JujuCharmConfig -Scope $Scope
}

function relation_get {
    Param(
        [string]$Attr=$null,
        [string]$Unit=$null,
        [string]$Rid=$null
    )

    return Get-JujuRelation -Attr $Attr -Unit $Unit -Rid $Rid
}

function relation_set {
    Param(
        [string]$Relation_Id=$null,
        [Hashtable]$Relation_Settings=@{}
    )

    return Set-JujuRelation -Relation_Id $Relation_Id `
                            -Relation_Settings $Relation_Settings
}

function relation_ids {
    Param(
        [string]$RelType=$null
    )

    return Get-JujuRelationIds -RelType $RelType
}

function related_units {
    Param(
        [string]$RelId=$null
    )

    return Get-JujuRelatedUnits -RelId $RelId
}

function relation_for_unit {
    Param(
        [string]$Unit=$null,
        [string]$Rid=$null
    )

    return Get-JujuRelationForUnit -Unit $Unit -Rid $Rid
}

function relations_for_id {
    Param(
        [string]$RelId=$null
    )

    return Get-JujuRelationsForId -RelId $RelId
}

function relations_of_type {
    Param(
        [string]$RelType=$null
    )

    return Get-JujuRelationsOfType -RelType $RelType
}

function is_relation_made {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Relation,
        [string]$Keys='private-address'
    )

    return Is-JujuRelationCreated -Relation $Relation -Keys $Keys
}

function unit_get {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Attr
    )

    return Get-JujuUnit -Attr $Attr
}

function unit_private_ip {
    return Get-JujuUnitPrivateIP
}


function Get-MainNetadapter {
    Param()

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

function Get-PrimaryAdapterDNSServers {
    Param()

    $netAdapter = Get-MainNetadapter
    $dnsServers = (Get-DnsClientServerAddress -InterfaceAlias $netAdapter `
                  -AddressFamily IPv4).ServerAddresses
    return $dnsServers
}

function Is-JujuPortRangeOpen {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$port
    )

    $cmd = @("opened-ports.exe", "--format=json")
    try {
        $openedPorts = Execute-Command $cmd | ConvertFrom-Json
    } catch {
        return $false
    }

    if (!$openedPorts) {
        return $false
    }
    if (!$port.Contains("/")) {
        $port = "$port/tcp"
    }
    foreach ($i in $openedPorts) {
        if ($i -eq $port) {
            return $true
        }
    }
    return $false
}

function Open-JujuPort {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$port
    )

    $isOpen = Is-JujuPortRangeOpen $port
    if (!$isOpen) {
        $cmd = @("open-port.exe", $port)
        try {
            Execute-Command -Cmd $cmd
            Write-JujuLog "Port opened."
        } catch {
            Write-JujuError "Failed to open port."
        }
    } else {
        Write-JujuLog "Port $port already opened. Skipping..."
    }
}

function Close-JujuPort {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$port
    )

    $isOpen = Is-JujuPortRangeOpen $port
    if ($isOpen) {
        $cmd = @("close-port.exe", $port)
        try {
            Execute-Command -Cmd $cmd
            Write-JujuLog "Port closed."
        } catch {
            Write-JujuError "Failed to close port."
        }
    } else {
        Write-JujuLog "Port $port already closed. Skipping..."
    }
}

function Is-Leader {
    return $true
    $cmd = @("is-leader.exe", "--format=json")
    try {
        return Execute-Command -Cmd $cmd | ConvertFrom-Json
    } catch {
        Write-JujuError "Failed to run is-leader.exe"
    }
}

function Set-LeaderData {
    Param(
        [Parameter(Mandatory=$true)]
        [Hashtable]$params
    )

    $cmd = @("leader-set.exe")

    foreach ($i in $params.GetEnumerator()) {
       $cmd += $i.Name + "=" + $i.Value
    }
    try {
        return Execute-Command $cmd
    } catch {
        return $false
    }

    return $false
}

function Get-LeaderData {
    Param(
        [string]$Attr=$null
    )

    $cmd = @("leader-get.exe", "--format=json")
    if ($Attr) {
        $cmd += $Attr
    }
    try {
        return Execute-Command -Cmd $cmd | ConvertFrom-Json
    } catch {
        return $false
    }
}

function Get-JujuRemoteUnitRelation {
    Param(
        [Parameter(Mandatory=$true)]
        [Hashtable]$relationMap
    )

    $ctx = @{ }
    $rid = Get-JujuRelationId
    $unit = Get-JujuRemoteUnit
    foreach ($key in $relationMap.Keys) {
        $ctx[$key] = Get-JujuRelation -attr $relationMap[$key] `
                     -rid $rid -unit $unit
    }
    $ctx["context"] = $true
    $ctx["context"] = Check-ContextComplete -ctx $ctx

    return $ctx
}

Export-ModuleMember -Function *
