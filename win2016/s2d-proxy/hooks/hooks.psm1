#
# Copyright 2014 Cloudbase Solutions SRL
#

$env:PSModulePath += ";$env:CHARM_DIR\lib\Modules"
$ErrorActionPreference = "Stop"

Import-Module -Force -DisableNameChecking CharmHelpers
$clusterName = charm_config -scope "cluster-name"
$storagePool = charm_config -scope "storage-pool"
$volumeName = charm_config -scope "volume-name"
$staticAddress = charm_config -scope "static-address"
$fqdn = (gcim Win32_ComputerSystem).Domain.ToLower()

function Flush-DNS {
    ipconfig /flushdns
    if($LASTEXITCODE){
        Throw "Failed to flush dns"
    }
}

function Create-S2DCluster {
    Param(
        [Parameter(Mandatory=$true)]
        [array]$nodes
    )
    if(!$staticAddress){
        Throw "Static address was not set in charm config and is required"
    }
    $cluster = Get-Cluster -Name $clusterName -Domain $fqdn -ErrorAction SilentlyContinue
    if(!$cluster){
        juju-log.exe "Running create cluster"
        New-Cluster -Name $clusterName -Node $nodes -NoStorage -StaticAddress $staticAddress.Split(" ")
        Flush-DNS
    }
    return $true
}

function Add-NodesToCluster {
    Param(
        [Parameter(Mandatory=$true)]
        [array]$nodes
    )
    Flush-DNS
    try {
        $cluster = Get-Cluster -Name $clusterName -Domain $fqdn
    }catch{
        juju-log.exe "Warning: Cluster not initialized"
        juju-log.exe "Delaying Add-ClusterNode"
        return $false
    }
    foreach ($node in $nodes) {
        $isAdded = Get-ClusterNode -Name $node.ToString() -Cluster ($clusterName + "." + $fqdn) -ErrorAction SilentlyContinue
        if (!$isAdded) {
            Add-ClusterNode -Name $node.ToString() -Cluster $clusterName -NoStorage
        }
    }
    return $true
}

function Enable-S2D {
    try {
        $cluster = Get-Cluster -Name $clusterName -Domain $fqdn
    }catch{
        juju-log.exe "Warning: Cluster not initialized"
        juju-log.exe "Delaying Enable-ClusterStorageSpacesDirect"
        return $false
    }
    if($cluster.DASModeEnabled -eq 1){
        return $true
    }
    Enable-ClusterStorageSpacesDirect -Cluster ($clusterName + "." + $fqdn)
    return $true
}

function Create-StoragePool {
    Flush-DNS
    $node = (Get-ClusterNode -Cluster $clusterName).name[0]
    $session = New-CimSession -ComputerName $node

    if (!$session){
        Throw "Failed to get CimSession"
    }
    $storagePool = Get-StoragePool -FriendlyName $storagePool -CimSession $session -ErrorAction SilentlyContinue
    if($storagePool){
        return $true
    }
    $storagePool = charm_config -scope "storage-pool"
    $storageSubsystem = Get-StorageSubSystem  -Name ($clusterName + "." + $fqdn) -CimSession $session
    
    $physicalDisks = $storageSubsystem | Get-PhysicalDisk -CimSession $session
    juju-log.exe "Creating storage pool $storagePool"
    New-StoragePool -StorageSubSystemName ($clusterName + "." + $fqdn) `
                    -FriendlyName $storagePool -WriteCacheSizeDefault 0 `
                    -ProvisioningTypeDefault Fixed -ResiliencySettingNameDefault Mirror `
                    -PhysicalDisk $physicalDisks -CimSession $session
    Remove-CimSession $session
}

function Create-S2DVolume {
    $node = (Get-ClusterNode -Cluster $clusterName).name[0]
    $session = New-CimSession -ComputerName $node

    $exists = Get-Volume -CimSession $session -FileSystemLabel $volumeName -ErrorAction SilentlyContinue
    if ($exists){
        return $true
    }
    $storagePool = charm_config -scope "storage-pool"

    $pool = Get-StoragePool -CimSession $session -FriendlyName $storagePool
    # TODO: This is not correnct. Need to find the proper way to do this
    $maxSize = ($pool.Size/2-$pool.AllocatedSize)
    $vol = New-Volume -StoragePool $pool -FriendlyName $volumeName -PhysicalDiskRedundancy 1 -FileSystem CSVFS_REFS -Size $maxSize -CimSession $session

    Set-FileIntegrity $vol.Path -Enable $false -CimSession $session
    Remove-CimSession $session
    return $true
}

function Enable-ScaleOutFileServer {
    $node = (Get-ClusterNode -Cluster $clusterName).name[0]
    $session = New-CimSession -ComputerName $node

    $scaleoutname = charm_config -scope "scaleout-name"
    $exists = Get-StorageFileServer -CimSession $session -FriendlyName $scaleoutname -ErrorAction SilentlyContinue
    if($exists){
        return $true
    }
    New-StorageFileServer -StorageSubSystemName ($clusterName + "." + $fqdn) `
                          -FriendlyName $scaleoutname `
                          -HostName $scaleoutname -Protocols SMB -CimSession $session
    Remove-CimSession $session
    return $true
}

function Broadcast-VolumeCreated {
    $node = (Get-ClusterNode -Cluster $clusterName).name[0]
    $session = New-CimSession -ComputerName $node
    
    $virtualDisk = Get-VirtualDisk -CimSession $session -FriendlyName $volumeName -ErrorAction SilentlyContinue
    if(!$virtualDisk){
        juju-log.exe "Volume not created yet"
        return $false
    }
    $path = ($virtualDisk | Get-Disk | Get-Partition | Where-Object {$_.Type -eq "Basic"}).AccessPaths[0]
    $relation_set = @{
        "volumepath"=$path.Replace('\', '/');
    }

    $rids = relation_ids -reltype "s2d"
    foreach ($rid in $rids){
        $ret = relation_set -relation_id $rid -relation_settings $relation_set
        if ($ret -eq $false){
            Write-JujuError "Failed to set s2d relation" -Fatal $false
        }
    }
}

function Run-S2DRelationChanged {
    $isInDomain = (gcim Win32_ComputerSystem).PartOfDomain

    if (!$isInDomain){
        juju-log.exe "Not yet in any domain. Skipping"
        return $false
    }
    
    $relations = relation_ids -reltype 's2d'
    $minimumUnits = charm_config -scope "minimum-nodes"

    $nodes = @()

    foreach($rid in $relations){
        juju-log.exe "Getting related units for: $rid"
        $related_units = related_units -relid $rid
        juju-log.exe "Found related units: $related_units"
        foreach($unit in $related_units){
            $computername = relation_get -attr "computername" -rid $rid -unit $unit
            if(!$computername){
                continue
            }
            $ready = relation_get -attr "ready" -rid $rid -unit $unit
            if(!$ready){
                juju-log.exe "Node $private_address is not yet ready"
                continue
            }
            $nodes += $computername
        }
    }
    juju-log.exe "Running Run-SetKCD"
    Run-SetKCD
    juju-log.exe "Nodes count is: $nodes $minimumUnits"
    if ($nodes.Count -ne $minimumUnits){
        juju-log.exe ("Minimum required nodes not achieved($minimumUnits). Got: " + $nodes.Count)
        return $false
    }
    juju-log.exe "Running Create-S2DCluster"
    ExecuteWith-Retry {
        Create-S2DCluster -nodes $nodes
    } -RetryInterval 10 -MaxRetryCount 10
    juju-log.exe "Running Add-NodesToCluster"
    ExecuteWith-Retry {
        Add-NodesToCluster -nodes $nodes
    } -RetryInterval 10 -MaxRetryCount 10
    juju-log.exe "Running Enable-S2D"
    ExecuteWith-Retry {
        Enable-S2D
    } -RetryInterval 10 -MaxRetryCount 10
    juju-log.exe "Running Create-StoragePool"
    ExecuteWith-Retry {
        Create-StoragePool
    } -RetryInterval 10 -MaxRetryCount 10
    juju-log.exe "Running Create-S2DVolume"
    ExecuteWith-Retry {
        Create-S2DVolume
    } -RetryInterval 10 -MaxRetryCount 10
    juju-log.exe "Running Enable-ScaleOutFileServer"
    ExecuteWith-Retry {
        Enable-ScaleOutFileServer
    } -RetryInterval 10 -MaxRetryCount 10
    Broadcast-VolumeCreated
}

function Run-SetKCD {
    $name = relation_get -attr "computername"
    $charm_dir = charm_dir

    $relations = relation_ids -reltype 's2d'
    $peers = @()
    foreach($rid in $relations){
        $related_units = related_units -relid $rid
        foreach($unit in $related_units){
            $name = relation_get -attr "computername" -rid $rid -unit $unit
            $ready = relation_get -attr "ready" -rid $rid -unit $unit 
            if($ready){ 
                $peers += $name
            }
        }
    }

    foreach($i in $peers){
        if($i -eq $name){
            continue
        }
        & $charm_dir\hooks\Set-KCD.ps1 $name $i -ServiceType "Microsoft Virtual System Migration Service"
        & $charm_dir\hooks\Set-KCD.ps1 $name $i -ServiceType "cifs"
        & $charm_dir\hooks\Set-KCD.ps1 $i $name -ServiceType "Microsoft Virtual System Migration Service"
        & $charm_dir\hooks\Set-KCD.ps1 $i $name -ServiceType "cifs"
    }
    return $true
}

Export-ModuleMember -Function *
