#
# Copyright 2016 Cloudbase Solutions Srl
#

$env:PSModulePath += ";$env:CHARM_DIR\lib\Modules"
$ErrorActionPreference = "Stop"

Import-Module ADCharmUtils
Import-Module JujuLoging
Import-Module JujuWindowsUtils
Import-Module JujuUtils
Import-Module JujuHooks
Import-Module S2DUtils

$global:cimCreds = $null

function Get-S2DNodes {
    $relations = relation_ids -reltype 's2d'
    $nodes = @()

    $ctx = Get-ActiveDirectoryContext
    if(!$ctx.Count) {
        Write-JujuWarning "Could not get AD context"
        return $nodes
    }

    foreach($rid in $relations){
        Write-JujuInfo "Getting related units for: $rid"
        $related_units = related_units -relid $rid
        Write-JujuInfo "Found related units: $related_units"
        foreach($unit in $related_units){
            $computername = relation_get -attr "computername" -rid $rid -unit $unit
            if(!$computername){
                continue
            }
            $ready = relation_get -attr "ready" -rid $rid -unit $unit
            Write-JujuInfo "Unit $unit has ready state set to: $ready"
            if(!$ready -or $ready -eq "False"){
                Write-JujuInfo "Node $computername is not yet ready"
                continue
            }
            try{
                $isInAD = Get-ADComputer $computername -ErrorAction SilentlyContinue 
                if(!$isInAD){
                    Write-JujuWarning "Node $computername is not yet in AD"
                    continue
                }
            } catch {
                Write-JujuWarning "Node $computername is not yet in AD: $_"
                continue
            }
            $nodes += $computername
        }
    }
    Write-JujuInfo "Returning $nodes"
    return ($nodes -as [array])
}

function Create-S2DCluster {
    Param(
        [Parameter(Mandatory=$true)]
        [array]$Nodes,
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        [Parameter(Mandatory=$true)]
        [string]$ClusterName
    )
    $staticAddress = charm_config -scope "static-address"
    if(!$staticAddress){
        Throw "Static address was not set in charm config and is required"
    }

    $cluster = Get-Cluster -Name $ClusterName -Domain $Domain -ErrorAction SilentlyContinue
    if(!$cluster){
        Write-JujuInfo "Running create cluster"
        New-Cluster -Name $ClusterName -Node $nodes -NoStorage -StaticAddress $staticAddress.Split(" ")
        Flush-DNS
    }
    return $true
}

function Add-NodesToCluster {
    Param(
        [Parameter(Mandatory=$true)]
        [array]$nodes,
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        [Parameter(Mandatory=$true)]
        [string]$ClusterName
    )
    Flush-DNS
    try {
        $cluster = Get-Cluster -Name $ClusterName -Domain $Domain
        if (!$cluster){
            Throw "Could not get cluster"
        }
    }catch{
        Write-JujuWarning "Cluster not initialized: $_"
        Write-JujuWarning "Delaying Add-ClusterNode"
        return $false
    }
    Write-JujuInfo "Got nodes: $nodes"
    foreach ($node in $nodes) {
        $n = $node -as [string]
        Write-JujuInfo "Looking for $n in AD"
        $isInAD = Get-ADComputer $n -ErrorAction SilentlyContinue
        if(!$isInAD){
            Write-JujuWarning "Node $n is not in AD yet."
            continue
        }
        $isAdded = Get-ClusterNode -Name $n -Cluster ($ClusterName + "." + $Domain) -ErrorAction SilentlyContinue
        if (!$isAdded) {
            Write-JujuInfo "Trying to add $node"
            Add-ClusterNode -Name $n -Cluster $ClusterName -NoStorage
        }
    }
    return $true
}

function Enable-S2D {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        [Parameter(Mandatory=$true)]
        [string]$ClusterName
    )
    try {
        Write-JujuInfo "Getting cluster status"
        $cluster = Get-Cluster -Name $clusterName -Domain $Domain
    }catch{
        Write-JujuWarning "Cluster not initialized"
        Write-JujuWarning "Delaying Enable-ClusterStorageSpacesDirect"
        return $false
    }
    Write-JujuInfo ("cluster DAS mode is: " + $cluster.DASModeEnabled)
    if($cluster.DASModeEnabled -eq 1){
        return $true
    }
    Enable-ClusterStorageSpacesDirect -Cluster ($clusterName + "." + $Domain)
    return $true
}

function Create-StoragePool {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ClusterName,
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimSession]$Session,
        [Parameter(Mandatory=$true)]
        [string]$StoragePool
    )
    Flush-DNS

    $pool = Get-StoragePool -FriendlyName $StoragePool -CimSession $Session -ErrorAction SilentlyContinue
    if($pool){
        return $true
    }
    $storageSubsystem = Get-StorageSubSystem  -Name ($ClusterName + "." + $Domain) -CimSession $Session
    
    $physicalDisks = $storageSubsystem | Get-PhysicalDisk -CimSession $Session
    Write-JujuInfo "Creating storage pool $StoragePool"
    New-StoragePool -StorageSubSystemName ($ClusterName + "." + $Domain) `
                    -FriendlyName $StoragePool -WriteCacheSizeDefault 0 `
                    -ProvisioningTypeDefault Fixed -ResiliencySettingNameDefault Mirror `
                    -PhysicalDisk $physicalDisks -CimSession $Session
}

function Get-VolumePath {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$vol,
        [Parameter(Mandatory=$true)]
        [string]$clusterName
    )
    $node = (Get-ClusterNode -Cluster $clusterName).name[0]

    $query = "SELECT * FROM MSFT_VirtualDisk WHERE FriendlyName='{0}'" -f $vol
    $obj = Get-WmiObject -Namespace "root/microsoft/windows/storage" -Query $query -ComputerName $node
    if(!$obj){
        Throw "Failed to get VirtualDisk"
    }
    $path = $obj.GetRelated("MSFT_StorageSubSystem").GetRelated("MSFT_Volume").Path
    if(!$path){
        Throw "Failed to find volume path"
    }
    return $path
}

function Create-S2DVolume {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$VolumeName,
        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimSession]$Session,
        [Parameter(Mandatory=$true)]
        [string]$StoragePool,
        [Parameter(Mandatory=$true)]
        [string]$ClusterName
    )

    $clusterVirtualDiskName = "Cluster Virtual Disk ({0})" -f $VolumeName
    Write-JujuInfo "Checking if volume already exists"
    $vdisk = Get-VirtualDisk -CimSession $Session -FriendlyName $VolumeName -ErrorAction SilentlyContinue
    if ($vdisk){
        Write-JujuInfo "Checking if virtual disk has been added as a shared storage disk"
        $sharedDiskExists = Get-ClusterSharedVolume -Cluster $ClusterName `
                                                    -Name $clusterVirtualDiskName `
                                                    -ErrorAction SilentlyContinue
        if($sharedDiskExists){
            Write-JujuInfo "Virtual disk $VolumeName already part of cluster. Skipping..."
            return $true
        }
    }

    if(!$vdisk){
        Write-JujuInfo "Getting Storage Pool $storagePool"
        $pool = Get-StoragePool -CimSession $Session -FriendlyName $storagePool
        Write-JujuInfo "Creating new virtual disk $VolumeName"
        $vdisk = New-VirtualDisk -CimSession $Session -StoragePoolFriendlyName $pool.FriendlyName `
                                 -FriendlyName $VolumeName -UseMaximumSize -ResiliencySettingName Mirror
    }
    
    # get the cluster resource and suspend it
    Write-JujuInfo "Fetching cluster resources"
    $clusterResources = Get-ClusterResource -Cluster $ClusterName
    $clusterDisks = $clusterResources | Where-Object {$_.ResourceType -eq "Physical Disk" -and $_.OwnerGroup -eq "Available Storage"} 
    $diskNames = $clusterDisks | Get-ClusterParameter -Name VirtualDiskName
    $name = ""
    foreach($i in $diskNames){
        if($i.Value -eq $VolumeName){
            $name = $i.ClusterObject.Name
            break
        }
    }
    if (!$name){
        Throw "Could not find cluster resource for $VolumeName"
    }

    # we need to suspend the cluster resource before we can format it
    Write-JujuInfo "Suspending cluster resource $name"
    Suspend-ClusterResource -Cluster $ClusterName -Name $name

    # clear partitions
    Write-JujuInfo "Clearing partitions on volume $VolumeName"
    $vdisk | Get-Disk | Get-Partition | Remove-Partition -Confirm:$false
    Write-JujuInfo "Creating New partition on virtual disk"
    $partition = $vdisk | Get-Disk | New-Partition -UseMaximumSize

    # format the volume
    Write-JujuInfo "Fromatting volume"
    Format-Volume -CimSession $Session -Partition $partition -FileSystem ReFS
    # Unsuspend cluster resource
    Write-JujuInfo "Resuming cluster resource $name"
    Resume-ClusterResource -Cluster $ClusterName -Name $name
    # Add the new volume as a cluster shared volume
    Write-JujuInfo "Adding $name to shared volumes"
    Add-ClusterSharedVolume -Cluster $ClusterName -Name $name

    Write-JujuInfo "Getting volume path for $VolumeName"
    $path = Get-VolumePath -Vol $volumeName -ClusterName $ClusterName
    Write-JujuWarning "Setting file integrity to `$false on $volumeName"
    Set-FileIntegrity $path -Enable $false -CimSession $Session
    return $true
}

function Enable-ScaleOutFileServer {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimSession]$Session,
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        [Parameter(Mandatory=$true)]
        [string]$ClusterName
    )
    $exists = Get-StorageFileServer -CimSession $Session -FriendlyName $Name -ErrorAction SilentlyContinue
    if($exists){
        return $true
    }
    New-StorageFileServer -StorageSubSystemName ($ClusterName + "." + $Domain) `
                          -FriendlyName $Name `
                          -HostName $Name -Protocols SMB -CimSession $Session
    return $true
}

function Broadcast-VolumeCreated {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$VolumeName,
        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimSession]$Session
    )
    $virtualDisk = Get-VirtualDisk -CimSession $Session -FriendlyName $VolumeName -ErrorAction SilentlyContinue
    if(!$virtualDisk){
        Write-JujuWarning "Volume $VolumeName not created yet"
        return $false
    }
    $paths = ($virtualDisk | Get-Disk | Get-Partition | Where-Object {$_.Type -eq "Basic"}).AccessPaths
    $path = ""
    foreach($i in $paths){
        if($i.StartsWith("\\?\")){
            continue
        }
        $path = $i
        break
    }
    if(!$path){
        Throw "Could not get volume access path"
    }
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

function Start-S2DRelationChanged {
    $isInDomain = (gcim Win32_ComputerSystem).PartOfDomain
    if (!$isInDomain){
        Write-JujuWarning "Not yet in any domain. Skipping"
        return $false
    }
    $ctx = Get-ActiveDirectoryContext
    if(!$ctx.Count) {
        return $false
    }
    $clusterName = charm_config -scope "cluster-name"
    $fqdn = (gcim Win32_ComputerSystem).Domain.ToLower()
    if($fqdn -ne $ctx["domainName"]){
        Throw ("We appear do be part or the wrong domain. Expected: {0}, We Are in domain: {1}" -f @($ctx["domainName"], $fqdn))
    }

    $scaleoutname = charm_config -scope "scaleout-name"
    $volumeName = charm_config -scope "volume-name"
    $storagePool = charm_config -scope "storage-pool"
    $minimumUnits = charm_config -scope "minimum-nodes"
    $nodes = Get-S2DNodes

    #juju-log.exe "Running Run-SetKCD"
    Write-JujuInfo "Found nodes: $nodes"
    if ($nodes.Count -ne $minimumUnits){
        Write-JujuInfo ("Minimum required nodes not achieved($minimumUnits). Got: " + $nodes.Count)
        return $false
    }
    Run-SetKCD
    Write-JujuInfo "Creating new CIM session"
    $session = Get-NewCimSession -Nodes $nodes
    Write-JujuInfo "Got new CIM session $session"
    try {
        Write-JujuInfo "Running Create-S2DCluster"
        Start-ExecuteWithRetry {
            Create-S2DCluster -Nodes $nodes -Domain $fqdn -ClusterName $clusterName
        } -RetryInterval 10 -MaxRetryCount 10
        Write-JujuInfo "Running Add-NodesToCluster"
        Start-ExecuteWithRetry {
            Add-NodesToCluster -nodes $nodes -Domain $fqdn -ClusterName $clusterName
        } -RetryInterval 10 -MaxRetryCount 10
        Write-JujuInfo "Running Enable-S2D"
        Start-ExecuteWithRetry {
            Enable-S2D -Domain $fqdn -ClusterName $clusterName
        } -RetryInterval 10 -MaxRetryCount 10
        Write-JujuInfo "Running Create-StoragePool"
        Start-ExecuteWithRetry {
            Create-StoragePool -Domain $fqdn -ClusterName $clusterName -Session $session -StoragePool $storagePool
        } -RetryInterval 10 -MaxRetryCount 10
        Write-JujuInfo "Running Create-S2DVolume"
        Start-ExecuteWithRetry {
            Create-S2DVolume -Session $session -VolumeName $volumeName -StoragePool $storagePool -ClusterName $clusterName
        } -RetryInterval 10 -MaxRetryCount 10
        Write-JujuInfo "Running Enable-ScaleOutFileServer"
        Start-ExecuteWithRetry {
            Enable-ScaleOutFileServer -Name $scaleoutname -Session $session -Domain $fqdn -ClusterName $clusterName
        } -RetryInterval 10 -MaxRetryCount 10
        Broadcast-VolumeCreated -VolumeName $volumeName -Session $session
    }finally{
        Remove-CimSession $session
    }
}

function Run-SetKCD {
    $name = relation_get -attr "computername"
    if(!$name){
        return $false
    }
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

Export-ModuleMember -Function Start-S2DRelationChanged
