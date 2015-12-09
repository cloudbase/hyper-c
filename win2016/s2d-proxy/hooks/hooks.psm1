#
# Copyright 2014 Cloudbase Solutions SRL
#

$env:PSModulePath += ";$env:CHARM_DIR\lib\Modules"
$ErrorActionPreference = "Stop"

Import-Module -Force -DisableNameChecking CharmHelpers

$activeDirectoryModule = Join-Path $psscriptroot active-directory.psm1
Import-Module -Force -DisableNameChecking $activeDirectoryModule

$global:cimCreds = $null

function Get-S2DNodes {
    $relations = relation_ids -reltype 's2d'
    $nodes = @()
    $creds = Get-CimCredentials
    if(!$creds){
        juju-log.exe "WARNING: Could not get credentials"
        return $nodes
    }

    $ctx = Get-ActiveDirectoryContext
    if(!$ctx.Count) {
        juju-log.exe "WARNING: Could not get AD context"
        return $nodes
    }

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
            juju-log.exe "Unit $unit has reaty state set to: $ready"
            if(!$ready){
                juju-log.exe "Node $private_address is not yet ready"
                continue
            }
            try{
                $isInAD = Get-ADComputer $computername -ErrorAction SilentlyContinue -Credential $creds -Server $ctx["ip_address"]
                if(!$isInAD){
                    juju-log.exe "Node $computername is not yet in AD"
                    continue
                }
            } catch {
                juju-log.exe "Node $computername is not yet in AD: $_"
                continue
            }
            $nodes += $computername
        }
    }
    juju-log.exe "Returning $nodes"
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
        juju-log.exe "Running create cluster"
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
        juju-log.exe "Warning: Cluster not initialized: $_"
        juju-log.exe "Delaying Add-ClusterNode"
        return $false
    }
    juju-log.exe "Got nodes: $nodes"
    foreach ($node in $nodes) {
        $n = $node -as [string]
        juju-log.exe "Looking for $n in AD"
        $isInAD = Get-ADComputer $n -ErrorAction SilentlyContinue
        if(!$isInAD){
            juju-log.exe "Node $n is not in AD yet."
            continue
        }
        $isAdded = Get-ClusterNode -Name $n -Cluster ($ClusterName + "." + $Domain) -ErrorAction SilentlyContinue
        if (!$isAdded) {
            juju-log.exe "Trying to add $node"
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
        juju-log.exe "Getting cluster status"
        $cluster = Get-Cluster -Name $clusterName -Domain $Domain
    }catch{
        juju-log.exe "Warning: Cluster not initialized"
        juju-log.exe "Delaying Enable-ClusterStorageSpacesDirect"
        return $false
    }
    juju-log.exe ("cluster DAS mode is: " + $cluster.DASModeEnabled)
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
    juju-log.exe "Creating storage pool $StoragePool"
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
    $creds = Get-CimCredentials
    if(!$creds) {
        Throw "Failed to get CIM credentials"
    }

    $query = "SELECT * FROM MSFT_VirtualDisk WHERE FriendlyName='{0}'" -f $vol
    $obj = Get-WmiObject -Namespace "root/microsoft/windows/storage" -Query $query -ComputerName $node -Credential $creds
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
    juju-log.exe "Checking if volume already exists"
    $volumeExists = Get-VirtualDisk -CimSession $Session -FriendlyName $VolumeName -ErrorAction SilentlyContinue
    if ($volumeExists){
        $sharedDiskExists = Get-ClusterSharedVolume -Cluster $ClusterName `
                                                    -Name $clusterVirtualDiskName `
                                                    -ErrorActionPreference SilentlyContinue
        if($sharedDiskExists){
            return $true
        }
    }

    if(!$volumeExists){
        juju-log.exe "Getting Storage Pool $storagePool"
        $pool = Get-StoragePool -CimSession $Session -FriendlyName $storagePool
        juju-log.exe "Creating new virtual disk $VolumeName"
        $vdisk = New-VirtualDisk -CimSession $Session -StoragePoolFriendlyName $pool.FriendlyName `
                                 -FriendlyName $VolumeName -UseMaximumSize -ResiliencySettingName Mirror
        juju-log.exe "Creating New partition on virtual disk"
        $partition = $vdisk | Get-Disk | New-Partition -UseMaximumSize
    }

    # get the cluster resource and suspend it
    juju-log.exe "Fetching cluster resources"
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
    juju-log.exe "Suspending cluster resource $name"
    Suspend-ClusterResource -Cluster $ClusterName -Name $name
    # format the volume
    juju-log.exe "Fromatting volume"
    Format-Volume -CimSession $Session -Partition $partition -FileSystem ReFS -FileSystemLabel $VolumeName
    # Unsuspend cluster resource
    juju-log.exe "Resuming cluster resource $name"
    Resume-ClusterResource -Cluster $ClusterName -Name $name
    # Add the new volume as a cluster shared volume
    juju-log.exe "Adding $name to shared volumes"
    Add-ClusterSharedVolume -Cluster $ClusterName -Name $name

    juju-log.exe "Getting volume path for $VolumeName"
    $path = Get-VolumePath -Vol $volumeName -ClusterName $ClusterName
    juju-log.exe "Setting file integrity to `$false on $volumeName"
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
        juju-log.exe "Volume not created yet"
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

function Run-S2DRelationChanged {
    $isInDomain = (gcim Win32_ComputerSystem).PartOfDomain
    if (!$isInDomain){
        juju-log.exe "Not yet in any domain. Skipping"
        return $false
    }
    $ctx = Get-ActiveDirectoryContext
    if(!$ctx.Count) {
        return $false
    }
    $clusterName = charm_config -scope "cluster-name"
    $fqdn = (gcim Win32_ComputerSystem).Domain.ToLower()
    if($fqdn -ne $ctx["ad_domain"]){
        Throw ("We appear do be part or the wrong domain. Expected: {0}, We Are in domain: {1}" -f @($ctx["domain_name"], $fqdn))
    }

    $scaleoutname = charm_config -scope "scaleout-name"
    $volumeName = charm_config -scope "volume-name"
    $storagePool = charm_config -scope "storage-pool"
    $minimumUnits = charm_config -scope "minimum-nodes"
    $nodes = Get-S2DNodes

    #juju-log.exe "Running Run-SetKCD"
    #Run-SetKCD
    juju-log.exe "Found nodes: $nodes"
    if ($nodes.Count -ne $minimumUnits){
        juju-log.exe ("Minimum required nodes not achieved($minimumUnits). Got: " + $nodes.Count)
        return $false
    }
    juju-log.exe "Creating new CIM session"
    $session = Get-NewCimSession -Nodes $nodes
    juju-log.exe "Got new CIM session $session"
    try {
        juju-log.exe "Running Create-S2DCluster"
        ExecuteWith-Retry {
            Create-S2DCluster -Nodes $nodes -Domain $fqdn -ClusterName $clusterName
        } -RetryInterval 10 -MaxRetryCount 10
        juju-log.exe "Running Add-NodesToCluster"
        ExecuteWith-Retry {
            Add-NodesToCluster -nodes $nodes -Domain $fqdn -ClusterName $clusterName
        } -RetryInterval 10 -MaxRetryCount 10
        juju-log.exe "Running Enable-S2D"
        ExecuteWith-Retry {
            Enable-S2D -Domain $fqdn -ClusterName $clusterName
        } -RetryInterval 10 -MaxRetryCount 10
        juju-log.exe "Running Create-StoragePool"
        ExecuteWith-Retry {
            Create-StoragePool -Domain $fqdn -ClusterName $clusterName -Session $session -StoragePool $storagePool
        } -RetryInterval 10 -MaxRetryCount 10
        juju-log.exe "Running Create-S2DVolume"
        ExecuteWith-Retry {
            Create-S2DVolume -Session $session -VolumeName $volumeName -StoragePool $storagePool -ClusterName $clusterName
        } -RetryInterval 10 -MaxRetryCount 10
        juju-log.exe "Running Enable-ScaleOutFileServer"
        ExecuteWith-Retry {
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

Export-ModuleMember -Function *
