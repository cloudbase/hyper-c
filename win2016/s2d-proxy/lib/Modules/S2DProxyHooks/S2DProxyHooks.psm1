#
# Copyright 2016 Cloudbase Solutions Srl
#

$ErrorActionPreference = "Stop"

Import-Module ADCharmUtils
Import-Module JujuLogging
Import-Module JujuWindowsUtils
Import-Module JujuUtils
Import-Module JujuHooks

function Get-S2DContext {
    $requiredCtxt = @{
        'joined-cluster-name' = $null;
    }
    $optionalCtxt = @{
        'volumepath' = $null;
    }
    $ctxt = Get-JujuRelationContext -Relation "s2d" `
                                    -RequiredContext $requiredCtxt `
                                    -OptionalContext $optionalCtxt
    if(!$ctxt.Count) {
        return @{}
    }
    return $ctxt
}

function Get-SMBContext {
    $requiredCtxt = @{
        "share-name" = $null;
        "computer-group" = $null
    }
    $ctxt = Get-JujuRelationContext -Relation "smb-share" -RequiredContext $requiredCtxt
    if(!$ctxt.Count) {
        return @{}
    }
    return $ctxt
}

function Get-S2DNodes {
    $nodes = @()
    $ctx = Get-ActiveDirectoryContext
    if(!$ctx.Count) {
        Write-JujuWarning "AD context is not ready yet."
        return $nodes
    }

    $relationsIds = Get-JujuRelationIds -Relation 's2d'
    foreach($rid in $relationsIds){
        Write-JujuInfo "Getting related units for: $rid"
        $relatedUnits = Get-JujuRelatedUnits -RelationId $rid
        Write-JujuInfo "Found related units: $relatedUnits"
        foreach($unit in $relatedUnits){
            $computername = Get-JujuRelation -Attribute "computername" -RelationId $rid -Unit $unit
            if(!$computername){
                continue
            }
            $ready = Get-JujuRelation -Attribute "ready" -RelationId $rid -Unit $unit
            Write-JujuInfo ("Unit $unit has ready state set to: {0} --> {1}" -f ($ready, $ready.GetType().FullName))
            if(!$ready){
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
    Clear-DnsClientCache

    $pool = Get-StoragePool -FriendlyName $StoragePool -CimSession $Session -ErrorAction SilentlyContinue
    if($pool){
        return $true
    }
    $storageSubsystem = Get-StorageSubSystem  -Name ($ClusterName + "." + $Domain) -CimSession $Session -ErrorAction Stop
    
    $physicalDisks = $storageSubsystem | Get-PhysicalDisk -CimSession $Session -ErrorAction Stop
    Write-JujuInfo "Creating storage pool $StoragePool"
    New-StoragePool -StorageSubSystemName ($ClusterName + "." + $Domain) `
                    -FriendlyName $StoragePool -WriteCacheSizeDefault 0 `
                    -ProvisioningTypeDefault Fixed -ResiliencySettingNameDefault Mirror `
                    -PhysicalDisk $physicalDisks -CimSession $Session -ErrorAction Stop
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
        $pool = Get-StoragePool -CimSession $Session -FriendlyName $storagePool -ErrorAction Stop
        Write-JujuInfo "Creating new virtual disk $VolumeName"
        $vdisk = New-VirtualDisk -CimSession $Session -StoragePoolFriendlyName $pool.FriendlyName `
                                 -FriendlyName $VolumeName -UseMaximumSize -ResiliencySettingName Mirror `
                                 -ErrorAction Stop
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
    Format-Volume -CimSession $Session -Partition $partition -FileSystem ReFS -ErrorAction Stop
    # Unsuspend cluster resource
    Write-JujuInfo "Resuming cluster resource $name"
    Resume-ClusterResource -Cluster $ClusterName -Name $name
    # Add the new volume as a cluster shared volume
    Write-JujuInfo "Adding $name to shared volumes"
    Add-ClusterSharedVolume -Cluster $ClusterName -Name $name

    Write-JujuInfo "Getting volume path for $VolumeName"
    $path = Get-VolumePath -Vol $volumeName -ClusterName $ClusterName
    Write-JujuWarning "Setting file integrity to `$false on $volumeName"
    Set-FileIntegrity $path -Enable $false -CimSession $Session -ErrorAction Stop
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
                          -FriendlyName $Name -ErrorAction Stop `
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
    $volumePath = $path.Replace('\', '/')
    Set-CharmState -Key "volumepath" -Value $volumePath
    $relationSet = @{
        "volumepath"=$volumePath;
    }
    $rids = Get-JujuRelationIds -Relation "s2d"
    foreach ($rid in $rids){
        $ret = Set-JujuRelation -RelationId $rid -Settings $relationSet
        if ($ret -eq $false){
            Write-JujuWarning "Failed to set s2d relation"
        }
    }
}

function Start-S2DRelationChanged {
    $adCtxt = Get-ActiveDirectoryContext
    if(!$adCtxt.Count) {
        Write-JujuWarning "AD context is not ready yet. Skipping"
        return $false
    }

    $s2dContext = Get-S2DContext
    if (!$s2dContext.Count) {
        Write-JujuWarning "S2D context is not ready yet. Skipping"
        return $false
    }

    $fqdn = (gcim Win32_ComputerSystem).Domain.ToLower()
    if($fqdn -ne $adCtxt["domainName"]){
        Throw ("We appear do be part or the wrong domain. Expected: {0}, We are in domain: {1}" -f @($adCtxt["domainName"], $fqdn))
    }

    $cfg = Get-JujuCharmConfig
    $minimumUnits = $cfg["minimum-nodes"]
    $nodes = Get-S2DNodes
    Write-JujuInfo "Found nodes: $nodes"
    if ($nodes.Count -ne $minimumUnits){
        Write-JujuInfo ("Minimum required nodes not achieved($minimumUnits). Got: " + $nodes.Count)
        return $false
    }
    Start-KCDScript -S2DNodes $nodes

    Write-JujuInfo "Creating new CIM session"
    $session = Get-NewCimSession -Nodes $nodes
    Write-JujuInfo "Got new CIM session $session"
    $scaleoutname = $cfg["scaleout-name"]
    $volumeName = $cfg["volume-name"]
    $storagePool = $cfg["storage-pool"]
    try {
        Write-JujuInfo "Running Enable-S2D"
        Start-ExecuteWithRetry {
            Enable-S2D -Domain $fqdn -ClusterName $s2dContext["joined-cluster-name"]
        } -RetryInterval 10 -MaxRetryCount 10
        Write-JujuInfo "Running Create-StoragePool"
        Start-ExecuteWithRetry {
            Create-StoragePool -Domain $fqdn -ClusterName $s2dContext["joined-cluster-name"] `
                               -Session $session -StoragePool $storagePool
        } -RetryInterval 10 -MaxRetryCount 10
        Write-JujuInfo "Running Create-S2DVolume"
        Start-ExecuteWithRetry {
            Create-S2DVolume -Session $session -VolumeName $volumeName `
                             -StoragePool $storagePool -ClusterName $s2dContext["joined-cluster-name"]
        } -RetryInterval 10 -MaxRetryCount 10
        Write-JujuInfo "Running Enable-ScaleOutFileServer"
        Start-ExecuteWithRetry {
            Enable-ScaleOutFileServer -Name $scaleoutname -Session $session `
                                      -Domain $fqdn -ClusterName $s2dContext["joined-cluster-name"]
        } -RetryInterval 10 -MaxRetryCount 10
        Broadcast-VolumeCreated -VolumeName $volumeName -Session $session
    } finally {
        Remove-CimSession $session
    }
}

function Start-KCDScript {
    Param(
        [Parameter(Mandatory=$true)]
        [string[]]$S2DNodes
    )
    $node = $S2DNodes[0]
    $peers = $S2DNodes[1..($S2DNodes.Length)]
    $charmDir = Get-JujuCharmDir
    foreach($peer in $peers){
        Start-ExternalCommand { & $charmDir\hooks\Set-KCD.ps1 $node $peer -ServiceType "Microsoft Virtual System Migration Service" }
        Start-ExternalCommand { & $charmDir\hooks\Set-KCD.ps1 $node $peer -ServiceType "cifs" }
        Start-ExternalCommand { & $charmDir\hooks\Set-KCD.ps1 $peer $node -ServiceType "Microsoft Virtual System Migration Service" }
        Start-ExternalCommand { & $charmDir\hooks\Set-KCD.ps1 $peer $node -ServiceType "cifs" }
    }
    return $true
}

function New-RelationSMBShare {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [string[]]$Accounts,
        [Parameter(Mandatory=$true)]
        [string]$SharePath,
        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimSession]$Session
    )
    $share = Get-SmbShare -Name $Name -ErrorAction SilentlyContinue
    if ($share) {
        Write-JujuWarning "Share was already created."
        return
    }
    New-SmbShare -Name $Name -Path $SharePath -CimSession $Session -ErrorAction Stop | Out-Null
    foreach($account in $Accounts) {
        try {
            Grant-SmbShareAccess -Name $Name -AccountName $account -AccessRight Full `
                                 -Force -Confirm:$false -CimSession $Session -ErrorAction Stop | Out-Null
        } catch {
            Write-JujuError "Failed to grant access on $Name to $account"
        }
    }
}

function Start-SMBShareRelationChanged {
    Write-JujuLog "Running SMB relation changed hook"
    $adCtx = Get-ActiveDirectoryContext
    if(!$adCtx.Count -or !$adCtx["domainName"] -or !(Confirm-IsInDomain $adCtx["domainName"])) {
        Write-JujuInfo "This node is not yet part of AD"
        return
    }
    $smbCtxt = Get-SMBContext
    if(!$smbCtxt.Count) {
        Write-JujuLog "SMB share context is not ready."
        return
    }
    $volumepath = Get-CharmState -Key "volumepath"
    if(!$volumepath) {
        Write-JujuLog "'volumepath' relation setting is not set yet."
        return
    }
    $s2dNodes = Get-S2DNodes
    $sharePath = Join-Path $volumepath $smbCtxt["share-name"]
    Start-ExecuteWithRetry {
        Invoke-Command -ComputerName $s2dNodes[0] -ScriptBlock {
            Param($sharePath)
            if (!(Test-Path $sharePath)) {
                mkdir $sharePath | Out-Null
            }
        } -ArgumentList $sharePath -ErrorAction Stop
    }
    $session = Get-NewCimSession -Nodes $s2dNodes
    New-RelationSMBShare -Name $smbCtxt["share-name"] -Accounts @($smbCtxt["computer-group"]) `
                         -SharePath $sharePath -Session $session
    Start-ExecuteWithRetry {
        Invoke-Command -ComputerName $s2dNodes[0] -ScriptBlock {
            Param($shareName, $account)
            $sharesPath = (Get-SmbShare -Name $shareName).Path
            $permissions = "{0}:(OI)(CI)(F)" -f $account
            icacls.exe $sharesPath /grant $permissions /T /C | Out-Null
            if ($LASTEXITCODE) {
                Throw "Exit code: $LASTEXITCODE"
            }
        } -ArgumentList @($smbCtxt["share-name"], $smbCtxt['computer-group']) -ErrorAction Stop
    }

    $rids = Get-JujuRelationIds -Relation 'smb-share'
    $scaleoutDNSName = Get-JujuCharmConfig -Scope 'scaleout-name'
    foreach($rid in $rids) {
        $sharePath = ("//{0}/{1}" -f @($scaleoutDNSName, $smbCtxt["share-name"]))
        $settings = @{"share" = $sharePath}
        $ret = Set-JujuRelation -RelationId $rid -Settings $settings
        if ($ret -ne $true) {
            Write-JujuWarning "Failed to set smb-share relation settings"
        }
    }
}
