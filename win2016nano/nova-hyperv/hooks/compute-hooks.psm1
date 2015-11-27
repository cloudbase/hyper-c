#
# Copyright 2014 Cloudbase Solutions SRL
#

$env:PSModulePath += "C:\Program Files\WindowsPowerShell\Modules;c:\windows\system32\windowspowershell\v1.0\Modules;$env:CHARM_DIR\lib\Modules"
import-module Microsoft.PowerShell.Management
import-module Microsoft.PowerShell.Utility
$ErrorActionPreference = "Stop"

Import-Module -Force -DisableNameChecking CharmHelpers

$ovs_vsctl = "${env:ProgramFiles(x86)}\Cloudbase Solutions\Open vSwitch\bin\ovs-vsctl.exe"
$env:OVS_RUNDIR = "$env:ProgramData\openvswitch"

$ovsExtName = "Open vSwitch Extension"
$distro_urls = @{
    'icehouse' = @{
        "installer" = @{
            'msi' = 'https://www.cloudbase.it/downloads/HyperVNovaCompute_Icehouse_2014_1_3.msi#md5=e5211ff8d62351778bdbe80a26c8e0b2';
            'zip' = $null;
        };
        "ovs" = $false;
    };
    'juno' = @{
        "installer" = @{
            'msi' = 'https://www.cloudbase.it/downloads/HyperVNovaCompute_Juno_2014_2_1.msi#md5=6b27228f6a264707124f20b09398e2dc';
            'zip' = $null;
        };
        "ovs" = $false;
    };
    'kilo' = @{
        "installer" = @{
            'msi' = 'https://www.cloudbase.it/downloads/HyperVNovaCompute_Kilo_2015_1.msi#md5=49a9f59f8800de378c995032cf26aaaf';
            'zip' = $null;
        }
        "ovs" = $true;
    };
    'liberty' = @{
        "installer" = @{
            'msi' = 'https://www.cloudbase.it/downloads/HyperVNovaCompute_Beta.msi';
            'zip' = 'https://www.cloudbase.it/downloads/HyperVNovaCompute_Liberty_12_0_0.zip';
            #'zip' = 'http://192.168.200.1/nova-liberty.zip';
        };
        "ovs" = $true;
    };
}

function Install-JsonModule {
    if(!(Is-NanoServer)){
        return $false
    }
    $files = Join-Path $env:CHARM_DIR "files"
    $moduleFile = Join-Path $files "Json.Silverlight4.dll"
    $module = "${env:SystemDrive}\Windows\System32\WindowsPowerShell\v1.0\Json.Silverlight4.dll"
    if ((Test-Path $module)){
        return $true
    }
    if (!(Test-Path $moduleFile)){
        return $false
    }
    cp $moduleFile "${env:SystemDrive}\Windows\System32\WindowsPowerShell\v1.0"
    return $true
}

function Run-TimeResync {
    Write-JujuLog "Synchronizing time..."
    try {
        Start-Service "w32time"
        Execute-ExternalCommand {
            w32tm.exe /config /manualpeerlist:time.windows.com /syncfromflags:manual /update
        }
    } catch {
        Write-JujuError "Failed to synchronize time..." -Fatal $false
    }
    Write-JujuLog "Finished synchronizing time."
}

function Extract-FromZip {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Archive,
        [Parameter(Mandatory=$true)]
        [string]$Destination
    )
    if(!(Test-Path $Destination)){
        mkdir $Destination
    }
    [System.IO.Compression.ZipFile]::ExtractToDirectory($Archive, $Destination)
}

function Is-NanoServer {
    $serverLevels = Get-ItemProperty "HKLM:Software\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels"
    if ($serverLevels.NanoServer -eq 1){
        return $true
    }
    return $false
}

function Install-Prerequisites
{
    if ((Is-NanoServer)){
        return $true
    }

    try {
        $needsHyperV = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V
    }catch{
        Throw "Failed to get Hyper-V role status: $_"
    }

    if ($needsHyperV.State -ne "Enabled"){
        $installHyperV = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
        if ($installHyperV.RestartNeeded){
            juju-reboot.exe --now
        }
    }else{
        if ($needsHyperV.RestartNeeded){
            juju-reboot.exe --now
        }
    }
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -All -NoRestart
    Import-Module hyper-v
}


function Get-OpenstackVersion {
    $distro = charm_config -scope "openstack-version"
    if($distro -eq $false){
        $distro = charm_config -scope "openstack-origin"
    }
    return $distro
}

function Get-NetType {
    $net_type = charm_config -scope "network-type"

    $distro = Get-OpenstackVersion
    if($distro_urls["ovs"] -eq $false -or (Is-NanoServer) -eq $true){
        #force hyperv network manager for versions that do now support ovs
        $net_type = "hyperv"
    }
    return $net_type
}

function Juju-GetVMSwitch {
    $VMswitchName = charm_config -scope "vmswitch-name"
    if (!$VMswitchName){
        return "br100"
    }
    return $VMswitchName
}

function WaitFor-BondUp {
    Param(
    [Parameter(Mandatory=$true)]
    [string]$bond
    )

    $b = Get-NetLbfoTeam -Name $bond -ErrorAction SilentlyContinue
    if (!$b){
        Write-JujuLog "Bond interface $bond not found"
        return $false
    }
    Write-JujuLog "Found bond: $bond"
    $count = 0
    while ($count -lt 30){
        Write-JujuLog ("Bond status is " + $b.Status)
        $b = Get-NetLbfoTeam -Name $bond -ErrorAction SilentlyContinue
        if ($b.Status -eq "Up" -or $b.Status -eq "Degraded"){
            Write-JujuLog ("bond interface status is " + $b.Status)
            return $true
        }
        Start-Sleep 1
        $count ++
    }
    return $false
}

function Generate-ExeWrappers {
    $novaDir = Get-NovaDir
    $pythonDir = Join-Path $novaDir "Python"
    $python = Join-Path $pythonDir "python.exe"
    $updateWrapper = Join-Path $pythonDir "Scripts\UpdateWrappers.py"
    & $python $updateWrapper "nova-compute = nova.cmd.compute:main"
    if($LASTEXITCODE){
        Throw "Failed to generate nova-compute wrapper"
    }
    & $python $updateWrapper "neutron-hyperv-agent = neutron.cmd.eventlet.plugins.hyperv_neutron_agent:main"
    if($LASTEXITCODE){
        Throw "Failed to generate neutron-hyperv-agent wrapper"
    }
}

function Setup-BondInterface {
    $enabled = charm_config -scope "use-bonding"
    if (!$enabled) { return $false }

    $bondExists = Get-NetLbfoTeam -Name "bond0" -ErrorAction SilentlyContinue
    if ($bondExists -ne $null){
        return $true
    }
    $bondPorts = Get-InterfaceFromConfig -ConfigOption "bond-ports"
    if ($bondPorts.Length -eq 0) {
        return $false
    }
    try {
        $bond = New-NetLbfoTeam -Name "bond0" -TeamMembers $bondPorts.Name -TeamNicName "bond0" -TeamingMode LACP -Confirm:$false
        if ($? -eq $false){
            Write-JujuError "Failed to create Lbfo team"
        }
    }catch{
        Write-JujuError "Failed to create Lbfo team: $_.Exception.Message"
    }
    $isUp = WaitFor-BondUp -bond $bond.Name
    if (!$isUp){
        Write-JujuError "Failed to bring up bond0"
    }
    ipconfig /release bond0
    if ($lastexitcode){
        Write-JujuLog "failed to release DHCP lease on bond0"
    }
    ipconfig /renew bond0
    if ($lastexitcode){
        Write-JujuLog "Failed to renew DHCP lease on bond0"
    }
    return $true
}

function Get-TemplatesDir {
    $templates =  Join-Path "$env:CHARM_DIR" "templates"
    return $templates
}

function Get-PackageDir {
    $packages =  Join-Path "$env:CHARM_DIR" "packages"
    return $packages
}

function Get-FilesDir {
    $packages =  Join-Path "$env:CHARM_DIR" "files"
    return $packages
}

function Install-RootWrap {
    $template = Get-TemplatesDir
    $rootWrap = Join-Path $template "ovs\rootwrap.cmd"

    if(!(Test-Path $rootWrap)){
        return $true
    }

    $dst = "${env:ProgramFiles(x86)}\Cloudbase Solutions\OpenStack\Nova\bin\rootwrap.cmd"
    $parent = Split-Path -Path $dst -Parent
    $exists = Test-Path $parent
    if (!$exists){
        mkdir $parent
    }
    cp $rootWrap $dst
    return $?
}

function Get-NovaDir {
    if ((Is-NanoServer)) {
        return "${env:programfiles}\Cloudbase Solutions\Openstack\Nova"
    } else {
        return "${env:programfiles(x86)}\Cloudbase Solutions\Openstack\Nova"
    }
}

function Charm-Services {
    $template_dir = Get-TemplatesDir
    $distro = Get-OpenstackVersion
    $novaDir = Get-NovaDir
    $nova_config = Join-Path $novaDir "etc\nova.conf"
    $neutron_config = Join-Path $novaDir "etc\neutron_hyperv_agent.conf"
    $neutron_ml2 = Join-Path $novaDir "etc\ml2_conf.ini"

    $serviceWrapper = Join-Path $novaDir "bin\OpenStackService.exe"
    $novaExe = Join-Path $novaDir "Python\Scripts\nova-compute.exe"
    $neutronHypervAgentExe = Join-Path $novaDir "Python\Scripts\neutron-hyperv-agent.exe"
    $neutronOpenvswitchExe = Join-Path $novaDir "Python\Scripts\neutron-openvswitch-agent.exe"

    $JujuCharmServices = @{
        "nova"=@{
            "myname"="nova";
            "template"="$template_dir\$distro\nova.conf";
            "service"="nova-compute";
            "binpath"="$novaExe";
            "serviceBinPath"="`"$serviceWrapper`" nova-compute `"$novaExe`" --config-file `"$nova_config`"";
            "config"="$nova_config";
            "context_generators"=@(
                "Get-RabbitMQContext",
                "Get-NeutronContext",
                "Get-GlanceContext",
                "Get-CharmConfigContext",
                "Get-SystemContext",
                "Get-S2DContainerContext"
                );
        };
        "neutron"=@{
            "myname"="neutron";
            "template"="$template_dir\$distro\neutron_hyperv_agent.conf"
            "service"="neutron-hyperv-agent";
            "binpath"="$neutronHypervAgentExe";
            "serviceBinPath"="`"$serviceWrapper`" neutron-hyperv-agent `"$neutronHypervAgentExe`" --config-file `"$neutron_config`"";
            "config"="$neutron_config";
            "context_generators"=@(
                "Get-RabbitMQContext",
                "Get-NeutronContext",
                "Get-CharmConfigContext",
                "Get-SystemContext",
                "Get-S2DContainerContext"
                );
        };
        "neutron-ovs"=@{
            "myname"="neutron-ovs";
            "template"="$template_dir\$distro\ml2_conf.ini"
            "service"="neutron-openvswitch-agent";
            "binpath"="$neutronOpenvswitchExe";
            "serviceBinPath"="`"$serviceWrapper`" neutron-openvswitch-agent `"$neutronOpenvswitchExe`" --config-file `"$neutron_ml2`"";
            "config"="$neutron_ml2";
            "context_generators"=@(
                "Get-NeutronContext",
                "Get-RabbitMQContext",
                "Get-CharmConfigContext",
                "Get-SystemContext",
                "Get-S2DContainerContext"
                );
        };
    }
    return $JujuCharmServices
}


function Get-RabbitMQContext {
    Write-JujuLog "Generating context for RabbitMQ"
    $username = charm_config -scope 'rabbit-user'
    $vhost = charm_config -scope 'rabbit-vhost'
    if (!$username -or !$vhost){
        Write-JujuError "Missing required charm config options: rabbit-user or rabbit-vhost"
    }

    $ctx = @{
        "rabbit_host"=$null;
        "rabbit_userid"=$username;
        "rabbit_password"=$null;
        "rabbit_virtual_host"=$vhost
    }

    $relations = relation_ids -reltype 'amqp'
    foreach($rid in $relations){
        juju-log.exe "Getting related units for: $rid"
        $related_units = related_units -relid $rid
        juju-log.exe "Found related units: $related_units"
        foreach($unit in $related_units){
            $ctx["rabbit_host"] = relation_get -attr "private-address" -rid $rid -unit $unit
            $ctx["rabbit_password"] = relation_get -attr "password" -rid $rid -unit $unit
            $ctx_complete = Check-ContextComplete -ctx $ctx
            if ($ctx_complete){
                break
            }
        }
    }
    $ctx_complete = Check-ContextComplete -ctx $ctx
    if ($ctx_complete){
        return $ctx
    }
    Write-JujuLog "RabbitMQ context not yet complete. Peer not ready?"
    return @{}
}


function Get-NeutronUrl {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$rid,
        [Parameter(Mandatory=$true)]
        [string]$unit
    )

    $url = relation_get -attr 'neutron_url' -rid $rid -unit $unit
    if ($url){
        return $url
    }
    $url = relation_get -attr 'quantum_url' -rid $rid -unit $unit
    return $url
}


function Get-S2DContainerContext {
    $instancesDir = (charm_config -scope 'instances-dir').Replace('/', '\')
    $ctx = @{
        "instances_dir"=$instancesDir;
    }
    $rids = relation_ids -reltype "s2d"
    foreach ($rid in $rids){
        $units = related_units -relid $rid
        foreach ($unit in $units){
            $volumePath = relation_get -attr 's2dvolpath' -rid $rid -unit $unit
            juju-log.exe ">>> $volumePath"
            if($volumePath){
                $ctx["instances_dir"] = $volumePath.Replace('/', '\')
                if(!(Test-Path $volumePath)){
                    # Got s2dvolpath from relation, but its not actually present
                    # on disk. Not setting this to instances dir as it will fail
                    continue
                }
                $ctx["instances_dir"] = $volumePath.Replace('/', '\')
                juju-log.exe ("<<<<" + $ctx["instances_dir"])
                return $ctx
            }
        }
    }
    # If we get here, it means there was no s2dvolpath
    if (!(Test-Path $ctx["instances_dir"])){
        mkdir $ctx["instances_dir"]
    }
    return $ctx
}

function Get-NeutronContext {
    Write-JujuLog "Generating context for Neutron"

    $logdir = (charm_config -scope 'log-dir').Replace('/', '\')
    $logdirExists = Test-Path $logdir
    $switchName = Juju-GetVMSwitch

    if (!$logdirExists){
        mkdir $logdir
    }

    $ctx = @{
        "neutron_url"=$null;
        "keystone_host"=$null;
        "auth_port"=$null;
        "auth_protocol"=$null;
        "neutron_auth_strategy"="keystone";
        "neutron_admin_tenant_name"=$null;
        "neutron_admin_username"=$null;
        "neutron_admin_password"=$null;
        "log_dir"=$logdir;
        "vmswitch_name"=$switchName;
    }

    $rids = relation_ids -reltype 'cloud-compute'
    foreach ($rid in $rids){
        $units = related_units -relid $rid
        foreach ($unit in $units){
            $url = Get-NeutronUrl -rid $rid -unit $unit
            if (!$url){
                continue
            }
            $ctx["neutron_url"] = $url
            $ctx["keystone_host"] = relation_get -attr 'auth_host' -rid $rid -unit $unit
            $ctx["auth_port"] = relation_get -attr 'auth_port' -rid $rid -unit $unit
            $ctx["auth_protocol"] = relation_get -attr 'auth_protocol' -rid $rid -unit $unit
            $ctx["neutron_admin_tenant_name"] = relation_get -attr 'service_tenant_name' -rid $rid -unit $unit
            $ctx["neutron_admin_username"] = relation_get -attr 'service_username' -rid $rid -unit $unit
            $ctx["neutron_admin_password"] = relation_get -attr 'service_password' -rid $rid -unit $unit
            $ctx_complete = Check-ContextComplete -ctx $ctx
            if ($ctx_complete){
                break
            }
        }
    }
    $ctx_complete = Check-ContextComplete -ctx $ctx
    if (!$ctx_complete){
        Write-JujuLog "Missing required relation settings for Neutron. Peer not ready?"
        return @{}
    }
    $ctx["neutron_admin_auth_url"] = $ctx["auth_protocol"] + "://" + $ctx['keystone_host'] + ":" + $ctx['auth_port'].Trim('"') + "/v2.0"
    $ctx["local_ip"] = unit_private_ip
    return $ctx
}

function Get-GlanceContext {
    Write-JujuLog "Getting glance context"
    $rids = relation_ids -reltype 'image-service'
    if(!$rids){
        return @{}
    }
    foreach ($i in $rids){
        $units = related_units -relid $i
        foreach ($j in $units){
            $api_server = relation_get -attr 'glance-api-server' -rid $i -unit $j
            if($api_server){
                return @{"glance_api_servers"=$api_server}
            }
        }
    }
    Write-JujuLog "Glance context not yet complete. Peer not ready?"
    return @{}
}


function Get-CharmConfigContext {
    $config = charm_config
    $asHash = @{}
    foreach ($i in $config.GetEnumerator()){
        $name = $i.Key
        if($name -eq "instances-dir"){
            continue
        }
        if($i.Value.Gettype() -is [System.String]){
            $v = ($i.Value).Replace('/', '\')
        }else{
            $v = $i.Value
        }
        $asHash[$name.Replace("-", "_")] = $v 
    }
    $asHash["my_ip"] = unit_private_ip
    return $asHash
}

function Get-SystemContext {
    $asHash = @{
        "nova_dir" = Get-NovaDir;
        "force_config_drive" = "False";
        "config_drive_inject_password" = "False";
        "config_drive_cdrom" = "False";
    }
    if((Is-NanoServer)){
        $asHash["force_config_drive"] = "True";
        $asHash["config_drive_inject_password"] = "True";
        $asHash["config_drive_cdrom"] = "True";
    }
    return $asHash
}

function Generate-Config {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )
    $JujuCharmServices = Charm-Services
    $should_restart = $true
    $service = $JujuCharmServices[$ServiceName]
    if (!$service){
        Write-JujuError -Msg "No such service $ServiceName" -Fatal $false
        return $false
    }
    $config = gc $service["template"]
    # populate config with variables from context
    foreach ($context in $service['context_generators']){
        Write-JujuLog "Getting context for $context"
        $ctx = & $context
        Write-JujuLog "Got $context context $ctx"
        if ($ctx.Count -eq 0){
            # Context is empty. Probably peer not ready
            Write-JujuLog "Context for $context is EMPTY"
            $should_restart = $false
            continue
        }
        foreach ($val in $ctx.GetEnumerator()) {
            $regex = "{{[\s]{0,}" + $val.Name + "[\s]{0,}}}"
            $config = $config -Replace $regex,$val.Value
        }
    }
    # Any variables not available in context we remove
    $config = $config -Replace "{{[\s]{0,}[a-zA-Z0-9_-]{0,}[\s]{0,}}}",""
    Set-Content $service["config"] $config
    # Restart-Service $service["service"]
    return $should_restart
}

function Get-FallbackNetadapter {
    $name = Get-MainNetadapter
    $net = Get-NetAdapter -Name $name
    return $net
}

function Get-InterfaceFromConfig {
    Param (
        [string]$ConfigOption="data-port",
        [switch]$MustFindAdapter=$false
    )

    $nic = $null
    $DataInterfaceFromConfig = charm_config -scope $ConfigOption
    Write-JujuLog "Looking for $DataInterfaceFromConfig"
    if ($DataInterfaceFromConfig -eq $false -or $DataInterfaceFromConfig -eq ""){
        if($MustFindAdapter) {
            Throw "No data-port was specified"
        }
        return $null
    }
    $byMac = @()
    $byName = @()
    $macregex = "^([a-f-A-F0-9]{2}:){5}([a-fA-F0-9]{2})$"
    foreach ($i in $DataInterfaceFromConfig.Split()){
        if ($i -match $macregex){
            $byMac += $i.Replace(":", "-")
        }else{
            $byName += $i
        }
    }
    Write-JujuLog "We have MAC: $byMac  Name: $byName"
    if ($byMac.Length -ne 0){
        $nicByMac = Get-NetAdapter | Where-Object { $_.MacAddress -in $byMac }
    }
    if ($byName.Length -ne 0){
        $nicByName = Get-NetAdapter | Where-Object { $_.Name -in $byName }
    }
    if ($nicByMac -ne $null -and $nicByMac.GetType() -ne [System.Array]){
        $nicByMac = @($nicByMac)
    }
    if ($nicByName -ne $null -and $nicByName.GetType() -ne [System.Array]){
        $nicByName = @($nicByName)
    }
    $ret = $nicByMac + $nicByName
    if ($ret.Length -eq 0 -and $MustFindAdapter){
        Throw "Could not find network adapters"
    }
    return $ret
}

function Get-RealInterface {
    Param(
        [system.object]$interface
    )
    # TODO(gabriel-samfira): this must be replaced with proper implementation
    if($interface.Name.StartsWith("vEthernet")){
        $bridgeName = $interface.Name.Replace('vEthernet (', '').Replace(')', '')
        $br = get-vmswitch -name $bridgeName
        $interface = Get-NetAdapter -InterfaceDescription $br.NetAdapterInterfaceDescription
        Write-JujuLog "Getting parent $adapter"
    }
    return $interface
}

function Get-DataPortFromDataNetwork {

    $dataNetwork = charm_config -scope "os-data-network"
    if ($dataNetwork -eq $false -or $dataNetwork -eq "") {return $false}
    $netDetails = $dataNetwork.Split("/")
    $decimalMask = ConvertTo-Mask $netDetails[1]

    $configuredAddresses = Get-NetIPAddress -AddressFamily IPv4
    foreach ($i in $configuredAddresses){
        if ($i.PrefixLength -ne $netDetails[1]){
            continue
        }
        $network = Get-NetworkAddress $i.IPv4Address $i.PrefixLength
        if ($network -eq $netDetails[0]){
            return Get-NetAdapter -ifindex $i.IfIndex
        }
    }
    return $false
}

function Reset-Bond {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$switch
    )
    # This charm assumes that no human intervention will be done on a machine
    # configured by it. As such, the bond name is hardcoded.
    # TODO: make the bond name a config option.
    $enabled = charm_config -scope "use-bonding"
    if (!$enabled) { return $false }

    $isUp = WaitFor-BondUp -bond "bond0"
    if (!$isUp){
        $s = Get-VMSwitch -name $switch -ErrorAction SilentlyContinue
        if ($s){
            stop-vm *
            Remove-VMSwitch -Name $VMswitchName -Confirm:$false -Force
        }
        $bond = Get-NetLbfoTeam -name "bond0" -ErrorAction SilentlyContinue
        if($bond){
            Remove-NetlbfoTeam -name "bond0" -Confirm:$false
        }
        Setup-BondInterface
        return $true
    }
    return $false
}

function Get-OVSDataPort {
    $dataPort = Get-DataPortFromDataNetwork
    if ($dataPort){
        $port = $dataPort
    }else{
        $port = Get-FallbackNetadapter
    }

    return Get-RealInterface $port
}

function Get-DataPort {
    # try and set up bonding early. This will create
    # a new Net-LbfoTeam and try to acquire an IP address
    # via DHCP. This interface may receive os-data-network IP.
    $useBonding = Setup-BondInterface
    $managementOS = charm_config -scope "vmswitch-management"

    $net_type = Get-NetType
    Write-JujuLog "NetType is $net_type"
    if ($net_type -eq "ovs"){
        Write-JujuLog "Trying to fetch OVS data port"
        $dataPort = Get-OVSDataPort
        return @($dataPort[0], $true)
    }

    if ($useBonding) {
        $adapter = Get-NetAdapter -Name "bond0"
        return @($adapter, $managementOS)
    }

    Write-JujuLog "Trying to fetch data port from config"
    $nic = Get-InterfaceFromConfig
    if(!$nic) {
        $nic = Get-FallbackNetadapter
        $managementOS = $true
    }
    $nic = Get-RealInterface $nic[0]
    return @($nic, $managementOS)
}

function Juju-ConfigureVMSwitch {
    $dataPort, $managementOS = Get-DataPort
    $useBonding = charm_config -scope "use-bonding"

    $VMswitches = Get-VMSwitch -SwitchType External -ErrorAction SilentlyContinue
    $VMswitchName = Juju-GetVMSwitch
    Write-JujuLog "Found switch $VMswitchName"
    if ($VMswitches -and $VMswitches.Count -gt 0){
        $vmswitch = $VMswitches[0]
        Write-JujuLog "Renaming switch"
        Rename-VMSwitch $vmswitch -NewName $VMswitchName
        Write-JujuLog "renamed switch"
    }else{
        $vmswitch = $false
    }

    if ($vmswitch){
        if ($useBonding) {
            # There is a bug in the teaming feature with some drivers. If you create a VMSwitch using a bond
            # as external. After a reboot, the bond will be down unless you remove the vmswitch
            Reset-Bond $vmswitch.Name
        }
    }else{
        Write-JujuLog "Adding new vmswitch"
        New-VMSwitch -Name $VMswitchName -NetAdapterName $dataPort.Name -AllowManagementOS $managementOS
        return $true
    }

    $configuredPort = $vmswitch.NetAdapterInterfaceDescription
    $configuredManagementOS = $vmswitch.AllowManagementOS

    if ($configuredPort -ne $dataPort.InterfaceDescription -or $configuredManagementOS -ne $managementOS){
        $n = $dataPort.Name
        Set-VMSwitch -Name $VMswitchName -AllowManagementOS $managementOS -NetAdapterName $dataPort.Name
    }
    return $true
}

function Invoke-FastWebRequest
{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=0)]
    [System.Uri]$Uri,
    [Parameter(Mandatory=$True,Position=1)]
    [string]$OutFile
    )
    PROCESS
    {
        $client = new-object System.Net.Http.HttpClient
        $task = $client.GetAsync($Uri)
        $task.wait()
        $response = $task.Result
        $status = $response.EnsureSuccessStatusCode()

        $outStream = New-Object IO.FileStream $OutFile, Create, Write, None

        try
        {
            $task = $response.Content.ReadAsStreamAsync()
            $task.Wait()
            $inStream = $task.Result
            
            $buffer = New-Object Byte[] 1024    
            while (($read = $inStream.Read($buffer, 0, $buffer.Length)) -gt 0) 
            {
                $outStream.Write($buffer, 0, $read);    
            }
        }
        finally
        {
            $outStream.Close()
        }
    }
}

function Download-File {
     param(
        [Parameter(Mandatory=$true)]
        [string]$url
    )
    $URI = [System.Uri]$url
    $msi = $URI.segments[-1]
    $download_location = Join-Path "$env:TEMP" $msi

    if ($URI.fragment){
        $fragment = $URI.fragment.Trim("#").Split("=")
        if($fragment[0] -eq "md5"){
            $md5 = $fragment[1]
        }
    }

    $fileExists = Test-Path $download_location
    if ($fileExists){
        if ($md5){
            $fileHash = (Get-FileHash -Algorithm MD5 $download_location).Hash
            if ($fileHash -eq $md5){
                return $download_location
            }
        }else{
            return $download_location
        }
    }
    Write-JujuLog "Downloading file from $url to $download_location"
    try {
        if((Is-NanoServer)){
            ExecuteWith-Retry { Invoke-FastWebRequest -Uri $url -OutFile $download_location }
        } else {
            ExecuteWith-Retry { (new-object System.Net.WebClient).DownloadFile($url, $download_location) }
        }
    } catch {
        Write-JujuError "Could not download $url to destination $download_location"
    }

    return $download_location
}

function Get-NovaInstaller {
    $distro = Get-OpenstackVersion
    $installer_url = charm_config -scope "installer-url"
    if ($distro -eq $false){
        $distro = "liberty"
    }
    Write-JujuLog "URL: $installer_url"
    if ($installer_url -eq $false -or $installer_url -eq "") {
        if (!$distro_urls[$distro] -or !$distro_urls[$distro]["installer"]){
            Write-JujuError "Could not find a download URL for $distro"
        }
        if ((Is-NanoServer))  {
            if (!$distro_urls[$distro]["installer"]["zip"]) {
                Write-JujuError "Distro $distro does not support Nano server"
            }
            $url = $distro_urls[$distro]["installer"]["zip"]
        } else {
            $url = $distro_urls[$distro]["installer"]["msi"]
        }
    }else {
        $url = $installer_url
    }
    $location = Download-File $url
    return $location
}

function Install-NovaFromMSI {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath
    )
    Write-JujuLog "Running Nova install"
    $hasInstaller = Test-Path $InstallerPath
    if($hasInstaller -eq $false){
        $InstallerPath = Get-NovaInstaller
    }
    Write-JujuLog "Installing from $InstallerPath"
    cmd.exe /C call msiexec.exe /i $InstallerPath /qn /l*v $env:APPDATA\log.txt SKIPNOVACONF=1

    if ($lastexitcode){
        Write-JujuError "Nova failed to install"
    }
    return $true
}

function Install-NovaFromZip {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath
    )
    $files = Join-Path $env:CHARM_DIR "files"
    $policyFile = Join-Path $files "policy.json"
    $novaDir = Get-NovaDir
    if((Test-Path $novaDir)){
        rm -Recurse -Force $novaDir
    }
    $configDir = Join-Path $novaDir "etc"
    Extract-FromZip -Archive $InstallerPath -Destination $novaDir
    if (!(Test-Path $configDir)){
        mkdir $configDir
        cp $policyFile $configDir
    }
    return $true
}

function Install-Nova {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath
    )
    if ($InstallerPath.EndsWith(".zip")){
        return Install-NovaFromZip $InstallerPath
    }
    return Install-NovaFromMSI $InstallerPath
}

function Disable-Service {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )

    $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($svc -eq $null) {
        return $true
    }
    Get-Service $ServiceName | Set-Service -StartupType Disabled
}

function Enable-Service {
     param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )

    Get-Service $ServiceName | Set-Service -StartupType Automatic
}

function Get-OVSInstaller {
    $installer_url = charm_config -scope "ovs-installer-url"
    if ($installer_url -eq $false) {
        Throw "Could not find a download URL for $distro"
    }else {
        $url = $installer_url
    }
    $location = Download-File $url
    return $location
}

function Run-CommandMustSucceed {
    Param(
        [Parameter(Mandatory=$true)]
        [array]$cmd
    )
    if ($cmd.Length -gt 1){
        & $cmd[0] $cmd[1..$cmd.Length]
    }else{
        & $cmd[0]
    }

    if ($LASTEXITCODE){
        Throw ("Failed to run: " + $cmd -Join " ")
    }
}

function Ensure-InternalOVSInterfaces {
    Run-CommandMustSucceed @($ovs_vsctl, "--may-exist", "add-br", "br-tun")
    Run-CommandMustSucceed @($ovs_vsctl, "--may-exist", "add-port", "br-tun", "external.1")
    Run-CommandMustSucceed @($ovs_vsctl, "--may-exist", "add-port", "br-tun", "internal")
}

function Install-OVS {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath
    )

    Write-JujuLog "Running OVS install"
    $ovs = gwmi Win32_Product | Where-Object {$_.Name -match "open vswitch"}
    if ($ovs){
        Write-JujuLog "OVS is already installed"
        return
    }
    $hasInstaller = Test-Path $InstallerPath
    if($hasInstaller -eq $false){
        $InstallerPath = Get-OVSInstaller
    }
    Write-JujuLog "Installing from $InstallerPath"
    cmd.exe /C call msiexec.exe /i $InstallerPath /qn /l*v $env:APPDATA\ovs-log.txt

    if ($lastexitcode){
        Write-JujuError "OVS FAILED to install"
    }
    return $true
}

function Check-OVSPrerequisites {
    $services = Charm-Services
    try {
        $ovsdbSvc = Get-Service "ovsdb-server"
        $ovsSwitchSvc = Get-Service "ovs-vswitchd"
    } catch {
        $InstallerPath = Get-OVSInstaller
        Install-OVS $InstallerPath
    }
    if(!(Test-Path $ovs_vsctl)){
        Write-JujuError "Could not find ovs_vsctl.exe in location: $ovs_vsctl"
    }

    try {
        $ovsAgent = Get-Service $services["neutron-ovs"]["service"]
    } catch {
        $name = $services["neutron-ovs"].service
        $svcPath = $services["neutron-ovs"].serviceBinPath
        Create-Service -Name $name -Path $svcPath -Description "Neutron Open vSwitch Agent"
        Disable-Service $name
    }
}

function Check-ServicePrerequisites {
    $services = Charm-Services
    $hypervAgent = Get-Service $services["neutron"]["service"] -ErrorAction SilentlyContinue
    $novaCompute = Get-Service $services["nova"]["service"] -ErrorAction SilentlyContinue

    if(!$hypervAgent) {
        $name = $services["neutron"]["service"]
        $svcPath = $services["neutron"]["serviceBinPath"]
        Create-Service -Name $name -Path $svcPath -Description "Neutron Hyper-V Agent"
        Disable-Service $name
    }

    if(!$novaCompute){
        $name = $services["nova"]["service"]
        $svcPath = $services["nova"]["serviceBinPath"]
        Create-Service -Name $name -Path $svcPath -Description "Nova Compute"
    }
}

function Get-OVSExtStatus {
    $br = Juju-GetVMSwitch
    Write-JujuLog "Switch name is $br"
    $ext = Get-VMSwitchExtension -VMSwitchName $br -Name $ovsExtName

    if ($ext -eq $null){
        Write-JujuLog "Open vSwitch extension not installed"
        return $null
    }

    return $ext
}

function Enable-OVSExtension {
    $ext = Get-OVSExtStatus
    if ($ext -eq $null){
       Write-JujuError "Cannot enable OVS extension. Not installed"
    }
    if ($ext.Enabled -eq $false) {
        Enable-VMSwitchExtension $ovsExtName $ext.SwitchName
    }
    return $true
}

function Disable-OVSExtension {
    $ext = Get-OVSExtStatus
    if ($ext -ne $null -and $ext.Enabled -eq $true) {
        Disable-VMSwitchExtension $ovsExtName $ext.SwitchName
    }
    return $true
}

function Disable-OVS {
    Stop-Service "ovs-vswitchd" -ErrorAction SilentlyContinue
    Stop-Service "ovsdb-server" -ErrorAction SilentlyContinue

    Disable-Service "ovs-vswitchd"
    Disable-Service "ovsdb-server"

    Disable-OVSExtension
}

function Enable-OVS {
    Enable-OVSExtension

    Enable-Service "ovsdb-server"
    Enable-Service "ovs-vswitchd"

    Start-Service "ovsdb-server"
    Start-Service "ovs-vswitchd"
}

function Configure-NeutronAgent {
    $services = Charm-Services
    $vmswitch = Juju-GetVMSwitch
    $net_type = Get-NetType

    if ($net_type -eq "hyperv"){
        Disable-Service $services["neutron-ovs"]["service"]
        Stop-Service $services["neutron-ovs"]["service"] -ErrorAction SilentlyContinue

        Disable-OVS
        Enable-Service $services["neutron"]["service"]

        return $services["neutron"]
    }

    Check-OVSPrerequisites

    Disable-Service $services["neutron"]["service"]
    Stop-Service $services["neutron"]["service"]

    Enable-OVS
    Enable-Service $services["neutron-ovs"]["service"]

    Ensure-InternalOVSInterfaces
    return $services["neutron-ovs"]
}

function Restart-Neutron {
    $svc = Configure-NeutronAgent
    Stop-Service $svc.service
    Start-Service $svc.service
}

function Restart-Nova {
    $services = Charm-Services
    Stop-Service $services.nova.service
    Start-Service $services.nova.service
}

function Stop-Neutron {
    $services = Charm-Services
    Stop-Service $services.neutron.service
}

function Import-CloudbaseCert {
    Param(
    [switch]$NoRestart = $false
    )
    $filesDir = Get-FilesDir
    $crt = Join-Path $filesDir "Cloudbase_signing.cer"
    if (!(Test-Path $crt)){
        return $false
    }
    Import-Certificate $crt -StoreLocation LocalMachine -StoreName TrustedPublisher
}

function Run-ConfigChanged {
    Juju-ConfigureVMSwitch
    Check-ServicePrerequisites
    Generate-ExeWrappers
    
    $net_type = Get-NetType

    if ($net_type -eq "ovs"){
        $neutron_restart = Generate-Config -ServiceName "neutron-ovs"
    }else{
        $neutron_restart = Generate-Config -ServiceName "neutron"
    }

    $nova_restart = Generate-Config -ServiceName "nova"
    $JujuCharmServices = Charm-Services

    if ($nova_restart){
        juju-log.exe "Restarting service Nova"
        Restart-Nova
    }

    if ($neutron_restart){
        juju-log.exe "Restarting service Neutron"
        Restart-Neutron
    }
    if($nova_restart -and $neutron_restart){
        status-set.exe "active"
    }
}

Export-ModuleMember -Function * -Variable JujuCharmServices
