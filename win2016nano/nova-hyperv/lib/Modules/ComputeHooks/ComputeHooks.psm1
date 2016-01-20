#
# Copyright 2014 Cloudbase Solutions SRL
#

Import-Module JujuHelper
Import-Module JujuHooks
Import-Module JujuUtils
Import-Module JujuWindowsUtils
Import-Module Networking

$installDir = "${env:ProgramFiles}\Cloudbase Solutions\OpenStack\Nova"
$novaDir = $installDir

$ovsInstallDir = "${env:ProgramFiles}\Cloudbase Solutions\Open vSwitch"
$ovs_vsctl = Join-Path $ovsInstallDir "bin\ovs-vsctl.exe"
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
            'msi' = 'https://cloudbase.it/downloads/HyperVNovaCompute_Liberty_12_0_0.msi#md5=71b77c82dd7990891e108a98a1ecd234';
            'zip' = 'https://www.cloudbase.it/downloads/HyperVNovaCompute_Liberty_12_0_0.zip';
        };
        "ovs" = $true;
    };
}

function Install-Prerequisites
{
    if ((Get-IsNanoServer)){
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
            Invoke-JujuReboot -Now
        }
    }else{
        if ($needsHyperV.RestartNeeded){
            Invoke-JujuReboot -Now
        }
    }
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -All -NoRestart
    Import-Module hyper-v
}


function Get-OpenstackVersion {
    $distro = Get-JujuCharmConfig -Scope "openstack-version"
    if($distro -eq $false){
        $distro = Get-JujuCharmConfig -Scope "openstack-origin"
    }
    return $distro
}

function Get-NetType {
    $net_type = Get-JujuCharmConfig -Scope "network-type"

    $distro = Get-OpenstackVersion
    if($distro_urls["ovs"] -eq $false -or (Get-IsNanoServer)){
        #force hyperv network manager for versions that do now support ovs
        $net_type = "hyperv"
    }
    return $net_type
}

function Juju-GetVMSwitch {
    $VMswitchName = Get-JujuCharmConfig -Scope "vmswitch-name"
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
    if(!(Get-IsNanoServer)){
        return
    }
    $pythonDir = Join-Path $novaDir "Python27"
    $python = Join-Path $pythonDir "python.exe"
    $updateWrapper = Join-Path $pythonDir "Scripts\UpdateWrappers.py"

    $cmd = @($python, $updateWrapper, "nova-compute = nova.cmd.compute:main")
    Invoke-JujuCommand -Command $cmd | Out-Null

    $cmd = @($python, $updateWrapper, "neutron-hyperv-agent = neutron.cmd.eventlet.plugins.hyperv_neutron_agent:main")
    Invoke-JujuCommand -Command $cmd
}

function New-BondInterface {
    if((Get-IsNanoServer)){
        # not supported on nano yet
        return $false
    }
    $name = Get-JujuCharmConfig -Scope "bond-name"
    $bondPorts = Get-InterfaceFromConfig -ConfigOption "bond-ports"
    if ($bondPorts.Length -eq 0) {
        return $false
    }

    $bondExists = Get-NetLbfoTeam -Name $name -ErrorAction SilentlyContinue
    if ($bondExists){
        return $true
    }

    $bond = New-NetLbfoTeam -Name $name -TeamMembers $bondPorts.Name -TeamNicName $name -TeamingMode LACP -Confirm:$false
    $isUp = WaitFor-BondUp -bond $bond.Name
    if (!$isUp){
        Throw "Failed to bring up $name"
    }

    $adapter = Get-NetAdapter -Name $name
    if(!$adapter){
        Throw "Failed to find $name"
    }
    $returnCode = Invoke-DHCPRenew $adapter
    if($returnCode -eq 1) {
        Invoke-JujuReboot -Now
    }
    return $name
}

function Get-TemplatesDir {
    $charmDir = Get-JujuCharmDir
    $templates =  Join-Path $charmDir "templates"
    return $templates
}

function Get-PackageDir {
    $charmDir = Get-JujuCharmDir
    $packages =  Join-Path $charmDir "packages"
    return $packages
}

function Get-FilesDir {
    $charmDir = Get-JujuCharmDir
    $packages =  Join-Path $charmDir "files"
    return $packages
}

function Install-RootWrap {
    $template = Get-TemplatesDir
    $rootWrap = Join-Path $template "ovs\rootwrap.cmd"

    if(!(Test-Path $rootWrap)){
        return $true
    }

    $dst = Join-Path $novaDir "bin\rootwrap.cmd"
    $parent = Split-Path -Path $dst -Parent
    $exists = Test-Path $parent
    if (!$exists){
        mkdir $parent | Out-Null
    }
    cp $rootWrap $dst
    return $true
}

function Get-CharmServices {
    $template_dir = Get-TemplatesDir
    $distro = Get-OpenstackVersion
    $nova_config = Join-Path $novaDir "etc\nova.conf"
    $neutron_config = Join-Path $novaDir "etc\neutron_hyperv_agent.conf"
    $neutron_ml2 = Join-Path $novaDir "etc\ml2_conf.ini"

    $serviceWrapperNova = Join-Path $novaDir "bin\OpenStackServiceNova.exe"
    $serviceWrapperNeutron = Join-Path $novaDir "bin\OpenStackServiceNeutron.exe"
    $novaExe = Join-Path $novaDir "Python27\Scripts\nova-compute.exe"
    $neutronHypervAgentExe = Join-Path $novaDir "Python27\Scripts\neutron-hyperv-agent.exe"
    $neutronOpenvswitchExe = Join-Path $novaDir "Python27\Scripts\neutron-openvswitch-agent.exe"

    $JujuCharmServices = @{
        "nova"=@{
            "myname"="nova";
            "template"="$template_dir\$distro\nova.conf";
            "service"="nova-compute";
            "binpath"="$novaExe";
            "serviceBinPath"="`"$serviceWrapperNova`" nova-compute `"$novaExe`" --config-file `"$nova_config`"";
            "config"="$nova_config";
            "context_generators"=@(
                @{
                    "generator"="Get-RabbitMQContext";
                    "relation"="amqp";
                },
                @{
                    "generator"="Get-NeutronContext";
                    "relation"="cloud-compute";
                },
                @{
                    "generator"="Get-GlanceContext";
                    "relation"="image-service";
                },
                @{
                    "generator"="Get-CharmConfigContext";
                    "relation"="config";
                },
                @{
                    "generator"="Get-SystemContext";
                    "relation"="system";
                },
                @{
                    "generator"="Get-S2DContainerContext";
                    "relation"="s2d";
                }
                );
        };
        "neutron"=@{
            "myname"="neutron";
            "template"="$template_dir\$distro\neutron_hyperv_agent.conf"
            "service"="neutron-hyperv-agent";
            "binpath"="$neutronHypervAgentExe";
            "serviceBinPath"="`"$serviceWrapperNeutron`" neutron-hyperv-agent `"$neutronHypervAgentExe`" --config-file `"$neutron_config`"";
            "config"="$neutron_config";
            "context_generators"=@(
                @{
                    "generator"="Get-RabbitMQContext";
                    "relation"="amqp";
                },
                @{
                    "generator"="Get-NeutronContext";
                    "relation"="cloud-compute";
                },
                @{
                    "generator"="Get-CharmConfigContext";
                    "relation"="config";
                },
                @{
                    "generator"="Get-SystemContext";
                    "relation"="system";
                },
                @{
                    "generator"="Get-S2DContainerContext";
                    "relation"="s2d";
                }
                );
        };
        "neutron-ovs"=@{
            "myname"="neutron-ovs";
            "template"="$template_dir\$distro\ml2_conf.ini"
            "service"="neutron-openvswitch-agent";
            "binpath"="$neutronOpenvswitchExe";
            "serviceBinPath"="`"$serviceWrapperNeutron`" neutron-openvswitch-agent `"$neutronOpenvswitchExe`" --config-file `"$neutron_ml2`"";
            "config"="$neutron_ml2";
            "context_generators"=@(
                @{
                    "generator"="Get-RabbitMQContext";
                    "relation"="amqp";
                },
                @{
                    "generator"="Get-NeutronContext";
                    "relation"="cloud-compute";
                },
                @{
                    "generator"="Get-CharmConfigContext";
                    "relation"="config";
                },
                @{
                    "generator"="Get-SystemContext";
                    "relation"="system";
                },
                @{
                    "generator"="Get-S2DContainerContext";
                    "relation"="s2d";
                }
                );
        };
    }
    return $JujuCharmServices
}


function Get-RabbitMQContext {
    Write-JujuLog "Generating context for RabbitMQ"
    $username = Get-JujuCharmConfig -Scope 'rabbit-user'
    $vhost = Get-JujuCharmConfig -Scope 'rabbit-vhost'
    if (!$username -or !$vhost){
        Write-JujuError "Missing required charm config options: rabbit-user or rabbit-vhost"
    }

    $required = @{
        "hostname"=$null;
        "password"=$null;
    }

    $ctx = Get-JujuRelationContext -Relation "amqp" -RequiredContext $required

    if($ctx.Count) {
        $ctx["rabbit_userid"] = $username;
        $ctx["rabbit_virtual_host"] = $vhost;
        $ctx["rabbit_host"]=$ctx["hostname"];
        $ctx["rabbit_password"]=$ctx["password"];
        $ctx.Remove("hostname")
        $ctx.Remove("password")
    }
    return $ctx
}


function Get-NeutronUrl {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$rid,
        [Parameter(Mandatory=$true)]
        [string]$unit
    )
    foreach($i in @("neutron_url", "quantum_url")) {
        $url = Get-JujuRelation -Attribute 'neutron_url' -RelationID $rid -Unit $unit
        if ($url){
            return $url
        }
    }
    return
}


function Get-S2DContainerContext {
    $instancesDir = (Get-JujuCharmConfig -Scope 'instances-dir').Replace('/', '\')
    $ctx = @{
        "instances_dir"=$instancesDir;
    }

    $required = @{
        "s2dvolpath"=$null;
    }

    $ctx = Get-JujuRelationContext -Relation "s2d" -RequiredContext $required
    if($ctx.Count){
        if($ctx["s2dvolpath"] -and (Test-Path $ctx["s2dvolpath"])){
            $ctx["instances_dir"] = $ctx["s2dvolpath"]
            return $ctx
        }
        Write-JujuWarning "Relation information states that an s2d volume should be present, but could not be found locally."
    }
    $ctx["instances_dir"] = $instancesDir
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

    $required = @{
        "auth_host"=$null;
        "auth_port"=$null;
        "auth_protocol"=$null;
        "service_tenant_name"=$null;
        "service_username"=$null;
        "service_password"=$null;
    }

    $optionalCtx = @{
        "neutron_url"=$null;
        "quantum_url"=$null;
    }

    $ctx = Get-JujuRelationContext -Relation 'cloud-compute' -RequiredContext $required -OptionalContext $optionalCtx

    if(!$ctx.Count -or (!$ctx["neutron_url"] -and !$ctx["quantum_url"])) {
        Write-JujuWarning "Missing required relation settings for Neutron. Peer not ready?"
        return @{}
    }

    if(!$ctx["neutron_url"]){
        $ctx["neutron_url"] = $ctx["quantum_url"]
    }
    $ctx["neutron_auth_strategy"] = "keystone"
    $ctx["log_dir"] = $logdir
    $ctx["vmswitch_name"] = $switchName
    $ctx["neutron_admin_auth_url"] =  "{0}://{1}:{2}/v2.0" -f @($ctx["auth_protocol"], $ctx['auth_host'], $ctx['auth_port'])
    $ctx["local_ip"] = (Get-CharmState -Namespace "novahyperv" -Key "local_ip")
    return $ctx
}

function Get-GlanceContext {
    Write-JujuLog "Getting glance context"
    $rids = relation_ids -reltype 'image-service'
    if(!$rids){
        return @{}
    }

    $required = @{
        "glance-api-server"=$null;
    }
    $ctx = Get-JujuRelationContext -Relation 'image-service' -RequiredContext $required -OptionalContext $optionalCtx
    $new = @{}
    foreach($i in $ctx.Keys){
        $new[$i.Replace("-", "_")] = $ctx[$i]
    }
    return $new
}


function Get-CharmConfigContext {
    $config = Get-JujuCharmConfig
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
    $asHash["my_ip"] = Get-JujuUnitPrivateIP
    return $asHash
}

function Get-SystemContext {
    $asHash = @{
        "installDir" = $installDir;
        "force_config_drive" = "False";
        "config_drive_inject_password" = "False";
        "config_drive_cdrom" = "False";
    }
    if((Get-IsNanoServer)){
        $asHash["force_config_drive"] = "True";
        $asHash["config_drive_inject_password"] = "True";
        $asHash["config_drive_cdrom"] = "True";
    }
    return $asHash
}

function Set-IncompleteStatusContext {
    Param(
        [array]$ContextSet=@(),
        [array]$Incomplete=@()
    )
    $status = Get-JujuStatus -Full
    $currentIncomplete = @()
    if($status["message"]){
        $msg = $status["message"].Split(":")
        if($msg.Count -ne 2){
            return
        }
        if($msg[0] -eq "Incomplete contexts") {
            $currentIncomplete = $msg[1].Split(", ")
        }
    }
    $newIncomplete = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
    if(!$Incomplete){
        foreach($i in $currentIncomplete) {
            if ($i -in $ContextSet){
                continue
            }
            $newIncomplete.Add($i)
        }
    } else {
        foreach($i in $currentIncomplete) {
            if($i -in $ContextSet -and !($i -in $Incomplete)){
                continue
            } else {
                $newIncomplete.Add($i)
            }
        }
        foreach($i in $Incomplete) {
            if ($i -in $newIncomplete) {
                continue
            }
            $newIncomplete.Add($i)
        }
    }
    if($newIncomplete){
        $msg = "Incomplete contexts: {0}" -f ($newIncomplete -Join ", ")
        Set-JujuStatus -Status blocked -Message $msg
    } else {
        Set-JujuStatus -Status waiting -Message "Contexts are complete"
    }
}

function Generate-Config {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )
    $JujuCharmServices = Get-CharmServices
    $should_restart = $true
    $service = $JujuCharmServices[$ServiceName]
    if (!$service){
        Write-JujuWarning "No such service $ServiceName. Not generating config"
        return $false
    }
    $config = gc $service["template"]
    # populate config with variables from context
    
    $incompleteContexts = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
    $allContexts = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")

    foreach ($context in $service['context_generators']){
        Write-JujuInfo "Getting context for $context"
        $allContexts.Add($context["relation"])
        $ctx = & $context["generator"]
        Write-JujuInfo "Got $context context $ctx"
        if (!$ctx.Count){
            # Context is empty. Probably peer not ready
            Write-JujuWarning "Context for $context is EMPTY"
            $incompleteContexts.Add($context["relation"])
            $should_restart = $false
            continue
        }
        foreach ($val in $ctx.GetEnumerator()) {
            $regex = "{{[\s]{0,}" + $val.Name + "[\s]{0,}}}"
            $config = $config -Replace $regex,$val.Value
        }
    }
    Set-IncompleteStatusContext -ContextSet $allContexts -Incomplete $incompleteContexts
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
    $DataInterfaceFromConfig = Get-JujuCharmConfig -Scope $ConfigOption
    Write-JujuInfo "Looking for $DataInterfaceFromConfig"
    if (!$DataInterfaceFromConfig){
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
    if ($byMac.Length){
        $nicByMac = Get-NetAdapter | Where-Object { $_.MacAddress -in $byMac -and $_.DriverFileName -ne "vmswitch.sys" }
    }
    if ($byName.Length){
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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Microsoft.Management.Infrastructure.CimInstance]$interface
    )
    PROCESS {
        if($interface.DriverFileName -ne "vmswitch.sys") {
            return $interface
        }
        $realInterface = Get-NetAdapter | Where-Object {
            $_.MacAddress -eq $interface.MacAddress -and $_.ifIndex -ne $interface.ifIndex
        }

        if(!$realInterface){
            Throw "Failed to find interface attached to VMSwitch"
        }
        return $realInterface
    }
}

function Confirm-LocalIP {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$IPaddress,
        [Parameter(Mandatory=$true)]
        [int]$ifIndex
    )
    PROCESS {
        $exists = Get-NetIPAddress -IPAddress $IPaddress -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue
        return ($exists -ne $null)
    }
}

function Get-DataPortFromDataNetwork {

    $dataNetwork = Get-JujuCharmConfig -Scope "os-data-network"
    if (!$dataNetwork) {
        Write-JujuInfo "os-data-network is not defined"
        return $false
    }

    $local_ip = Get-CharmState -Namespace "novahyperv" -Key "local_ip"
    $ifIndex = Get-CharmState -Namespace "novahyperv" -Key "dataNetworkIfindex"

    if($local_ip -and $ifIndex){
        if((Confirm-LocalIP -IPaddress $ifIndex -ifIndex $ifIndex)){
            return Get-NetAdapter -ifindex $ifIndex
        }
    }

    # If there is any network interface configured to use DHCP and did not get an IP address
    # we manually renew its lease and try to get an IP address before searching for the data network
    $interfaces = Get-CimInstance -Class win32_networkadapterconfiguration | Where-Object { 
        $_.IPEnabled -eq $true -and $_.DHCPEnabled -eq $true -and $_.DHCPServer -eq "255.255.255.255"
    }
    if($interfaces){
        $interfaces.InterfaceIndex | Invoke-DHCPRenew -ErrorAction SilentlyContinue
    }
    $netDetails = $dataNetwork.Split("/")
    $decimalMask = ConvertTo-Mask $netDetails[1]

    $configuredAddresses = Get-NetIPAddress -AddressFamily IPv4
    foreach ($i in $configuredAddresses) {
        Write-JujuInfo ("Checking {0} on interface {1}" -f @($i.IPAddress, $i.InterfaceAlias))
        if ($i.PrefixLength -ne $netDetails[1]){
            continue
        }
        $network = Get-NetworkAddress $i.IPv4Address $decimalMask
        Write-JujuInfo ("Network address for {0} is {1}" -f @($i.IPAddress, $network))
        if ($network -eq $netDetails[0]){
            Set-CharmState -Namespace "novahyperv" -Key "local_ip" -Value $i.IPAddress
            Set-CharmState -Namespace "novahyperv" -Key "dataNetworkIfindex" -Value $i.IfIndex
            return Get-NetAdapter -ifindex $i.IfIndex
        }
    }
    return $false
}

function Get-OVSDataPort {
    $dataPort = Get-DataPortFromDataNetwork
    if ($dataPort){
        return Get-RealInterface $dataPort
    }else{
        $port = Get-FallbackNetadapter
        $local_ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $port.IfIndex -ErrorAction SilentlyContinue
        if(!$local_ip){
            Throw "failed to get fallback adapter IP address"
        }
        Set-CharmState -Namespace "novahyperv" -Key "local_ip" -Value $local_ip[0]
        Set-CharmState -Namespace "novahyperv" -Key "dataNetworkIfindex" -Value $port.IfIndex
    }

    return Get-RealInterface $port
}

function Get-DataPort {
    # try and set up bonding early. This will create
    # a new Net-LbfoTeam and try to acquire an IP address
    # via DHCP. This interface may receive os-data-network IP.
    $bondName = New-BondInterface
    $managementOS = Get-JujuCharmConfig -Scope "vmswitch-management"

    $net_type = Get-NetType
    if ($net_type -eq "ovs"){
        Write-JujuInfo "Trying to fetch OVS data port"
        $dataPort = Get-OVSDataPort
        return @($dataPort[0], $true)
    }

    if ($bondName) {
        $adapter = Get-NetAdapter -Name bondName
        return @($adapter, $managementOS)
    }

    Write-JujuInfo "Trying to fetch data port from config"
    $nic = Get-InterfaceFromConfig
    if(!$nic) {
        $nic = Get-FallbackNetadapter
        $managementOS = $true
    }
    $nic = Get-RealInterface $nic[0]
    return @($nic, $managementOS)
}

function Start-ConfigureVMSwitch {
    $VMswitchName = Juju-GetVMSwitch
    $vmswitch = Get-VMSwitch -SwitchType External -Name $VMswitchName -ErrorAction SilentlyContinue

    if($vmswitch){
        return $true
    }

    $dataPort, $managementOS = Get-DataPort
    $VMswitches = Get-VMSwitch -SwitchType External -ErrorAction SilentlyContinue
    if ($VMswitches -and $VMswitches.Count -gt 0){
        foreach($i in $VMswitches){
            if ($i.NetAdapterInterfaceDescription -eq $dataPort.InterfaceDescription) {
                Rename-VMSwitch $i -NewName $VMswitchName
                Set-VMSwitch -Name $VMswitchName -AllowManagementOS $managementOS
                return $true
            }
        }
    }

    Write-JujuInfo "Adding new vmswitch: $VMswitchName"
    New-VMSwitch -Name $VMswitchName -NetAdapterName $dataPort.Name -AllowManagementOS $managementOS
    return $true
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
    Write-JujuInfo "Downloading file from $url to $download_location"
    try {
        Start-ExecuteWithRetry {
            Invoke-FastWebRequest -Uri $url -OutFile $download_location
        }
    } catch {
        Write-JujuErr "Could not download $url to destination $download_location"
        Throw
    }
    return $download_location
}

function Get-NovaInstaller {
    $distro = Get-OpenstackVersion
    $installer_url = Get-JujuCharmConfig -Scope "installer-url"
    if ($distro -eq $false){
        $distro = "liberty"
    }
    Write-JujuInfo "installer-url is set to: $installer_url"
    if (!$installer_url) {
        if (!$distro_urls[$distro] -or !$distro_urls[$distro]["installer"]){
            Throw "Could not find a download URL for $distro"
        }
        if ((Get-IsNanoServer))  {
            if (!$distro_urls[$distro]["installer"]["zip"]) {
                Throw "Distro $distro does not support Nano server"
            }
            $url = $distro_urls[$distro]["installer"]["zip"]
        } else {
            $url = $distro_urls[$distro]["installer"]["msi"]
        }
    }else {
        $url = $installer_url
    }
    [string]$location = Download-File $url
    return $location
}

function Install-NovaFromMSI {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath
    )
    Write-JujuInfo "Running Nova install"
    $hasInstaller = Test-Path $InstallerPath
    if($hasInstaller -eq $false){
        $InstallerPath = Get-NovaInstaller
    }
    Write-JujuInfo "Installing from $InstallerPath"
    $ret = Start-Process -FilePath msiexec.exe -ArgumentList "SKIPNOVACONF=1","INSTALLDIR=`"$installDir`"","/qn","/l*v","$env:APPDATA\log.txt","/i","$InstallerPath" -Wait -PassThru

    if($ret.ExitCode) {
        Throw ("Failed to install Nova: {0}" -f $ret.ExitCode)
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
    if((Test-Path $novaDir)){
        rm -Recurse -Force $novaDir
    }
    $configDir = Join-Path $novaDir "etc"
    Expand-ZipArchive -ZipFile $InstallerPath -Destination $novaDir
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
    $installer_url = Get-JujuCharmConfig -Scope "ovs-installer-url"
    if ($installer_url -eq $false) {
        Throw "Could not find a download URL for $distro"
    }
    $location = Download-File $installer_url
    return $location
}

function Ensure-InternalOVSInterfaces {
    Invoke-JujuCommand -Command @($ovs_vsctl, "--may-exist", "add-br", "br-tun")
    Invoke-JujuCommand -Command @($ovs_vsctl, "--may-exist", "add-port", "br-tun", "external.1")
    Invoke-JujuCommand -Command @($ovs_vsctl, "--may-exist", "add-port", "br-tun", "internal")
}

function Install-OVS {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath
    )

    Write-JujuInfo "Running OVS install"
    $ovs = Get-ManagementObject -Class Win32_Product | Where-Object {$_.Name -match "open vswitch"}
    if ($ovs){
        Write-JujuInfo "OVS is already installed"
        return $true
    }

    $hasInstaller = Test-Path $InstallerPath
    if($hasInstaller -eq $false){
        $InstallerPath = Get-OVSInstaller
    }
    Write-JujuInfo "Installing from $InstallerPath"
    $ret = Start-Process -FilePath msiexec.exe -ArgumentList "INSTALLDIR=`"$ovsInstallDir`"","/qb","/l*v","$env:APPDATA\ovs-log.txt","/i","$InstallerPath" -Wait -PassThru
    if($ret.ExitCode) {
        Throw "Failed to install OVS: $LASTEXITCODE"
    }
    return $true
}

function Check-OVSPrerequisites {
    try {
        $ovsdbSvc = Get-Service "ovsdb-server"
        $ovsSwitchSvc = Get-Service "ovs-vswitchd"
    } catch {
        $InstallerPath = Get-OVSInstaller
        Install-OVS $InstallerPath
    }
    if(!(Test-Path $ovs_vsctl)){
        Throw "Could not find ovs-vsctl.exe in location: $ovs_vsctl"
    }

    $services = Get-CharmServices
    try {
        $ovsAgent = Get-Service $services["neutron-ovs"]["service"]
    } catch {
        $name = $services["neutron-ovs"].service
        $svcPath = $services["neutron-ovs"].serviceBinPath
        New-Service -Name $name -BinaryPathName $svcPath -DisplayName $name -Description "Neutron Open vSwitch Agent" -Confirm:$false
        Disable-Service $name
    }
}

function Confirm-ServicePrerequisites {
    $services = Get-CharmServices
    $hypervAgent = Get-Service $services["neutron"]["service"] -ErrorAction SilentlyContinue
    $novaCompute = Get-Service $services["nova"]["service"] -ErrorAction SilentlyContinue

    if(!$hypervAgent) {
        $name = $services["neutron"]["service"]
        $svcPath = $services["neutron"]["serviceBinPath"]
        New-Service -Name $name -BinaryPathName $svcPath -DisplayName $name -Description "Neutron Hyper-V Agent" -Confirm:$false
        Disable-Service $name
    }

    if(!$novaCompute){
        $name = $services["nova"]["service"]
        $svcPath = $services["nova"]["serviceBinPath"]
        New-Service -Name $name -BinaryPathName $svcPath -DisplayName $name -Description "Nova Compute" -Confirm:$false
    }
}

function Get-OVSExtStatus {
    $br = Juju-GetVMSwitch
    Write-JujuInfo "Switch name is $br"
    $ext = Get-VMSwitchExtension -VMSwitchName $br -Name $ovsExtName

    if (!$ext){
        Write-JujuInfo "Open vSwitch extension not installed"
        return $null
    }

    return $ext
}

function Enable-OVSExtension {
    $ext = Get-OVSExtStatus
    if (!$ext){
       Throw "Cannot enable OVS extension. Not installed"
    }
    if (!$ext.Enabled) {
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

function Start-ConfigureNeutronAgent {
    $services = Get-CharmServices
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
    $svc = Start-ConfigureNeutronAgent
    Stop-Service $svc.service
    Start-Service $svc.service
}

function Restart-Nova {
    $services = Get-CharmServices
    Stop-Service $services.nova.service
    Start-Service $services.nova.service
}

function Stop-Neutron {
    $services = Get-CharmServices
    Stop-Service $services.neutron.service
}

function Import-CloudbaseCert {
    $filesDir = Get-FilesDir
    $crt = Join-Path $filesDir "Cloudbase_signing.cer"
    if (!(Test-Path $crt)){
        return $false
    }
    Import-Certificate $crt -StoreLocation LocalMachine -StoreName TrustedPublisher
}

function Start-ConfigChangedHook {
    Start-ConfigureVMSwitch
    Confirm-ServicePrerequisites
    Generate-ExeWrappers
    
    $net_type = Get-NetType

    if ($net_type -eq "ovs"){
        $neutron_restart = Generate-Config -ServiceName "neutron-ovs"
    }else{
        $neutron_restart = Generate-Config -ServiceName "neutron"
    }

    $nova_restart = Generate-Config -ServiceName "nova"
    $JujuCharmServices = Get-CharmServices

    if ($nova_restart){
        Write-JujuInfo "Restarting service Nova"
        Restart-Nova
    }

    if ($neutron_restart){
        Write-JujuInfo "Restarting service Neutron"
        Restart-Neutron
    }
    if($nova_restart -and $neutron_restart){
        Set-JujuStatus -Status active -Message "Unit is ready"
    }
}

function Start-InstallHook {
    PROCESS {
        if(!(Get-IsNanoServer)){
            try {
                Set-MpPreference -DisableRealtimeMonitoring $true
            } catch {
                # No need to error out the hook if this fails.
                Write-JujuWarning "Failed to disable antivirus: $_"
            }
        }
        # Set machine to use high performance settings.
        try {
            Set-PowerProfile -PowerProfile Performance
        } catch {
            # No need to error out the hook if this fails.
            Write-JujuWarning "Failed to set power scheme."
        }
        Install-Prerequisites
        Start-TimeResync
        Import-CloudbaseCert
        Start-ConfigureVMSwitch
        $installerPath = Get-NovaInstaller
        Install-Nova -InstallerPath $installerPath
        Confirm-ServicePrerequisites
        Start-ConfigureNeutronAgent
    }    
}

Export-ModuleMember -Function "Start-ConfigChangedHook","Start-InstallHook","Restart-Nova","Restart-Neutron","Stop-Neutron" -Variable JujuCharmServices
