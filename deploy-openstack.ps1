Param(
    [Parameter(Mandatory=$true)]
    [string]$Config,
    [string]$CharmRepository
)

if(!(Test-Path $Config)){
    Write-Host "Config file $Config does not exist"
    exit 1
}

if($CharmRepository){
    if(!(Test-Path $CharmRepository)){
        Write-Host "Juju charm repository path $CharmRepository does not exist"
        exit 1
    }
    $env:JUJU_REPOSITORY = $CharmRepository
} else {
    if(!$env:JUJU_REPOSITORY){
        $env:JUJU_REPOSITORY = $PWD.Path
    }
}

$Charms = @{
    "local:win2016/active-directory" = @{
        "num_units" = 1;
        "config" = $true;
        "subordonate" = $false;
        "tags" = "ad";
    };
    "local:trusty/glance" = @{
        "num_units" = 1;
        "config" = $true;
        "subordonate" = $false;
        "to" = "lxc:neutron-gateway";
    };
    "local:trusty/keystone" = @{
        "num_units"=1;
        "config" = $true;
        "subordonate" = $false;
        "to" = "lxc:neutron-gateway";
    };
    "local:trusty/mysql" = @{
        "num_units" = 1;
        "config" = $true;
        "subordonate" = $false;
        "to" = "lxc:neutron-gateway";
    };
    "local:trusty/rabbitmq-server" = @{
        "num_units" = 1;
        "config" = $false;
        "subordonate" = $false;
        "to" = "lxc:neutron-gateway";
    };
    "local:trusty/neutron-api" = @{
        "num_units" = 1;
        "config" = $true;
        "subordonate" = $false;
        "to" = "lxc:neutron-gateway";
    };
    "local:trusty/neutron-gateway" = @{
        "num_units" = 1;
        "config" = $true;
        "subordonate" = $false;
        "tags" = "services";
    };
    "local:trusty/neutron-openvswitch" = @{
        "config" = $true;
        "subordonate" = $true;
    };
    "local:trusty/nova-cloud-controller" = @{
        "num_units" = 1;
        "config" = $true;
        "subordonate" = $false;
        "to" = "lxc:neutron-gateway";
    };
    "local:trusty/openstack-dashboard" = @{
        "num_units" = 1;
        "config" = $true;
        "subordonate" = $false;
        "to" = "lxc:neutron-gateway";
    };
    "local:win2016nano/nova-hyperv" = @{
        "num_units" = 4;
        "config" = $true;
        "subordonate" = $false;
    };
    "local:win2016/s2d-proxy" = @{
        "num_units" = 1;
        "config" = $true;
        "subordonate" = $false;
        "tags" = "s2d-proxy";
    };
    "local:win2016nano/s2d" = @{
        "config" = $true;
        "subordonate" = $true;
    };
}

$relations = @(
    @("nova-hyperv", "nova-cloud-controller"),
    @("nova-hyperv", "rabbitmq-server:amqp"),
    @("nova-hyperv", "glance"),
    @("nova-hyperv", "active-directory"),
    @("nova-hyperv", "s2d"),
    @("s2d-proxy", "s2d"),
    @("s2d-proxy", "active-directory"),
    @("keystone", "mysql"),
    @("nova-cloud-controller", "glance"),
    @("nova-cloud-controller", "keystone"),
    @("nova-cloud-controller", "mysql"),
    @("nova-cloud-controller", "rabbitmq-server"),
    @("glance", "keystone"),
    @("glance", "mysql"),
    @("openstack-dashboard", "keystone"),
    @("neutron-gateway", "mysql"),
    @("neutron-gateway", "nova-cloud-controller"),
    @("neutron-gateway:amqp", "rabbitmq-server"),
    @("neutron-api", "mysql"),
    @("neutron-api", "rabbitmq-server"),
    @("neutron-api", "nova-cloud-controller"),
    @("neutron-api", "neutron-openvswitch"),
    @("neutron-openvswitch", "neutron-gateway"),
    @("neutron-api", "neutron-gateway"),
    @("neutron-api", "keystone"),
    @("neutron-openvswitch", "rabbitmq-server")
)

function Deploy-Charm{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [System.Object]$Options
    )
    $cmd = @("juju.exe", "deploy", "$Name")
    if($Options["config"]){
        $cmd += "--config","$Config"
    }
    if (!$Options["subordonate"] -and $Options["num_units"]){
        $units = $Options["num_units"]
        $cmd += "-n","$units"
    }
    if($Options["tags"] -and $Options["to"]){
        Throw "Conflicting placement options for $name : to and tags"
    }
    if($Options["tags"] -and !$Options["subordonate"]){
        $tag = $Options["tags"]
        $cmd += "--constraints","tags=$tag"
    }
    if($Options["to"] -and !$Options["subordonate"]){
        $to = $Options["to"]
        if ($to.StartsWith("lxc:")){
            $ret = juju.exe add-machine $to
            if($LASTEXITCODE){
                Throw "Failed to run juju.exe"
            }
            $id = $ret.split()[-1]
        }
        $cmd += "--to","$id"
    }
    & $cmd[0] $cmd[1..$cmd.Length]
    if ($LASTEXITCODE){
        Throw "Failed to run juju.exe"
    }
}

function Deploy-TaggedCharms {
    foreach($i in $Charms.GetEnumerator()){
        $name = $i.Name
        $value = $i.Value
        if(!$value["tags"]){
            continue
        }
        Deploy-Charm -Name $name -Options $value
    }    
}

function Deploy-UntaggedCharms {
    foreach($i in $Charms.GetEnumerator()){
        $name = $i.Name
        $value = $i.Value
        if(!$value["tags"]){
            Deploy-Charm -Name $name -Options $value
        }
    }
}

function Add-Relations {
    foreach($i in $relations){
        juju.exe add-relation $i
    }
}

Deploy-TaggedCharms
Deploy-UntaggedCharms
Add-Relations
