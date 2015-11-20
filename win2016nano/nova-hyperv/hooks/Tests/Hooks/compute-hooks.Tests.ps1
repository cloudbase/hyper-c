$moduleBasePath = "..\..\"
$moduleLoaded = "..\..\Modules"
$moduleNameBasic = ((Split-Path `
                   -Leaf $MyInvocation.MyCommand.Path).Split(".")[0])
$moduleName = $moduleNameBasic + ".psm1"
$moduleNamePs1 = $moduleNameBasic + ".ps1"
$modulePath = Join-Path $moduleBasePath $moduleName
$moduleCpy = Join-Path $env:Temp $moduleNamePs1

if ((Test-Path $modulePath) -eq $false) {
 
    write-host "path not found"
    return
}
else {
    Remove-Item (($env:Temp) + "\Modules") -Force -Recurse
    Remove-Item $moduleCpy -Force -Recurse
    Copy-Item $moduleLoaded ($env:Temp) -Force -Recurse
    Copy-Item $modulePath $moduleCpy -Force
    pushd ($env:Temp)
    try {
        . $moduleCpy
    } catch {
        popd
        throw $_.Exception
    }
}
 
$ErrorActionPreference = 'Stop'

Describe "Juju-GetVMSwitch" {

    Context "No vmswitch name in config" {
        Mock charm_config { return $false }
        $result = Juju-GetVMSwitch
        It "should return br100" {
            $result  | Should Be "br100"
        }
    }

    Context "Vmswitch name in config" {
        Mock charm_config { return "br-int" }
        It "should return br-int" {
            Juju-GetVMSwitch | Should Be "br-int"
        }
    }
}

Describe "Get-RabbitMQContext" {

    Context "No relation ids available" {
        Mock Juju-Log {}
        Mock charm_config { return "fake-user" } `
            -ParameterFilter { $scope -eq "rabbit-user" }
        Mock charm_config { return "fake-vhost" } `
            -ParameterFilter { $scope -eq "rabbit-vhost" }
        Mock relation_ids { return $null } `
            -ParameterFilter { $reltype -eq "amqp" }

        $result = Get-RabbitMQContext
        $expect = @{}
        $compare = Compare-HashTables $result $expect
        It "should return empty context" {
            $compare | Should Be $true
        }
    }

    Context "Missing relation information" {
        Mock Juju-Log {}
        Mock relation_get { return "fake-pass" } `
            -ParameterFilter { $attr -eq "password" }
        Mock relation_get { return $null } `
            -ParameterFilter { $attr -eq "private-address" }
        Mock charm_config { return "fake-user" } `
            -ParameterFilter { $scope -eq "rabbit-user" }
        Mock charm_config { return "fake-vhost" } `
            -ParameterFilter { $scope -eq "rabbit-vhost" }
        Mock relation_ids { return @("fake-id") } `
            -ParameterFilter { $reltype -eq "amqp" }
        Mock related_units { return "fake-id" } `
            -ParameterFilter { $relid -eq "fake-id" }

        $result = Get-RabbitMQContext
        $expect = @{}
        $compare = Compare-HashTables $result $expect

        It "should return empty context" {
            $compare | Should Be $true
        }
    }

    Context "Context is complete" {
        $ctx = @{
            "rabbit_host"="192.168.1.1";
            "rabbit_userid"="fake-user";
            "rabbit_password"="fake-pass";
            "rabbit_virtual_host"="fake-vhost"
        }
        Mock Juju-Log {}
        Mock relation_get { return "fake-pass" } `
            -ParameterFilter { $attr -eq "password" }
        Mock relation_get { return "192.168.1.1" } `
            -ParameterFilter { $attr -eq "private-address" }
        Mock charm_config { return "fake-user" } `
            -ParameterFilter { $scope -eq "rabbit-user" }
        Mock charm_config { return "fake-vhost" } `
            -ParameterFilter { $scope -eq "rabbit-vhost" }
        Mock relation_ids { return @("fake-id") } `
            -ParameterFilter { $reltype -eq "amqp" }
        Mock related_units { return "fake-id" } `
            -ParameterFilter { $relid -eq "fake-id" }

        $result = Get-RabbitMQContext
        $compare = Compare-HashTables $result $ctx

        It "should return valid context" {
            $compare | Should Be $true
        }
    }
}

Describe "Get-NeutronContext" {

    Context "No relation ids" {
        Mock Juju-Log {}
        Mock relation_ids { return $null } `
            -ParameterFilter { $reltype -eq "cloud-compute" }
        Mock charm_config { return "$env:TEMP" } `
            -ParameterFilter { $scope -eq "log-dir" }
        Mock charm_config { return "$env:TEMP" } `
            -ParameterFilter { $scope -eq "instances-dir" }
        Mock relation_ids { return $null } `
            -ParameterFilter { $reltype -eq "cloud-compute" }

        $result = Get-NeutronContext
        $expect = @{}
        $compare = Compare-HashTables $result $expect

        It "should return empty context" {
            $compare | Should Be $true
        }
    }

    Context "Empty neutron URL should return empty context" {
        Mock Juju-Log {}
        Mock relation_ids { return $null } `
            -ParameterFilter { $reltype -eq "cloud-compute" }
        Mock charm_config { return "$env:TEMP" } `
            -ParameterFilter { $scope -eq "log-dir" }
        Mock charm_config { return "$env:TEMP" } `
            -ParameterFilter { $scope -eq "instances-dir" }
        Mock relation_ids { return $null } `
            -ParameterFilter { $reltype -eq "cloud-compute" }
        Mock relation_get { return $null } `
            -ParameterFilter { $attr -eq "neutron_url" }
        Mock relation_get { return $null } `
            -ParameterFilter { $attr -eq "quantum_url" }

        $result = Get-NeutronContext
        $expect = @{}
        $compare = Compare-HashTables $result $expect

        It "should return empty context" {
            $compare | Should Be $true
        }
    }

    Context "Missing relation information should return empty context" {
        Mock Juju-Log {}
        Mock relation_ids { return @("fake-id") } `
            -ParameterFilter { $reltype -eq "cloud-compute" }
        Mock related_units { return "fake-id" } `
            -ParameterFilter { $relid -eq "fake-id" }
        Mock charm_config { return "C:\Fake\Path" } `
            -ParameterFilter { $scope -eq "log-dir" }
        Mock charm_config { return "C:\Fake\Path" } `
            -ParameterFilter { $scope -eq "instances-dir"}
        Mock relation_get { return "http://example.com" } `
            -ParameterFilter { $attr -eq "neutron_url" }
        Mock relation_get { return $null } `
            -ParameterFilter { $attr -eq "quantum_url" }
        Mock relation_get { return "fake-host" } `
            -ParameterFilter { $attr -eq "auth_host" }
        Mock relation_get { return "80" } `
            -ParameterFilter { $attr -eq "auth_port" }
        Mock relation_get { return "443" } `
            -ParameterFilter { $attr -eq "service_tenant_name" }
        Mock relation_get { return "fake-name" } `
            -ParameterFilter { $attr -eq "service_username" }
        Mock relation_get { return $null } `
            -ParameterFilter { $attr -eq "service_password" }

        $result = Get-NeutronContext
        $expect = @{}
        $compare = Compare-HashTables $result $expect

        It "should return empty context" {
            $compare | Should Be $true
        }
    }

    Context "Complete context" {
        $ctx = @{
            "neutron_url"="http://example.com";
            "keystone_host"="fake-host";
            "auth_port"="80";
            "neutron_auth_strategy"="keystone";
            "neutron_admin_tenant_name"="fake-tenant";
            "neutron_admin_username"="fake-name";
            "neutron_admin_password"="fake-pass";
            "log_dir"="C:\Fake\Path";
            "instances_dir"="C:\Fake\Path";
            "neutron_admin_auth_url"="http://fake-host:80/v2.0"
        }
        Mock Juju-Log {}
        Mock relation_ids { return @("fake-id") } `
            -ParameterFilter { $reltype -eq "cloud-compute" }
        Mock related_units { return "fake-id" } `
            -ParameterFilter { $relid -eq "fake-id" }
        Mock charm_config { return "C:\Fake\Path" } `
            -ParameterFilter { $scope -eq "log-dir" }
        Mock charm_config { return "C:\Fake\Path" } `
            -ParameterFilter { $scope -eq "instances-dir"}
        Mock relation_get { return "http://example.com" } `
            -ParameterFilter { $attr -eq "neutron_url" }
        Mock relation_get { return $null } `
            -ParameterFilter { $attr -eq "quantum_url" }
        Mock relation_get { return "fake-host" } `
            -ParameterFilter { $attr -eq "auth_host" }
        Mock relation_get { return "80" } `
            -ParameterFilter { $attr -eq "auth_port" }
        Mock relation_get { return "fake-tenant" } `
            -ParameterFilter { $attr -eq "service_tenant_name" }
        Mock relation_get { return "fake-name" } `
            -ParameterFilter { $attr -eq "service_username" }
        Mock relation_get { return "fake-pass" } `
            -ParameterFilter { $attr -eq "service_password" }

        $result = Get-NeutronContext
        $compare = Compare-HashTables $result $ctx

        It "should return complete context" {
            $compare | Should Be $True
        }
    }
}

Describe "Get-GlanceContext" {
    Context "Missing relation ids" {
        Mock Juju-Log {}
        Mock relation_ids { return $null } `
            -ParameterFilter { $reltype -eq "image-service" }

        $result = Get-GlanceContext
        $expect = @{}
        $compare = Compare-HashTables $result $expect

        It "should return empty context" {
            $compare | Should Be $true
        }
    }

    Context "Missing glance server" {
        Mock Juju-Log {}
        Mock relation_ids { return @("fake-id") } `
            -ParameterFilter { $reltype -eq "image-service" }
        Mock related_units { return "fake-units" } `
            -ParameterFilter { $relid -eq "fake-id" }
        Mock relation_get { return $false } `
            -ParameterFilter { $attr -eq "glance-api-server" }

        $result = Get-GlanceContext
        $expect = @{}
        $compare = Compare-HashTables $result $expect

        It "should return empty context" {
            $compare | Should Be $true
        }
    }
    Context "Context complete" {
        $ctx = @{
            "glance_api_servers"="http://example.com"
        }
        Mock Juju-Log {}
        Mock relation_ids { return @("fake-id") } `
            -ParameterFilter { $reltype -eq "image-service" }
        Mock related_units { return "fake-units" } `
            -ParameterFilter { $relid -eq "fake-id" }
        Mock relation_get { return "http://example.com" } `
            -ParameterFilter { $attr -eq "glance-api-server" }

        $result = Get-GlanceContext
        $compare = Compare-HashTables $result $ctx

        It "should return empty context" {
            $compare | Should Be $true
        }
    }
}
