$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleHome = Split-Path -Parent $here
$moduleRoot = Split-Path -Parent $moduleHome

$modulePath = ${env:PSModulePath}.Split(";")
if(!($moduleRoot -in $modulePath)){
    $env:PSModulePath += ";$moduleRoot"
}
$savedEnv = [System.Environment]::GetEnvironmentVariables()

Import-Module JujuHooks

function Clear-Environment {
    $current = [System.Environment]::GetEnvironmentVariables()
    foreach($i in $savedEnv.GetEnumerator()) {
        [System.Environment]::SetEnvironmentVariable($i.Name, $i.Value, "Process")
    }
    $current = [System.Environment]::GetEnvironmentVariables()
    foreach ($i in $current.GetEnumerator()){
        if(!$savedEnv[$i.Name]){
            [System.Environment]::SetEnvironmentVariable($i.Name, $null, "Process")
        }
    }
}

Describe "Test Confirm-ContextComplete" {
    AfterEach {
        Clear-Environment
    }
    It "Should return False" {
        $ctx = @{
            "test" = $null;
            "test2" = "test";
        }
        Confirm-ContextComplete -Context $ctx | Should Be $false

        $ctx = @{
            "test" = $null;
            "test2" = "test";
        }
        Confirm-ContextComplete -Context $ctx | Should Be $false

        $ctx = @{}
        Confirm-ContextComplete -Context $ctx | Should Be $false
    }

    It "Should return True" {
        $ctx = @{
            "hello" = "world";
        }
        Confirm-ContextComplete -Context $ctx | Should Be $true
    }

    It "Should Throw an exception" {
        $ctx = "not a hashtable"
        { Confirm-ContextComplete -Context $ctx} | Should Throw
    }
}

Describe "Test hook environment functions" {
    AfterEach {
        Clear-Environment
    }
    It "Should return charm_dir" {
        $env:CHARM_DIR = "bogus"
        Get-JujuCharmDir | Should Be "bogus"
    }

    It "Should return relation name" {
        $env:JUJU_RELATION = "bogus"
        Get-JujuRelationType | Should be "bogus"
    }

    It "Confirm-JujuRelation should return True" {
        $env:JUJU_RELATION = "bogus"
        Confirm-JujuRelation | Should be $true
    }

    It "Confirm-JujuRelation should return False" {
        $env:JUJU_RELATION = ""
        Confirm-JujuRelation | Should be $false
    }

    It "Get-JujuRelationId should return relation ID" {
        $env:JUJU_RELATION_ID = "bogus:1"
        Get-JujuRelationId | Should Be "bogus:1"
    }

    It "Get-JujuLocalUnit should return unit name" {
        $env:JUJU_UNIT_NAME = "unit-1"
        Get-JujuLocalUnit | Should Be "unit-1"
    }

    It "Get-JujuRemoteUnit should return remote unit" {
        $env:JUJU_REMOTE_UNIT = "remote-1"
        Get-JujuRemoteUnit | Should Be "remote-1"
    }

    It "Get-JujuServiceName should get service name" {
        $env:JUJU_UNIT_NAME = "active-directory/0"
        Get-JujuServiceName | Should Be "jujud-active-directory-0"
    }
}

Describe "Test Get-JujuCharmConfig" {
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        $ret = @{
            "stringOption"="Hello";
            "intOption"=1;
        }
        if($Command.Length -gt 2) {
            $x = $Command[2]
            if($ret[$x]){
                return (ConvertTo-Yaml $ret[$x])
            }
            return ""
        }
        return (ConvertTo-Yaml $ret)
    }
    It "Should return a Hashtable" {
        (Get-JujuCharmConfig).GetType() | Should Be "Hashtable"
        (Get-JujuCharmConfig).stringOption | Should Be "Hello"
        (Get-JujuCharmConfig).intOption | Should Be 1
    }

    It "Should return a string" {
        Get-JujuCharmConfig -Scope "stringOption" | Should Be "Hello"
    }

    It "Should return an int" {
        Get-JujuCharmConfig -Scope "intOption" | Should Be 1
    }

    It "Should return empty" {
        Get-JujuCharmConfig -Scope "nonexisting" | Should BeNullOrEmpty
    }
}

Describe "Test Get-JujuRelation" {
    AfterEach {
        Clear-Environment
    }
    Context "Invoke Get-JujuRelation without params" {
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-get.exe", "--format=yaml", "-")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
            return '{"user": "guest"}'
        }

        It "Should pass only - as attr" {
            $env:JUJU_REMOTE_UNIT = "bogus"
            $env:JUJU_RELATION_ID = "amqp:1"
            (Get-JujuRelation).GetType() | Should Be "Hashtable"
            (Get-JujuRelation).user | Should Be "guest"
        }
        It "Should throw an exception" {
            { Get-JujuRelation }| Should Throw
        }
    }

    Context "Invoke Get-JujuRelation with Unit"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-get.exe", "--format=yaml", "-", "bogus")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
        }
        It "Should pass - and unit" {
            $env:JUJU_RELATION_ID = "amqp:1"
            Get-JujuRelation -Unit "bogus" | Should BeNullOrEmpty
        }
        It "Should throw an exception" {
            { Get-JujuRelation -Unit "bogus" } | Should Throw
        }
    }

    Context "Invoke Get-JujuRelation with Unit and relation ID"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-get.exe", "--format=yaml", "-r", "amqp:1", "-", "bogus")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
            return '{"test": "test", "hello": "world"}'
        }

        It "Should pass unit, relation id and attribute" {
            $r = Get-JujuRelation -Unit "bogus" -RelationID "amqp:1"
            $r.GetType() | Should Be "hashtable"
            $r["test"] | Should Be "test"
            $r["hello"] | Should Be "world"
        }
    }

    Context "Invoke Get-JujuRelation with Unit, relation ID and attribute"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-get.exe", "--format=yaml", "-r", "amqp:1", "name", "bogus")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
            return '"test"'
        }

        It "Should pass unit, relation id and attribute" {
            Get-JujuRelation -Unit "bogus" -RelationID "amqp:1" -Attribute "name" | Should Be "test"
        }
    }
}

Describe "Test Set-JujuRelation"{
    AfterEach {
        Clear-Environment
    }

    Context "Call Set-JujuRelation without RelationID" {
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-set.exe", "--file")
            if ((Compare-Object $Command[0..1] $expect) -or !(Test-Path $Command[-1])) {
                Throw ("Invalid parameters: {0}" -f ($Command -Join " "))
            }
        }

        It "Should pass name=value" {
            $env:JUJU_RELATION_ID = "amqp:1"
            $params = @{
                "name"="value";
            }
            Set-JujuRelation -Settings $params | Should Be $true
        }
        It "Should throw an exception (Missing relation ID)" {
            $params = @{
                "name"="value";
            }
            { Set-JujuRelation -Settings $params } | Should Throw
        }
    }

    Context "Call Set-JujuRelation with RelationID" {
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-set.exe", "-r", "amqp:1", "--file")
            if ((Compare-Object $Command[0..3] $expect) -or !(Test-Path $Command[-1])) {
                Throw ("Invalid parameters: {0}" -f ($Command -Join " "))
            }
        }
        It "Should pass relationID" {
            $params = @{
                "name"="value";
            }
            Set-JujuRelation -Settings $params -RelationID "amqp:1" | Should Be $true
        }

        It "Should Throw an exception (Missing relation ID)" {
            { Set-JujuRelation -RelationID "amqp:1" } | Should Throw
        }
    }

}

Describe "Test Get-JujuRelationIds" {
    AfterEach {
        Clear-Environment
    }
    Context "Call Get-JujuRelationIds without -Relation"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-ids.exe", "--format=yaml", "amqp")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
            return '["amqp:1", "amqp:2"]'
        }
        It "Should throw an exception (Missing relation type)" {
            { Get-JujuRelationIds } | Should Throw
        }
        It "Should return relation ID" {
            $env:JUJU_RELATION = "amqp"
            Get-JujuRelationIds | Should Be @("amqp:1", "amqp:2")
            (Get-JujuRelationIds).GetType().BaseType.Name | Should Be "Array"
        }
    }
    Context "Call Get-JujuRelationIds with -Relation"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-ids.exe", "--format=yaml", "shared-db")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
            return '"mysql:1"'
        }
        It "Should return relation ID" {
            Get-JujuRelationIds -Relation "shared-db" | Should Be "mysql:1"
        }
    }
}

Describe "Test Get-JujuRelatedUnits" {
    AfterEach {
        Clear-Environment
    }
    Context "Call Get-JujuRelatedUnits without -RelationID"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-list.exe", "--format=yaml", "-r", "amqp:1")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
            return '["rabbitmq/0", "rabbitmq/1"]'
        }
        It "Should throw an exception (Missing relation ID)" {
            { Get-JujuRelatedUnits } | Should Throw
        }
        It "Should return related units" {
            $env:JUJU_RELATION_ID = "amqp:1"
            Get-JujuRelatedUnits | Should Be @("rabbitmq/0", "rabbitmq/1")
        }
    }
    Context "Get-JujuRelatedUnits with -Relation"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-list.exe", "--format=yaml", "-r","shared-db")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
            return '"mysql:1"'
        }
        It "Should return related units" {
            Get-JujuRelatedUnits -RelationID "shared-db" | Should Be "mysql:1"
        }
    }
}

Describe "Test Get-JujuRelationForUnit" {
    Context "Call Get-JujuRelationForUnit"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-get.exe", "--format=yaml", "-r", "amqp:1", "-", "bogus")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
            return '{"test": "test", "hello": "world", "test-list": "hello world"}'
        }

        It "Should pass unit and relation id. Return hashtable" {
            $r = Get-JujuRelationForUnit -Unit "bogus" -RelationId "amqp:1"
            $r.GetType() | Should Be "hashtable"
            $r["test"] | Should Be "test"
            $r["hello"] | Should Be "world"
            $r["test-list"] | Should Be @("hello", "world")
        }
    }
    
}

Describe "Test Get-JujuRelationForId" {
    Context "Call Get-JujuRelationForId"{
        Mock Get-JujuRelatedUnits -ModuleName JujuHooks {
            return @("rabbitmq/0", "rabbitmq/1")
        }
        Mock Get-JujuRelationForUnit -ModuleName JujuHooks {
            Param(
                [string]$Unit=$null,
                [Alias("Rid")]
                [string]$RelationId=$null
            )
            if ($RelationId -ne "amqp:1"){
                Throw "Invalid relationID. Expected amqp:1"
            }
            $ret = @{
                'rabbitmq/0'= @{"rabbit-0-test"="test-0"; "rabbit-0-hello"="rabbit-0-world";};
                'rabbitmq/1'= @{"rabbit-1-test"="test-1"; "rabbit-1-hello"="rabbit-1-world";};
            }
            return $ret[$Unit]
        }
        It "Should get array of relation data" {
            $r = Get-JujuRelationForId -RelationId "amqp:1"
            $r.GetType().BaseType.Name | Should Be "Array"
            $r.Count | Should Be 2
            $r[0]["rabbit-0-test"] | Should Be "test-0"
            $r[0]["rabbit-0-hello"] | Should Be "rabbit-0-world"
            $r[1]["rabbit-1-test"] | Should Be "test-1"
            $r[1]["rabbit-1-hello"] | Should Be "rabbit-1-world"
        }

        It "Should throw an exception (Missing relation ID)" {
            { Get-JujuRelationForId } | Should Throw
        }
    }
}

Describe "Test Get-JujuRelationsOfType" {
    Mock Get-JujuRelationIds -ModuleName JujuHooks {
        Param(
            [Alias("RelType")]
            [string]$Relation=$null
        )
        if($Relation -ne "amqp") {
            return $null
        }
        return @("amqp:1", "amqp:2")
    }
    Mock Get-JujuRelationForUnit -ModuleName JujuHooks {
        Param(
            [string]$Unit=$null,
            [Alias("Rid")]
            [string]$RelationId=$null
        )
        $data = @{
            "amqp:1"= @{
                'rabbitmq/0'= @{
                    "rabbit-0-test"="test-0";
                };
                'rabbitmq/1'= @{
                    "rabbit-1-test"="test-1";
                    "rabbit-1-test2"="test-2";
                };
            };
            "amqp:2" = @{
                'keystone/0'=@{
                    "id"="root";
                };
            };
        }
        if(!$data[$RelationID]){
            Throw "Invalid relation ID"
        }
        $x = $data[$RelationId][$Unit]
        return $x
    }
    Mock Get-JujuRelatedUnits -ModuleName JujuHooks {
        Param(
            [Alias("RelId")]
            [string]$RelationId=$null
        )
        $data = @{
            "amqp:1"=@("rabbitmq/0", "rabbitmq/1");
            "amqp:2"=@("keystone/0")
        }
        return $data[$RelationId]
    }
    It "Should return an array of relation data" {
        $r = Get-JujuRelationsOfType -Relation "amqp"
        $r.GetType().BaseType.Name | Should Be "Array"
        $r.Count | Should Be 3
    }

    It "Should return empty" {
        $r = Get-JujuRelationsOfType -Relation "bogus"
        $r | Should BeNullOrEmpty
    }
}

Describe "Test Confirm-JujuRelationCreated" {
    Mock Get-JujuRelationIds -ModuleName JujuHooks {
        Param(
            [Alias("RelType")]
            [string]$Relation=$null
        )
        $relations = @{
            "amqp" = @("amqp:1", "amqp:2");
            "testing" = @();
        }
        return $relations[$Relation]
    }
    It "Should return True" {
        Confirm-JujuRelationCreated -Relation "amqp" | Should Be $true
    }

    It "Should return False" {
        Confirm-JujuRelationCreated -Relation "bogus" | Should Be $false
    }
    It "Should return False on non existing relation" {
        Confirm-JujuRelationCreated -Relation "bogus" | Should Be $false
    }
    It "Should return False on uninitialized relation" {
        Confirm-JujuRelationCreated -Relation "testing" | Should Be $false
    }
}

Describe "Test Get-JujuUnit" {
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        if(!($Command[-1] -in @("private-address", "public-address"))){
            Throw "only private-address and public-address are supported"
        }
        $expect = @("unit-get.exe", "--format=yaml")
        if ((Compare-Object $Command ($expect + $Command[-1]))) {
            Throw "Invalid parameters"
        }
        $addr = @{
            "private-address"='"192.168.1.1"';
            "public-address"='"192.168.1.2"';
        }
        return $addr[$Command[-1]]
    }
    It "Should throw an exception (invalid attribute)" {
        { Get-JujuUnit -Attribute "Bogus" } | Should Throw
    }

    It "Should return private-address" {
        Get-JujuUnit -Attribute "private-address" | Should Be "192.168.1.1"
    }

    It "Should return public-address" {
        Get-JujuUnit -Attribute "public-address" | Should Be "192.168.1.2"
    }
}

Describe "Test Confirm-IP" {
    It "Should return False for 'bla'" {
        Confirm-IP -IP "bla" | Should Be $false
    }
    It "Should return False for '192.168.1'" {
        Confirm-IP -IP "192.168.1" | Should Be $false
    }
    It "Should return True for '192.168.1.1'" {
        Confirm-IP -IP "192.168.1.1" | Should Be $true
    }
    It "Should return True for '::1'" {
        Confirm-IP -IP "::1" | Should Be $true
    }
}

Describe "Test Get-JujuUnitPrivateIP" {
    AfterEach {
        Clear-Environment
    }
    Mock Resolve-Address -ModuleName JujuHooks -Verifiable {
        Param(
            [Parameter(Mandatory=$true)]
            [string]$Address
        )
        $data = @{
            "example.com"="192.168.1.1";
        }
        if(!$data[$Address]){
            Throw ("Could not resolve address {0} to IP" -f $Address)
        }
        return $data[$Address]
    }
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        if(!($Command[-1] -in @("private-address", "public-address"))){
            Throw "only private-address and public-address are supported"
        }
        $expect = @("unit-get.exe", "--format=yaml")
        if ((Compare-Object $Command ($expect + $Command[-1]))) {
            Throw "Invalid parameters"
        }
        if(!$env:privateIP){
            $pi = '"192.168.1.1"'
        }else {
            $pi = $env:privateIP
        }
        $addr = @{
            "private-address"=$pi;
            "public-address"='"192.168.1.2"';
        }
        return $addr[$Command[-1]]
    }
    It "Should return the private address (supply IP address)" {
        Get-JujuUnitPrivateIP | Should Be "192.168.1.1"
    }

    It "Should return the private address (supply hostname)" {
        $env:privateIP = '"example.com"'
        Get-JujuUnitPrivateIP | Should Be "192.168.1.1"
        Assert-VerifiableMocks
    }

    It "Should throw an exception" {
        $env:privateIP = '"example-bogus.com"'
        { Get-JujuUnitPrivateIP } | Should Throw
        Assert-VerifiableMocks
    }
}

Describe "Test Get-JujuRelationContext" {
    Mock Get-JujuRelationIds -ModuleName JujuHooks {
        Param(
            [Alias("RelType")]
            [string]$Relation=$null
        )
        $relations = @{
            "amqp" = @("amqp:1", "amqp:2");
            "identity" = @();
        }
        return $relations[$Relation]
    }
    Mock Get-JujuRelationsOfType -ModuleName JujuHooks {
        Param(
            [Alias("RelType")]
            [string]$Relation=$null
        )

        $data = @{
            "amqp"= @(
                @{
                    "username"="guest";
                    "private-address"="192.168.1.1";
                },
                @{
                    "username"="guest";
                    "password"="secret";
                    "private-address"="192.168.1.2";
                }
            );
            "identity"=@(
                @{
                    "url"="example.com";
                    "private-address"="192.168.1.3";
                }
            );
        }
        return $data[$Relation]
    }
    It "Should return an empty context" {
        $ctx = @{
            "username"=$null;
            "password"=$null;
            "url"=$null;
        }
        Get-JujuRelationContext -RequiredContext $ctx -Relation "identity" | Should BeNullOrEmpty
    }
    It "Should return populated context" {
        $ctx = @{
            "username"=$null;
            "password"=$null;
        }
        $r = Get-JujuRelationContext -RequiredContext $ctx -Relation "amqp"
        $r | Should Not BeNullOrEmpty
        $r["username"] | Should Be "guest"
        $r["password"] | Should Be "secret"
        $r.Keys | Should Be @("username", "password")
    }
    It "Should also contain the private-address" {
        $ctx = @{
            "username"=$null;
            "password"=$null;
            "private-address"=$null;
        }
        $r = Get-JujuRelationContext -RequiredContext $ctx -Relation "amqp"
        $r | Should Not BeNullOrEmpty
        $r["username"] | Should Be "guest"
        $r["password"] | Should Be "secret"
        $r["private-address"] | Should Be "192.168.1.2"
        $r.Keys | Should Be @("private-address", "username", "password")
    }
}

Describe "Test Invoke-JujuReboot" {
    Context "Reboot at end" {
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("juju-reboot.exe")
            if((Compare-Object $Command $expect)) {
                Throw "Invalid command"
            }
        }
        It "Should not send the --now flag" {
            Invoke-JujuReboot | Should BeNullOrEmpty
        }
    }
    Context "Reboot now" {
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("juju-reboot.exe", "--now")
            if((Compare-Object $Command $expect)) {
                Throw "Invalid command"
            }
        }
        It "Should send the --now flag" {
            Invoke-JujuReboot -Now | Should BeNullOrEmpty
        }
    }
}

Describe "Test Confirm-JujuPortRangeOpen" {
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        $expect = @("opened-ports.exe", "--format=yaml")
        if((Compare-Object $Command $expect)) {
            Throw "Invalid command"
        }
        return '["111/tcp", "222/udp", "2000-3000/tcp"]'
    }
    It "Should Throw an exception on invalid ports" {
        { Confirm-JujuPortRangeOpen -Port "dummy"} | Should Throw
        { Confirm-JujuPortRangeOpen -Port 1111111} | Should Throw
        { Confirm-JujuPortRangeOpen -Port "123/TTCP" } | Should Throw
        { Confirm-JujuPortRangeOpen } | Should Throw
    }
    It "Should return True" {
        Confirm-JujuPortRangeOpen -Port "111/tcp" | Should Be $true
        Confirm-JujuPortRangeOpen -Port "222/udp" | Should Be $true
        Confirm-JujuPortRangeOpen -Port "2000-3000/tcp" | Should Be $true
    }
    It "Should return False" {
        Confirm-JujuPortRangeOpen -Port "111/udp" | Should Be $false
        Confirm-JujuPortRangeOpen -Port "222/tcp" | Should Be $false
        Confirm-JujuPortRangeOpen -Port "2000-3001/tcp" | Should Be $false
    }
}

Describe "Test Open-JujuPort" {
    AfterEach {
        Clear-Environment
    }
    Mock Confirm-JujuPortRangeOpen -ModuleName JujuHooks {
        Param(
            [Parameter(Mandatory=$true)]
            [ValidatePattern('^(\d{1,5}-)?\d{1,5}/(tcp|udp)$')]
            [string]$Port

        )
        $p = $env:OpenedPortsTest.Split()
        foreach ($i in $p){
            if ($Port -eq $i){
                return $true
            }
        }
        return $false
    }
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        $p = $Command[-1]
        if($p -eq "999/tcp"){
            Throw "bogus error"
        }
        $expect = @("open-port.exe")
        if((Compare-Object $Command ($expect += $Command[-1]))) {
            Throw "Invalid command"
        }
        $p = $env:OpenedPortsTest.Split()
        foreach($i in $p) {
            if ($i -eq $Command[-1]){
                Throw "Port already open"
            }
        }
        $p += $Command[-1]
        $env:OpenedPortsTest = $p
    }
    Mock Write-JujuErr -Verifiable -ModuleName JujuHooks {
        Param(
            [Parameter(Mandatory=$true)]
            [string]$Message
        )
    }
    It "Should return if port already open" {
        $env:OpenedPortsTest = @("1024/tcp")
        Open-JujuPort -Port "1024/tcp" | Should BeNullOrEmpty
    }
    It "Should open a new port" {
        $env:OpenedPortsTest = @("1/tcp")
        Open-JujuPort -Port "1024/tcp" | Should BeNullOrEmpty
        $env:OpenedPortsTest.Split() | Should Be @("1/tcp", "1024/tcp")
    }
    It "Should throw an exception" {
        $env:OpenedPortsTest = @("1/tcp")
        { Open-JujuPort -Port "999/tcp" } | Should Throw
        Assert-VerifiableMocks
    }
}

Describe "Test Close-JujuPort" {
    AfterEach {
        Clear-Environment
    }
    Mock Confirm-JujuPortRangeOpen -ModuleName JujuHooks {
        Param(
            [Parameter(Mandatory=$true)]
            [ValidatePattern('^(\d{1,5}-)?\d{1,5}/(tcp|udp)$')]
            [string]$Port

        )
        $p = $env:OpenedPortsTest.Split()
        foreach ($i in $p){
            if ($Port -eq $i){
                return $true
            }
        }
        return $false
    }
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        $p = $Command[-1]
        if($p -eq "999/tcp"){
            Throw "bogus error"
        }
        $expect = @("close-port.exe")
        if((Compare-Object $Command ($expect += $Command[-1]))) {
            Throw "Invalid command"
        }
        $p = @()
        $found = $false
        foreach($i in $env:OpenedPortsTest.Split()) {
            if ($i -eq $Command[-1]){
                $found = $true
                continue
            }
            $p += $i
        }
        if(!$found){
            Throw "No such port"
        }
        $env:OpenedPortsTest = $p
    }
    Mock Write-JujuErr -Verifiable -ModuleName JujuHooks {
        Param(
            [Parameter(Mandatory=$true)]
            [string]$Message
        )
    }
    It "Should close a port" {
        $env:OpenedPortsTest = @("1/tcp", "1024/tcp")
        Close-JujuPort -Port "1024/tcp" | Should BeNullOrEmpty
        $env:OpenedPortsTest.Split() | Should Be @("1/tcp")
    }
    It "Should return if port not open" {
        $env:OpenedPortsTest = @("1/tcp")
        Close-JujuPort -Port "1024/tcp" | Should BeNullOrEmpty
        $env:OpenedPortsTest.Split() | Should Be @("1/tcp")
    }
    It "Should throw an exception" {
        $env:OpenedPortsTest = @("1/tcp", "999/tcp")
        { Close-JujuPort -Port "999/tcp" } | Should Throw
        Assert-VerifiableMocks
    }
}

Describe "Test Confirm-Leader" {
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        $expect = @("is-leader.exe", "--format=yaml")
        if((Compare-Object $Command $expect)) {
            Throw "Invalid command"
        }
        return '"True"'
    }
    It "Should return True" {
        Confirm-Leader | Should Be $true
    }
}

Describe "Test Set-LeaderData" {
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        $expect = @("leader-set.exe", "hello=world", "password=secret")
        if((Compare-Object $Command $expect)) {
            Throw "Invalid command"
        }
    }
    It "Should send proper parameters to leader-set" {
        $data = @{
            "hello"="world";
            "password"="secret";
        }
        Set-LeaderData -Settings $data | Should BeNullOrEmpty
    }
    It "Should throw an exception on invalid data" {
        { Set-LeaderData -Settings "bogus" } | Should Throw
        { Set-LeaderData -Settings @(1,2,3) } | Should Throw
    }
}

Describe "Test Get-LeaderData" {
    Context "Call Get-LeaderData with no attributes" {
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("leader-get.exe", "--format=yaml")
            if((Compare-Object $Command $expect)) {
                Throw "Invalid command"
            }
            return '{"bogus": "data", "hello": "world"}'
        }
        It "Should return leader data" {
            $r = Get-LeaderData
            $r.GetType() | Should Be "Hashtable"
            $r["bogus"] | Should Be "data"
            $r["hello"] | Should Be "world"
            $r.Keys.Count | Should Be 2
        }
    }
    Context "Call Get-LeaderData with attribute" {
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("leader-get.exe", "--format=yaml")
            if((Compare-Object $Command ($expect += $Command[-1]))) {
                Throw "Invalid command"
            }
            $data = @{
                "hello"='"world"';
            }
            $r = $data[$Command[-1]]
            if(!$r){
                return ''
            }
            return $data[$Command[-1]]
        }
        It "Should return world" {
            Get-LeaderData -Attribute "hello" | Should Be "world"
        }
        It "Should return empty" {
            Get-LeaderData -Attribute "empty" | Should BeNullOrEmpty
        }
    }
}

Describe "Test Get-JujuVersion" {
    AfterEach {
        Clear-Environment
    }
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        $expect = @("jujud.exe", "version")
        if((Compare-Object $Command $expect)) {
            Throw "Invalid command"
        }
        return $env:binVersion
    }
    Mock Write-JujuWarning -Verifiable -ModuleName JujuHooks {
        Param(
            [Parameter(Mandatory=$true)]
            [string]$Message
        )
    }
    It "Should return hashtable with 4 fields (development release)" {
        $env:binVersion = "1.25.1-alpha1-win2012r2-amd64"
        $r = Get-JujuVersion
        $r.Keys.Count | Should Be 4
        $r["version"] | Should Be "1.25.1"
        $r["subversion"] | Should Be "alpha1"
        $r["series"] | Should Be "win2012r2"
        $r["arch"] | Should Be "amd64"
        Assert-VerifiableMocks
    }
    It "Should return a hashtable with 3 fields (production)" {
        $env:binVersion = "1.25.1-win2012r2-amd64"
        $r = Get-JujuVersion
        $r.Keys.Count | Should Be 3
        $r["version"] | Should Be "1.25.1"
        $r["series"] | Should Be "win2012r2"
        $r["arch"] | Should Be "amd64"
    }
    It "Should Throw an exception" {
        $env:binVersion = "1.25.1"
        { Get-JujuVersion } | Should Throw
    }
}

Describe "Test Get-JujuStatus" {
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        $expect = @("status-get.exe", "--include-data","--format=yaml")
        if((Compare-Object $Command $expect)) {
            Throw "Invalid command"
        }
        return '{"message":"Unit is ready","status":"active","status-data":{"sample": 1}}'
    }
    It "Should return the status" {
        Get-JujuStatus | Should Be "active"
    }
    It "Should full status info" {
        $r = Get-JujuStatus -Full
        $r.GetType() | Should Be "hashtable"
        $r["message"] | Should Be "Unit is ready"
        $r["status"] | Should Be "active"
        $r["status-data"].GetType() | Should Be "hashtable"
        $r["status-data"].sample | Should Be 1
    }
}

Describe "Test Set-JujuStatus" {
    AfterEach {
        Clear-Environment
    }
    Mock Write-JujuWarning -Verifiable -ModuleName JujuHooks {
        Param(
            [Parameter(Mandatory=$true)]
            [string]$Message
        )
    }
    Mock Invoke-JujuCommand -ModuleName JujuHooks -Verifiable -ParameterFilter { $Command.Count -eq 2 } {
        $statuses = @("maintenance", "blocked", "waiting", "active")
        if(!($Command[1] -in $statuses)){
            throw "invalid status"
        }
        $expect = @("status-set.exe", $Command[1])
        if((Compare-Object $Command $expect)) {
            Throw "Invalid command"
        }
        $tmpStatus = @{
            "status"=$Command[1];
            "message"="";
            "status-data"=@{};
        }
        $env:PesterTestData = (ConvertTo-Yaml $tmpStatus)
    }
    Mock Invoke-JujuCommand -ModuleName JujuHooks -Verifiable -ParameterFilter { $Command.Count -eq 3 } {
        $statuses = @("maintenance", "blocked", "waiting", "active")
        if(!($Command[1] -in $statuses)){
            throw "invalid status"
        }
        $expect = @("status-set.exe", $Command[1], $Command[2])
        if((Compare-Object $Command $expect)) {
            Throw "Invalid command"
        }
        $tmpStatus = @{
            "status"=$Command[1];
            "message"=$Command[2];
            "status-data"=@{};
        }
        $env:PesterTestData = (ConvertTo-Yaml $tmpStatus)
    }
    Mock Get-JujuStatus -ModuleName JujuHooks {
        Param(
            [switch]$Full=$false
        )
        $js = $env:PesterTestData
        $data = ConvertFrom-Yaml $js
        if($Full) {
            return $js
        }
        return (ConvertTo-Yaml $data.status)
    }
    It "Should only set status" {
        $env:PesterTestData = '{"message":"","status":"unknown","status-data":{}}'
        Set-JujuStatus -Status "active" | Should BeNullOrEmpty
        $d = ConvertFrom-Yaml $env:PesterTestData
        $d["status"] | Should Be "active"
        $d["message"] | Should BeNullOrEmpty
        $d["status-data"] | Should BeNullOrEmpty 
    }

    It "Should set status and message" {
        $env:PesterTestData = '{"message":"","status":"unknown","status-data":{}}'
        Set-JujuStatus -Status "active" -Message "Unit is ready" | Should BeNullOrEmpty
        Assert-MockCalled Invoke-JujuCommand -Times 1 -ModuleName JujuHooks
        $d = ConvertFrom-Yaml $env:PesterTestData
        $d["status"] | Should Be "active"
        $d["message"] | Should Be "Unit is ready"
        $d["status-data"] | Should BeNullOrEmpty 
    }
    It "Should not change message if status is unchanged" {
        $env:PesterTestData = '{"message":"","status":"unknown","status-data":{}}'
        Set-JujuStatus -Status "active" -Message "Unit is ready" | Should BeNullOrEmpty
        $d = ConvertFrom-Yaml $env:PesterTestData
        $d["status"] | Should Be "active"
        $d["message"] | Should Be "Unit is ready"
        $d["status-data"] | Should BeNullOrEmpty

        Set-JujuStatus -Status "active" -Message "Unit is almost ready" | Should BeNullOrEmpty
        Assert-MockCalled Invoke-JujuCommand -Times 1 -ModuleName JujuHooks
        $d["status"] | Should Be "active"
        $d["message"] | Should Be "Unit is ready"
        $d["status-data"] | Should BeNullOrEmpty
    }
    It "Should Throw an exception on invalid status" {
        { Set-JujuStatus -Status "bogus" -Message "Unit is almost ready" } | Should Throw
        { Set-JujuStatus -Status "bogus" } | Should Throw
    }
}

Describe "Test Get-JujuAction" {
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        $data = @{
            "bla"="bla";
        }
        if ($Command.Count -gt 3 -or $Command.Count -lt 2){
            Throw "invalid command"
        }
        $expect = @("action-get.exe", "--format=yaml")
        if ($Command.Count -eq 3){
            $expect += $Command[-1]
        }
        if((Compare-Object $Command $expect)) {
            Throw "Invalid command"
        }
        if($Command.Count -eq 3){
            return (ConvertTo-Yaml $data[$Command[2]])
        }
        return (ConvertTo-Yaml $data)
    }
    It "Should send proper command" {
        (Get-JujuAction).GetType() | Should Be "hashtable"
    }
    It "Should return value" {
        Get-JujuAction -Parameter "bla" | Should be "bla"
    }
    It "Should return empty" {
        Get-JujuAction -Parameter "NotThere" | Should BeNullOrEmpty
    }
}

Describe "Test Set-JujuAction" {
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        $expect = @("action-set.exe", "hello=world", "password=secret")
        if((Compare-Object $Command $expect)) {
            Throw "Invalid command"
        }
    }
    It "Should send proper parameters to leader-set" {
        $data = @{
            "hello"="world";
            "password"="secret";
        }
        Set-JujuAction -Settings $data | Should BeNullOrEmpty
    }
    It "Should throw an exception on invalid data" {
        { Set-LeaderData -Settings "bogus" } | Should Throw
        { Set-LeaderData -Settings @(1,2,3) } | Should Throw
    }
}

Describe "Test Set-JujuActionFailed" {
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        if ($Command.Count -lt 1 -or $Command.Count -gt 2) {
            Throw "Invalid parameters"
        }
        $expect = @("action-fail.exe")
        if($Command.Count -eq 2) {
            $expect += $Command[-1]
        }
        if((Compare-Object $Command $expect)) {
            Throw "Invalid command"
        }
    }
    It "Should send action fail" {
        Set-JujuActionFailed | Should BeNullOrEmpty
    }
}

Describe "Test Convert-JujuUnitNameToNetbios" {
    AfterEach {
        Clear-Environment
    }
    Mock Get-JujuLocalUnit -ModuleName JujuHooks {
        return $env:PesterTestData
    }
    It "Should return a valid netbios name" {
        $env:PesterTestData = "active-directory/12"
        Convert-JujuUnitNameToNetbios | Should Be "active-direct12"
        $env:PesterTestData = "test/11"
        Convert-JujuUnitNameToNetbios | Should Be "test11"
        $env:PesterTestData = "thisisareallylonghostnamethatwillprobablybreakstuff/1"
        Convert-JujuUnitNameToNetbios | Should Be "thisisareallyl1"
    }
}

Describe "Test Set-CharmState" {
    AfterEach {
        $CharmStateKey = "HKCU:\Software\Juju-Charms"
        if($CharmStateKey -and (Test-Path $CharmStateKey)) {
            Remove-Item $CharmStateKey -Recurse -Force
        }
    }
    BeforeEach {
        $CharmStateKey = "HKCU:\Software\Juju-Charms"
        if($CharmStateKey -and (Test-Path $CharmStateKey)) {
            Remove-Item $CharmStateKey -Recurse -Force
        }
    }
    Mock Get-StateInformationRepository -ModuleName JujuHooks { return "HKCU:\Software\Juju-Charms"}
    It "Should set a registry key" {
        $p = "HKCU:\Software\Juju-Charms"
        (Test-Path -Path $p) | Should Be $false
        Set-CharmState -Namespace "active-directory" -Key "username" -Value "guest" | Should BeNullOrEmpty
        $keyPath = Join-Path $p "active-directory"
        (Test-Path -Path $keyPath) | Should Be $true
        $k = (Get-ItemProperty -Path $keyPath -Name "username")
        (Select-Object -InputObject $k -ExpandProperty "username") | Should Be (ConvertTo-Yaml "guest")
    }
}

Describe "Test Get-CharmState" {
    AfterEach {
        $CharmStateKey = "HKCU:\Software\Juju-Charms"
        if($CharmStateKey -and (Test-Path $CharmStateKey)) {
            Remove-Item $CharmStateKey -Recurse -Force
        }
    }
    BeforeEach {
        $CharmStateKey = "HKCU:\Software\Juju-Charms"
        if($CharmStateKey -and (Test-Path $CharmStateKey)) {
            Remove-Item $CharmStateKey -Recurse -Force
        }
    }
    Mock Get-StateInformationRepository -ModuleName JujuHooks { return "HKCU:\Software\Juju-Charms"}
    It "Should return charm state" {
        Set-CharmState -Namespace "active-directory" -Key "username" -Value "guest" | Should BeNullOrEmpty
        Get-CharmState -Namespace "active-directory" -Key "username" | Should be "guest"
    }
}

Describe "Test Remove-CharmState" {
    AfterEach {
        $CharmStateKey = "HKCU:\Software\Juju-Charms"
        if($CharmStateKey -and (Test-Path $CharmStateKey)) {
            Remove-Item $CharmStateKey -Recurse -Force
        }
    }
    BeforeEach {
        $CharmStateKey = "HKCU:\Software\Juju-Charms"
        if($CharmStateKey -and (Test-Path $CharmStateKey)) {
            Remove-Item $CharmStateKey -Recurse -Force
        }
    }
    Mock Get-StateInformationRepository -ModuleName JujuHooks { return "HKCU:\Software\Juju-Charms"}
    It "Should remove charm state" {
        Set-CharmState -Namespace "active-directory" -Key "username" -Value "guest" | Should BeNullOrEmpty
        Get-CharmState -Namespace "active-directory" -Key "username" | Should be "guest"
        Remove-CharmState -Namespace "active-directory" -Key "username" | Should BeNullOrEmpty
    }
}