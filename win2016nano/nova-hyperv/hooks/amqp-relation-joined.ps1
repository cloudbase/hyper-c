#
# Copyright 2014-2016 Cloudbase Solutions SRL
#

$ErrorActionPreference = "Stop"

Import-Module JujuLogging

try {
    Import-Module JujuHooks

    $rabbitUser = Get-JujuCharmConfig -Scope 'rabbit-user'
    $rabbitVhost = Get-JujuCharmConfig -Scope 'rabbit-vhost'

    $relation_set = @{
        'username'=$rabbitUser;
        'vhost'=$rabbitVhost
    }

    $rids = Get-JujuRelationIds -Relation "amqp"
    foreach ($rid in $rids){
        $ret = Set-JujuRelation -RelationId $rid -Settings $relation_set
        if ($ret -eq $false){
           Write-JujuWarning "Failed to set amqp relation"
        }
    }
}catch{
    Write-HookTracebackToLog $_
    exit 1
}
