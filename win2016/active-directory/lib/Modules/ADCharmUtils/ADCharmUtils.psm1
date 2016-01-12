function Set-UserRunAsRights {
    Param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $Username
    )
    # TODO: Check if we actually need all these...
    $privileges = @(
        "SeServiceLogonRight",
        "SeTakeOwnershipPrivilege",
        "SeSyncAgentPrivilege",
        "SeSecurityPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeRestorePrivilege",
        "SeShutdownPrivilege",
        "SeMachineAccountPrivilege",
        "SeTcbPrivilege",
        "SeInteractiveLogonRight",
        "SeBatchLogonRight",
        "SeNetworkLogonRight",
        "SeBackupPrivilege",
        "SeCreateTokenPrivilege",
        "SeCreatePermanentPrivilege",
        "SeCreatePagefilePrivilege",
        "SeSystemEnvironmentPrivilege",
        "SeProfileSingleProcessPrivilege",
        "SeCreateSymbolicLinkPrivilege")

    $allPrivillegesCount = $privileges.Count
    $allPrivillegesInstalled = 0
    foreach ($privilege in $privileges) {
        Grant-Privilege -User $Username -Grant $privilege
    }
    return $true
}