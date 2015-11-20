#######################################################
##
## Set-KCD.ps1, v1.2, 2012
##
## Created by Matthijs ten Seldam, Microsoft
##
#######################################################

<#
.SYNOPSIS
Configures Kerberos Constrained Delegation (KCD) on a single computer object or multiple computer objects in Active Directory.

.DESCRIPTION
Set-KCD supports adding, replacing, removing, clearing and listing of delegation records for a specified computer object or multiple computer objects in Active Directory.

.PARAMETER TrustedComputer
The name of the computer object in Active Directory trusted for delegation to a specific service type.

.PARAMETER TrustingComputer
The name of the computer to delegate authentication to. This is the computer that will accept your credentials on behalf of the TrustedComputer.

.PARAMETER ServiceType
The name of the ServiceType to delegate.

.PARAMETER Add
Switch to specify to add delegation records.

.PARAMETER Clear
Switch to specify to clear delegation records.

.PARAMETER File
The name of a CSV file containing entries for the Trusted and Trusting computers and the ServiceType.

.PARAMETER Import
Switch to specify to import delegation records.

.PARAMETER List
Switch to list current delegation settings for the specified TrustedComputer.

.PARAMETER lISTfROMfILE
Switch to list current delegation settings for the TrustedComputer entries spcified in the File.

.PARAMETER Remove
Switch to specify to remove delegation records.

.PARAMETER Replace
Switch to specify to replace delegation records.

.EXAMPLE
Set-KCD -TrustedComputer vmhost1 -TrustingComputer vmhost2 -ServiceType cifs -Add

This command adds the CIFS ServiceType type to the computer object vmhost1 for computer vmhost2 to trust vmhost1 for delegation to vmhost2 for this ServiceType.

.EXAMPLE
Set-KCD.ps1 -TrustedComputer vmhost2 -TrustingComputer vmhost3 -ServiceType "Microsoft Virtual System Migration ServiceType" -Add

This command adds the "Microsoft Virtual System Migration ServiceType" type to the computer object vmhost2 for computer vmhost3 to trust vmhost2 for delegation to vmhost3 for this ServiceType.

.EXAMPLE
Set-KCD -TrustedComputer vmhost1 -TrustingComputer vmhost2 -ServiceType cifs -Replace

This command replaces ALL delegation properties with the specified property set (vmhost2/cifs). Any existing properties will be removed.

.EXAMPLE
Set-KCD -TrustedComputer vmhost1 -TrustingComputer vmhost2 -ServiceType cifs -Remove

This command removes the specified delegation properties for vmhost2 and cifs.

.EXAMPLE
Set-KCD -TrustedComputer vmhost3 -Clear

This command clears ALL property sets currently specified for delegation.

.EXAMPLE
Set-KCD -TrustedComputer vmhost1 -List

This command lists the available property sets (service type | computer name) on the object of computer vmhost1 (if anything has been configured).

.EXAMPLE
Set-KCD -File .\ConfigFile.csv -ListFromFile

This command uses the TrustedComputer entries in the File to list the currently configured delegation records.

.EXAMPLE
Set-KCD -File .\ConfigFile.csv -Import

This command uses the contents in the CSV File to configure the TrustedComputer with delegation records for the TrustingComputer and ServiceType.
See below example for a correctly formatted file:

TrustedComputer,TrustingComputer,ServiceType
vmhost1,fhost1,CIFS
vmhost1,vmhost2,Microsoft Virtual System Migration Service
vmhost1,vmhost2,CIFS
vmhost2,vmhost1,Microsoft Virtual System Migration Service
vmhost2,vmhost1,CIFS

.INPUTS
None

.OUTPUTS
None

.NOTES
This script must be run using domain administrator credentials.
The script adds both entries for the target computer; unqualified and fully qualified computer names.
The script uses the UserDnsDomain environment variable to construct the fully qualified domain name of the TrustingComputer name.

.LINK
http://blogs.technet.com/matthts
#>

[CmdletBinding(DefaultParameterSetName="Add")]
param(
    [Parameter(Mandatory=$true, Position=0, ParameterSetName="Add")]
    [Parameter(Mandatory=$true, Position=0, ParameterSetName="Clear")]
    [Parameter(Mandatory=$true, Position=0, ParameterSetName="List")]
    [Parameter(Mandatory=$true, Position=0, ParameterSetName="Remove")]
    [Parameter(Mandatory=$true, Position=0, ParameterSetName="Replace")]
    [string] $TrustedComputer,
    [Parameter(Mandatory=$true, Position=1, ParameterSetName="Add")]
    [Parameter(Mandatory=$true, Position=1, ParameterSetName="Replace")]
    [Parameter(Mandatory=$true, Position=1, ParameterSetName="Remove")]
    [string] $TrustingComputer,
    [Parameter(Mandatory=$true, Position=2, ParameterSetName="Add")]
    [Parameter(Mandatory=$true, Position=2, ParameterSetName="Replace")]
    [Parameter(Mandatory=$true, Position=2, ParameterSetName="Remove")]
    [string]$ServiceType,
    [Parameter(Mandatory=$false, ParameterSetName="Add")]
    [switch]$Add,
    [Parameter(Mandatory=$true, ParameterSetName="Clear")]
    [switch]$Clear,
    [Parameter (Mandatory=$true, ParameterSetName="Import")]
    [Parameter (Mandatory=$true, ParameterSetName="ListFromFile")]
    [string]$File,
    [Parameter (Mandatory=$true, ParameterSetName="Import")]
    [switch]$Import,
    [Parameter(Mandatory=$true, ParameterSetName="List")]
    [switch] $List,
    [Parameter(Mandatory=$true, ParameterSetName="ListFromFile")]
    [switch] $ListFromFile,
    [Parameter(Mandatory=$true, ParameterSetName="Remove")]
    [switch] $Remove,
    [Parameter(Mandatory=$true, ParameterSetName="Replace")]
    [switch] $Replace
    )

Set-StrictMode -Version Latest

If ($PSCmdlet.ParameterSetName -ne "Import")
{
    If ($TrustedComputer.Contains("."))
    {
        $TrustedComputer=$TrustedComputer.Remove($TrustedComputer.IndexOf("."))
    }
}


Function Get-Delegation()
{
    try
    {
        $AdObject = Get-AdComputer $TrustedComputer -Properties msDS-AllowedToDelegateTo | Select-Object -ExpandProperty msDS-AllowedToDelegateTo
        If ($AdObject -ne $null)
        {
            Write-Host `n"Computer name $TrustedComputer is trusted for delegation for the following service(s) to computer(s):"
            Write-Host "--------------------------------------------------------------------------------------------"`n
            $AdObject | Sort-Object
            Write-Host `n"--------------------------------------------------------------------------------------------"`n
        }
        else
        {
            Write-Host `n"No delegation has been configured for computer $TrustedComputer."`n
        }
    }
    Catch
    {
        Write-Host `n"An error occurred searching for Computer name $TrustedComputer in Active Directory!"`n
    }
}


switch($PSCmdlet.ParameterSetName)
{
    {($_ -eq "Add") -or ($_ -eq "Replace") -or ($_ -eq "Remove")}
    {
        If ($TrustingComputer.Contains("."))
        {
            $TrustingComputer=$TrustingComputer.Remove($TrustingComputer.IndexOf("."))
        }
        try
        {
            $ParamHash=@{$PSCmdlet.ParameterSetName=@{"msDS-AllowedToDelegateTo"="$ServiceType/$TrustingComputer","$ServiceType/$TrustingComputer.$env:UserDnsDomain"}}
            Get-ADComputer $TrustedComputer | Set-ADObject @ParamHash
            Get-Delegation
        }
        Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
        {
            Write-Host "`nThe Object for computer $TrustedComputer could not be found in Active Directory.`n"
        }
    }

    "Clear"
    {
        Get-ADComputer $TrustedComputer | Set-ADObject -Clear msDS-AllowedToDelegateTo
        Get-Delegation
    }

    "Import"
    {
        If ($File -ne $null)
        {
            try
            {
                $Records=Import-Csv $File
            }
            Catch
            {
                Write-Host `n"$File file not found!`n"
                exit
            }

            foreach($Item in $Records)
            {
                $TrustedComputer=$Item.TrustedComputer
                $TrustingComputer=$Item.TrustingComputer
                $ServiceType=$Item.ServiceType

                Get-ADComputer $TrustedComputer | Set-ADObject -Add @{"msDS-AllowedToDelegateTo"="$ServiceType/$TrustingComputer","$ServiceType/$TrustingComputer.$env:UserDnsDomain"}
                Write-Host "--------------------------------------------------------------------------------------------"`n
                Write-Host "Added $ServiceType/$TrustingComputer,$ServiceType/$TrustingComputer.$env:UserDnsDomain to $TrustedComputer."`n
            }
        }
    }

    "List"
    {
        Get-Delegation
    }

    "ListFromFile"
    {
        If ($File -ne $null)
        {
            try
            {
                $Records=Import-Csv $File | Select-Object -Property TrustedComputer -Unique
            }
            Catch
            {
                Write-Host `n"$File file not found!`n"
                exit
            }

            foreach($Item in $Records)
            {
                $TrustedComputer=$Item.TrustedComputer
                Get-Delegation
            }
        }

        else
        {
            Get-Delegation
        }
    }
}





