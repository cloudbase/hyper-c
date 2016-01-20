# Copyright 2015 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Module manifest for module 'JujuHelper'
#
# Generated by: Gabriel Adrian Samfira
#
# Generated on: 17/12/2015
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'JujuHelper.psm1'

# Version number of this module.
ModuleVersion = '0.1'

# ID used to uniquely identify this module
GUID = '86f6b80c-19ce-4893-818d-9ad6872d2f1c'

# Author of this module
Author = 'Gabriel Adrian Samfira, Adrian Vladu, Ionut Madalin Balutoiu'

# Company or vendor of this module
CompanyName = 'Cloudbase Solutions SRL'

# Copyright statement for this module
Copyright = '(c) 2015 Cloudbase Solutions SRL. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Helper module for Juju Charms'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Functions to export from this module
FunctionsToExport = @(
    "Invoke-JujuCommand",
    "Invoke-FastWebRequest",
    "Get-RandomString")

# Cmdlets to export from this module
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = '*'

}