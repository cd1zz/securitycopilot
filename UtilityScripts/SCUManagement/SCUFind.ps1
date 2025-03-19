<#
.SYNOPSIS
Lists Azure resources of a specified type and outputs the result in JSON format for consumption by Logic Apps.

.DESCRIPTION
This runbook connects to Azure using the Automation Account's managed identity, retrieves resources of the specified type, and outputs the data in JSON format suitable for parsing in Logic Apps.

.EXAMPLE
Get-ResourceByType -ResourceType "Microsoft.SecurityCopilot/capacities"

.NOTES
Author: Your Name
Date: YYYY-MM-DD

Can be parameterized for any resource type:
param(
    [Parameter(Mandatory = $true, HelpMessage = "Specify the Azure resource type.")]
    [string]$ResourceType
)
#>


$ResourceType = "Microsoft.SecurityCopilot/capacities"

# Authenticate to Azure using the Automation Account's managed identity
$null = Connect-AzAccount -Identity

# Retrieve resources of the specified type
$resources = Get-AzResource -ResourceType $ResourceType 

# Select desired properties
$selectedResources = $resources | Select-Object -Property Name, ResourceGroupName, ResourceType

# Check if there are items in $selectedResources
if (($selectedResources | Measure-Object).Count -gt 0) {
    # Output resources in JSON format
    $selectedResources | ConvertTo-Json -Depth 10
} else {
    # Output an empty JSON array if no resources are found
    @() | ConvertTo-Json -Depth 10
}


