<#
.SYNOPSIS
Deletes Azure resources of a specified type.

.DESCRIPTION
This runbook connects to Azure using the Automation Account's managed identity, retrieves resources of the specified type, and deletes them. It outputs the names of deleted resources in JSON format, suitable for parsing in Logic Apps.

.EXAMPLE
Remove-ResourceByType -ResourceType "Microsoft.SecurityCopilot/capacities"

.NOTES
Author: Your Name
Date: YYYY-MM-DD

#>

param (
    [Parameter(Mandatory = $true, HelpMessage = "Specify the Azure resource type.")]
    [string]$ResourceType
)

# Authenticate to Azure using the Automation Account's managed identity
$null = Connect-AzAccount -Identity

# Retrieve resources of the specified type
$resources = Get-AzResource -ResourceType $ResourceType 

# Check if there are items to delete
if (($resources | Measure-Object).Count -gt 0) {
    # Loop through each resource and delete it
    $deletedResources = @()
    foreach ($resource in $resources) {

            # Delete the resource
            Remove-AzResource -ResourceId $resource.ResourceId -Force -ErrorAction Stop
            # Add resource details to the deleted resources list
            $deletedResources += [PSCustomObject]@{
                Name = $resource.Name
                ResourceGroupName = $resource.ResourceGroupName
                ResourceType = $resource.ResourceType
            }
    }

    # Output deleted resources in JSON format
    $deletedResources | ConvertTo-Json -Depth 5
} else {
    # Output an empty JSON array if no resources are found
    @() | ConvertTo-Json -Depth 5
}
