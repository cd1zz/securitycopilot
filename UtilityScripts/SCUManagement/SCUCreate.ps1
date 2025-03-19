<#
.SYNOPSIS
Creates an SCU resource with a name based on the current date if it does not already exist.

.DESCRIPTION
This runbook checks for the existence of an SCU resource named 'scuMMddyyyy' (e.g., 'scu11132024' for November 13, 2024) within a specified resource group.
If the resource does not exist, it creates the resource with the specified number of units.

.NOTES
Author: Your Name
Date: YYYY-MM-DD
#>

# Set error action preference to stop on errors
$ErrorActionPreference = 'Stop'

# Authenticate to Azure using the Automation Account's managed identity
$null = Connect-AzAccount -Identity

# Set values for the resource and resource group
$resourceGroupName = "craig_group"
$resourceType = "Microsoft.SecurityCopilot/capacities"
$location = "eastus"  # Specify the location, e.g., "eastus"
$numberOfUnits = 1    # Specify the number of SCUs

# Generate the resource name based on today's date
$currentDate = Get-Date -Format "MMddyyyy"
$resourceName = "scu$currentDate"

Write-Verbose "Generated resource name: '$resourceName'"

Write-Verbose "Checking for the existence of the resource '$resourceName' in resource group '$resourceGroupName'."

try {
    # Check if the specified resource exists
    $resource = Get-AzResource -ResourceGroupName $resourceGroupName `
                               -ResourceName $resourceName `
                               -ResourceType $resourceType `
                               -ErrorAction SilentlyContinue

    if ($resource) {
        # Resource exists; write output and exit
        Write-Output "Resource '$resourceName' already exists in resource group '$resourceGroupName'. No action needed."
    } else {
        # Resource does not exist; proceed to create it
        Write-Output "Resource '$resourceName' not found. Creating it in resource group '$resourceGroupName' with $numberOfUnits SCU(s)."

        # Define properties for the new resource
        $properties = @{
            numberOfUnits = $numberOfUnits
        }

        # Create the new resource
        New-AzResource -ResourceGroupName $resourceGroupName `
                       -ResourceName $resourceName `
                       -ResourceType $resourceType `
                       -Location $location `
                       -Properties $properties `
                       -Force

        # Verify resource creation
        $resource = Get-AzResource -ResourceGroupName $resourceGroupName `
                                   -ResourceName $resourceName `
                                   -ResourceType $resourceType `
                                   -ErrorAction Stop

        if ($resource) {
            Write-Output "Successfully created resource '$resourceName' in resource group '$resourceGroupName' with $numberOfUnits SCU(s)."
        } else {
            Write-Error "Failed to verify the creation of resource '$resourceName'."
        }
    }
} catch {
    Write-Error "An error occurred: $_"
}
