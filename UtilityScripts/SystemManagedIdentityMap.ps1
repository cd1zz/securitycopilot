function Get-ManagedIdentityResources {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IdentityName,
        
        [Parameter(Mandatory = $false)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDetails
    )
    
    try {
        # Step 1: Get the managed identity details
        if ($ResourceGroupName) {
            $identity = Get-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $IdentityName -ErrorAction Stop
        }
        else {
            # If resource group not provided, search across all resource groups
            $identity = Get-AzUserAssignedIdentity | Where-Object { $_.Name -eq $IdentityName } | Select-Object -First 1
            
            if (-not $identity) {
                Write-Error "Could not find managed identity with name '$IdentityName'"
                return
            }
        }
        
        # Step 2: Get the principal ID
        $principalId = $identity.PrincipalId
        
        if (-not $principalId) {
            Write-Error "Could not retrieve principal ID for the managed identity '$IdentityName'"
            return
        }
        
        Write-Verbose "Found managed identity: $($identity.Id)"
        Write-Verbose "Principal ID: $principalId"
        
        # Step 3: Find role assignments for this principal
        $roleAssignments = Get-AzRoleAssignment -ObjectId $principalId
        
        # Step 4: Extract resource information from role assignments
        $resources = @()
        foreach ($assignment in $roleAssignments) {
            # Skip assignments at management group or subscription level
            if ($assignment.Scope -match '/providers/') {
                $resourceInfo = @{
                    ResourceId = $assignment.Scope
                    Role = $assignment.RoleDefinitionName
                }
                
                # Get more details about the resource if requested
                if ($IncludeDetails) {
                    try {
                        $resource = Get-AzResource -ResourceId $assignment.Scope -ErrorAction SilentlyContinue
                        if ($resource) {
                            $resourceInfo.ResourceName = $resource.Name
                            $resourceInfo.ResourceType = $resource.ResourceType
                            $resourceInfo.ResourceGroup = $resource.ResourceGroupName
                        }
                    }
                    catch {
                        # Some resource IDs might not be directly queryable
                        Write-Verbose "Could not get additional details for $($assignment.Scope): $_"
                    }
                }
                
                $resources += [PSCustomObject]$resourceInfo
            }
        }
        
        # Step 5: Return the results
        $result = [PSCustomObject]@{
            Identity = [PSCustomObject]@{
                Id = $identity.Id
                Name = $identity.Name
                PrincipalId = $identity.PrincipalId
                ClientId = $identity.ClientId
                TenantId = $identity.TenantId
                ResourceGroupName = ($identity.Id -split '/')[4]  # Extract RG from resource ID
            }
            AssociatedResources = $resources
        }
        
        return $result
    }
    catch {
        Write-Error "Failed to map identity to resources: $_"
    }
}

# Additional function to find resources that have the managed identity attached
function Get-ResourcesUsingManagedIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IdentityClientId
    )
    
    try {
        # Query resources with managed identities
        $query = "Resources | where identity contains '$IdentityClientId' | project id, name, type, resourceGroup"
        $resources = Search-AzGraph -Query $query
        
        return $resources
    }
    catch {
        Write-Error "Failed to find resources using managed identity: $_"
    }
}

# Example usage:
#Connect-AzAccount  # Log in first
$identityMap = Get-ManagedIdentityResources -IdentityName "" -ResourceGroupName "craig_group" -IncludeDetails
#$identityMap | ConvertTo-Json -Depth 10

# To find resources directly using the identity:
$clientId = $identityMap.Identity.ClientId
$resourcesUsingIdentity = Get-ResourcesUsingManagedIdentity -IdentityClientId $clientId
$resourcesUsingIdentity | ConvertTo-Json -Depth 10