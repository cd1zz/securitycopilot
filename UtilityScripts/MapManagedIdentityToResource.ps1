function Find-ResourceByManagedIdentityObjectId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectId
    )
    
    try {
        Write-Verbose "Searching for resources with managed identity ObjectId: $ObjectId"
        
        # First, try to find if this is a user-assigned managed identity
        Write-Verbose "Checking user-assigned managed identities..."
        $userAssignedIdentities = Get-AzUserAssignedIdentity -ErrorAction SilentlyContinue | 
            Where-Object { $_.PrincipalId -eq $ObjectId }
        
        if ($userAssignedIdentities) {
            $result = [PSCustomObject]@{
                IdentityType = "UserAssigned"
                Resources = $userAssignedIdentities | ForEach-Object {
                    [PSCustomObject]@{
                        ResourceId = $_.Id
                        Name = $_.Name
                        ResourceType = "Microsoft.ManagedIdentity/userAssignedIdentities"
                        ResourceGroup = ($_.Id -split '/')[4]
                        ClientId = $_.ClientId
                        PrincipalId = $_.PrincipalId
                    }
                }
            }
            
            return $result
        }
        
        # If not found, search for system-assigned identities using Resource Graph
        Write-Verbose "Checking system-assigned managed identities..."
        
        # Make sure Resource Graph module is available
        if (-not (Get-Module -Name Az.ResourceGraph -ListAvailable)) {
            Write-Warning "Az.ResourceGraph module not found. Installing..."
            Install-Module -Name Az.ResourceGraph -Force -AllowClobber
        }
        
        # Query for resources with system-assigned identity matching the ObjectId
        $query = "Resources | where identity.principalId == '$ObjectId' | project id, name, type, resourceGroup, identity"
        $resources = Search-AzGraph -Query $query
        
        if ($resources -and $resources.Count -gt 0) {
            $result = [PSCustomObject]@{
                IdentityType = "SystemAssigned"
                Resources = $resources | ForEach-Object {
                    [PSCustomObject]@{
                        ResourceId = $_.id
                        Name = $_.name
                        ResourceType = $_.type
                        ResourceGroup = $_.resourceGroup
                        PrincipalId = $_.identity.principalId
                    }
                }
            }
            
            return $result
        }
        
        # If still not found, check Azure AD service principals
        # (this might be a managed identity from a different subscription or deleted resource)
        Write-Verbose "Checking Azure AD service principals..."
        $servicePrincipal = Get-AzADServicePrincipal -ObjectId $ObjectId -ErrorAction SilentlyContinue
        
        if ($servicePrincipal) {
            # This is a service principal, could be from a managed identity
            $result = [PSCustomObject]@{
                IdentityType = "ServicePrincipal (Possibly Managed Identity)"
                Resources = @([PSCustomObject]@{
                    DisplayName = $servicePrincipal.DisplayName
                    ApplicationId = $servicePrincipal.ApplicationId
                    ObjectId = $servicePrincipal.Id
                    AppOwnerOrganizationId = $servicePrincipal.AppOwnerOrganizationId
                    Note = "This appears to be a service principal, which may be associated with a managed identity. Check the DisplayName for clues about the source resource."
                })
            }
            
            return $result
        }
        
        # Nothing found
        Write-Warning "No resources found with managed identity ObjectId: $ObjectId"
        return $null
    }
    catch {
        Write-Error "Error searching for resources with managed identity ObjectId: $_"
    }
}

# Example usage:
# Connect-AzAccount  # Log in first
$result = Find-ResourceByManagedIdentityObjectId -ObjectId "6f1a8d0c-9bf9-4f73-808f-da74cf1c19ea"
$result | ConvertTo-Json -Depth 10