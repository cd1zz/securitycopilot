# ManageSecurityCopilotSCUs.ps1
# Script to list and create Security Copilot SCUs (Security Compute Units)

# Function to get access token
function Get-AzureAccessToken {
    param(
        [string]$Resource = "https://management.azure.com/"
    )
    
    $context = Get-AzContext
    if (-not $context) {
        throw "Not logged in to Azure. Please run Connect-AzAccount first."
    }
    
    try {
        $token = Get-AzAccessToken -ResourceUrl $Resource
        return $token.Token
    }
    catch {
        $profile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
        $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($profile)
        $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
        return $token.AccessToken
    }
}

# Function to list SCUs using Azure Resource Manager (more reliable)
function Get-SecurityCopilotSCUsFromARM {
    Write-Host "`nRetrieving SCUs from Azure Resource Manager..." -ForegroundColor Yellow
    
    try {
        $subscriptionId = (Get-AzContext).Subscription.Id
        $uri = "/subscriptions/$subscriptionId/providers/Microsoft.SecurityCopilot/capacities?api-version=2024-11-01-preview"
        
        $response = Invoke-AzRestMethod -Path $uri -Method GET
        
        if ($response.StatusCode -eq 200) {
            $capacities = ($response.Content | ConvertFrom-Json).value
            
            if ($capacities -and $capacities.Count -gt 0) {
                Write-Host "Found $($capacities.Count) SCU(s):" -ForegroundColor Green
                
                $scuList = @()
                foreach ($scu in $capacities) {
                    $scuInfo = [PSCustomObject]@{
                        Name = $scu.name
                        Location = $scu.location
                        ResourceGroup = $scu.id -replace '.*resourceGroups/([^/]+)/.*', '$1'
                        NumberOfUnits = $scu.properties.numberOfUnits
                        Geo = $scu.properties.geo
                        ProvisioningState = $scu.properties.provisioningState
                        CrossGeoCompute = $scu.properties.crossGeoCompute
                        ResourceId = $scu.id
                    }
                    $scuList += $scuInfo
                    
                    Write-Host "`n  SCU Name: $($scuInfo.Name)" -ForegroundColor Cyan
                    Write-Host "    Location: $($scuInfo.Location)"
                    Write-Host "    Resource Group: $($scuInfo.ResourceGroup)"
                    Write-Host "    Units: $($scuInfo.NumberOfUnits)"
                    Write-Host "    Geo: $($scuInfo.Geo)"
                    Write-Host "    State: $($scuInfo.ProvisioningState)"
                    Write-Host "    Cross-Geo: $($scuInfo.CrossGeoCompute)"
                }
                
                return $scuList
            }
            else {
                Write-Host "No SCUs found in subscription." -ForegroundColor Yellow
                return @()
            }
        }
        else {
            Write-Host "Failed to retrieve SCUs. Status: $($response.StatusCode)" -ForegroundColor Red
            return @()
        }
    }
    catch {
        Write-Host "Error retrieving SCUs from ARM: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# Function to list existing SCUs from Security Platform API (may fail with 401)
function Get-SecurityCopilotSCUsFromPlatform {
    Write-Host "`nAttempting to retrieve SCUs from Security Platform API..." -ForegroundColor Yellow
    
    $uri = "https://api.securityplatform.microsoft.com/account/capacities?api-version=2023-12-01-preview"
    $token = Get-AzureAccessToken
    
    $headers = @{
        'Authorization' = "Bearer $token"
        'Content-Type' = 'application/json'
    }
    
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -ErrorAction Stop
        
        if ($response.value -and $response.count -gt 0) {
            Write-Host "Successfully retrieved from Security Platform API" -ForegroundColor Green
            return $response.value
        }
        else {
            Write-Host "No SCUs found via Security Platform API." -ForegroundColor Yellow
            return @()
        }
    }
    catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 401) {
            Write-Host "Security Platform API authentication failed (401). This is expected if Security Copilot hasn't been fully provisioned." -ForegroundColor Yellow
            Write-Host "Using Azure Resource Manager API instead..." -ForegroundColor Yellow
        }
        elseif ($_.Exception.Response.StatusCode.value__ -eq 404) {
            Write-Host "Security Platform account not found. You may need to set up Security Copilot first." -ForegroundColor Yellow
        }
        else {
            Write-Host "Error from Security Platform API: $($_.Exception.Message)" -ForegroundColor Red
        }
        return $null
    }
}

# Combined function to get SCUs from best available source
function Get-SecurityCopilotSCUs {
    param(
        [switch]$ARMOnly
    )
    
    if ($ARMOnly) {
        return Get-SecurityCopilotSCUsFromARM
    }
    
    # Try Security Platform API first
    $platformSCUs = Get-SecurityCopilotSCUsFromPlatform
    
    # If that fails, use ARM
    if ($null -eq $platformSCUs) {
        return Get-SecurityCopilotSCUsFromARM
    }
    
    return $platformSCUs
}

# Function to create new SCU
function New-SecurityCopilotSCU {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory=$true)]
        [string]$SCUName,
        
        [Parameter(Mandatory=$true)]
        [string]$Location,
        
        [Parameter(Mandatory=$false)]
        [int]$NumberOfUnits = 1,
        
        [Parameter(Mandatory=$false)]
        [string]$Geo = "US",
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("NotAllowed", "Allowed")]
        [string]$CrossGeoCompute = "NotAllowed"
    )
    
    Write-Host "`nCreating Security Copilot SCU '$SCUName'..." -ForegroundColor Yellow
    
    # First check if resource group exists
    try {
        $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
        Write-Host "Using resource group: $($rg.ResourceGroupName)" -ForegroundColor Gray
    }
    catch {
        Write-Host "Resource group '$ResourceGroupName' not found!" -ForegroundColor Red
        $create = Read-Host "Would you like to create it? (Y/N)"
        if ($create -eq 'Y') {
            New-AzResourceGroup -Name $ResourceGroupName -Location $Location
            Write-Host "Created resource group '$ResourceGroupName'" -ForegroundColor Green
        }
        else {
            return
        }
    }
    
    $subscriptionId = (Get-AzContext).Subscription.Id
    $apiVersion = "2024-11-01-preview"
    
    $uri = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.SecurityCopilot/capacities/$SCUName`?api-version=$apiVersion"
    
    $body = @{
        name = $SCUName
        location = $Location
        properties = @{
            numberOfUnits = $NumberOfUnits
            crossGeoCompute = $CrossGeoCompute
            geo = $Geo
            overageState = "None"
        }
    } | ConvertTo-Json -Depth 3
    
    Write-Host "Creating with parameters:" -ForegroundColor Gray
    Write-Host "  Location: $Location"
    Write-Host "  Resource Group: $ResourceGroupName"
    Write-Host "  Units: $NumberOfUnits"
    Write-Host "  Geo: $Geo"
    Write-Host "  Cross-Geo Compute: $CrossGeoCompute"
    
    try {
        $response = Invoke-AzRestMethod -Path $uri -Method PUT -Payload $body
        
        if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 201) {
            Write-Host "`nSuccessfully created SCU: $SCUName" -ForegroundColor Green
            
            # Wait for provisioning
            Write-Host "Waiting for SCU to be provisioned..." -ForegroundColor Yellow
            Start-Sleep -Seconds 10
            
            # Verify creation
            Write-Host "Verifying SCU creation..." -ForegroundColor Yellow
            $allSCUs = Get-SecurityCopilotSCUsFromARM
            $newSCU = $allSCUs | Where-Object { $_.Name -eq $SCUName }
            
            if ($newSCU) {
                Write-Host "SCU '$SCUName' verified successfully!" -ForegroundColor Green
                Write-Host "Provisioning State: $($newSCU.ProvisioningState)" -ForegroundColor Green
            }
            else {
                Write-Host "SCU created but verification pending. Check again in a moment." -ForegroundColor Yellow
            }
            
            return $response
        }
        else {
            $errorContent = $response.Content | ConvertFrom-Json
            throw "Failed to create SCU. Status: $($response.StatusCode). Error: $($errorContent.error.message)"
        }
    }
    catch {
        Write-Host "Error creating SCU: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

# Function to delete SCU
function Remove-SecurityCopilotSCU {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SCUName,
        
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName
    )
    
    $confirm = Read-Host "Are you sure you want to delete SCU '$SCUName'? (Y/N)"
    if ($confirm -ne 'Y') {
        Write-Host "Deletion cancelled." -ForegroundColor Yellow
        return
    }
    
    Write-Host "`nDeleting SCU '$SCUName'..." -ForegroundColor Yellow
    
    $subscriptionId = (Get-AzContext).Subscription.Id
    $apiVersion = "2024-11-01-preview"
    
    $uri = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.SecurityCopilot/capacities/$SCUName`?api-version=$apiVersion"
    
    try {
        $response = Invoke-AzRestMethod -Path $uri -Method DELETE
        
        if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 202 -or $response.StatusCode -eq 204) {
            Write-Host "Successfully deleted SCU: $SCUName" -ForegroundColor Green
        }
        else {
            throw "Failed to delete SCU. Status: $($response.StatusCode)"
        }
    }
    catch {
        Write-Host "Error deleting SCU: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

# Main execution
Write-Host "Security Copilot SCU Management" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# Check Azure authentication
$context = Get-AzContext
if (-not $context) {
    Write-Host "`nNot logged in to Azure. Please run: Connect-AzAccount" -ForegroundColor Red
    return
}

Write-Host "`nAuthenticated as: $($context.Account.Id)" -ForegroundColor Green
Write-Host "Subscription: $($context.Subscription.Name) ($($context.Subscription.Id))" -ForegroundColor Green

# Register provider if needed
Write-Host "`nChecking Microsoft.SecurityCopilot provider registration..." -ForegroundColor Yellow
$provider = Get-AzResourceProvider -ProviderNamespace Microsoft.SecurityCopilot
if ($provider.RegistrationState -ne 'Registered') {
    Write-Host "Registering Microsoft.SecurityCopilot provider..." -ForegroundColor Yellow
    Register-AzResourceProvider -ProviderNamespace Microsoft.SecurityCopilot
    Write-Host "Provider registration initiated. This may take a few minutes." -ForegroundColor Yellow
}
else {
    Write-Host "Provider is registered." -ForegroundColor Green
}

# Display current SCUs
Write-Host "`n--- Current SCUs ---" -ForegroundColor Cyan
$currentSCUs = Get-SecurityCopilotSCUs

# Usage instructions
Write-Host "`n--- Usage Instructions ---" -ForegroundColor Cyan
Write-Host "Available commands:" -ForegroundColor Yellow
Write-Host "  Get-SecurityCopilotSCUs                # List all SCUs" -ForegroundColor Gray
Write-Host "  Get-SecurityCopilotSCUs -ARMOnly       # List SCUs using only ARM API" -ForegroundColor Gray
Write-Host "  New-SecurityCopilotSCU -ResourceGroupName 'YourRG' -SCUName 'YourSCU' -Location 'eastus' -NumberOfUnits 1" -ForegroundColor Gray
Write-Host "  Remove-SecurityCopilotSCU -SCUName 'YourSCU' -ResourceGroupName 'YourRG'" -ForegroundColor Gray
Write-Host "`nNote: If you get 401 errors from Security Platform API, the SCUs will still be listed via Azure Resource Manager." -ForegroundColor Yellow
