# Script to extract Azure Function App configuration and settings
# Make sure you're logged into Azure first with Connect-AzAccount

param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$true)]
    [string]$FunctionAppName
)

# Create a directory for the output
$outputDir = ".\FunctionAppExport_$FunctionAppName"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# Get function app details
Write-Host "Retrieving Function App details..." -ForegroundColor Cyan
$functionApp = Get-AzFunctionApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName
$functionApp | ConvertTo-Json -Depth 10 | Out-File "$outputDir\functionApp_details.json"

# Get app settings (environment variables)
Write-Host "Retrieving app settings..." -ForegroundColor Cyan
$appSettings = Get-AzFunctionAppSetting -ResourceGroupName $ResourceGroupName -Name $FunctionAppName
$appSettings | ConvertTo-Json | Out-File "$outputDir\app_settings.json"

# Get hosting plan information
Write-Host "Retrieving hosting plan details..." -ForegroundColor Cyan
try {
    $planName = $functionApp.ServerFarmId.Split('/')[-1]
    $hostingPlan = Get-AzFunctionAppPlan -ResourceGroupName $ResourceGroupName -Name $planName -ErrorAction Stop
    $hostingPlan | ConvertTo-Json -Depth 10 | Out-File "$outputDir\hosting_plan.json"
} catch {
    Write-Host "Could not retrieve hosting plan details. Error: $_" -ForegroundColor Yellow
}

# Get storage account connection string
Write-Host "Extracting storage account information..." -ForegroundColor Cyan
if ($appSettings.ContainsKey("AzureWebJobsStorage")) {
    $storageConnString = $appSettings["AzureWebJobsStorage"]
    "Storage Connection String: $storageConnString" | Out-File "$outputDir\storage_info.txt"
}

# Check for any application insights
Write-Host "Extracting Application Insights information..." -ForegroundColor Cyan
if ($appSettings.ContainsKey("APPINSIGHTS_INSTRUMENTATIONKEY")) {
    $appInsightsKey = $appSettings["APPINSIGHTS_INSTRUMENTATIONKEY"]
    "App Insights Instrumentation Key: $appInsightsKey" | Out-File "$outputDir\app_insights_info.txt"
}

# Get Python runtime information
Write-Host "Getting Python runtime information..." -ForegroundColor Cyan
$pythonVersion = $functionApp.Runtime
$pythonVersion | Out-File "$outputDir\python_version.txt"

# Extract important function app properties
Write-Host "Extracting key function app properties..." -ForegroundColor Cyan
$functionAppProperties = @{
    "Name" = $functionApp.Name
    "ResourceGroup" = $functionApp.ResourceGroup
    "Location" = $functionApp.Location
    "Runtime" = $functionApp.Runtime
    "RuntimeVersion" = $functionApp.RuntimeVersion
    "OSType" = $functionApp.OSType
    "FunctionsExtensionVersion" = $functionApp.FunctionsExtensionVersion
    "HttpsOnly" = $functionApp.HttpsOnly
}
$functionAppProperties | ConvertTo-Json | Out-File "$outputDir\function_app_properties.json"

Write-Host "Export completed to $outputDir" -ForegroundColor Green
Write-Host "This information will help create your deployment package."