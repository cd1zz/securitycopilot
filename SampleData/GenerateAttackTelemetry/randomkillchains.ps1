$reconnaissance = @('T1592', 'T1596.003', 'T1597.002', 'T1590.005', 'T1590.002', 'T1596.002', 'T1594', 'T1596.001', 'T1591.003')
$initialAccess = @('T1133', 'T1195.001', 'T1566.002', 'T1566.001', 'T1195.003', 'T1091', 'T1195')
$execution = @('T1053.005', 'T1047', 'T1129', 'T1059.007', 'T1053.007', 'T1559.002', 'T1204.002')
$persistence = @('T1053.005', 'T1205.002', 'T1037', 'T1556.003', 'T1574.007', 'T1546.013', 'T1543')
$privilegeEscalation = @('T1055.011', 'T1053.005', 'T1037', 'T1574.007', 'T1546.013', 'T1543')
$lateralMovement = @('T1021.005', 'T1080', 'T1021.004', 'T1091', 'T1021.008', 'T1563.001', 'T1021.002')
$commandAndControl = @('T1205.002', 'T1132.001', 'T1568.002', 'T1071.004', 'T1573.001', 'T1568.001')
$exfiltration = @('T1567', 'T1567.004', 'T1029', 'T1011', 'T1011.001', 'T1020', 'T1048.001')

# Set up variables
$UserProfile = [Environment]::GetFolderPath('UserProfile')
$PathToAtomicsFolder = "$UserProfile\atomic-red-team\atomics"
$atomicRedTeamPath = "$UserProfile\atomic-red-team"

# Exclude the atomic-red-team folder from Microsoft Defender scanning
Write-Host "Adding Defender exclusion for $atomicRedTeamPath" -Verbose
Add-MpPreference -ExclusionPath $atomicRedTeamPath

# Get all folders under the atomics folder that start with "T" (e.g., T1059.001, T1087.001)
Write-Host "Getting all technique folders under $PathToAtomicsFolder" -Verbose
$techniqueFolders = Get-ChildItem -Path $PathToAtomicsFolder -Directory | Where-Object { $_.Name -like "T*" }
$availableTechniques = $techniqueFolders.Name
Write-Host "Available techniques: $($availableTechniques -join ', ')" -Verbose

# Filter the techniques for each category based on availability
$validTechniqueMapping = @{
    'Reconnaissance'       = $reconnaissance | Where-Object { $availableTechniques -contains $_ }
    'InitialAccess'        = $initialAccess | Where-Object { $availableTechniques -contains $_ }
    'Execution'            = $execution | Where-Object { $availableTechniques -contains $_ }
    'Persistence'          = $persistence | Where-Object { $availableTechniques -contains $_ }
    'PrivilegeEscalation'  = $privilegeEscalation | Where-Object { $availableTechniques -contains $_ }
    'LateralMovement'      = $lateralMovement | Where-Object { $availableTechniques -contains $_ }
    'CommandAndControl'    = $commandAndControl | Where-Object { $availableTechniques -contains $_ }
    'Exfiltration'         = $exfiltration | Where-Object { $availableTechniques -contains $_ }
}

# Generate a random kill chain using the pre-filtered techniques
$selectedKillChain = @()
foreach ($step in $validTechniqueMapping.Keys) {
    if ($validTechniqueMapping[$step].Count -gt 0) {
        Write-Host "Selecting technique for step: $step" -Verbose
        $selectedTechnique = Get-Random -InputObject $validTechniqueMapping[$step]
        Write-Host "Selected valid technique for ${step}: $selectedTechnique" -Verbose
        $selectedKillChain += [PSCustomObject]@{
            Step      = $step
            Technique = $selectedTechnique
        }
    } else {
        Write-Warning "Skipping step '$step' as no valid techniques are available."
    }
}

# Execute the techniques using Atomic Red Team
foreach ($action in $selectedKillChain) {
    Write-Host "Executing $($action.Step) using technique $($action.Technique)" -ForegroundColor Cyan -Verbose
    
    # Assuming Invoke-AtomicTest is available in the environment
    try {
        Write-Host "Invoking Atomic Test for technique $($action.Technique)" -Verbose
        Invoke-AtomicTest $action.Technique -PathToAtomicsFolder $PathToAtomicsFolder -Confirm:$false
        Write-Host "Cleaning up after technique $($action.Technique)" -ForegroundColor Yellow -Verbose
        Invoke-AtomicTest $action.Technique -PathToAtomicsFolder $PathToAtomicsFolder -Cleanup -Confirm:$false
    } catch {
        Write-Warning "Failed to execute technique $($action.Technique). Error: $_" -Verbose
    }
}

Write-Host "Kill chain execution completed." -ForegroundColor Green -Verbose
