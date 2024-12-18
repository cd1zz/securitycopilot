# Set the path to the atomics folder
$PathToAtomicsFolder = "C:\Users\craig\atomic-red-team\atomics"

# Add Microsoft Defender for Endpoint (MDE) exclusion
# Exclude the atomic-red-team folder from Microsoft Defender scanning
$atomicRedTeamPath = "C:\Users\$env:USERNAME\atomic-red-team"
Add-MpPreference -ExclusionPath $atomicRedTeamPath

# Get all folders under the atomics folder that start with "T" (e.g., T1059.001, T1087.001)
$techniqueFolders = Get-ChildItem -Path $PathToAtomicsFolder -Directory | Where-Object { $_.Name -like "T*" }

foreach ($folder in $techniqueFolders) {
    # Extract the Technique ID from the folder name
    $techniqueID = $folder.Name

    Write-Output "Running Atomic Test for Technique ID: $techniqueID"
    
    try {
        # Invoke the Atomic Test using the Technique ID directly as a parameter
        Invoke-AtomicTest $techniqueID -PathToAtomicsFolder $PathToAtomicsFolder -Verbose
    } catch {
        Write-Error "Failed to run Atomic Test for Technique ID: $techniqueID - $($_.Exception.Message)"
    }

    # Add delay between each test to simulate dwell time
    Start-Sleep -Seconds 10
}

# Optional: Clean up artifacts created by the above steps (use with caution in a non-test environment)
foreach ($folder in $techniqueFolders) {
    # Extract the Technique ID from the folder name
    $techniqueID = $folder.Name

    Write-Output "Cleaning up artifacts for Technique ID: $techniqueID"
    
    try {
        # Invoke the cleanup using the Technique ID directly as a parameter
        Invoke-AtomicTest $techniqueID -PathToAtomicsFolder $PathToAtomicsFolder -Cleanup -Verbose
    } catch {
        Write-Error "Failed to clean up Atomic Test for Technique ID: $techniqueID - $($_.Exception.Message)"
    }

    # Add delay between each cleanup step to simulate dwell time
    Start-Sleep -Seconds 5
}
