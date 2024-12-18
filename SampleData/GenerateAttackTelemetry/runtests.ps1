# Set the path to the atomics folder
$PathToAtomicsFolder = "C:\Users\craig\atomic-red-team\atomics"

# Add Microsoft Defender for Endpoint (MDE) exclusion
# Exclude the atomic-red-team folder from Microsoft Defender scanning
$atomicRedTeamPath = "C:\Users\$env:USERNAME\atomic-red-team"
Add-MpPreference -ExclusionPath $atomicRedTeamPath

# --- Reconnaissance ---
# 1. Command Line Interface - Gather User Information (T1087.001)
# This step attempts to discover user accounts available on the machine.
Invoke-AtomicTest T1087.001 -PathToAtomicsFolder $PathToAtomicsFolder -Verbose

# 2. Network Service Scanning - Identify Services Running on the System (T1046)
# Using command line tools to scan and identify available network services.
Invoke-AtomicTest T1046 -PathToAtomicsFolder $PathToAtomicsFolder -Verbose

# --- Exploitation ---
# 3. Command and Scripting Interpreter - Execute Exploit via PowerShell (T1059.001)
# Execute a PowerShell command to simulate exploitation by running arbitrary scripts.
Invoke-AtomicTest T1059.001 -PathToAtomicsFolder $PathToAtomicsFolder -Verbose

# 4. Command and Scripting Interpreter - Windows Command Shell (T1059.003)
# Use cmd.exe to run commands that may be part of an exploit chain.
Invoke-AtomicTest T1059.003 -PathToAtomicsFolder $PathToAtomicsFolder -Verbose

# --- Persistence ---
# 5. Scheduled Task/Job - Establish Persistence with a Scheduled Task (T1053.005)
# Use command line to create a scheduled task for persistence.
Invoke-AtomicTest T1053.005 -PathToAtomicsFolder $PathToAtomicsFolder -Verbose

# 6. Registry Run Keys / Startup Folder - Persistence via Registry Modification (T1547.001)
# Add an entry to the registry run key to ensure the command runs on startup.
Invoke-AtomicTest T1547.001 -PathToAtomicsFolder $PathToAtomicsFolder -Verbose

# 7. Boot or Logon Initialization Scripts - Add Startup Script (T1037.001)
# Modify startup scripts via command line to establish persistence.
Invoke-AtomicTest T1037.001 -PathToAtomicsFolder $PathToAtomicsFolder -Verbose

# Add delay between steps to simulate dwell time
Start-Sleep -Seconds 10

# Optional: Clean up artifacts created by the above steps (use with caution in a non-test environment)
Invoke-AtomicTest T1053.005 -PathToAtomicsFolder $PathToAtomicsFolder -Cleanup
Invoke-AtomicTest T1547.001 -PathToAtomicsFolder $PathToAtomicsFolder -Cleanup
Invoke-AtomicTest T1037.001 -PathToAtomicsFolder $PathToAtomicsFolder -Cleanup
