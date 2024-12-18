# Kill all instances of a user-submitted process
param (
    [string]$processName
)

if ($processName) {
    Write-Output "Attempting to kill all instances of process: $processName"
    try {
        Get-Process -Name $processName -ErrorAction Stop | ForEach-Object { $_.Kill() }
        Write-Output "Successfully killed all instances of process: $processName"
    } catch {
        Write-Error "Failed to kill process: $processName - $($_.Exception.Message)"
    }
} else {
    Write-Output "No process name provided to kill."
}
