# Create Windows VM (assuming this script is running on an already provisioned VM)

# Check if the script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "You need to run this script as an Administrator. Exiting script."
    exit
}

# Store original Execution Policy
$originalPolicy = Get-ExecutionPolicy
Set-ExecutionPolicy Bypass -Scope Process -Force

# Install Microsoft Defender and disable PUA protection
# (Assuming Defender is already part of the Windows system. Set PUA Protection to Disabled)
try {
    Set-MpPreference -PUAProtection Disabled
} catch {
    Write-Error "Failed to set PUA Protection to Disabled: $($_.Exception.Message)"
}

# Install Chocolatey for Package Management
try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    # Verify Chocolatey installation
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Error "Chocolatey installation failed. Exiting script."
        exit
    }
} catch {
    Write-Error "Failed to install Chocolatey: $($_.Exception.Message)"
    exit
}

# Install Git
try {
    choco install git -y
    # Verify Git installation
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Error "Git installation failed. Exiting script."
        exit
    }
} catch {
    Write-Error "Failed to install Git: $($_.Exception.Message)"
    exit
}

# Install PowerShell Core (Optional, but recommended for more features and stability)
try {
    choco install powershell-core -y
    # Verify PowerShell Core installation
    if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
        Write-Error "PowerShell Core installation failed. Exiting script."
        exit
    }
} catch {
    Write-Error "Failed to install PowerShell Core: $($_.Exception.Message)"
    exit
}

# Reload the system environment variables into the current session
try {
    $currentPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $newPath = "$currentPath;$userPath"
    [System.Environment]::SetEnvironmentVariable("Path", $newPath, "Process")
} catch {
    Write-Error "Failed to reload system environment variables: $($_.Exception.Message)"
    exit
}

# Install Atomic Red Team repository and related tools
# Clone the Atomic Red Team repository
try {
    git clone https://github.com/redcanaryco/atomic-red-team.git
    cd atomic-red-team
} catch {
    Write-Error "Failed to clone Atomic Red Team repository: $($_.Exception.Message)"
    exit
}

# Install Invoke-AtomicRedTeam PowerShell module (installing locally in the current user's scope)
try {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser
    Set-ExecutionPolicy Bypass -Scope Process -Force
    Install-Module -Name Invoke-AtomicRedTeam -Force -Scope CurrentUser
    Import-Module Invoke-AtomicRedTeam
} catch {
    Write-Error "Failed to install or import Invoke-AtomicRedTeam PowerShell module: $($_.Exception.Message)"
    exit
}

# Go back and clone Invoke-AtomicRedTeam scripts repository
try {
    cd ..
    git clone https://github.com/redcanaryco/invoke-atomicredteam.git
    cd invoke-atomicredteam
} catch {
    Write-Error "Failed to clone Invoke-AtomicRedTeam scripts repository: $($_.Exception.Message)"
    exit
}

# Import the Invoke-AtomicRedTeam module locally
try {
    Import-Module .\Invoke-AtomicRedTeam.psd1
} catch {
    Write-Error "Failed to import Invoke-AtomicRedTeam module: $($_.Exception.Message)"
    exit
}

# Setup exclusions for Defender to avoid interference with Atomic Red Team
try {
    $atomicRedTeamPath = "C:\Users\$env:USERNAME\atomic-red-team"
    Add-MpPreference -ExclusionPath $atomicRedTeamPath
    
    $invokeatomicRedTeamPath = "C:\Users\$env:USERNAME\invoke-atomicredteam"
    Add-MpPreference -ExclusionPath $invokeatomicRedTeamPath
} catch {
    Write-Error "Failed to add exclusions to Defender: $($_.Exception.Message)"
}

# Clean up Execution Policy (restore original policy)
Set-ExecutionPolicy $originalPolicy -Scope Process -Force

Write-Output "Installation script completed successfully."