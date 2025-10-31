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
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "Installing Chocolatey..."
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        # Verify Chocolatey installation
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Error "Chocolatey installation failed. Exiting script."
            exit
        }
    } else {
        Write-Host "Chocolatey already installed, skipping installation." -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to install Chocolatey: $($_.Exception.Message)"
    exit
}

# Install Git
try {
    choco install git -y
} catch {
    Write-Error "Failed to install Git: $($_.Exception.Message)"
    exit
}

# Install PowerShell Core (Optional, but recommended for more features and stability)
try {
    choco install powershell-core -y
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

# Verify PowerShell Core installation AFTER reloading environment
if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
    Write-Warning "PowerShell Core (pwsh) not found in PATH after installation. You may need to restart your shell."
    Write-Warning "Continuing with installation..."
}

# Install Atomic Red Team repository and related tools
# Set up paths in user profile directory
$UserProfile = [Environment]::GetFolderPath('UserProfile')
$atomicRedTeamPath = "$UserProfile\atomic-red-team"
$invokeAtomicRedTeamPath = "$UserProfile\invoke-atomicredteam"

# Clone the Atomic Red Team repository to user profile
try {
    if (Test-Path $atomicRedTeamPath) {
        Write-Host "Atomic Red Team already exists at $atomicRedTeamPath, skipping clone." -ForegroundColor Yellow
    } else {
        Write-Host "Cloning Atomic Red Team to $atomicRedTeamPath" -ForegroundColor Cyan
        Set-Location $UserProfile
        git clone https://github.com/redcanaryco/atomic-red-team.git
    }
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

# Clone Invoke-AtomicRedTeam scripts repository to user profile
try {
    if (Test-Path $invokeAtomicRedTeamPath) {
        Write-Host "Invoke-AtomicRedTeam already exists at $invokeAtomicRedTeamPath, skipping clone." -ForegroundColor Yellow
    } else {
        Write-Host "Cloning Invoke-AtomicRedTeam to $invokeAtomicRedTeamPath" -ForegroundColor Cyan
        Set-Location $UserProfile
        git clone https://github.com/redcanaryco/invoke-atomicredteam.git
    }
} catch {
    Write-Error "Failed to clone Invoke-AtomicRedTeam scripts repository: $($_.Exception.Message)"
    exit
}

# Import the Invoke-AtomicRedTeam module locally
try {
    Set-Location $invokeAtomicRedTeamPath
    Import-Module .\Invoke-AtomicRedTeam.psd1
} catch {
    Write-Error "Failed to import Invoke-AtomicRedTeam module: $($_.Exception.Message)"
    exit
}

# Setup exclusions for Defender to avoid interference with Atomic Red Team
try {
    Write-Host "Adding Defender exclusions for Atomic Red Team directories" -ForegroundColor Cyan
    Add-MpPreference -ExclusionPath $atomicRedTeamPath
    Add-MpPreference -ExclusionPath $invokeAtomicRedTeamPath
    Write-Host "Defender exclusions added successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to add exclusions to Defender: $($_.Exception.Message)"
}

# Clean up Execution Policy (restore original policy)
Set-ExecutionPolicy $originalPolicy -Scope Process -Force

Write-Output "Installation script completed successfully."