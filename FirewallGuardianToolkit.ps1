<#
    Firewall Logs Manager Script
    Author: Ignacio Fontan
    Date: March 18, 2025

    This script provides a set of functions to manage Windows Firewall logs for 
    Domain, Private, and Public profiles. It includes functionality to configure 
    log folders, retrieve dropped and allowed packets, export logs to CSV, and 
    analyze denied connections for a specific source IP.

    --- Features ---
    1. Set-FirewallLogFolder:
        - Ensures the existence of the log folder for a specific profile.
        - Assigns necessary permissions to the Windows Firewall service (MpsSvc).
    
    2. Get-FirewallDrops:
        - Retrieves the logs for dropped packets within the last specified minutes.

    3. Get-FirewallAllow:
        - Retrieves the logs for allowed packets within the last specified minutes.

    4. Export-FirewallLogsToCsv:
        - Exports the logs of a specified profile to a CSV file with a profile-specific name.

    5. Get-DeniedConnectionsForSourceIP:
        - Analyzes the logs to find denied connection attempts for a specified source IP.
        - Displays the destination ports and traffic type for each denied connection.

    --- How to Use ---
    1. Run the script with administrative privileges.
    2. When executed, a menu will be displayed for selecting the desired operation.
    3. Follow the prompts to provide required inputs like profile name, time range, or source IP.
    4. Ensure log files for each profile (domainfw.log, privatefw.log, publicfw.log) 
       are properly configured in Windows Firewall settings.

    --- Requirements ---
    - PowerShell 5.1 or higher.
    - Administrative privileges to access and modify system logs and permissions.

    --- Notes ---
    - Log files must exist in the folder: %SystemRoot%\System32\LogFiles\Firewall\.
    - The output CSV files will be saved in C:\Temp\ by default.

    --- License ---
    This script is provided "as-is" without warranty of any kind.

    --- Contact ---
    For issues or contributions, feel free to reach out via GitHub.

    --- Signed by ---
    Ignacio Fontan
#>


function Set-FirewallLogFolder {
    
    # Define the folder path based on the profile
    $folderPath = "$env:SystemRoot\System32\LogFiles\Firewall"

    # Check if the folder exists
    if (-Not (Test-Path -Path $folderPath)) {
        Write-Output "The folder does not exist. Creating it..."
        New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
        Write-Output "Folder created successfully."
    } else {
        Write-Output "The folder already exists."
    }

    # Define the user (MpsSvc) and permissions to check
    $user = "NT SERVICE\MpsSvc"
    $permissionToCheck = "Modify"

    # Check permissions for the user
    $acl = Get-Acl -Path $folderPath
    $userHasPermission = $acl.Access | Where-Object {
        $_.IdentityReference -eq $user -and $_.FileSystemRights -match $permissionToCheck
    }

    if ($userHasPermission) {
        Write-Output "The user '$user' already has the required permissions."
    } else {
        Write-Output "The user '$user' does not have the required permissions. Adding permissions..."
        $permission = New-Object System.Security.AccessControl.FileSystemAccessRule($user, $permissionToCheck, "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($permission)
        Set-Acl -Path $folderPath -AclObject $acl
        Write-Output "Permissions added successfully."
    }
}

function Get-FirewallDrops {
    param (
        [string]$Profile,
        [int]$Minutes
    )

    # Calculate the start time and end time for the time range
    $endTime = Get-Date
    $startTime = $endTime.AddMinutes(-$Minutes)

    # Determine the log file path based on the profile
    $logFile = switch ($Profile) {
        "Domain" { "$env:SystemRoot\System32\LogFiles\Firewall\domain.log" }
        "Private" { "$env:SystemRoot\System32\LogFiles\Firewall\private.log" }
        "Public" { "$env:SystemRoot\System32\LogFiles\Firewall\public.log" }
        default { 
            Write-Output "Invalid profile specified. Please use Domain, Private, or Public."
            return
        }
    }

    if (-Not (Test-Path -Path $logFile)) {
        Write-Output "Log file for profile '$Profile' not found."
        return
    }

    # Filter for dropped packets in the given time range
    Get-Content -Path $logFile | Where-Object { $_ -notmatch '^#' } | ForEach-Object {
        $fields = $_ -split '\s+'
        try {
            $timestamp = Get-Date ($fields[0] + ' ' + $fields[1]) -ErrorAction Stop
            # Verify if the log entry falls within the specified time range
            if ($timestamp -ge $startTime -and $timestamp -le $endTime -and $_ -match 'DROP') {
                $_
            }
        } catch {
            # Ignore lines with invalid timestamp formatting
        }
    }
}


function Get-FirewallAllow {
    param (
        [string]$Profile,
        [int]$Minutes
    )

    # Calculate the start time and end time for the time range
    $endTime = Get-Date
    $startTime = $endTime.AddMinutes(-$Minutes)

    # Determine the log file path based on the profile
    $logFile = switch ($Profile) {
        "Domain" { "$env:SystemRoot\System32\LogFiles\Firewall\domain.log" }
        "Private" { "$env:SystemRoot\System32\LogFiles\Firewall\private.log" }
        "Public" { "$env:SystemRoot\System32\LogFiles\Firewall\public.log" }
        default { 
            Write-Output "Invalid profile specified. Please use Domain, Private, or Public."
            return
        }
    }

    if (-Not (Test-Path -Path $logFile)) {
        Write-Output "Log file for profile '$Profile' not found."
        return
    }

    # Filter for allowed packets in the given time range
    Get-Content -Path $logFile | Where-Object { $_ -notmatch '^#' } | ForEach-Object {
        $fields = $_ -split '\s+'
        try {
            $timestamp = Get-Date ($fields[0] + ' ' + $fields[1]) -ErrorAction Stop
            # Verify if the log entry falls within the specified time range
            if ($timestamp -ge $startTime -and $timestamp -le $endTime -and $_ -match 'ALLOW') {
                $_
            }
        } catch {
            # Ignore lines with invalid timestamp formatting
        }
    }
}



function Get-DeniedConnectionsForSourceIP {
    param (
        [string]$Profile
    )

    # Ask user for the source IP
    $sourceIP = Read-Host "Enter the source IP to search for"

    if (-not $sourceIP) {
        Write-Output "Source IP cannot be empty. Please provide a valid IP address."
        return
    }

    # Determine the log file path based on the profile
    $logFile = switch ($Profile) {
        "Domain" { "$env:SystemRoot\System32\LogFiles\Firewall\domain.log" }
        "Private" { "$env:SystemRoot\System32\LogFiles\Firewall\private.log" }
        "Public" { "$env:SystemRoot\System32\LogFiles\Firewall\public.log" }
        default { 
            Write-Output "Invalid profile specified. Please use Domain, Private, or Public."
            return
        }
    }

    if (-Not (Test-Path -Path $logFile)) {
        Write-Output "Log file for profile '$Profile' not found."
        return
    }

    # Filter for denied connections from the specified source IP
    Get-Content -Path $logFile | Where-Object { $_ -notmatch '^#' } | ForEach-Object {
        $fields = $_ -split '\s+'
        try {
            # Check if the action is DROP and the source IP matches
            if ($fields[2] -eq "DROP" -and $fields[4] -eq $sourceIP) {
                $_
            }
        } catch {
            # Ignore errors from malformed or unexpected lines
        }
    }
}



function Export-FirewallLogsToCsv {
    # Ask user which profile to export
    $profile = Read-Host "Enter the profile to export (Domain, Private, Public)"
    $validProfiles = @("Domain", "Private", "Public")

    if (-Not ($validProfiles -contains $profile)) {
        Write-Output "Invalid profile specified. Please use Domain, Private, or Public."
        return
    }

    # Set the log file path
    $logFile = switch ($profile) {
        "Domain" { "$env:SystemRoot\System32\LogFiles\Firewall\domain.log" }
        "Private" { "$env:SystemRoot\System32\LogFiles\Firewall\private.log" }
        "Public" { "$env:SystemRoot\System32\LogFiles\Firewall\public.log" }
    }

    if (-Not (Test-Path -Path $logFile)) {
        Write-Output "Log file for profile '$profile' not found."
        return
    }

    # Define the output CSV file
    $outputCsvFile = "C:\Temp\FirewallLogs_$profile.csv"

    # Read the log file and convert to objects for CSV export
    $logs = Get-Content -Path $logFile | ForEach-Object {
        $fields = $_ -split ' '
        if ($fields.Length -ge 3) {
            [PSCustomObject]@{
                Date      = $fields[0]
                Time      = $fields[1]
                Action    = $fields[2]
                Protocol  = $fields[3]
                SrcIP     = $fields[4]
                DstIP     = $fields[5]
                SrcPort   = $fields[6]
                DstPort   = $fields[7]
                Size      = $fields[8]
                TcpFlags  = $fields[9]
                Interface = $fields[10]
            }
        }
    }

    # Export to CSV
    $logs | Export-Csv -Path $outputCsvFile -NoTypeInformation
    Write-Output "Logs exported to $outputCsvFile successfully."
}

function DisplayMenu {
    while ($true) {
        Write-Output "`n===== Firewall Logs Manager ====="
        Write-Output "1. Set Firewall Log Folder"
        Write-Output "2. Get Firewall Drops"
        Write-Output "3. Get Firewall Allow"
        Write-Output "4. Export Logs to CSV"
        Write-Output "5. Get Denied Connections for Source IP"
        Write-Output "6. Exit"
        $choice = Read-Host "Enter your choice (1-6)"

        switch ($choice) {
            "1" {
                Set-FirewallLogFolder
            }
            "2" {
                $profile = Read-Host "Enter the profile (Domain, Private, Public)"
                $minutes = [int](Read-Host "Enter the number of minutes to retrieve logs")
                Get-FirewallDrops -Profile $profile -Minutes $minutes
            }
            "3" {
                $profile = Read-Host "Enter the profile (Domain, Private, Public)"
                $minutes = [int](Read-Host "Enter the number of minutes to retrieve logs")
                Get-FirewallAllow -Profile $profile -Minutes $minutes
            }
            "4" {
                Export-FirewallLogsToCsv
            }
            "5" {
                $profile = Read-Host "Enter the profile (Domain, Private, Public)"
                Get-DeniedConnectionsForSourceIP -Profile $profile
            }
            "6" {
                Write-Output "Exiting the script. Goodbye!"
                exit
            }
            default {
                Write-Output "Invalid choice. Please try again."
            }
        }
    }
}
# Start the menu
DisplayMenu
