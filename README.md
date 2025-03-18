# FirewallGuardianToolkit

## Overview
**FirewallGuardianToolkit** is a comprehensive PowerShell script designed to help system administrators manage Windows Firewall logs efficiently for Domain, Private, and Public profiles. This toolkit provides functionalities to configure log folders, retrieve specific log entries, analyze denied connections, and export logs to CSV files—all from an easy-to-use, menu-driven interface.

## Features
1. **Set Firewall Log Folder**: 
   - Ensures that the log folder exists for the selected profile.
   - Assigns necessary permissions for the Windows Firewall service (`MpsSvc`).

2. **Retrieve Dropped Packets**:
   - Analyzes firewall logs for packets that were dropped in the last specified number of minutes.

3. **Retrieve Allowed Packets**:
   - Analyzes firewall logs for packets that were allowed in the last specified number of minutes.

4. **Export Logs to CSV**:
   - Exports logs for the selected profile to a CSV file with a profile-specific name.

5. **Analyze Denied Connections**:
   - Searches the logs for denied connections from a specified source IP.
   - Displays destination ports and traffic types associated with the denied connections.

## Requirements
- PowerShell 5.1 or higher.
- Administrator privileges to modify log folders and permissions.
- Configured log files for each firewall profile:
  - `domain.log` for Domain Profile.
  - `private.log` for Private Profile.
  - `public.log` for Public Profile.

## Installation
1. Download the `FirewallGuardianToolkit.ps1` script.
2. Save it to your preferred directory.
3. Open PowerShell with administrative privileges.
4. Run the script using the command:
   ```powershell
   .\FirewallGuardianToolkit.ps1
