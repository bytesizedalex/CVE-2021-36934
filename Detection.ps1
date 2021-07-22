# CVE-2021-36934 detection script
# Note: This version is designed for ad-hoc use and outputs data to the shell
# https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934
# Flag requirement for PowerShell version 4.0 or above and executing with Administrator rights
#requires -version 4.0
#requires -RunAsAdministrator
# Set variable with current SAM permissions
$samPermissions = (Get-Acl -Path "$env:windir\System32\config\sam").Access
# Check permissions for existence of BUILTIN\Users and alert user if present. In each case, right the current permissions to the console for validation
if ($samPermissions.IdentityReference -contains 'BUILTIN\Users') {Write-Host "WARNING: BUILTIN\Users Permissions Detected" -ForegroundColor Red ; $samPermissions} else {Write-Host "BUILTIN\Users Permissions NOT Detected" -ForegroundColor Green; $samPermissions}
