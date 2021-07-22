# Remediation
# CVE-2021-36934 SCCM remediation script
# https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934
# Flag requirement for PowerShell version 4.0 or above and executing with Administrator rights
#requires -version 4.0
#requires -RunAsAdministrator
# Apply restrictions to NTFS ACLs
icacls.exe $env:windir\system32\config\*.* /inheritance:e
# Remove all VSS shadow copies on system drive
vssadmin.exe delete shadows /for=$env:SystemDrive /Quiet
