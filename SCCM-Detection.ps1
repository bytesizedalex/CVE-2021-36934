# Detection
# CVE-2021-36934 SCCM detection script
# https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934
# Flag requirement for PowerShell version 4.0 or above and executing with Administrator rights
#requires -version 4.0
#requires -RunAsAdministrator
$userAccess = $false
if (((Get-Acl -Path "$env:windir\System32\config\sam").Access.IdentityReference.Value) -contains 'BUILTIN\Users') {Set-Variable -Name userAccess -Value $true}
