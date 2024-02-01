#!/usr/bin/env -S pwsh -nop
#Requires -Version 5
#Requires -RunAsAdministrator

using namespace System;
using namespace System.Security.Principal;


# [CmdletBinding()]
# param (
#     # [Parameter()]
#     # [TypeName]
#     # $ParameterName
# )

# Is Windows Powershell

[Boolean]$isWindowsPowershell = ($PSVersionTable.PSVersion.Major -eq 5); # is version 5.*

# Check am I Admin?
[WindowsPrincipal]$principal = [WindowsPrincipal]::new([WindowsIdentity]::GetCurrent());
[Boolean]$isAdmin = $principal.IsInRole([WindowsBuiltInRole]::Administrator);

# if (-not $isAdmin){
#     Write-Error -Message 'You must execute this script as an administrator.';
#     exit 1;
# }

## part 1 remove Appx version

# Get User ID
[NTAccount]$account = [NTAccount]::new($env:USERNAME);
[String]$uid = $account.Translate([SecurityIdentifier]).Value;


if ($isWindowsPowershell) {
    Import-Module Appx;
}
else {
    Import-Module Appx -UseWindowsPowerShell -WarningAction SilentlyContinue;
}

# Edge packages
[String[]]$edgeAppxPackageNameList = Get-AppxPackage -AllUsers -Name '*MicrosoftEdge*' | Select-Object -ExpandProperty PackageFullName;

# Deprovisioned Edge
$edgeAppxPackageNameList | ForEach-Object -Process {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\$uid\$_" -Force;
    New-Item -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\S-1-5-18\$_" -Force;
    New-Item -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\$_" -Force;
};

# Remove Edge
$edgeAppxPackageNameList | ForEach-Object -Process {
    Remove-AppxPackage -Package $_;
    Remove-AppxPackage -AllUsers -Package $_;
};
