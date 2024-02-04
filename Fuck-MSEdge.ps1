#!/usr/bin/env -S pwsh -nop
#Requires -Version 5
#Requires -RunAsAdministrator

using namespace System;
using namespace System.IO;
using namespace System.Security.Principal;


# [CmdletBinding()]
# param (
#     # [Parameter()]
#     # [TypeName]
#     # $ParameterName
# )

Set-StrictMode -Version Latest;

[String]$SetupFile = '';
[String]$WebviewSetupFile = '';
[Switch]$AllowForceRemove = $false;



# Is Windows Powershell
[Boolean]$isWindowsPowershell = ($PSVersionTable.PSVersion.Major -le 5); # is version 5.*

# Check am I Admin?
[WindowsPrincipal]$principal = [WindowsPrincipal]::new([WindowsIdentity]::GetCurrent());
[Boolean]$isAdmin = $principal.IsInRole([WindowsBuiltInRole]::Administrator);
if (-not $isAdmin) {
    Write-Error -Message 'You must execute this script as an administrator.';
    exit 1;
}

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
    New-Item -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\$uid\$_" -Force | Out-Null;
    New-Item -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\S-1-5-18\$_" -Force | Out-Null;
    New-Item -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\$_" -Force | Out-Null;
    # Remove package
    Remove-AppxPackage -Package $_;
    Remove-AppxPackage -AllUsers -Package $_;
};

## Part 2 Edge Main

[String]$edgeRootDir = [Path]::Combine(${env:ProgramFiles(x86)}, 'Microsoft');
[String]$edgeName = 'Edge';
[String]$edgeVersion = Get-ChildItem -Path ([Path]::Combine($edgeRootDir, $edgeName, 'Application')) -Name | Where-Object -FilterScript { $_ -match '^\d+\.\d+\.\d+\.\d+$' };

[String]$coreName = 'EdgeCore';
[String]$coreVersion = Get-ChildItem -Path ([Path]::Combine($edgeRootDir, $coreName)) -Name | Where-Object -FilterScript { $_ -match '^\d+\.\d+\.\d+\.\d+$' };

[String]$updateName = 'EdgeUpdate';
[String]$updateVersion = Get-ChildItem -Path ([Path]::Combine($edgeRootDir, $updateName)) -Name | Where-Object -FilterScript { $_ -match '^\d+\.\d+\.\d+\.\d+$' };

[String]$webviewName = 'EdgeWebView';
[String]$webviewVersion = Get-ChildItem -Path ([Path]::Combine($edgeRootDir, $webviewName, 'Application')) -Name | Where-Object -FilterScript { $_ -match '^\d+\.\d+\.\d+\.\d+$' };

if (-not [String]::IsNullOrWhiteSpace($SetupFile)) {
    if (Test-Path -Path $SetupFile) {
        $SetupFile = [Path]::GetFullPath($SetupFile);
    }
    else {
        Write-Error -Message "Setup file not found: $SetupFile";
        exit 1;
    }
}
else {
    # C:\Program Files (x86)\Microsoft\ Edge\ Application\92.0.902.67\Installer\setup.exe
    $SetupFile = [Path]::Combine($edgeRootDir, $edgeName, 'Application', $edgeVersion, 'Installer', 'setup.exe');
}

if (Test-Path -Path $SetupFile) {
    $setup_exe = Get-Command -Name $SetupFile;
    # setup.exe --uninstall --system-level --force-uninstall
    &$setup_exe --uninstall --system-level --force-uninstall;
    Start-Sleep -Seconds 3;
    if (Test-Path -Path $SetupFile) {
        if ($AllowForceRemove) {
            Remove-Item -Path ([Path]::Combine($edgeRootDir, $edgeName)) -Recurse -Force;
        }
        else {
            Write-Error -Message 'Cannot remove Edge by `setup.exe`';
            Write-Error -Message 'Some newer versions of Edge no longer allow users to uninstall it by `setup.exe` that is located in the installation directory. You can use the `--AllowForceRemove` switch to force remove the installation directory, or use the `--SetupFile` parameter to specify the setup file that still has this functionality.';
        }
    }
}



## Part 3 Edge WebView

if (-not [String]::IsNullOrWhiteSpace($WebviewSetupFile)) {
    if (Test-Path -Path $WebviewSetupFile) {
        $WebviewSetupFile = [Path]::GetFullPath($WebviewSetupFile);
    }
    else {
        Write-Error -Message "WebView2 setup file not found: $WebviewSetupFile";
        exit 1;
    }
}else {
    # C:\Program Files (x86)\Microsoft\EdgeWebView\Application\120.0.2210.144\Installer\setup.exe
    $WebviewSetupFile = [Path]::Combine($edgeRootDir, $webviewName, 'Application', $webviewVersion, 'Installer', 'setup.exe');
}

if (Test-Path -Path $WebviewSetupFile) {
    $setup_exe = Get-Command -Name $WebviewSetupFile;
    # setup.exe --uninstall --msedgewebview --system-level --force-uninstall

}
