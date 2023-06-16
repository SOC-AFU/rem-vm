# REM VM

<#
                           _               _ 
 __      ____ _ _ __ _ __ (_)_ __   __ _  | |
 \ \ /\ / / _` | '__| '_ \| | '_ \ / _` | | |
  \ V  V / (_| | |  | | | | | | | | (_| | |_|
   \_/\_/ \__,_|_|  |_| |_|_|_| |_|\__, | (_)
                                   |___/     

Once you have run it, you will no longer have any sort of antivirus protection, and WILL NOT BE ABLE to reactivate it.

Think twice before running it, or read the blog post to understand and modify it to suit **your** needs.



#>
$winowsUpdate =   "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
$winowsUpdateAU = "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
$windowsNotification = "Registry::HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer"
$desktopPath = [Environment]::GetFolderPath("Desktop")
$crntusr = [Environment]::UserName

Write-Host "[+] Checking if script is running as administrator..."

if(-Not $($(whoami) -eq "nt authority\system")) {

    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        Write-Host "    [i] Elevate to Administrator"
        $CommandLine = "-ExecutionPolicy Bypass `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
} 

Write-Host "[+] Clear user password ..." -ForegroundColor Green
Set-LocalUser -name $crntusr -Password ([securestring]::new())

Write-Host "[+] Disabling Windows Update..."

if(!(Test-Path -Path $winowsUpdateAU)){
    try{
        if(!(Test-Path -Path $winowsUpdate)){
            New-Item -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows" -Name "WindowsUpdate" | Out-Null
        }
        New-Item -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AU" | Out-Null
        New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 | Out-Null
        Write-Host "`t[+] Windows Update is disabled" -ForegroundColor Green
    }catch {
            Write-Host "`t[!] Please ensure that '1' is set to NoAutoUpdate which is located at 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU''  " -ForegroundColor Red
            Read-Host "Press any key to exit..."
            exit 1
    }
}else{
    Write-Host "[+] Checking property NoAutoUpdate ..."
    if(!(Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue )){
        Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 | Out-Null
        Write-Host "`t[+] Windows Update is disabled" -ForegroundColor Green
    }
    if(!(Get-ItemPropertyValue -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue )){
        Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 | Out-Null
        Write-Host "`t[+] Windows Update is disabled" -ForegroundColor Green
    }else{
        Write-Host "`t[+] Windows Update has been already disabled" -ForegroundColor Green
    }
}

Write-Host "[+] Disabling Notifications and Action Center...."

if(!(Get-ItemProperty -Path "Registry::HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue )){
    New-ItemProperty -Path "Registry::HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Value 1 -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[+]  Notifications and Action Center is disabled"
}else {
    Set-ItemProperty -Path "Registry::HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Value 1 -ErrorAction SilentlyContinue | Out-Null
     Write-Host "[+]  Notifications and Action Center set to disabled"
}

Write-Host "[+] Removing unnecessary applications, stopping telemetry, stopping Cortana, disabling unnecessary scheduled tasks ..."

Invoke-WebRequest "https://github.com/Sycnex/Windows10Debloater/archive/refs/heads/master.zip" -Outfile "C:\Windows\Temp\debloater.zip"   -ErrorAction SilentlyContinue 
Expand-Archive -Path "C:\Windows\Temp\debloater.zip" -DestinationPath "C:\Windows\Temp\debloater" -Force  -ErrorAction SilentlyContinue 
Set-Location -Path "C:\Windows\Temp\debloater\Windows10Debloater-master"
.\Windows10SysPrepDebloater.ps1 -Sysprep -Debloat -Privacy


Write-Host "[+] Downloading Eric Zimmerman Tools..."

Invoke-WebRequest "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1" -OutFile "C:\Windows\Temp\dfir-tools.ps1"
Set-Location -Path "C:\Windows\Temp\"
New-Item  "C:\DFIR-Tools" -Type Directory -ErrorAction SilentlyContinue | Out-Null
New-Item  "$desktopPath\DFIR-Tools" -Type Directory -ErrorAction SilentlyContinue | Out-Null
.\dfir-tools.ps1 -Dest "C:\DFIR-Tools"
$WshShell = New-Object -comObject WScript.Shell

$EZViewer = $WshShell.CreateShortcut("$desktopPath\DFIR-Tools\EZViewer.lnk")
$EZViewer.TargetPath = "C:\DFIR-Tools\net6\EZViewer\EZViewer.exe"
$EZViewer.Save()

$JumpListExplorer = $WshShell.CreateShortcut("$desktopPath\DFIR-Tools\JumpListExplorer.lnk")
$JumpListExplorer.TargetPath = "C:\DFIR-Tools\net6\JumpListExplorer\JumpListExplorer.exe"
$JumpListExplorer.Save()

$MFTExplorer = $WshShell.CreateShortcut("$desktopPath\DFIR-Tools\MFTExplorer.lnk")
$MFTExplorer.TargetPath = "C:\DFIR-Tools\net6\MFTExplorer\MFTExplorer.exe"
$MFTExplorer.Save()

$MFTExplorer = $WshShell.CreateShortcut("$desktopPath\DFIR-Tools\MFTExplorer.lnk")
$MFTExplorer.TargetPath = "C:\DFIR-Tools\net6\MFTExplorer\MFTExplorer.exe"
$MFTExplorer.Save()

$RegistryExplorer = $WshShell.CreateShortcut("$desktopPath\DFIR-Tools\RegistryExplorer.lnk")
$RegistryExplorer.TargetPath = "C:\DFIR-Tools\net6\RegistryExplorer\RegistryExplorer.exe"
$RegistryExplorer.Save()

$SDBExplorer = $WshShell.CreateShortcut("$desktopPath\DFIR-Tools\SDBExplorer.lnk")
$SDBExplorer.TargetPath = "C:\DFIR-Tools\net6\SDBExplorer\SDBExplorer.exe"
$SDBExplorer.Save()

$ShellBagsExplorer = $WshShell.CreateShortcut("$desktopPath\DFIR-Tools\ShellBagsExplorer.lnk")
$ShellBagsExplorer.TargetPath = "C:\DFIR-Tools\net6\ShellBagsExplorer\ShellBagsExplorer.exe"
$ShellBagsExplorer.Save()

$TimelineExplorer = $WshShell.CreateShortcut("$desktopPath\DFIR-Tools\TimelineExplorer.lnk")
$TimelineExplorer.TargetPath = "C:\DFIR-Tools\net6\TimelineExplorer\TimelineExplorer.exe"
$TimelineExplorer.Save()

$SQLECmd = $WshShell.CreateShortcut("$desktopPath\DFIR-Tools\SQLECmd.lnk")
$SQLECmd.TargetPath = "C:\DFIR-Tools\net6\SQLECmd\"
$SQLECmd.Save()

$EvtxeCmd = $WshShell.CreateShortcut("$desktopPath\DFIR-Tools\EvtxeCmd.lnk")
$EvtxeCmd.TargetPath = "C:\DFIR-Tools\net6\EvtxeCmd\"
$EvtxeCmd.Save()

[Environment]::SetEnvironmentVariable("PATH", $Env:PATH + ";C:\DFIR-Tools\net6", [EnvironmentVariableTarget]::Machine)

New-Item  "$desktopPath\MANUAL_SETUP_REQUIRED" -Type Directory -ErrorAction SilentlyContinue | Out-Null

Write-Host "[+] Downloading DidierStevensSuite ..."
Invoke-WebRequest "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/xorsearch.py" -OutFile "C:\Windows\System32\xorsearch.py"
Invoke-WebRequest "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/emldump.py" -OutFile "C:\Windows\System32\emldump.py"
Invoke-WebRequest "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/oledump.py" -OutFile "C:\Windows\System32\oledump.py"
Invoke-WebRequest "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdfid.py" -OutFile "C:\Windows\System32\pdfid.py"
Invoke-WebRequest "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py" -OutFile "C:\Windows\System32\pdf-parser.py"
Invoke-WebRequest "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/rtfdump.py" -OutFile "C:\Windows\System32\rtfdump.py"
Invoke-WebRequest "https://www.winpcap.org/windump/install/bin/windump_3_9_5/WinDump.exe" -OutFile "C:\Windows\System32\WinDump.exe"
Invoke-WebRequest "https://github.com/adamkramer/jmp2it/releases/download/v1.4/jmp2it.exe" -OutFile "C:\Windows\System32\jump2it.exe"

Write-Host "[+] Downloading additional tools ..."
Invoke-WebRequest "https://github.com/hasherezade/pe_unmapper/releases/download/v1.0/pe_unmapper.zip" -OutFile "$desktopPath\MANUAL_SETUP_REQUIRED\pe_unmapper.zip"
Invoke-WebRequest "https://www.procdot.com/download/procdot/binaries/procdot_1_22_57_windows.zip" -OutFile "$desktopPath\MANUAL_SETUP_REQUIRED\procdot.zip"
Invoke-WebRequest "https://www.technipages.com/downloads/OrcaMSI.zip" -OutFile "$desktopPath\MANUAL_SETUP_REQUIRED\orcaMsi.zip"
Invoke-WebRequest "https://github.com/ViRb3/de4dot-cex/releases/download/v4.0.0/de4dot-cex.zip" -OutFile "$desktopPath\MANUAL_SETUP_REQUIRED\de4dot-cex.zip"
Invoke-WebRequest "https://github.com/wickyhu/simple-assembly-explorer/releases/download/v1.14.4/SAE.v1.14.4.x64.7z" -OutFile "$desktopPath\MANUAL_SETUP_REQUIRED\simple_assembly_explorer.7z"
Invoke-WebRequest "https://github.com/0x59-Cl/Eazfixer/blob/master/eaz%20fixer.rar" -OutFile "$desktopPath\MANUAL_SETUP_REQUIRED\eaz_fixer.rar"


Write-Host "[+] Downloading flare-vm install.ps1..."

(New-Object net.webclient).DownloadFile('https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1',"$desktopPath\install.ps1")

Set-Location -Path $desktopPath -PassThru | Out-Null

Write-Host "[+] Setting Execution Policy and unblocking install.ps1."
try{
    Unblock-File $desktopPath\install.ps1;
    Write-Host "`t[+] Execution Policy is unrestricted and install.ps1 is unblocked" -ForegroundColor Green
}catch {
        Write-Host "`t[+] Unblock the file and set execution policy  to Unrestricted $desktopPath 'Unblock-File .\install.ps1; Set-ExecutionPolicy Unrestricted;' " -ForegroundColor Red
        Read-Host "Press any key to exit..."
        exit 1
}

.\install.ps1 -customConfig "https://raw.githubusercontent.com/SOC-AFU/rem-vm/main/rem-config.xml" -noPassword -noWait -noGui -noChecks 

New-Item  "$desktopPath\SAMPLES" -Type Directory -ErrorAction SilentlyContinue | Out-Null
