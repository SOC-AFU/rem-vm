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
param (
  [string]$password = $null,
  [switch]$noPassword
)
$winowsUpdate =   "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
$winowsUpdateAU = "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
$desktopPath = [Environment]::GetFolderPath("Desktop")
$flare_install = $false

Write-Host "[+] Checking if script is running as administrator..."

if(-Not $($(whoami) -eq "nt authority\system")) {

    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        Write-Host "    [i] Elevate to Administrator"
        $CommandLine = "-ExecutionPolicy Bypass `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
} 

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

if (-not $noPassword.IsPresent) {
    if ([string]::IsNullOrEmpty($password)) {
        $password = "Passw0rd!"
    } else {
        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        $credentials = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList ${Env:username}, $securePassword
    }
}

Write-Host "[+] Downloading DidierStevensSuite ..."
Invoke-WebRequest "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/xorsearch.py" -OutFile "C:\Windows\System32\xorsearch.py"
Invoke-WebRequest "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/emldump.py" -OutFile "C:\Windows\System32\emldump.py"
Invoke-WebRequest "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/oledump.py" -OutFile "C:\Windows\System32\oledump.py"
Invoke-WebRequest "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdfid.py" -OutFile "C:\Windows\System32\pdfid.py"
Invoke-WebRequest "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py" -OutFile "C:\Windows\System32\pdf-parser.py"
Invoke-WebRequest "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/rtfdump.py" -OutFile "C:\Windows\System32\rtfdump.py"


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

.\install.ps1 -password $password -noWait -noGui -noChecks -customConfig "https://raw.githubusercontent.com/SOC-AFU/rem-vm/main/rem-config.xml"

New-Item  "$desktopPath\SAMPLES" -Type Directory -ErrorAction SilentlyContinue | Out-Null

if((Get-Command pip -ErrorAction SilentlyContinue)){
    Write-Host "[+] Installing oletools ..."
}else{
    Write-Host "[+] pip not found try install oletools later ..."
}
