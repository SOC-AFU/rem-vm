# Recommendation for customizing FLARE-VM

## Quick Start
 * Disable Tamper Protection and any Anti-Malware solution (e.g., Windows Defender), preferably via Group Policy.
    * Disabling Tamper Protection
      * https://support.microsoft.com/en-us/windows/prevent-changes-to-security-settings-with-tamper-protection-31d51aaa-645d-408e-6ce7-8d7f8e593f87
      * https://www.tenforums.com/tutorials/123792-turn-off-tamper-protection-windows-defender-antivirus.html
    * Disabling Windows Defender
      * https://stackoverflow.com/questions/62174426/how-to-permanently-disable-windows-defender-real-time-protection-with-gpo
      * https://www.windowscentral.com/how-permanently-disable-windows-defender-windows-10
      * https://github.com/jeremybeaume/tools/blob/master/disable-defender.ps1


* Open Powershell as Administrator than download the installation script [`rem-installer.ps1`](https://github.com/SOC-AFU/rem-vm/blob/main/rem-installer1.ps1) to your desktop
````
(New-Object net.webclient).DownloadFile('https://raw.githubusercontent.com/SOC-AFU/rem-vm/main/rem-installer.ps1',"$([Environment]::GetFolderPath("Desktop"))\rem-installer.ps1")
````
* Unblock the installation script by running:
````
Unblock-File  Unblock-File $HOME\rem-installer.ps1
````
* Enable script execution by running:
````
Set-ExecutionPolicy Unrestricted
````
* Paste "A" (Yes to All) and press Enter
* Finally, execute the installer script as follow:
````
.\rem-installer.ps1
````
------

## Manual Mode

Follow the steps described in the official [`FLARE-VM`](https://github.com/mandiant/flare-vm/tree/main) repository before running `.\install.ps1`.
Next run `install.ps1` with the parameter 
`-customConfig "https://raw.githubusercontent.com/SOC-AFU/rem-vm/main/rem-config.xml"`
````
.\install.ps1 -customConfig "https://raw.githubusercontent.com/SOC-AFU/rem-vm/main/rem-config.xml" -noWait -noGui -noChecks 
````

[ Copy and Paste all of the commands below at once ]

````cmd (powershell)
Invoke-WebRequest https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/xorsearch.py -OutFile "C:\Windows\System32\xorsearch.py"; `
Invoke-WebRequest https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/emldump.py -OutFile "C:\Windows\System32\emldump.py"; `
Invoke-WebRequest https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/oledump.py -OutFile "C:\Windows\System32\oledump.py"; `
Invoke-WebRequest https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdfid.py -OutFile "C:\Windows\System32\pdfid.py"; `
Invoke-WebRequest https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py -OutFile "C:\Windows\System32\pdf-parser.py"; `
Invoke-WebRequest https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/rtfdump.py -OutFile "C:\Windows\System32\rtfdump.py";

````

````cmd (powershell)
pip install -U oletools[full]
New-Item $HOME\Desktop\SAMPLES -ItemType Directory
````


[ Customize your desktop/cli environment to quickly launch the software from the list below: ] 

````
------------ Static Analysis -----------
* Detect It Easy 	[ Desktop Shortcut ]	[ https://github.com/horsicq/Detect-It-Easy/releases ]
* PEstudio 			[ Desktop Shortcut ]	[ https://www.winitor.com/download ]	
* Exiftool			[ Command Line Env ]	[ https://exiftool.org/index.html ]
* Exeinfo PE 		[ Desktop Shortcut ]	[ https://www.nirsoft.net/utils/exeinfo.html ]
* file 				[ Command Line Env ]	[ https://github.com/nscaife/file-windows/releases ]
* peid 				[ Desktop Shortcut ]	[ https://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml ]
* Floss 			[ Command Line Env ]	[ https://github.com/mandiant/flare-floss/releases/tag/v2.2.0 ]
* 010 Editor 		[ Desktop Shortcut ]	[ https://www.sweetscape.com/download/010editor/ ]
* CFF Explorer		[ Desktop Shortcut ]	[ https://www.sweetscape.com/download/010editor/ ]
* HashMyFiles 		[ Desktop Shortcut ]	[ https://www.nirsoft.net/utils/hash_my_files.html ]
* xorsearch			[ Command Line Env ]	[ https://github.com/DidierStevens/DidierStevensSuite/blob/master/xorsearch.py ]

------------ Behaviour Analysis -----------
* Sysinternal Suite 						[ https://download.sysinternals.com/files/SysinternalsSuite.zip ]
	- strings		[ Command Line Env ]
	- procmon		[ Desktop Shortcut ]
	- autoruns		[ Desktop Shortcut ]
	- procexplorer	[ Desktop Shortcut ]
	- tcpview		[ Desktop Shortcut ]
* Process Hacker 2 	[ Desktop Shortcut ]	[ https://processhacker.sourceforge.io/downloads.php ]
* Procdot 			[ Desktop Shortcut ]	[ https://www.procdot.com/downloadprocdotbinaries.htm ]
* RegShot 			[ Desktop Shortcut ]	[ https://sourceforge.net/projects/regshot/ ]
* API Monitor x32	[ Desktop Shortcut ]	[ http://www.rohitab.com/downloads ]
* API Monitor x64	[ Desktop Shortcut ]	[ http://www.rohitab.com/downloads ]
* Scylla x32 		[ Desktop Shortcut ]	[ https://github.com/NtQuery/Scylla/releases ]
* Scylla x64		[ Desktop Shortcut ]	[ https://github.com/NtQuery/Scylla/releases ]
* Wireshark			[ Desktop Shortcut ]	[ https://www.wireshark.org/download.html ]
* Network Miner		[ Desktop Shortcut ]	[ https://www.netresec.com/?page=NetworkMiner ]
* FakeNet-ng 		[ Desktop Shortcut ]	[ https://github.com/mandiant/flare-fakenet-ng/releases/tag/v1.4.11 ]
* Fiddler 			[ Desktop Shortcut ]	[ https://www.telerik.com/download/fiddler ]
* Postman 			[ Desktop Shortcut ]	[ https://www.postman.com/downloads/ ]

------------ Office Documents Analysis -----------
* oletools			[ Command Line Env ]	[ https://github.com/decalage2/oletools ]
* oledump			[ Command Line Env ]	[ https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py ]
* emldump 			[ Command Line Env ]	[ https://github.com/DidierStevens/DidierStevensSuite/blob/master/emldump.py ]
* pdfid				[ Command Line Env ]	[ https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdfid.py ]
* pdfparser			[ Command Line Env ]	[ https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py ]
* rtfobj			[ Command Line Env ]	[ https://github.com/decalage2/oletools ]
* rtfdump			[ Command Line Env ]	[ https://github.com/DidierStevens/DidierStevensSuite/blob/master/rtfdump.py ]

------------ Shellcode/Binary Analysis -----------
* capa				[ Command Line Env ]	[ https://github.com/mandiant/capa/releases ]
* scdbg				[ Desktop Shortcut ]	[ http://sandsprite.com/blogs/index.php?uid=7&pid=152 ]
* Jmp2it			[ Command Line Env ]	[ https://github.com/adamkramer/jmp2it/releases ]

------------ Disassembler/Decompliler/Debugger Analysis -----------
* IDA Freeware/Pro 	[ Desktop Shortcut ]	[ https://hex-rays.com/ida-free/ ]
* Ghidra  			[ Desktop Shortcut ]	[ https://github.com/NationalSecurityAgency/ghidra/releases ]
* x32dbg  			[ Desktop Shortcut ]	[ https://github.com/x64dbg/x64dbg/releases/tag/snapshot ]
* x64dbg 			[ Desktop Shortcut ]	[ https://x64dbg.com/ ]
* dnSpy x64 		[ Desktop Shortcut ]	[ https://github.com/dnSpy/dnSpy/releases ]
* dnSpy x32 		[ Desktop Shortcut ]	[ https://github.com/dnSpy/dnSpy/releases ]
* ORCA MSI Editor	[ Desktop Shortcut ]	[ https://www.technipages.com/download-orca-msi-editor/ ]
* pe_unmapper		[ Command Line Env ]	[ https://github.com/hasherezade/pe_unmapper/releases ]		

------------ .NET Deobfuscators -----------
* de4dot 			[ Command Line Env ]	[ https://github.com/wickyhu/simple-assembly-explorer/releases ]
* SEA 				[ Desktop Shortcut ]	[ https://github.com/ViRb3/de4dot-cex/releases ]
* EazFixer 			[ Command Line Env ]	[ https://github.com/0x59-Cl/Eazfixer/blob/master/eaz%20fixer.rar ]

------------ User Utils -----------
* Sublime Text 4 	[ Desktop Shortcut ]	[ https://www.sublimetext.com/download ]
* Chrome			[ Desktop Shortcut ]	[ https://www.google.com/chrome/ ]
* Thunderbird		[ Desktop Shortcut ]	[ https://www.thunderbird.net/en-US/ ]
* WinRAR			[ Desktop Shortcut ]	[ https://www.win-rar.com/download.html?&L=0 ]
* 7zip				[ Desktop Shortcut ]	[ https://www.7-zip.org/ ]
* yara				[ Command Line Env ]	[ https://github.com/VirusTotal/yara/releases ]

````

[ Customize configurations for the specific software: ]

````
------------ 010 Editor -----------
* View -> Edit As -> check Hex

------------ Process Hacker 2 -----------
* Hacker -> Options -> General Tab -> Collapse services on start

------------ Procdot -----------
* Download WinDump.exe and put it to C:\Windows\System32\							 https://www.winpcap.org/windump/install/default.htm ]
* Edit -> Options -> Path to windump/tcpdump -> C:\Windows\System32\WinDump.exe
* Edit -> Options -> Path to Graphviz -> C:\Program Files\Graphviz\bin\dot.exe

------------ Procmon -----------
* Options-> uncheck "Show Resolved Network Addresses" 
* Filter -> uncheck "Enable Advanced Output"
* Options -> Select Columns -> uncheck "Sequence"
* Options -> Select Columns -> check "Thread ID"

````

[ Optional: Microsoft Office 2013 Pro. License required ]
````cmd (powershell)
choco install OfficeProPlus2013
````

[ Customize other configurations and/or tools to your liking ]

[ Create a snapshot. Enjoy your analysis 😉 ]
