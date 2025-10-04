# Email-phishing-analyser-script
Script to analyse emails for phishing analysis using Powershell 5.1

**Environment & Compatibility
**This script was developed and tested on Windows PowerShell 5.1, running on the Windows 10/11 platform.

**Detail	Value	Notes
**PowerShell Version	5.1.19041.6392	The core engine version. This is the older, built-in Windows PowerShell (not PowerShell Core 7+).
PowerShell Edition	Desktop	Confirms it's running on a Windows desktop operating system (Windows 10/11).
Compatible Versions	1.0 - 5.1	Indicates the script should be compatible with most modern Windows versions of PowerShell.
.NET Framework	CLRVersion 4.0.30319.42000	The underlying framework used by this PowerShell version.

1. Open Powershell from the same location script stored
2. Call the script using  .\Analyze-PhishingHeaders.ps1
3. View original message and copy all text (Windows OS = CTRL +A, CTRL +C)
4. Paste text into the running script terminal (continuation of step 2)
5. Press **ENTER** and then **ENDINPUT** and the script will instantly extract key phishing indicators
6. Attachment analysis is advised to be done manually - Instruction included within the script.

Screenshot of analysed email

<img width="1893" height="1019" alt="image" src="https://github.com/user-attachments/assets/d442d7e8-ec20-4b8d-889f-88b444b8c609" />
