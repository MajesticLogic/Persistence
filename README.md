# Persistence

This Repository is for documentation and files associated with testing persistence techniques


Windows Registry is a database that stores settings and options for Microsoft Windows operating systems. It contains information and settings for system hardware, software, users, and preferences.

To use Windows Registry for persistence, a malicious user will inject malicious code into the Registry and then set it up to run at predictable times.

Most scenarios will not invlove a graphically user interface so the only techniques that will be documented will be via terminal, command-line, powershell, etc.

Note: Add the following special characters to the name of the run key
! Delete after command runs successfully
* Run in safe mode
 no prefix runonce will delete key prior to being run and will not run in safe mode

Here are the steps to set-up Windows Registry for persistence:

1. List of Registry Keys:
Current User Permissions

Interval: When user logs in

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

Interval: When user login occurs run once and the key will be deleted
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows


System or Admin Permissions
Interval:
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager


Press the Windows Key + R, type in “regedit”, and then press Enter.

2. Determine which registry key you want to alter:

Navigate to HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run

3. Does current permission allow access to registry key:

Right-click the Run key and select New > String Value.

4. Name the value:

Name the value something that is unique and recognizable.

5. Set a path for the value:

Double-click the value that was created and put in the path to the malicious program that is to be executed each time the computer starts.

6. Save the changes:

Select File > Exit to save the changes and close the Registry Editor.
