# Persistence

This Repository is for documentation and files associated with testing persistence techniques


Windows Registry is a database that stores settings and options for Microsoft Windows operating systems. It contains information and settings for system hardware, software, users, and preferences.

To use Windows Registry for persistence, a malicious user will inject malicious code into the Registry and then set it up to run each time the computer starts.

Here are the steps to use Windows Registry for persistence:

1. Open Registry Editor:

Press the Windows Key + R, type in “regedit”, and then press Enter.

2. Find the Run key:

Navigate to HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run

3. Create a new value:

Right-click the Run key and select New > String Value.

4. Name the value:

Name the value something that is unique and recognizable.

5. Set a path for the value:

Double-click the value that was created and put in the path to the malicious program that is to be executed each time the computer starts.

6. Save the changes:

Select File > Exit to save the changes and close the Registry Editor.
