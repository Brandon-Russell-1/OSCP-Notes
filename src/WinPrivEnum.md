## Windows Enumeration
### Automate

- [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

### Manual

```

whoami # username/hostname
whoami /groups # check user is in which group

net user
net user <username>
Get-LocalUser # Powershell

net localgroup
net localgroup <groupname>
Get-localgroup # Powershell

systeminfo
netstat -ano

# Installed Apps # Powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

Get-Process # Powershell - running process
Get-Process | Select ProcessName,Path # With Path

# Powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

# Powershell
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue

# Default xampp passwords
type C:\xampp\passwords.txt
type C:\xampp\mysql\bin\my.ini

# Change username
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

Get-History # Powershell History
(Get-PSReadlineOption).HistorySavePath # Powershell History

```


### More Automate

### PowerUp

1. **Download and Import the Script:**
    
    - First, you need to download the `PowerUp.ps1` script from the PowerSploit repository. You can do this by cloning the PowerSploit repository from GitHub or by downloading the script directly.
        
    - Once you have the script, you can import it into your PowerShell session using the `Import-Module` cmdlet.
        
                
        `Import-Module ./Path/To/PowerUp.ps1`
        
2. **Run Functions to Find Vulnerabilities:**
    
    - `PowerUp.ps1` offers a variety of functions to check for common misconfigurations that can lead to privilege escalation. For example:
        
        - **Invoke-AllChecks:** This function runs all current escalation checks and returns a consolidated object with the results.
            
                        
            `Invoke-AllChecks`
            
        - **Get-ServiceUnquoted:** This function checks for services with unquoted paths that also have a space in their path. This can potentially lead to privilege escalation.
            
                        
            `Get-ServiceUnquoted`
            
        - **Write-UserAddMSI:** This function generates an MSI file in the specified path that prompts for installation. When installed, it adds a local or domain user with the specified username and password.
            
                        
            `Write-UserAddMSI -UserName "NewAdminUser" -Password "P@ssword!"`
            
1. **Write-ServiceBinary**: This function writes out a binary that adds a local admin user or executes a custom command when a service with an unquoted path (and a writable space in the path) is started.
    
        
    `Write-ServiceBinary -Name 'VulnerableServiceName' -Path 'C:\Path\To\Output\Binary.exe'`
    
2. **Invoke-ServiceAbuse**: This function abuses writable service binaries to write out a payload that adds a local admin user.
    
        
    `Invoke-ServiceAbuse -Name 'VulnerableServiceName' -UserName 'NewAdminUser'`
    
3. **Get-ModifiablePath**: This function finds paths that are modifiable by the current user and are in the system's PATH environment variable. This can be exploited if a service or application executes a binary from a directory that the user can write to.
    
        
    `Get-ModifiablePath`



