## Scanning
### Nmap Scans
```
export ip=192.168.201.222 

nmap -A -p- -T4 -O $ip

--script vuln, http-enum, http-headers

nmap -T4 -p- -A <IP> # T0 -> slowest but covert, T4 -> aggressive but noisy.
nmap -sU --top-ports 100 -vvv <IP> # UDP Ports
nmap --top-ports 100 -F # Top 100 Ports 
nmap -p1-1023 <IP> # Port Range 
nmap -p22,80,443 <IP> # Specific Ports 
nmap <IP>/24 # Subnet
nmap -sT -p- --min-rate 5000 --max-retries 1 <IP> # TCP Ports 
nmap -sU -p- --min-rate 5000 --max-retries 1 <IP> # UDP Ports

TFTP
nmap -Pn -sU -p69 --script tftp-enum 192.168.10.250
nmap -sU -p 69 --script tftp-enum.nse --script-args tftp-enum.filelist=customlist.txt <host>
```

### RustScan & Autorecon & nmapAutomator
```
RustScan:  docker run -it --rm --name rustscan rustscan/rustscan:2.0.0 -a <IP> range 0-65535 -- -A

Autorecon: autorecon <IP> 

or if root I think supposed to do this:

env "PATH=$PATH" autorecon $ip

./nmapAutomator.sh -H $ip -t Recon
``` 

### Powershell Port Scan

```
Test-NetConnection -Port 445 192.168.50.151
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```

### Bash Port Scan

```

for i in $(seq 1 254); do nc -zv -w 1 172.16.210.$i 445; done

```

### Python Port Scan

```

import pyfiglet
import sys
import socket
from datetime import datetime

ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
print(ascii_banner)

# Defining a target
if len(sys.argv) == 2:
	
	# translate hostname to IPv4
	target = socket.gethostbyname(sys.argv[1]) 
else:
	print("Invalid amount of Argument")

# Add Banner 
print("-" * 50)
print("Scanning Target: " + target)
print("Scanning started at:" + str(datetime.now()))
print("-" * 50)

try:
	
	# will scan ports between 1 to 65,535
	for port in range(1,65535):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		socket.setdefaulttimeout(1)
		
		# returns an error indicator
		result = s.connect_ex((target,port))
		if result ==0:
			print("Port {} is open".format(port))
		s.close()
		
except KeyboardInterrupt:
		print("\n Exiting Program !!!!")
		sys.exit()
except socket.gaierror:
		print("\n Hostname Could Not Be Resolved !!!!")
		sys.exit()
except socket.error:
		print("\ Server not responding !!!!")
		sys.exit()


```


### Directory Busting
```
dirb http:///<IP>/ # If port -> 443, Do HTTPS

gobuster dir -x php,txt,xml,asp,aspx --url http://<IP>/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -b 404 -f 

feroxbuster --url http://<IP>/ --filter-status 401,402,403,404 -x txt,cgi,sh,pl,asp,aspx,php --depth 2 --output ferox.result -k --

wordlist=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -f

ffuf -c -u http://<IP>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

python /opt/Sublist3r/sublist3r.py -d devvortex.htb

dirbuster -u http://10.10.105.213/

dirsearch -u url -w wordlist

dirsearch -u http://192.168.213.98 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt


wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --hc 404 http://$ip/FUZZ


```

### Vulnerability Scanner 
```
nikto -host http://<IP>/ # If port -> 443, Do HTTPS



enum4linux $ip
```

### WP Scan

```
Enumerating Users
wpscan --url [target-url] --enumerate u

Enumerating Plugins
wpscan --url [target-url] --enumerate p

Enumerating Themes
wpscan --url [target-url] --enumerate t

Brute Forcing Passwords
wpscan --url [target-url] --passwords [path-to-wordlist] --usernames [user1,user2,...

Detecting Vulnerable Plugins or Themes
wpscan --url [target-url] --enumerate vp,vt

Running All Scans
wpscan --url [target-url] -e

API Token
wpscan --url [target-url] --api-token [YourWPScanAPIToken]

```

### Nmap Cheat Sheet

![nMap Cheat Sheet](nmapcheatsheet.png)
