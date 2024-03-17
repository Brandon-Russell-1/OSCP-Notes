## Linux Enumeration

I only transfer linpeas, if I am not able to find anything manually

### Links
- [LinPeas.sh](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- [LinEnum](https://github.com/rebootuser/LinEnum)

### Writable Paths

```
/dev/shm/
/tmp/
/home/<USER>/
/var/www/html/<>
```

### Alternatives of `cat`

```
# using grep 
grep . <filename> 

# print all files in current dir 
grep -R . 

# script 
while read line; do echo $line; done < FILE
```
### Path Fix

```
export PATH=/bin:/usr/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$PATH
```
### Quick Wins

```
ls -la /etc/passwd # See if you can write into /etc/passwd
find / -writable -type d 2>/dev/null # insecure file perms
cat /etc/crontab # crontab
uname -r # Kernel exploit
find / -perm -u=s -type f 2>/dev/null # GTFO Bins now.
docker run -v /:/mnt --rm -it alpine chroot /mnt sh # Docker
sudo -l # Sudo privs on what
getcap -r / 2>/dev/null # ep in end means privilege everything # GTFO Bins.
cat /etc/exports  # Check if rw and "no_root_squash" both are present  # The directory in which both are present is shareable and mountable.
env
cat .bashrc
history
watch -n 1 "ps -aux | grep pass" # grep pass in processes
sudo tcpdump -i lo -A | grep "pass" # sometimes password in here

grep "CRON" /var/log/syslog # inspecting cron logs
```

### Manual Enumeration

```
bash -i # Interactive bash
whoami
id
cat /etc/passwd # If www user us then meaning web server is there
uname -a # Kernel Version and Arch
cat /etc/issue # Kernel Version
Sysinfo
ps aux # What's running by root?
hostname
hostnamectl
ifconfig
ip route
ip a # If connection is connected to more than 1 network
arp -a
/opt/linux_privesc/chisel # Internal running ports
netstat -a # Internal running ports
cat /var/html # Config Files
/sbin/route # Route table
ls -la passwd
cat /etc/passwd | cut -d : -f 1 # Usernames
cat /etc/shadow
cat /etc/group
cat /etc/os-release
cat .bash_history
history
grep -Hs iptables /etc/* # Firewall rules if lucky

'sudo -u#-1 /bin/bash' # !root (no root)

# Find commands
locate flag.txt
which flag.txt
find / -name flag.txt >2/dev/null


```


### Search for text in files (and !)

```
# search keyword in all files recursive
grep -iR "<keyword>" <SEARCH-PATH> --color=alwauys 2>/dev/null
grep -Rnw <path-to-search> -ie "<keyword>" --color=always 2>/dev/null

# grep all files not containing certain text
grep -L "TEXT_FILE_SHOULD_NOT_CONTAIN" [files | *.extension]

# print file contents without comments (#) and removes the empty lines.
grep -v "^[#;]" FILE | grep -v "^$" 
```
