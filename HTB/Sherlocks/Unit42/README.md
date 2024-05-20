# Unit42
> Write-up author: jon-brandy

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/920cd552-7e29-4191-a309-d9601e97ad76)


## Lessons Learned:
- Sysmon EventID definition.
- Reviewing sysmon logs using Event Viewer.
- Analyzing UltraVNC Infection Incident.

## SCENARIO:
In this Sherlock, you will familiarize yourself with Sysmon logs and various useful EventIDs for identifying and analyzing malicious activities on a Windows system. 
Palo Alto's Unit42 recently conducted research on an UltraVNC campaign, wherein attackers utilized a backdoored version of UltraVNC to maintain access to systems. 
This lab is inspired by that campaign and guides participants through the initial access stage of the campaign.


## STEPS:
1. In this challenge, we're tasked to analyze malicious act on a Windows system by reviewing a Windows Event Log file which contains sysmon logs.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/c450b9d7-bf21-4e10-b6d9-4efe9409f5ee)


#### NOTES:

```
Sysmon (System Monitor) logs are a type of log generated by the Sysinternals Sysmon utility, which is a Windows system
service and device driver thatprovides advanced system monitoring and logging capabilities. Sysmon logs capture
detailed information about various activities happening on a Windows system, including process creation,
network connections, file creation, registry modifications, and more.
```

2. To analyze this type of log file we can use **Event Viewer**.

> Result in Event Viewer


![image](https://github.com/jon-brandy/hackthebox/assets/70703371/c644bf5d-2d78-4d65-b2b7-c280f2da5f89)


> 1ST QUESTION --> ANS: 56

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/0208a2b3-6758-4887-8462-36387ffc08bb)


3. There are 2 ways to identify the total logs for EventID 11. The first one is by filtering the log displayed in EventViewer then count it manually or check the top diplayed number.


![image](https://github.com/jon-brandy/hackthebox/assets/70703371/61294a7b-87c2-4d0d-a1bf-7a9009798214)


4. Or, simply execute this powershell command.

> COMMAND

```ps
Get-WinEvent -Path '.\Microsoft-Windows-Sysmon-Operational.evtx' -FilterXPath "*[System[(EventID=11)]]" | Measure-Object
```

> THE RESULT OF PS COMMAND


![image](https://github.com/jon-brandy/hackthebox/assets/70703371/b684310b-a9fb-4fc4-8803-eabd8140ef53)


> 2ND QUESTION --> ANS: `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/f05510da-8da4-4658-a6ab-2ff24e46529e)


5. In analyzing sysmon logs, I used [this](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx) online WIKI to help me identify the meaning of each eventID.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/0fc978e4-2b37-451f-86dc-7ec0474086cd)


6. It said that there is a malicious process that infected the victim's system, hence we can conclude that **the malicious process** is created in memory and it should be logged.
7. To hunt the malicious process, let's filter the logs displayed to logs which have EventID 1.

> RESULT

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/c17ef370-913b-42f8-9d59-6b46093a857f)


8. We got 6 results. Long story short, after reviewing each logs, found one log with suspicious binary name.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/4b4fa5b7-06ae-4290-873d-89b0191077eb)


9. It has double extension. The easiest way to bust whether it's the malware or not is not by contextual analysis. But sends the hash values provided at the sysmon log to virustotal.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/34bb71e6-990e-45ad-a706-9bfa4d2ab8ac)


> RESULT IN VIRUSTOTAL

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/9f4e5d97-320c-4291-9f3d-61fa0dc51079)


10. It's tagged as malicious! Noticed it's categorized as Trojan and it's family is `winvnc`. Exactly what is the scenario told us.
11. Hence we hunted the malware.

#### NOTES:

```
WinVNC (Windows Virtual Network Computing) malware is a specific type of malicious software that exploits
the VNC protocol to gain unauthorized remote desktop access to a victim's computer running the Windows operating system.
```

> 3RD QUESTION --> ANS: dropbox

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/d3eff909-9df2-488a-a056-3454a52532eb)


12. At the first sysmon log, we can identified that there is an access to a cloud storage named `dropbox` from the victim's system.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/d8041814-f2d4-4a25-8043-49549f328fc5)


13. EventID 22 itself indicates a DNSEvent.
14. The next sysmon log has eventID 11 which indicates a file creation event.
15. Interesting! We can speculate that the dropbox google cloud is accessed and the malware is downloaded to the victim's system from there.
16. Our speculation can be proven by reviewing the 2nd eventID 11 log and the 4th eventID 11 log.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/82c62dc1-327c-4ea4-abd9-8d5970dd1c50)


17. There is a `.part` file for `skZdsnwf.exe` file. This indicates a download is attempted and not finished.
18. Then at the 4th log with eventID 11, we can see a firefox.exe still used at the same timestamp as the previous download attempt but this time the malware is downloaded.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/6a09a9c5-0b12-4b8b-add7-6676f244f371)


19. It's clear that **dropbox** is the cloud used to distribute the malware.

> 4TH QUESTION --> ANS: `2024-01-14 08:10:06`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/dbcf19b4-6c90-49d9-9f46-77025d4a9c9f)


20. To identify an **attempt for modifying file creation time**, we can filter for EventID 2.
21. Long story short, found the log which contain a pdf file and it's the only one.

> RESULT

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/c4ee1835-0f76-420b-8a07-1809dddb8952)

22. Based from the log's content above, it's clear that the attacker used the malicoius file to modify the pdf timestamp to `2024-01-14 08:10:06`. To make it appear old.
23. To make sure of it, open the `Details` tab. We can see that the creation timestamps is changed.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/6cf9117b-0340-4bb8-bdab-01f604b39fbe)


> 5TH QUESTION --> ANS: `C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/289a5892-5062-454b-be9c-7884c3c2fd54)


24. Further analysis, noticed that the malicious file dropped several files to the vicim's system. One of them is `once.cmd`. The full path is shown at the log's general tab.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/e00054b1-8281-4968-bf82-2c02070c68c3)


> 6TH QUESTION --> ANS: `www.example.com`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/dec896fd-5771-427e-83a8-ef78d6b92d23)


25. To identify which dummy domain accessed by the malicious file, we can easily find it by filter the log shown with EventID 22 (DNSEvent).
26. Reviewing the 3rd log shown, we can identified that `www.example.com` is the dummy domain accessed by the malicious file.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/c9b264d7-f11b-432e-a5c9-a63c56b78789)


> 7TH QUESTION --> ANS: `93.184.216.34`


![image](https://github.com/jon-brandy/hackthebox/assets/70703371/f47bba48-7d38-4fce-95ca-c987ddb59368)


27. If a process tried to reach a network connection, hence sysmon log with EventID 3 is created.
28. Reviewing the content of it, we can identified that the malicious process tried to establish a connection to `93.184.216.34`.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/360648e1-c1b4-4885-b27d-1a9178d48bb0)


> 8TH QUESTION --> ANS: `2024-02-14 03:41:58`


![image](https://github.com/jon-brandy/hackthebox/assets/70703371/c00f492c-812c-422a-8ca1-608a74e0d4ed)

29. At certain time, the malicious file terminated it's process after infecting the PC with a backdoored varient of UltraVNC.
30. If a process is terminated, then EventID 5 is created. Reviewing the log's content, we can identify the timestamp of the termination.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/46714be2-535f-4821-a2dd-91571ab70981)


## IMPORTANT LINKS

```
https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx
```