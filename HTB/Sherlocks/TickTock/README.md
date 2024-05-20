# TickTock
> Write-up author: jon-brandy

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/c3aac728-10f3-4ffc-8344-fa0f7699be18)


## Lessons Learned:
- Reviewing TeamViewer logs (hunting C2 agent, hunting the attacker session).
- Reviewing Prefetch logs to identify previously opened or executed binaries.
- Reviewing Sysmon log to identify outbound / inbound network connections.
- Reviewing Windows Defender and Powershell log to identify the C2 Agent, Drive Mounting Execution, and C2's hashes.
- Parsing raw Master File Table using MFTECmd.exe
- Reviewing parsed MFT using Time Explorer.
- Using Get-WinEvent grab for timestamp change event.

## SCENARIO:

<p align="justify">
Gladys is a new joiner in the company, she has recieved an email informing her that the IT department is due to do some work on her PC, she is guided to call the IT team where they will inform her on how to allow them remote access. The IT team however are actually a group of hackers that are attempting to attack Forela.
</p>

## STEPS:
1. In this case, we're tasked to investigate a malicious remote access connection through the logs given.
2. Based from the scenario and the questions, we can conclude that a new employee gets a call from the attacker to allow them remote access to her PC. After they get a TeamViewer connection, they also launch a C2 agent. 

> ARTIFACTS GIVEN

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/5decd5b4-7c6b-4a00-a791-7ecc902d4e30)


![image](https://github.com/jon-brandy/hackthebox/assets/70703371/0a3a50b3-026c-41d4-9135-e51ad91b7bbb)


3. It seems we're gonna dealing with parsing **Master File Table** and reviewing Windows Event Logs if needed.


> 1ST QUESTION --> ANS: Merlin.exe

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/6a2a5b43-ad89-4a75-923c-6d1e79375e39)


4. Since the initial entry is from the **gladys** PC, where she allowed the attacker to do remote access to her PC. Let's check the log file inside her directory for any remote access application avail.

```
Navigating through --> /C/Users/gladys/AppData/Local/
```

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/a68ffb92-4da2-4719-878c-cb70e147f6bc)


5. Seems we identified what remote access application gladys used, it's **TeamViewer**. Now let's review the log start by the **TeamViewer15_Logfile.log**

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/333fef0c-099b-49fc-b908-8fb14a3ff875)


![image](https://github.com/jon-brandy/hackthebox/assets/70703371/eb701865-a5b7-41ee-a783-b0f7c152e96b)


6. Long story short, upon reviewing the logs. Found an outbound connection at `11:21:34` from **Gladys** PC.
7. It downloaded a binary file named `Merlin.exe`. The binary stored at the desktop.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/3c31f9f8-7ce4-45a1-8ba6-3156faed2ccb)

8. This could be the C2 Agent, but further checking is needed.
9. Upon reviewing the csv file which contains prefetch log, found that `Merlin.exe` is part of the prefetch. Meaning it's previously **Opened** or **Executed** on the PC.
10. It can be found at timestamp --> `11:51:15` row 63.
 
![image](https://github.com/jon-brandy/hackthebox/assets/70703371/f31ceacb-cfcb-4ae6-9d73-3063d59d8cb2)


11. But again, we need more evidence whether it is indeed acts as a C2 agent.
12. Now let's review the Windows Event log.
13. The simplest way to identify whether the binary is malicious or not, we can start by reviewing the `Windows Defender` event log.
14. Long story short, found that `Merlin.exe` is logged inside the log.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/a3652b77-7333-4e0f-84f2-054d3622a1df)


15. Reviewing the logs previous it, Windows Defender categorized the `Merlin.exe` as `VirTool:Win32/Myrddin.D`.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/1c90fbb4-21a1-4366-af91-6120837dc0ca)


![image](https://github.com/jon-brandy/hackthebox/assets/70703371/27ea07dc-af5b-436b-b99e-b4217972de15)


16. So to summarize this up, `Merlin.exe` gets executed then quarantined by the Windows Defender, then it freed again.
17. Great! We hunted the C2 agent.

> 2ND QUESTION --> ANS: `-2102926010`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/1a66d9f4-a934-46dd-85fb-5ffb9c44b945)


18. Now, to identify the initial access's session ID, we need to review again the Team Viewer logfile.
19. Found that an initial connection started at `11:35:27` and the login attempt is at `11:35:27`, then it authenticated at `11:35:31`.
20. Which means the session ID is --> `-2102926010`.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/c2c6de0c-fc27-4ba0-a7c9-6e4e8e3f2c96)


![image](https://github.com/jon-brandy/hackthebox/assets/70703371/425adad3-1a78-4dbc-b39f-7b1339723ec4)


> 3RD QUESTION --> ANS: `reallylongpassword`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/77210ffa-b07a-46c3-8ef5-07722ed7e8d6)


21. To identify this event where the attacker attempted to set a bitlocked password on the C drive, we need to review Windows Powershell event log.
22. Found an interesting powershell execution at `18:14:33`, the contents are encoded with base64.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/98700fd8-d07d-4b8e-b30c-f7ead928857f)


23. Upon decoding it, it's indeed the command used by the attacker to mount the C drive. Also we identified the password used.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/240b9cf0-7016-4437-ab84-208ded626901)


> 4TH QUESTION --> ANS: `fritjof olfasson`.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/68f1a606-026e-4cba-84bf-055222807c00)


24. Next, to identify the name used by the attacker, again we need to review the TeamViewer logfile.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/d9c3d1f7-be39-43fa-b929-1450ccd47407)


25. Based, from the evidence above, after the attacker authenticated. It saved the session and saved the local participant as `1764218403`.
26. Not long after it, around 4 seconds later, we can identified 2 participants inside the session.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/efc8f4bb-8358-4df4-9665-f00a16fc5c22)


27. The first one, likely is Gladys PC's Hostname. The other one should be the attacker --> `fritjof olfasson`.
28. As an additional information. There is an attempt to screenshot the desktop.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/bf55918e-5cfc-4b7d-b337-8ee7b7f0ad94)


> 5TH QUESTION --> ANS: `52.56.142.81`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/0f77df07-0fb5-4a38-9916-c908b9c46c14)


29. To identify the destination of the C2 agent, simply review the **sysmon** log and filter for event ID 3 --> `Network Connection Detected`.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/3a58aa5f-39bc-445b-92d7-a4f131e12ae6)


30. Great! Now we know the destination IP is --> `52.56.142.81`.

> Destination IP details

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/6a9ae3dc-a744-4461-bc11-c68be8becc7c)


> 6TH QUESTION --> ANS: `VirTool:Win32/Myrddin.D`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/4ce8c9b4-139f-421a-bbc9-12dfdaf58093)


31. Previously, by analyzing the **Windows Defender** event log, we identified the C2 binary categorized as --> `VirTool:Win32/Myrddin.D`.


 
> 7TH QUESTION --> ANS: Invoke-TimeWizard.ps1

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/54560c19-0fbb-4d51-8556-138a3bcca3b3)


32. If you notice, when reviewing the TeamViewer log, the timestamp of the next logs seems manipulated (?)

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/30c62a32-55c3-4e4b-9284-b13271e8bd36)


33. This must be the attacker doing to confuse the analyst or the Incident Responds team.
34. After reviewing several log at sysmon for eventID 11, found few powershell script with interesting filename.
35. Seems this time we're gonna need to review the MFT, let's parse the MFT to CSV file then open it using Time Explorer. Anyway there's another simple method if you don't want to parse it, simply using MFTExplorer you can open the raw MFT file without converting it first to CSV file.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/9327feb9-d942-40fb-824f-ce3251e39ddf)


> TIME EXPLORER

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/17bcc86c-f923-4f20-a124-7113b32891c1)


36. Let's start the search by filtering for **gladys**'s Desktop first.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/98ce0f79-5aa1-40c8-8d9d-ab2695d853ba)


37. Interestingly, there is a powershell script named `Invoke-TimeWizard`. Based from the filename and it's location. It's indeed the script used by the attacker to manipulate the TeamViewer timestamp. It manipulate the windows timestamp as a whole.

> ADDITION RESULT USING MFT Explorer

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/ddf4508b-4d05-417f-a1f9-10867453eba6)


38. As you can see, using MFT Explorer shall help us with the visibility to review each timestamp of files.

> 8TH QUESTION --> ANS: `2023/05/04 11:35:27`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/508aad12-731d-437d-83c7-c81c1dcb18e3)


38. Again, based on our previous analsis on TeamViewer logfile. The initial connection starts at `2023/05/04 11:35:27`.

> 9TH QUESTION --> ANS: ac688f1ba6d4b23899750b86521331d7f7ccfb69:42ec59f760d8b6a50bbc7187829f62c3b6b8e1b841164e7185f497eb7f3b4db9

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/077adf97-e116-4fa7-aa0b-6c891ade17ae)


39. Rather than carving the binary from the raw MFT file manually, let's review the Windows Defender log.

```
PATH TO DEFENDER LOGS:
C/ProgramData/Microsoft/Windows Defender/Support
```

40. Reviewing the MPLog shall help us to identify both sha1 and sha2.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/92e19bee-622c-46cb-8a3c-b604ec706c67)


> 10TH QUESTION --> ANS: 2371

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/a67891d5-2989-4f21-92c0-1f2878b4d3df)


41. To identify the count, we need to review the `security` event log then filter for eventID **4616** and with keyword **powershell**.

> COMMAND

```
Get-WinEvent -Path '.\Collection\C\Windows\System32\winevt\logs\Security.evtx' -FilterXPath "*[System[(EventID=4616)]]" | Where-Object { $_.Message -like '*powershell*' } | Measure-Object
```


![image](https://github.com/jon-brandy/hackthebox/assets/70703371/d9324c1e-8686-41d8-a50a-f70812b20def)



> 11TH QUESTION --> ANS: S-1-5-21-3720869868-2926106253-3446724670-1003

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/d53a6817-f667-44b3-9f74-acd9422cb6e6)



42. Again, reviewing the security event log, we can identify the SID for **gladys**.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/8c7095fb-5ed7-4a11-a2d5-c64e4d147b5d)


43. Great! We've investigated the case!


## IMPORTANT LINKS

```
https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j
```
