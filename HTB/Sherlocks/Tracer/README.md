# Tracer
> Write-up author: jon-brandy

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/6a82121a-8a9f-4c90-8b4d-d8e12adaf889)


## Lessons learned:
- Analyzing windows event log file.
- Parsing a prefetch file and extract the information into csv format using PECmd.
- Parsing $MFT using MFTECmd.
- Analyzing sysmon operational event log to identify fullname of the named Pipe ending with stderr.

## SCENARIO:
A junior SOC analyst on duty has reported multiple alerts indicating the presence of PsExec on a workstation.
They verified the alerts and escalated the alerts to tier II. As an Incident responder you triaged the endpoint for artefacts of interest.
Now please answer the questions regarding this security event so you can report it to your incident manager.

## STEPS:
1. In this challenge we're given few files of windows event log and prefetch files.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/41106a98-cdf9-4eaa-b2d6-0999af903523)


> 1ST QUESTION --> ANS: 9

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/e9ab6274-0181-4426-ba61-8cf85ecff92c)


2. To identify how many times was PsExec executed by the attacker, we need to analyze the **Security** event log file.
3. Analyzing the content of the latest log, we can identified the attacker's binary filename.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/3aef0425-ecfd-4bc4-baa9-3aa341b907ed)


4. As you can see, it states **Caller Process Name**, it means the result is executed using this binary.
5. Hence, to check how many times it executed we just need to filter the **Event ID** displayed to --> **4625**.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/eebf76f1-8077-4466-b241-e4e838c7a056)


6. I count it manually, by reviewing each contents. Counted +1 if psexesvc.exe executed.

> 2ND QUESTION --> ANS: psexesvc.exe

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/73d2c743-4d79-426c-abb1-25899b40faca)


7. Based from our previous identification, we identified the binary filename is --> psexesvc.exe.

> 3RD QUESTION --> ANS: `07/09/2023 12:06:54`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/434c9c70-fa2c-4d25-802b-bb2bd5a1a8b2)


8. Next, to get the timestamp for the 5th last instance of the PsExec, I tried to parse the prefetch file we extracted from the .zip file before.

```
Why prefetch file is the interest now?
-> Because Prefetch files is used to preloading certain data and code into memory.
Hence analyzing it helps us to understand the execution patterns of applications on a system,
as these files can provide insights into which applications are frequently used and how they are
loaded into memory during system startup.
```

9. To parse the prefetch file I used [this](https://github.com/EricZimmerman/PECmd) online tool created by Eric Zimmerman.

```
.\PECmd.exe -f 'C:\Users\saput\Downloads\CYBERDEFENDER\Tracer\C\Windows\prefetch\PSEXESVC.EXE-AD70946C.pf'
```

> RESULT

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/0e84482e-1a98-4810-8d6e-31b096aa8fa6)


![image](https://github.com/jon-brandy/hackthebox/assets/70703371/ab7bb046-6144-435d-9acd-5831d8747dc7)


10. Noticed, there's a **run count** header which states 9. Another solution is to parse the prefetch file if we want to identify how many times a binary is executed.
11. Based from the Github's documentation, we can extract the information to a json or csv format.
12. I tried to extract the information into csv format and saved them to a directory named `new_directory`.

```
.\PECmd.exe -f 'C:\Users\saput\Downloads\CYBERDEFENDER\Tracer\C\Windows\prefetch\PSEXESVC.EXE-AD70946C.pf' --csv new_directory
```

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/86cac15e-0320-4332-b4b9-cf0770898974)


13. The **output_timeline** csv should be our interest here.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/fc20aae3-6aa1-4d24-85c7-a576ca6f174b)


14. Simply viewing the timeline for the 6th row shall gave us the correct timestamp.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/f21f846b-d31b-455b-8eb0-64575173704e)


> 4TH QUESTION --> ANS: FORELA-WKSTN001

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/dcf41fa7-96ef-4a73-ac31-d3345953e04b)


15. To identify the hostname, we just need to view the `Files Referenced` result from the prefetch parser.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/6afb92ba-901d-4054-87c3-63b9d24dfafe)


> 5TH QUESTION --> ANS: PSEXEC-FORELA-WKSTN001-95F03CFE.key


![image](https://github.com/jon-brandy/hackthebox/assets/70703371/b21dc320-cf6b-4761-aa1f-e063478c116f)


16. To identify the fullname of the key file dropped by 5th last instance, we can try to parse the Master File Table (MFT).

```
MFT stands for Master File Table, and it is a crucial component of the NTFS (New Technology File System) file system used in Windows operating systems.
The MFT is a database that stores information about every file and directory on an NTFS-formatted volume.
It acts as a centralized index, keeping track of metadata for each file, including attributes such as file name, size,
creation time, permissions, and the location of the file data on the disk.
```

17. To parse it, we can use an online tool created by Eric Zimmerman named **MFTECmd**.
18. I tried to extract the information into csv format and stored it on a directory named --> mftparse_result.

```
.\MFTECmd.exe -f 'C:\Users\saput\Downloads\CYBERDEFENDER\Tracer\C\$Extend\$J' --csv mftparse_result
```

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/bf4f5e53-26a0-4e07-9985-c9901f89aaa7)


19. Upon analyzing the csv file, I noticed the timestamp is descending. To get the correct key, we just need to search for timestamp which is **ONE SECOND** different than the execution of the last 5th instance.
20. Long story short, I managed to find the correct key at row 145570. Noticed the timestamp is different one second only.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/2ce7de9f-ba0e-43a7-a7e2-de00290dcb80)


21. Alternatives way to identify it, simply check the results from PECmd.exe at the `Files Referenced` header.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/8d81dc7b-cf80-4f8e-8ed6-15be218b0ea5)


> 6TH QUESTION --> ANS: `07/09/2023 12:06:55`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/5554716f-12c1-4546-b9b1-1aa1838027ec)


21. We managed to find the timestamp previously.

> 7TH QUESTION --> ANS: \PSEXESVC-FORELA-WKSTN001-3056-stderr

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/0406686d-fdd5-4d64-83c5-a3b8c2fcceab)


22. To identify the fullname of the named Pipe ending with **stderr** keyword, we can start by analysing `Sysmon` event log.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/f7e8ac91-64e4-4c86-8a25-c076dc7022cc)

```
Sysmon logs events related to various system activities, providing detailed information about processes, network connections, file creation, registry modifications, and more. The information logged by Sysmon can be crucial for detecting and investigating security incidents.
```


23. As we know, sysmon provide many event log. However there is a way to speeding the analysis, first we just need to analyze the same timestamp as the 5th.
24. Then our second interest is this timestamp:

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/a7daa328-96e8-446b-b0bc-3d5d37652b3c)


25. Just focusing when the second timestamp is close to `12:06:55`.
26. Long story short, found the correct name.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/ff189064-a491-44e4-a66e-fa410a077a2e)


## IMPORTANT LINKS

```
https://github.com/EricZimmerman/PECmd
https://ericzimmerman.github.io/#!index.md
https://github.com/EricZimmerman/MFTECmd
```


