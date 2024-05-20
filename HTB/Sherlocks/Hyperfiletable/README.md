# Hyperfiletable
> Write-up author: jon-brandy

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/210fd377-ebdc-42a1-8304-4300f8b7e0fc)


## Lessons Learned:
- Parsing raw mft data using analyzeMFT.
- Searching ZoneID, physical size, and logical size for a specific file using MFTExplorer.

## SCENARIO:
There has been a new joiner in Forela, they have downloaded their onboarding documentation, however someone has managed to phish the user with a malicious attachment. 
We have only managed to pull the MFT record for the new user, are you able to triage this information?

## STEPS:
1. In this challenge we're given a raw data file of MFT record for the new user.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/9e4f3b11-5442-4fde-b8aa-403bb4a309fa)


2. To analyze this file, we need to parse it first.
3. To parse the file I used **analyzeMFT** and convert the output to .csv file.

```
python3 'C:\CTF\TOOLS-FOREN\analyzeMFT\analyzeMFT.py' -f .\mft.raw -o analyzed_mft.csv
```

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/d20d5f3b-5563-4df5-aa7e-0da650204c47)

> 1ST QUESTION --> ANS: 3730c2fedcdc3ecd9b83cbea08373226

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/05226cef-3ce0-4714-b307-bf26447616ae)


4. To get the MD5 hash of the MFT, we can use md5sum command in Linux.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/9e6b248c-048e-40ae-a406-9feb5b82f9dc)


> 2ND QUESTION --> ANS: Randy Savage

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/5a89a8df-a628-4d3b-86b1-73462c5387fe)


5. To identify the user's name on the system, we can filter our search with this --> `/Users/`.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/5240e0df-0e42-4961-b259-09ca63176ffd)


6. **Randy Savage** stands out as the only user we can see here.

> 3RD QUESTION --> ANS: Onboarding.hta

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/6434cc11-abfb-46ad-9a85-7d596254a627)


7. To get the malicious filename, I start by searching .hta and it resulting to only 1 filename namely --> Onboarding.hta.
8. This concludes that it is indeed the malicious file.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/c9d7d23e-5ffb-4ca8-b2b2-47129948f14b)


> 4TH QUESTION --> ANS: 3

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/afb69561-172b-42ee-9e00-0d1adec8b87f)


9. To identify the ZoneIdentifier of the download for the malicious HTA file, we can parse the mft.raw file using **MFTExplorer**. 

```
What is ZoneID?
The Zone Identifier is a piece of metadata associated with files that are downloaded from the internet. It is a security feature implemented in Microsoft Windows to help protect the system from potentially harmful content.
```

> RESULT

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/d29081f9-db45-4b36-b0de-398feb895d60)


10. Now open the path for the .hta file, at the **data interpreter** section, we can see the ZoneID value --> 3.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/3fd89649-c746-45a9-8ce8-e863dfd5302d)


> 5TH QUESTION --> ANS: `https://doc-10-8k-docs.googleusercontent.com/docs/securesc/9p3kedtu9rd1pnhecjfevm1clqmh1kc1/9mob6oj9jdbq89eegoedo0c9f3fpmrnj/1680708975000/04991425918988780232/11676194732725945250Z/1hsQhtmZJW9xZGgniME93H3mXZIV4OKgX?e=download&uuid=56e1ab75-ea1e-41b7-bf92-9432cfa8b645&nonce=u98832u1r35me&user=11676194732725945250Z&hash=j5meb42cqr57pa0ef411ja1k70jkgphq`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/d2855386-f550-4511-8db9-af380a4461cf)


11. To find the download URL, simply scroll down at the same data interpreter.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/90b61b48-9896-4663-9c51-47b631facde4)


> 6TH QUESTION --> ANS: 4096

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/e2059637-730a-41dc-af25-be9af334a015)


12. At the **overview** tab we can see the physical size (allocated size for the HTA file) and logical size (the real size of the HTA file).

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/45d70545-2b3b-436f-92e9-342153d817b6)


```
Physical size (allocated size) --> 0x1000 = 4096
```


> 7TH QUESTION --> ANS: 1144

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/c664039a-81b4-49aa-84db-543e4e9788cc)


```
Logical size (actual size) --> 0x478 = 1144
```

> 8TH QUESTION --> ANS: 05/04/2023 13:11:49

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/cd9609be-f7b0-4a44-b610-a9324b0c59ce)


13. Enumerating directories shall found our interest is at **Documents --> Work**.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/efc44a8b-dc42-4c12-8d0b-14da5228ccbf)


> 9TH QUESTION --> ANS: ReallyC00lDucks2023!

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/3b042188-9781-41d1-9007-8a6310b09d33)


14. To find the password, simply click the notes.txt file then check the data interpreter section.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/79bcad10-157b-48db-8ec1-0f73370a7ab7)



> 10TH QUESTION --> ANS: 3471

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/d5a5b2b4-6e13-46c6-9888-5ddee4659e54)


15. To identify how many files remain under, I didn't figure out the fastest way. But from what I did, every time I click a directory I continuously adding the value shown at the bottom right.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/0c2ae89d-e70f-4adc-8996-87e58788cea0)


## IMPORTANT LINKS

```
https://andreafortuna.org/2017/07/18/how-to-extract-data-and-timeline-from-master-file-table-on-ntfs-filesystem/
https://github.com/dkovar/analyzeMFT
https://ericzimmerman.github.io/#!index.md
```
