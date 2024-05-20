# BFT
> Write-up author: jon-brandy

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/bfaf309d-3852-4098-ba7f-fe722f04cb51)


## Lessons Learned:
- Parsing Master File Table (MFT) raw file using MFT Explorer.
- Using MFTECmD to convert MFT raw file to csv.
- Identify downloaded malicious file.

## SCENARIO:

In this Sherlock, you will become acquainted with MFT (Master File Table) forensics. You will be introduced to well-known tools 
and methodologies for analyzing MFT artifacts to identify malicious activity. During our analysis, you will utilize the MFTECmd 
tool to parse the provided MFT file, TimeLine Explorer to open and analyze the results from the parsed MFT, and a Hex editor 
to recover file contents from the MFT.


## STEPS:
1. In this task we're given a MFT file which we can analyze using MFT Explorer. But I prefer to analyze it by converting the raw MFT file to a .csv format.
2. Then analyze the CSV file using Timeline Explorer.
3. To convert the raw MFT file to .csv format, you can either use `analyzeMFT` or `MFTECmD.exe`. Both also can be used for the same purpose.

> 1ST QUESTION --> ANS: Stage-20240213T093324Z-001.zip

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/c6838e00-5a77-458f-ab52-7d544a525ebe)


4. For this writeup, I used `MFTECmD.exe` to convert the raw MFT to .csv file.

> Converting mft.raw file to .csv file.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/a5a79e2f-1029-4a2c-9df4-ed1ea2968957)


5. Now let's upload it to `Timeline Explorer`.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/39d7836a-1b65-4c79-93c4-f8381a708ac6)


6. The easiest way to identify the zip filename which Simon downloaded at 13th February, we just have to search for `.zip` and correlate the timestamp.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/86a998d8-397d-4c1a-9303-8ed5fb95a88e)


7. Found one zip file that looks convincing based on it's timestamp and it's file path.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/e1bf4356-751f-4e34-99f2-12aee2bb2dd3)


8. However, found another zip file that resides in the Download directory. Interesting!

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/2edaf7cc-e593-4b47-ab45-e932e82fc40b)


9. To improve the visibility, I sorted the parent path then custom the filter for only `Downloads` directory of user Simon.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/97f3315b-4b05-4a83-abab-48ce65dcea44)

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/c9715566-3d7b-430b-840f-1bc6bb5df538)



10. Great! Based from the results above, seems there are only 2 .zip files inside Simon `Downloads` directory at 13th February 2024.
11. Further analysis, found that `Stage-20240213T093324Z-001.zip` is unzipped and has another .zip file inside it named `invoices.zip`.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/9631bebb-c611-461e-9ebf-399e505e1e2e)


12. Then found out a .bat file inside invoice.zip. This is absolutely indicating a malicious file.

#### Notes

```
A .bat file is a batch file in Windows, which is essentially a script containing a series of commands that are
executed in sequence. These files are often used to automate tasks or run multiple commands at once.
```

13. Noticed the file size is only 286 bytes. Hence it should be stored directly at the MFT entry.

#### Notes

```
When a file is small enough to be stored entirely within the MFT record, it can improve access times because the file
data can be read directly from the MFT without the need to access additional disk sectors. This technique is often used
for system files and other small files that are frequently accessed.
```


14. Knowing this, then let's analyze invoice.bat's content by uploading raw MFT file using `MFT Explorer`.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/bae66771-6510-4e1d-a827-553cc186c664)


15. Based from the result above, we can see there is a C2 IP and it's port which are as the web server to download a file.
16. Another alternative way to review the content of invoice.bat file, simply upload the raw MFT file to a hexeditor then calculate the offset.

```MD
OFFSET for MFT Entry

Entry number of invoice.bat file --> 23436 (you can see it at Timeline Explorer, there's a column for it).
Each entry is 1024 bytes.

Offset --> 23436 * 1024 = 23998464.
Convert it to hex = 0x16E3000

Using hexeditor and open at offset 0x16E3000, shows the invoice.bat's content.
```

18. Great! We hunted the malicious file then.

> 2ND QUESTION --> ANS: `https://storage.googleapis.com/drive-bulk-export-anonymous/20240213T093324.039Z/4133399871716478688/a40aecd0-1cf3-4f88-b55a-e188d5c1c04f/1/c277a8b4-afa9-4d34-b8ca-e1eb5e5f983c?authuser`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/67acd946-ad3b-464d-8721-009130d27a14)


19. To identify the full HOST URL, open `Time Explorer` again then filter the malicious zip file and check the **Zone id Contents** column.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/8e9558df-f1c4-4d5f-a61b-85035d5d2b31)


> 3RD QUESTION --> ANS: `C:\Users\simon.stark\Downloads\Stage-20240213T093324Z-001\Stage\invoice\invoices\invoice.bat`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/d4bfc30b-fbfc-4c8d-aff7-f625a576de33)


20. To identify the full path, simply filter for the malicious file we hunt before (invoice.bat) then look at the bottom for the full path.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/06fce1b1-9404-4163-a772-e8464bdc9130)


> 4TH QUESTION --> ANS: `2024-02-13 16:38:39`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/832cd8ff-b6c5-46a6-b1fe-e295b84ae818)


21. To identify the timestamp for the file creation on disk, simply check **Created0x30** column.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/17bc136e-93d0-4637-bc90-2aeca40b3f57)


> 5TH QUESTION --> ANS: 16E3000

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/082f4e7c-4f96-4172-b568-ac812da368b1)


22. Previously we already calculated the offset as an alternative way to investigate the .bat's content.
23. The calculation is performed by multiply the **Entry Number** with **1024** then convert it to hex.


> 6TH QUESTION --> ANS: `43.204.110.203:6666`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/47ac6334-4072-46e0-ba7d-e5be553442f4)


24. Again, previously we already identified the C2 IP and it's port by reviewing the .bat's file content.
25. Finally, we investigated the case!

## IMPORTANT LINKS

```
https://library.mosse-institute.com/articles/2022/05/windows-master-file-table-mft-in-digital-forensics/windows-master-file-table-mft-in-digital-forensics.html
https://andreafortuna.org/2017/07/18/how-to-extract-data-and-timeline-from-master-file-table-on-ntfs-filesystem/
https://github.com/dkovar/analyzeMFT
https://ericzimmerman.github.io/#!index.md
```
