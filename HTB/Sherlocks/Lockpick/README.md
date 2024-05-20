# Lockpick

> Write-up author: jon-brandy

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/cf34454d-f333-4a0c-aa92-cb0d63b1cc1d)


## Lessons Learned:
- Conducting static malware analysis using ghidra.
- Reviewing C code-based Malware.
- Developing a python script to reverse the encryption logic.
- Developing a python script to parse json file.

## SCENARIO:

<p align="justify">
  Forela needs your help! A whole portion of our UNIX servers have been hit with what we think is ransomware. We are refusing to pay the attackers and need you to find a way to recover the files provided. Warning This is a warning that this Sherlock includes software that is going to interact with your computer and files. This software has been intentionally included for educational purposes and is NOT intended to be executed or used otherwise. Always handle such files in isolated, controlled, and secure environments. One the Sherlock zip has been unzipped, you will find a DANGER.txt file. Please read this to proceed.
</p>

## STEPS:
1. In this challenge we're given 15 files.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/066c6ce2-ab48-4db5-93cf-68369107fc2e)


> 1ST QUESTION --> ANS: bhUlIshutrea98liOp

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/0dadd44b-893c-4160-8feb-16f0f41bc8cc)


2. Reviewing the DANGER.txt file, we can conclude that the malware is inside the .zip file. This .txt file gives several warning upon analyzing the software and gave us the password for the zip file.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/555669bc-772e-4908-9b73-28adcfe8dd26)


3. Unzipping it, we found the malware named --> `bescrypt3.2`.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/0d0ec4d9-84c6-45eb-9043-a62f87602db1)


4. To identify the encryption key used, I decompiled the binary using ghidra.
5. At the main() function, we can see a function named process_directory() is called, it have 2 parameters and both are strings.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/cc293ba0-462d-4612-a9d1-74965e62666b)


6. Then analyzig the process_directory() function, we can tell that the second parameter is used again by another function named encrypt_file().

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/392168fd-8d31-4173-942e-10762ef9f502)


7. Reviewing the encrypt_file() code, it's clear that param2 is used as a key for XOR operation.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/bdca4868-b1fc-4331-804a-b5acb5277bd2)


8. Hence it concludes that --> `bhUlIshutrea98liOp` is the key.

> 2ND QUESTION --> ANS: Walden Bevans

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/037de062-cb14-49b6-acec-f329f522ba59)


9. To get his firstname and lastname, we just need to check the sql file of forela.
10. But sadly it's already encrypted by the malware.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/f967784a-3ad0-4b2f-aeaa-fe581eae2e33)


11. Now we need to do malware reversing.
12. Upon reviewing all the functions available in the binary, seems our interest should be the `encrypt_file()` function.
13. The logic for the encryption lies at the XOR operation.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/4fea2b1e-9bcd-4a6a-bcd8-a10e685ae734)


14. Hence, we just need to re-write the code focusing on this function. Things to note in XOR logic, if we XOR the encrypted data with the same key it used to encrypt, we shall retrieved the plaintext.
15. Remembering we already identified the key before, hence the rest should be just do the same operation again.
16. To decrypt the encrypted file I used python script.

> THE SCRIPT

```py
from pwn import *
import os
os.system('clear')

# function to grab all the encrypted files
def grab_encrypted(dir):
    files=[]
    for filename in os.listdir(dir): # enumerate every files inside the specified path
        if filename.endswith('.24bes'): # if it ends with .24bes, add it to our list.
            files.append(filename)
    return files

# function to decrypt the encrypted files.
def decrypt_files(path, file, output_directory):
    key = 'bhUlIshutrea98liOp' # param2
    key_length = len(key)

    output_path = os.path.join(output_directory, file[:-6]) # the slicing is to remove the .24bes name for the decrypted files.

    current_path = os.path.join(path, file) # current path

    with open(current_path, 'rb') as file:
        data_file = file.read()# read all the files inside the dir.
    
    file_content = bytearray()
    for i,y in enumerate(data_file):
        file_content.append(y ^ ord(key[i % key_length])) # DECRYPTING
    
    with open(output_path, 'wb') as f:
        f.write(file_content) # write the decrypted content to the output path

path = './' # current path
files = grab_encrypted(path) # grab all the encrypted files
output_directory = os.path.join(path, 'decrypted-files')
os.makedirs(output_directory) # create the output-dir

# decrypt each files
for i, file in enumerate(files, start=1):
    decrypt_files(path, file, output_directory)
    log.progress(f'IS DECRYPTING THE FILES')

log.success(f'DECRYPTION DONE')
```

> RESULT

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/b2e6e1e7-5545-4065-a42f-e8aa10d8b331)


17. Awesome! Now to identify the firstname and lastname of this --> `wbevansn1@cocolog-nifty.com` applicant, we can review the `forela_uk_applicants.sql` file.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/c5511b63-eefe-4e07-8b1d-8c7a47e92e36)


> 3RD QUESTION --> ANS: E8-16-DF-E7-52-48, 1316262

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/f4027aec-1470-49fa-ac6d-375cc0b042b9)


18. Next, to identify MAC Address and serial number of the laptop assigned to Hart Manifould, we should review the `it_assets.xml` file.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/e52edee1-362e-4ae7-bf9d-e8942c4ca729)

> 4TH QUESTION --> ANS: `bes24@protonmail.com`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/e7d29a43-4921-4291-98e2-f07e98477f1a)


19. Previously, upon reviewing the notes and the malware's logic, we can identified the attacker's mail. The attacker told Forela to discuss payment by contacting his email --> bes24@protonmail.com.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/ad3d8190-d1f6-46ab-a066-a81ef00fba79)


> 5TH QUESTION --> ANS: `fmosedale17a@bizjournals.com, 142303.1996053929628411706675436`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/ed700e63-c803-4c8e-a81b-79c4267a25bf)


20. The city of London Police told us suspiciouns of some insider trading taking part within Forela trading organization.
21. Now we're tasked to identify the email address and the profit percentage of the person which has the highest profit percentage.
22. Noticed, there is around 2521 trading datas inside the .json file.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/af38f294-300a-498c-bc49-de675c07c15b)


23. Hence, a short script should be involved to sort the data shown descending by the profit percentage.

> GET MAX SCRIPT

```py
from pwn import *
import os
import json

# os.system('clear')

filename = './trading-firebase_bkup.json'
with open(filename, 'r') as f:
    content = json.load(f) # read the json data

# get the person with the highest profit percentage
highest_profit = max(content.values(), key=lambda x: x['profit_percentage'])

log.success(f"EMAIL ADDRESS: {highest_profit['email']}")
log.success(f"PROFIT PERCENTAGE: {highest_profit['profit_percentage']}")
```

> RESULT

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/0b660af0-6cf9-4418-88cc-00fa51dabcbb)


![image](https://github.com/jon-brandy/hackthebox/assets/70703371/212eda02-61f4-43f1-b7f9-64c77fd5613e)


> 6TH QUESTION --> ANS: `8.254.104.208`

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/af68e25c-17ba-4a73-abaf-31200839d5f0)


24. To identify the IP address of **Karylin O'Hederscroll** simply review the `sales_forecast.xlsx` file.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/9685c296-14e6-47ed-931b-a97650224b60)


> 7TH QUESTION --> ANS: .ppt

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/ae8ecd3d-52bd-49f0-aa51-e0e7a7d5d112)


25. Again, upon reviewing the malware's code, we can identified that `.ppt` file is not targeted by the malware.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/9e922955-2e46-4cac-8004-a5e534225e05)


> 8TH QUESTION --> ANS: f3894af4f1ffa42b3a379dddba384405

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/6b4491f3-dd96-4e7c-9332-5e2cf76fc37b)


26. Executing `md5sum` command at the terminal (for linux) shall shows us the checksum.

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/e402c3e1-5148-401a-961d-6e55471fd553)


> 9TH QUESTION --> ANS: 87baa3a12068c471c3320b7f41235669

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/a7f1edf3-f4bc-4d08-8b61-2359d122dd19)


![image](https://github.com/jon-brandy/hackthebox/assets/70703371/1a2f1f3d-888a-4c43-93ca-2bef47d80f3a)


> 10TH QUESTION --> ANS: c3f05980d9bd945446f8a21bafdbf4e7

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/c715808a-aa2b-4a9f-aac4-68253139e943)

![image](https://github.com/jon-brandy/hackthebox/assets/70703371/61d06c66-e3ff-4cba-9771-c556a24a0181)


27. Great! We've investigated the case.

## IMPORANT LINKS

```
https://www.loginradius.com/blog/engineering/how-does-bitwise-xor-work/
```
