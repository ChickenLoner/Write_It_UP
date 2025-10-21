# [LetsDefend - PDFURI](https://app.letsdefend.io/challenge/pdfuri)
Created: 11/03/2024 16:00
Last Updated: 22/11/2024 18:55
* * *
<div align=center>

**PDFURI**
![5b218efbcc2ec8abbf69baa6b26696d2.png](/resources/5b218efbcc2ec8abbf69baa6b26696d2.png)
</div>
Our friend "Dee" was looking for a job in Tanta, but it seems she was hacked by one of the malicious websites, so can you examine her hard drive and find some evidence?

**File Location**: C:\Users\LetsDefend\Desktop\ChallengeFile\PDFURI.7z

**WSL Username**: letsdefend
**WSL Password**: letsdefend

* * *
## Start Investigation

As soon as the machine is up, I extracted the 7zip file right away and Iook like I got an image to work with
![70dac945fe01d067b51ad66c6a068c33.png](/resources/70dac945fe01d067b51ad66c6a068c33.png)

Next I opened FTK Imager and add an image as the evidence 
![98fa8391083b165f642e1fcb5bcceb5b.png](/resources/98fa8391083b165f642e1fcb5bcceb5b.png)

After scrolling for a while, I found that there is a user `Work` that is not the default user and within the Downloads folder, there is a pdf document file there
![830a0c658303edef848bcb7aa786cb68.png](/resources/830a0c658303edef848bcb7aa786cb68.png)
I exported both hash and file then loaded the file to PDFStreamDumper
![4298e8a8125baafe14c223b6fe2e5405.png](/resources/4298e8a8125baafe14c223b6fe2e5405.png)
This is definitely a suspicious document or even malicious according to this challenge, It will run a powershell commands once it opened
![551c4088056a75e83eb27a93fc014fcd.png](/resources/551c4088056a75e83eb27a93fc014fcd.png)
And After executing this command, a new registry entry with the name **s3cr3tF1o0w** and the specified value will be created under `HKEY_CURRENT_USER\Environment`.
![afb5e4a94cbb5d0cf67ba815452eec17.png](/resources/afb5e4a94cbb5d0cf67ba815452eec17.png)

Next I went on `\Users\Work\AppData\Local\Microsoft\Edge\User Data` to find Microsoft Edge Browser Artifacts and export them as mush as needed
![8630f16285452c10e46e080d0f6a2318.png](/resources/8630f16285452c10e46e080d0f6a2318.png)

I opened them using DB Browser for SQLite

On `Login Data`, I've got an email on the user.
![c3d26b46175a52f7c6978541b7577f41.png](/resources/c3d26b46175a52f7c6978541b7577f41.png)
and it also could be found on `Web Data`
![cecdcd90d8986f6ba74465162748a61c.png](/resources/cecdcd90d8986f6ba74465162748a61c.png)
On `History`, I found the domain that the malicious document was hosted
![6ca92cb1949334c2c4269848b311d124.png](/resources/6ca92cb1949334c2c4269848b311d124.png)

And lastly to answer the final question, I went to find SAM registry hive then loaded to Registry Viewer
![cc42745ef0d791b86c7b467ec8622e56.png](/resources/cc42745ef0d791b86c7b467ec8622e56.png)
Which I've found that there is no `Work` user anymore but instead `Sl3awy` were there so the user changed the username from `Work` to `Sl3awy`.
![2dd57901374f0e36083e5d1d71b29958.png](/resources/2dd57901374f0e36083e5d1d71b29958.png)
* * *
>What is the MD5 hash of the malicious document?
```
9cd09e5cd94e83ed4824f652829b0b52
```

>What is the domain from which the document was downloaded?
```
http://www.freejobin-kafr-elshiekh.org/
```

>What is the email address of the victim?
```
Sl3awy@gmail.com
```

>What is the command that is executed by the malicious document?
```
powershell -EncodedCommand TmV3LUl0ZW1Qcm9wZXJ0eSAtUGF0aCAiSEtDVTpcRW52aXJvbm1lbnQiIC1OYW1lICJzM2NyM3RGMW8wdyIgLVZhbHVlICJTMHJyeUJ1N0lOM2VkVGgxc00wTjNZIiAgLVByb3BlcnR5VHlwZSAiU3RyaW5nIg==
```

>Seems the PC username changed to another one. Can you identify the new Username?
```
Sl3awy
```
* * *
## Summary
On this challenge, We used FTK Imager to investigate Windows disk image to find the culprit of the incident which is malicious PDF file that will execute PowerShell command.

<div align=center>

![7b7fd6d5318c61ff02cc325ae46162fa.png](/resources/7b7fd6d5318c61ff02cc325ae46162fa.png)
https://app.letsdefend.io/my-rewards/detail/f470e74ccdcc450e86cb16287b58c943
</div>

* * *