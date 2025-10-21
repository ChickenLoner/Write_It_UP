# [CyberDefenders - HireMe](https://cyberdefenders.org/blueteam-ctf-challenges/hireme/)
Created: 30/04/2024 22:01
Last Updated: 01/05/2024 12:38
* * *
>Category: Endpoint Forensics
>Tags: Disk Forensic, Eric Zimmerman's Tools, FTK Imager, Autopsy, Registry, LECmd, Registry Explorer, RegRipper, AccessData, T1204, T1071, T1003, T1016, T1083, T1082
* * *
Karen is a security professional looking for a new job. A company called "TAAUSAI"  offered her a position and asked her to complete a couple of tasks to prove her technical competency. As a soc analyst Analyze the provided disk image and answer the questions based on your understanding of the cases she was assigned to investigate.

**Tools**:
- [FTK Imager](https://accessdata.com/product-download/ftk-imager-version-4-5)
- [Autopsy](https://www.autopsy.com/download/)
- [RegistryExplorer](https://f001.backblazeb2.com/file/EricZimmermanTools/RegistryExplorer_RECmd.zip)
- [LEcmd](https://f001.backblazeb2.com/file/EricZimmermanTools/LECmd.zip)
- [Regripper](https://github.com/keydet89/RegRipper3.0)
- [OST Viewer](https://www.sysinfotools.com/recovery/ost-file-viewer.php)
* * *
## Questions
> Q1: What is the administrator's username?

Lets open evidence file on FTK Imager
![8c7f031545ace8e5b4f9b4f08a245283.png](../../_resources/8c7f031545ace8e5b4f9b4f08a245283.png)
As you can see that this evidence file have 2 partitions, one is C drive and the other one have RECYCLE.BIN
![b0bd9b8026aba8687411a38976fd896d.png](../../_resources/b0bd9b8026aba8687411a38976fd896d.png)
And the only user we found on this evidence is Karen which should be an admin of this system too
```
Karen
```

> Q2: What is the OS's build number?

![18a3e4735ab457039b8f52f532466e6b.png](../../_resources/18a3e4735ab457039b8f52f532466e6b.png)
Go to `Windows\System32\config`, you will find `SOFTWARE` hive there then export it and open with any tool that can inspect `HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion` which holds an information about SYSTEM INFORMATION
![f554ea035f0c3e31103cf37925ecaee2.png](../../_resources/f554ea035f0c3e31103cf37925ecaee2.png)
```
16299
```

> Q3: What is the hostname of the computer?

In the same directory, Export `SYSTEM` hive so we can parse `HKLM\SYSTEM\ControlSet001\Control\ComputerName\ComputerName` to get hostname
![735a23efe69f3055b99cb3fc90690bf1.png](../../_resources/735a23efe69f3055b99cb3fc90690bf1.png)
```
TOTALLYNOTAHACK
```

> Q4: A messaging application was used to communicate with a fellow Alpaca enthusiest. What is the name of the software?

An answer of this question can be found using registry too, go back to `SOFTWARE` hive then `HKLM\SOFTWARE\Windows\CurrentVersion\App Paths` which holds information about all application paths installed on a system
![b0ae845148dedd94d3cf90d677e3e06f.png](../../_resources/b0ae845148dedd94d3cf90d677e3e06f.png)
You can see that only skype is the messaging application here(outlook is emailing application).
```
Skype
```

> Q5: What is the zip code of the administrator's post?

Windows does not store ZIP code of a user but I found chrome artifacts on this evidence file too which mean that user could save her own zip code in autofill then she doesn't have to keep typing the same information everytime she visits different websites
![7ffef8bb103688103612f1651e2bd941.png](../../_resources/7ffef8bb103688103612f1651e2bd941.png)
Go to `Appdata\Local\Google\Chrome\User Data\Default`, you will find `Web Data` there, export it and use DB Browser for SQLite to open this database file
![7d4d666670d0c36ee4194406fa9617df.png](../../_resources/7d4d666670d0c36ee4194406fa9617df.png)
Query data from `autofill` table, There it is
```
19709
```

> Q6: What are the initials of the person who contacted the admin user from TAAUSAI?

![9f87d4dab73c9d45f1f05ec75d55d134.png](../../_resources/9f87d4dab73c9d45f1f05ec75d55d134.png)
There is an ost(Offline Outlook Data File) file which used to store and synchronize copy of user mailbox information on local system, export it and use any OST File Viewer you have to open it 

You can read about more about this file [here](https://support.microsoft.com/en-us/office/introduction-to-outlook-data-files-pst-and-ost-222eaf92-a995-45d9-bde2-f331f60e2790)
![01694da44ddd00b96d3e1bafae7fd878.png](../../_resources/01694da44ddd00b96d3e1bafae7fd878.png)
I used [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html) free version then go to Inbox to find all inbox mails, there are several mails from Alpaca Activists claiming to recruit Karen to his org and he also wrote his name on recruting mail too 
```
MS
```

> Q7: How much money was TAAUSAI willing to pay upfront?

![8ce150ecbf82267ec74da8f6f1f6cb7f.png](../../_resources/8ce150ecbf82267ec74da8f6f1f6cb7f.png)
Continue reading mail from Alpaca Activists, you will find an answer 
```
150000
```

> Q8: What country is the admin user meeting the hacker group in?

![0e09b88d3ef90c1dd31bf98807eb5c7c.png](../../_resources/0e09b88d3ef90c1dd31bf98807eb5c7c.png)
Alpaca Activists gave Karen location in Latitude and Longtitude, go to https://www.gps-coordinates.net/ and insert both values to find an address
![cfd221b08d1bb24d1a8f3212e17e4f32.png](../../_resources/cfd221b08d1bb24d1a8f3212e17e4f32.png)
Which is in Egypt
```
Egypt
```

> Q9: What is the machine's timezone? (Use the three-letter abbreviation)

Back to `SYSTEM` hive to find an information about timezone in `HKLM\SYSTEM\ControlSet001\Control\TimeZoneInformation`
![1ee10de0bcb047c57ebfa18e6c91c18b.png](../../_resources/1ee10de0bcb047c57ebfa18e6c91c18b.png)
```
UTC
```

> Q10: When was AlpacaCare.docx last accessed?

Alpaca Activists finally sent Karen an attachment but no where to be found on C drive so we have to look for other partition, inside RECYCLE.BIN
![8a9e0eed953cfd3200a775bc3f75358e.png](../../_resources/8a9e0eed953cfd3200a775bc3f75358e.png)
There is it
```
03/17/2019 09:52 PM
```

> Q11: There was a second partition on the drive. What is the letter assigned to it?

Every document files that was opened using Microsoft Office, Windows will create a shortcut file due to Recent File feature that will make user access recent opened document file easier
![3db4a5d8a32191e23b302f0bf889247a.png](../../_resources/3db4a5d8a32191e23b302f0bf889247a.png)
You can export LNK file to analyze it but for me This is already enough, I still can read file path from FTK Imager 
```
A
```

> Q12: What is the answer to the question Company's manager asked Karen?

Go back to OST File Viewer
![76269a5f9d61eeade4ff932cf59ba9eb.png](../../_resources/76269a5f9d61eeade4ff932cf59ba9eb.png)
You can see that there is some challenge that manager gave Karen
![76290aa56fb9824576dda83f081431c7.png](../../_resources/76290aa56fb9824576dda83f081431c7.png)
Which Karen solved it
![a82db271e76ca2a7688b7cc93bfd23b2.png](../../_resources/a82db271e76ca2a7688b7cc93bfd23b2.png)
Since this is a replied mail, you can scroll down a little bit to see the message that was replied
```
TheCardCriesNoMore
```

> Q13: What is the job position offered to Karen? (3 words, 2 spaces in between)

![2cba648c64d58509439a87a40a4863db.png](../../_resources/2cba648c64d58509439a87a40a4863db.png)
When Karen solved this challenge, Manager offered her entry level cyber security analyst
```
cyber security analyst
```

> Q14: When was the admin user password last changed?

Now time to grab `SAM` hive
![e685954fb3ed61d0f62f96f81e410d1b.png](../../_resources/e685954fb3ed61d0f62f96f81e410d1b.png)
go to `SAM\Domains\Account\Users`, you can see the time that Karen changed her password
```
03/21/2019 19:13:09
```

> Q15: What version of Chrome is installed on the machine?

I clicked for hint this time and found that an answer lying in `WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, so i did some [research](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key) and found that most of softwares installed on Windows, it will also created uninstaller and keep file path and properties inside this registry
![8d7788e09a5eb6592fb1c8a80142232b.png](../../_resources/8d7788e09a5eb6592fb1c8a80142232b.png)
```
72.0.3626.121
```

> Q16: What is the HostUrl of Skype?

![3c121ab6035127cbabe5f8c582ab5292.png](../../_resources/3c121ab6035127cbabe5f8c582ab5292.png)
An answer lying on alternate data stream (ADS) of Skype executable file
Here are resources you can read to understand what is ADS 
- https://insights.sei.cmu.edu/blog/using-alternate-data-streams-in-the-collection-and-exfiltration-of-data/
- https://www.forensicfocus.com/articles/dissecting-ntfs-hidden-streams/

To put it simply, it used to store meta-information about the file

Check `Zone.Identifier`, you will see HostURL there
```
https://download.skype.com/s4l/download/win/Skype-8.41.0.54.exe
```

> Q17: What is the domain name of the website Karen browsed on Alpaca care that the file AlpacaCare.docx is based on?

![ef9fd370446974d6481293f343afab5f.png](../../_resources/ef9fd370446974d6481293f343afab5f.png)
Lets download document file and examine it
![5b2887eb56083a5f53a7b30b8884f9d8.png](../../_resources/5b2887eb56083a5f53a7b30b8884f9d8.png)
I do not want to open a file so I have to use another way to get a hyperlink, luckily there is a way 
By decompress DOCX file and open `document.xml` which store document properties and contents of this document
![7f9ef4100c4e20e8fecf845c9855aca1.png](../../_resources/7f9ef4100c4e20e8fecf845c9855aca1.png)
I copied content and used CyberChef to beatufiy XML for me which you can see that hyperlink is also there
```
palominoalpacafarm.com
```

![a8721e5526a861af1e2488049277486c.png](../../_resources/a8721e5526a861af1e2488049277486c.png)
* * *
