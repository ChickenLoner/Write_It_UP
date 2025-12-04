# [CyberDefenders - CorporateSecrets](https://cyberdefenders.org/blueteam-ctf-challenges/corporatesecrets/)
## Table of Contents

- [Scenario](#scenario)
- [Questions](#questions)

* * *
## Scenario

A windows forensics challenge prepared by Champlain College Digital Forensics Association for their yearly CTF.

Windows Image Forensics Case created By AccessData® FTK® Imager 4.2.1.4 

Acquired using: ADI4.2.1.4  

--------------------------------------------------------------
Information for F:\DFA_Windows\DFA_SP2020_Windows:

Physical Evidentiary Item (Source) Information:
- [Device Info]  
   - Source Type: Physical
- [Drive Geometry]  
   - Cylinders: 6,527  
   - Heads: 255  
   - Sectors per Track: 63  
   - Bytes per Sector: 512  
   - Sector Count: 104,857,600

[Physical Drive Information]  
- Drive Interface Type: lsilogic [Image]  
- Image Type: VMWare Virtual Disk  
- Source data size: 51200 MB  
- Sector count:    104857600
 
[Computed Hashes]  
- MD5 checksum:    e5fe043aa84454237438cdb2b78d08b3  
- SHA1 checksum:   ada83cd44e294ab840fa7acd77cf77e81c3431b3
 
Image Information: 
 - Segment list:  
   - F:\DFA_Windows\DFA_SP2020_Windows.E01  
   - F:\DFA_Windows\DFA_SP2020_Windows.E02  
   - F:\DFA_Windows\DFA_SP2020_Windows.E03  
   - F:\DFA_Windows\DFA_SP2020_Windows.E04  
   - F:\DFA_Windows\DFA_SP2020_Windows.E05  
   - F:\DFA_Windows\DFA_SP2020_Windows.E06  
   - F:\DFA_Windows\DFA_SP2020_Windows.E07  
   - F:\DFA_Windows\DFA_SP2020_Windows.E08  
   - F:\DFA_Windows\DFA_SP2020_Windows.E09

Your objective as a soc analyst is to analyze the image and answer the question.

**Category**: Endpoint Forensics

**Tools**: 
- [FTK Imager](https://accessdata.com/product-download/ftk-imager-version-4-5)
- [Registry Explorer](https://ericzimmerman.github.io/#!index.md)
- [RegRipper](https://github.com/keydet89/RegRipper3.0)
- [HxD](https://mh-nexus.de/en/downloads.php?product=HxD20)
- [DB Browser for SQLite](https://sqlitebrowser.org/)
- [HindSight](https://github.com/obsidianforensics/hindsight/releases)
- [Event Log Explorer](https://eventlogxp.com/)
- [MFTDump](https://sectechno.com/mftdump-tool-to-parse-mft-files/)
* * *
## Questions
> Q1: What is the current build number on the system?

![f9dcf7973bd31f1806764b8ba8080be8.png](/resources/f9dcf7973bd31f1806764b8ba8080be8.png)

We can get system information from registry hive that located in `Windows\System32\config`, export all the hive so we don't need to come back later when needed

![bf73eecf94b73dfd40fd93c062b41611.png](/resources/bf73eecf94b73dfd40fd93c062b41611.png)

Use RegRipper or RegistryExplorer then to go `SOFTWARE\Microsoft\Windows NT\CurrentVersion` which hold this information
```
16299
```

> Q2: How many users are there?

![72696cc96241ff08da3fd570c2892c9d.png](/resources/72696cc96241ff08da3fd570c2892c9d.png)

A registry key that hold all SID and profile path of all users inside a system is `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
Which we can see that there are 6 users on this system

Alternatively, you can see locate to `Users` folder and count all folders there
```
6
```

> Q3: What is the CRC64 hash of the file "fruit_apricot.jpg"?

![4e0599321ab384182e1ce8fd5d66bfb1.png](/resources/4e0599321ab384182e1ce8fd5d66bfb1.png)

This image is located in `hansel.apricot\Pictures\Saved Picture`

![433295b3e70ec819cf4f74cf0a2011ef.png](/resources/433295b3e70ec819cf4f74cf0a2011ef.png)

export it and we can use 7z to calculate CRC34 hash for us with this command `7z j -scrcCRC64 fruit_apricot.jpg` 
- h parameter telling 7z that we're using this program to calculate filehash while we need to pass an algorithm as an argument after then and lastly is the file we will calculate filehash
```
ED865AA6DFD756BF
```

> Q4: What is the logical size of the file "strawberry.jpg" in bytes?

![5c6b6a6224804a65ce8bfaf3fe9960f4.png](/resources/5c6b6a6224804a65ce8bfaf3fe9960f4.png)

This file located inside `suzy.strawberry\Pictures`

![7a9bc7957d7cd389bfdcc743b3dab9e0.png](/resources/7a9bc7957d7cd389bfdcc743b3dab9e0.png)

Export it and we can just use our cmd, powershell and bash to display logical file size 
```
72448
```

> Q5: What is the processor architecture of the system? (one word)

![b592114491192f8cad098544093dde1f.png](/resources/b592114491192f8cad098544093dde1f.png)

I asked ChatGPT for this question and it told us which registry key we need to get `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

![96a56ad321c3f693fd5a6793f72f4148.png](/resources/96a56ad321c3f693fd5a6793f72f4148.png)

```
AMD64
```

> Q6: Which user has a photo of a dog in their recycling bin?

![4fdda8a0f42200a23b9fc4e6c55a9e37.png](/resources/4fdda8a0f42200a23b9fc4e6c55a9e37.png)

Go to recycle bin and searching through all image files which the only photo of a dog is this image

![72696cc96241ff08da3fd570c2892c9d.png](/resources/72696cc96241ff08da3fd570c2892c9d.png)

This image belong to hansel
```
hansel.apricot
```

> Q7: What type of file is "vegetable"? Provide the extension without a dot.

![a3f79fe7ff2585dfa7723010adf31d2b.png](/resources/a3f79fe7ff2585dfa7723010adf31d2b.png)

This file was located in `miriam.grapes\Pictures`

![5f657e22c71393477f9983a9804a50c4.png](/resources/5f657e22c71393477f9983a9804a50c4.png)

Export it and use `file` to detect it signature which turn out it's a 7z file

![da2769479405fbe175f64498bd04e273.png](/resources/da2769479405fbe175f64498bd04e273.png)

![0d36952f62ac29353d0f057063e5f765.png](/resources/0d36952f62ac29353d0f057063e5f765.png)

The other way we can solve this question without exporting this file is to look at magic number which totally matched 7z file format (https://en.wikipedia.org/wiki/List_of_file_signatures)
```
7z
```

> Q8: What type of girls does Miriam Grapes design phones for (Target audience)?

![4b7469c802e45dfe334f9bc84f2f5f7f.png](/resources/4b7469c802e45dfe334f9bc84f2f5f7f.png)

Inside Miriam's Pictures folder, we can see other image file (`thisisMyDesign.jpg`) which is an image of her design for new phone

![6ba058a84511dbf90802dcf94fd30f19.png](/resources/6ba058a84511dbf90802dcf94fd30f19.png)

When trying to design something for target audience, we need to know our target audience first which research is required which means browser history has riched information when it comes to researching something online

Miriam doesn't have Google folder inside App Data but Mozilla folder is there which mean she's using FireFox as her main browser and we need to export `places.sqlite` from FireFox profiles folder

![4a4c38ed56614035d6934958ef654a85.png](/resources/4a4c38ed56614035d6934958ef654a85.png)

Using MZHistoryView or BrowserHistoryView from Nirsoft, we can see that the target audience of this phone is VSCO girl
```
VSCO
```

> Q9: What is the name of the device?

This `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName` key hold an information about Computer Name

![7ee1a1dbef093dba37549bb5c9631fc2.png](/resources/7ee1a1dbef093dba37549bb5c9631fc2.png)

```
DESKTOP-3A4NLVQ
```

> Q10: What is the SID of the machine?

![c49f4572064163eeacebbbd64991cb14.png](/resources/c49f4572064163eeacebbbd64991cb14.png)

Looking at these bunch of series of number, last 4 digits are SID of each user and the rest is SID of this machine
```
S-1-5-21-2446097003-76624807-2828106174
```

> Q11: How many web browsers are present?

![e36316980b545d705970d2bad0a1fad1.png](/resources/e36316980b545d705970d2bad0a1fad1.png)

I was too lazy to search for every AppData folders so I went to Software hive and find this `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths` registry key that hold path of all (mostly) installed software on this system

We have Chrome, Firefox and Interet Explorer which is obviously came with Edge but look like 4 is not the right answer

![497aa2dc94be2d11c6bc1e799aefcca7.png](/resources/497aa2dc94be2d11c6bc1e799aefcca7.png)

I had to choice but to search for other browser which I found Tor browser shortcut which have weird target as `firefox.exe`

![c15d510cb17d0169253e093c9b441279.png](/resources/c15d510cb17d0169253e093c9b441279.png)

But in the end, it's a Tor Browser so this system has 5 browsers
```
5
```

> Q12: How many super secret CEO plans does Tim have? (Dr. Doofenshmirtz Type Beat)

![9a90871e6254bff6ac83951718942a46.png](/resources/9a90871e6254bff6ac83951718942a46.png)

Navigate to tim folder then I located this `secret.odt` file inside Documents folder

![a39baca596bffd896662d71b01440fdc.png](/resources/a39baca596bffd896662d71b01440fdc.png)

[What is this file?,](https://www.howtogeek.com/765461/what-is-an-odt-file-and-how-do-you-open-one/) its a file generated by LibreOffice function like doc for Microsoft Word

![de37ddc2ae4bf45669da53f1361b7a43.png](/resources/de37ddc2ae4bf45669da53f1361b7a43.png)

On App Paths registry key, It confirmed that LibreOffice was installed on this system

![20218c029705d445d45972fc29f320c2.png](/resources/20218c029705d445d45972fc29f320c2.png)

You can export and open it with LibreOffice and the inside of this file holds 4 objectives of Tim 
```
4
```

> Q13: Which employee does Tim plan to fire? (He's Dead, Tim. Enter the full name - two words - space separated)

![8ebcb3083c05f0fd194696db364c6764.png](/resources/8ebcb3083c05f0fd194696db364c6764.png)

We know from Tim's secret file that he want to fire Jim
```
Jim Tomato
```

> Q14: What was the last used username? (I didn't start this conversation, but I'm ending it!)

![33bd87215df2e18bc7bbc324c5f6e9de.png](/resources/33bd87215df2e18bc7bbc324c5f6e9de.png)

I asked ChatGPT for last logged on username 

![ea0770091435615ae0612da83608fb2b.png](/resources/ea0770091435615ae0612da83608fb2b.png)

When to this key but turn out this is not the right answer so I did some more research on my own

![12b31691720b5dc39810450f410b298e.png](/resources/12b31691720b5dc39810450f410b298e.png)

And went to this `SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon` key which holds the answer of this question as it hold "LastUsedUsername" not "Last Logged In User" as i thought
```
jim.tomato
```

> Q15: What was the role of the employee Tim was flirting with?

![a2bfd6e47e1ed5376cc0bd4bb9ca0ae5.png](/resources/a2bfd6e47e1ed5376cc0bd4bb9ca0ae5.png)

I tried to search through Tim's folders which I found that Chrome and Firefox history might return something for me so I exported both history file (`places.sqlite`,`History`)

![9fd56f9020fde9cc7a3536ac0b4c3bbc.png](/resources/9fd56f9020fde9cc7a3536ac0b4c3bbc.png)

![ff303702ab616ffdbe6f14881859a98a.png](/resources/ff303702ab616ffdbe6f14881859a98a.png)

Use BrowserHistoryView from Nirsoft to import both files then display browser of both browsers all at once

![c0b2b31e9569e7af55286606f7e7cca3.png](/resources/c0b2b31e9569e7af55286606f7e7cca3.png)

Tim did search Google about it so now we know that secretary is his target

And we also know that he also want to fire some stinky employee based on this browser history
```
secretary
```

> Q16: What is the SID of the user "suzy.strawberry"?

![72696cc96241ff08da3fd570c2892c9d.png](/resources/72696cc96241ff08da3fd570c2892c9d.png)

Back to ProfileList registry key, user suzy's SID is 1004
```
1004
```

> Q17: List the file path for the install location of the Tor Browser.

![4485a19cfd4d1cdf7c5772214e22cf4c.png](/resources/4485a19cfd4d1cdf7c5772214e22cf4c.png)

We all know it was installed in `\Program1` as the shortcut file guided us through 
```
C:\Program1
```

> Q18: What was the URL for the Youtube video watched by Jim?

![e1797bc416f8ab0db913d61971c2dd1f.png](/resources/e1797bc416f8ab0db913d61971c2dd1f.png)

Jim has Chrome installed so lets export history file

![2861beaebb5a0af78d515523a1ad713e.png](/resources/2861beaebb5a0af78d515523a1ad713e.png)

And using our friend from Nirsoft to display them, only Youtube url here is "How to Hack into a Computer" video
```
https://www.youtube.com/watch?v=Y-CsIqTFEyY
```

> Q19: Which user installed LibreCAD on the system?

![43803126452bb57eeecf69fd8eefde0e.png](/resources/43803126452bb57eeecf69fd8eefde0e.png)

It has to be installer software on any user folder which I found it on Miriam's Downloads folder
```
miriam.grapes
```

> Q20: How many times "admin" logged into the system?

We can answer this by using Event log or SAM hive and I chose SAM

![5119442e1e21fb5dc44d392bee5a8832.png](/resources/5119442e1e21fb5dc44d392bee5a8832.png)

Go to `SAM\Domains\Account\Users`, we can see that it stores total login count of all users and admin user logged into system 10 times
```
10
```

> Q21: What is the name of the DHCP domain the device was connected to?

![b931814aac902c56b29ff7975fc8a9f7.png](/resources/b931814aac902c56b29ff7975fc8a9f7.png)

I asked my friend ChatGPT for this question which tell me to get this `SYSTEM\ControlSet001\Services\Tcpip\Parameters` key

![bb9c00db74500c409383738ec207afc6.png](/resources/bb9c00db74500c409383738ec207afc6.png)

```
fruitinc.xyz
```

> Q22: What time did Tim download his background image? (Oh Boy 3AM . Answer in MM/DD/YYYY HH:MM format (UTC).)

![9e1d2b15b74bf0eff94531325afd5c4c.png](/resources/9e1d2b15b74bf0eff94531325afd5c4c.png)

I asked ChatGPT that if there is a registry key that store a path to background image on Windows which there is one in NTUSER.DAT hive

![91df9f608e5a89a3c221e87d50f216f9.png](/resources/91df9f608e5a89a3c221e87d50f216f9.png)

![dc43531e5f43547c3abead87a13de09b.png](/resources/dc43531e5f43547c3abead87a13de09b.png)

Once we got path to this file, we can navigate to this folder directly

![01e7846588a919358280c87d2a57895a.png](/resources/01e7846588a919358280c87d2a57895a.png)

We don't need to use export and use exiftool to analyze this file for us but Date Modified display on FTK Image is enough to answer this question
```
04/05/2020 03:49
```

> Q23: How many times did Jim launch the Tor Browser?

![6a84171d8823974066cc241bd5305056.png](/resources/6a84171d8823974066cc241bd5305056.png)

We know that this Tor Browser executable was renamed to `firefox.exe`

![428363c2792aed4de0040f67a934a257.png](/resources/428363c2792aed4de0040f67a934a257.png)

Which help of TryHackMe Windows Forensic room ([Here this the write-up](https://medium.com/@jcm3/windows-forensics-1-tryhackme-walkthrough-1aa28d562e30))

![c0e112b9ebf1e79504cc7d956854c182.png](/resources/c0e112b9ebf1e79504cc7d956854c182.png)

We know where to look for (`Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\`)

![c9bed38ecef8a1a9b340c05bca587346.png](/resources/c9bed38ecef8a1a9b340c05bca587346.png)

Now its time to find through all GUID to find which one is the right one

![5c7c410b4d508783baacce428ce91be5.png](/resources/5c7c410b4d508783baacce428ce91be5.png)

And the only registry key that count `firefox.exe` is this GUID which was executed Tor 2 times
```
2
```

> Q24: There is a png photo of an iPhone in Grapes's files. Find it and provide the SHA-1 hash.

![51c2e50d958de7ac7103e693aeddc1d0.png](/resources/51c2e50d958de7ac7103e693aeddc1d0.png)

I didn't find any png file but I found this image file on Grapes's Downloads folder and FTK image refused to display this image to me

![df075c16f92d8aabad6d805b2b5693a6.png](/resources/df075c16f92d8aabad6d805b2b5693a6.png)

![bf20945cd4dbc8a25489507728e669b1.png](/resources/bf20945cd4dbc8a25489507728e669b1.png)

But after checking [magic number](https://en.wikipedia.org/wiki/List_of_file_signatures) of this file, turn out it's not a legitimate jpeg file which could be use to hide png file inside of it 

![81b12020159a4ec4deba652d9ddc635d.png](/resources/81b12020159a4ec4deba652d9ddc635d.png)

After disappointing from steghide now binwalk is confirming the existence of this PNG file (`binwalk samplePhone.jpg`)

![4651236ee1989c0ac36ae93a490ccdfb.png](/resources/4651236ee1989c0ac36ae93a490ccdfb.png)

Now use binwalk with --dd to extract any files inside this image
`binwalk  --dd=".*" samplePhone.jpg` 
Then use sha1sum to calculate sha1 hash of this png file
`sha1sum _samplePhone.jpg.extracted/174A`

```
537fe19a560ba3578d2f9095dc2f591489ff2cde
```

> Q25: When was the last time a docx file was opened on the device? (An apple a day keeps the docx away. Answer in UTC, YYYY-MM-DD HH:MM:SS)

![fc4696984736b166f34b480c2797baee.png](/resources/fc4696984736b166f34b480c2797baee.png)

My friend told me that RecentDocs registry key could be used for this but we need to get all NTUSER.DAT hives available on this system
 
I found only 4 users have `NTUSER.DAT` hive which are
- admin
- jim.tomato
- miriam.graps
- tim.apple

So lets grab all of them and Check out each `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` keys

![d2bef19588635fb2d5ea6d00b206994c.png](/resources/d2bef19588635fb2d5ea6d00b206994c.png)

admin didn't open any docx file

![93fe79f065c0f6ea3d5211b33615ee33.png](/resources/93fe79f065c0f6ea3d5211b33615ee33.png)

on the other hand, Jim opened 1 docx file

![787a6beb447d5fb093d7fb811377c5ef.png](/resources/787a6beb447d5fb093d7fb811377c5ef.png)

![457aa0adc1735b77b52d3e58f6669381.png](/resources/457aa0adc1735b77b52d3e58f6669381.png)

while Tim and Miriam didn't open any docx file neither

So we can use timestamp from `Document1.docx` that was opened by Jim to answer this question
```
2020-04-11 23:23:36
```

> Q26: How many entries does the MFT of the filesystem have?

To solve this question, we need to use `mftdump.exe` which can be downloaded from
https://web.archive.org/web/20190705161925/http://malware-hunters.net/all-downloads 

Its archive url from wayback machine because site was downed at the time I went to download this file But don't worry, We can still download this tool via Archive url 

![3637a489a74bd09a1af7b9473e7c4597.png](/resources/3637a489a74bd09a1af7b9473e7c4597.png)

![dd6c22fbde2d7e38692c17b66d667616.png](/resources/dd6c22fbde2d7e38692c17b66d667616.png)

Export `$MFT` from root folder

![3c3f11f5f976f5e4037c80f3368e88ad.png](/resources/3c3f11f5f976f5e4037c80f3368e88ad.png)

Use it to parse Master File Record file directly (`mftdump.exe $MFT`) and while processing it will tell us how many file records on this MFT file 
```
219904
```

> Q27: Tim wanted to fire an employee because they were ......?(Be careful what you wish for)

![60e35ac1664dc662076a011d0f5f849f.png](/resources/60e35ac1664dc662076a011d0f5f849f.png)

In question 15, we know that he wanted to kick out stinky employee based on his browser history
```
stinky
```

> Q28: What cloud service was a Startup item for the user admin?

Grab admin's `NTUSER.DAT` hive then go to `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` key 

![b505988a075b0a5466194ddf3bbd81ce.png](/resources/b505988a075b0a5466194ddf3bbd81ce.png)

Only 1 service was stored in this key which is OneDrive, a cloud service from Microsoft
```
OneDrive
```

> Q29: Which Firefox prefetch file has the most runtimes? (Flag format is <filename/#oftimesrun>)

![1b9ff986ffa9cd7e80d01f1532b47199.png](/resources/1b9ff986ffa9cd7e80d01f1532b47199.png)

Export Prefetch folder then use PECmd from EZ tools to parse all Prefetch files

![bcaa89fd6cb6328c5b2e116302a5981d.png](/resources/bcaa89fd6cb6328c5b2e116302a5981d.png)

Use this command `PECmd.exe -d Prefetch --csv pf.csv` to process Prefetch folder and files then we got 2 csv files inside a folder we provided on this command

![de79ee9ce91205f69d23750a0a9f6b50.png](/resources/de79ee9ce91205f69d23750a0a9f6b50.png)

Ignore Timeline file but open the larger file on Timeline Explorer 

![abae63f36aedf57b161f8bab16cfe159.png](/resources/abae63f36aedf57b161f8bab16cfe159.png)

We can see that this firefox prefetch file has the most run count among it peers 
```
FIREFOX.EXE-A606B53C.pf/21
```

> Q30: What was the last IP address the machine was connected to?

![de885c7af2f563c9ceb4a873d2c73e53.png](/resources/de885c7af2f563c9ceb4a873d2c73e53.png)

I was going to go to Event Log to search for this but I decided to take a hint and it tell me to go back to this registry key `SYSTEM\ControlSet001\Services\Tcpip\Parameter\Interfaces`
An answer of this question is the Dhcp IP Address

![334e9970461a188afbcbfed323ddb5b7.png](/resources/334e9970461a188afbcbfed323ddb5b7.png)

Which doesn't make sense to me at all, to be honest if we're really want to know the last IP address we should dig into Event Log but it is what it is
```
192.168.2.242
```

> Q31: Which user had the most items pinned to their taskbar?

![ab59afbf5361831d3803f984b68a1bf2.png](/resources/ab59afbf5361831d3803f984b68a1bf2.png)

I did some research on this question about which registry key I should look at when it comes to taskbar and the [most upvoted answer of this question](https://superuser.com/questions/171096/where-is-the-list-of-pinned-start-menu-and-taskbar-items-stored-in-windows-7) tell me that I didn't need to dig into any register key, I just need to go to each user TaskBar folder which is located under AppData folder
`Users\<username>\Appdata\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar`

![08503ae22fc892ba52cc41b5070d8323.png](/resources/08503ae22fc892ba52cc41b5070d8323.png)
admin user has 2 shortcuts

![727d8ea85557689c6a17a5ccd41e1523.png](/resources/727d8ea85557689c6a17a5ccd41e1523.png)

![963ae4afeed44ca7c13940efcfe0609f.png](/resources/963ae4afeed44ca7c13940efcfe0609f.png)

![ab11437f8db5a71c7f5af987a0df5b48.png](/resources/ab11437f8db5a71c7f5af987a0df5b48.png)

![64d26b98a9e8dcce93c35218337a87d2.png](/resources/64d26b98a9e8dcce93c35218337a87d2.png)

meanwhile all the rest have only 1 shortcut so admin pinned the most items to his taskbar
```
admin
```

> Q32: What was the last run date of the executable with an MFT record number of 164885? (Format: MM/DD/YYYY HH:MM:SS (UTC).)

![25b41243e37a40ae2e8ffe7f2d3eeb31.png](/resources/25b41243e37a40ae2e8ffe7f2d3eeb31.png)

Using output file we got from `mtfdump.exe` to find which file has this record number 

![f028317ec30c7c94cf002e9192f99ffc.png](/resources/f028317ec30c7c94cf002e9192f99ffc.png)

It's `7ZG.EXE`

![367eb92305cfd816ae2f307bb503b6bd.png](/resources/367eb92305cfd816ae2f307bb503b6bd.png)

Find prefetch of this file then we got last run time

To verify this question we can use and output from `PECmd` 

![a90d8ce14f870c90fb722a01276c407b.png](/resources/a90d8ce14f870c90fb722a01276c407b.png)

![7035ac4771210455dba1703a0424f4dd.png](/resources/7035ac4771210455dba1703a0424f4dd.png)

Well it's different from MFT output file but an answer of this question is the time we got from PECmd 
```
04/12/2020 02:32:09
```

> Q33: What is the log file sequence number for the file "fruit_Assortment.jpg"?

Output from `MFTDump` is not enough for this question, we need to use `MFTCmd.exe` from EZ tools

![c69bd96828339bd00e17a241a2042aca.png](/resources/c69bd96828339bd00e17a241a2042aca.png)

Parsing MFT using this command `MFTECmd.exe -f $MFT --csv .`

![0753db678c6b78dabc49e61469a5bacc.png](/resources/0753db678c6b78dabc49e61469a5bacc.png)

Open it with your CSV file viewer then we can see that there is LogfileSequenceNumber column which is the one we're looking for

![a4a152f1fc2c56268636bc2f94046571.png](/resources/a4a152f1fc2c56268636bc2f94046571.png)

Using search function to find for this image file and look up for LogfileSequenceNumber column 
```
1276820064
```

> Q34: Jim has some dirt on the company stored in a docx file. Find it, the flag is the fourth secret, in the format of <"The flag is a sentence you put in quotes">. (Secrets, secrets are no fun)

![f0a473b7a004e7e13d40c6f921909384.png](/resources/f0a473b7a004e7e13d40c6f921909384.png)

Using output from MFTECmd, we can search for docx file on Timeline Explorer directly which you can see that there is 1 docx file located inside Jim's Desktop

![2a978fa8e828522aa7428e8c42d7ead4.png](/resources/2a978fa8e828522aa7428e8c42d7ead4.png)

Go export this file

![41bd692691194dc8fe383aeeb9235def.png](/resources/41bd692691194dc8fe383aeeb9235def.png)

For safety sake, I used oleid from oletools suite to check if there is any suspicious indicator on this file (`python oleid.py Document1.docx`)

![eb6f17aac196f13185c759d0f826e03a.png](/resources/eb6f17aac196f13185c759d0f826e03a.png)

After confirming there is no suspicicious indicator, I opened docx file using LibreOffice which I found this message

![3dd8558d066638a4ffcacc676149a52e.png](/resources/3dd8558d066638a4ffcacc676149a52e.png)

So I extracted docx file using 7z and `file.xml` caught my eyes immediately because it would have some message inside of it

![107a3d468f9b1481ef9ed740243d9237.png](/resources/107a3d468f9b1481ef9ed740243d9237.png)

change file extension to doc and open it with LibreOffice again

![ac8c6fad6d93b2923a9e8d308aa4af32.png](/resources/ac8c6fad6d93b2923a9e8d308aa4af32.png)

Then we finally see 4 company secrets 
```
Customer data is not stored securely
```

> Q35: In the company Slack, what is threatened to be deactivated if the user gets their email deactivated?

![d0d64a51233a60f5883498fd2f900586.png](/resources/d0d64a51233a60f5883498fd2f900586.png)

Searching for slack artifact using Timeline Explorer with an output from MFTECmd, we can see there is 1 log file located under jim's AppData

![ad8b4ddee4a96a352d044605790dc988.png](/resources/ad8b4ddee4a96a352d044605790dc988.png)

Grab it

![3140dc7d4e06b6537843ed2b5302d9fa.png](/resources/3140dc7d4e06b6537843ed2b5302d9fa.png)

Using strings and searching for "deactivate", we found a message that if someone deactivate his email then he will deactivate kneecaps of that guy
```
kneecaps
```

https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/corporatesecrets/

* * *
