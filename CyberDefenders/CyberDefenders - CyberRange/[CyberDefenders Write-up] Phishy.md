# [CyberDefenders - Phishy](https://cyberdefenders.org/blueteam-ctf-challenges/phishy/)
## Table of Contents

- [Scenario](#scenario)
- [Questions](#questions)

* * *
## Scenario
A company’s employee joined a fake iPhone giveaway. Our team took a disk image of the employee's system for further analysis.
As a soc analyst, you are tasked to identify how the system was compromised.

**Category**: Endpoint Forensics

**Tools**:
- [FTK Imager](https://accessdata.com/products-services/forensic-toolkit-ftk/ftkimager)
- [Autopsy](https://www.sleuthkit.org/autopsy/)
- [Registry Explorer](https://f001.backblazeb2.com/file/EricZimmermanTools/RegistryExplorer_RECmd.zip)
- [SQLite Browser](https://sqlitebrowser.org/)
- [browsinghistoryview](https://www.nirsoft.net/utils/browsing_history_view.html)
- [passwordfox](https://www.nirsoft.net/utils/passwordfox.html)
- [Whatsapp viewer](https://github.com/andreas-mausch/whatsapp-viewer/releases/download/v1.13/WhatsApp.Viewer.zip)
- [oledump](https://blog.didierstevens.com/programs/oledump-py/)
- [virustotal](https://www.virustotal.com/gui/home/upload)
- [HybridAnalysis](https://www.hybrid-analysis.com/)
* * *
## Questions
> Q1: What is the hostname of the victim machine?

![11b8af412ab9742777cdf9385e9f1865.png](/resources/11b8af412ab9742777cdf9385e9f1865.png)

We can get an information about system's hostname within `SYSTEM` hive at `HKLM\SYSTEM\ControlSet001\Control\ComputerName\ComputerName`

![ae7100a4c3732c2cba4d513f24942bbb.png](/resources/ae7100a4c3732c2cba4d513f24942bbb.png)

Export the hive and open it with Registry Explorer or RegRipper and navigate to the registry key 
```
WIN-NF3JQEU4G0T
```

> Q2: What is the messaging app installed on the victim machine?

![9a679a599526784f718ebb1cf72639ae.png](/resources/9a679a599526784f718ebb1cf72639ae.png)

I searched User folders which I found `WhatsApp.exe` in Downloads folder

![96658f3b53c2d259705c1e64e8380f65.png](/resources/96658f3b53c2d259705c1e64e8380f65.png)

Which I also found WhatsApp folders inside AppData folder which mean WhatsApp was installed on this system
```
WhatsApp
```

> Q3: The attacker tricked the victim into downloading a malicious document. Provide the full download URL.

I did some research on how to collect and analyze WhatsApp forensics

![d29412c45a99cc89cec6ceb4706f15a0.png](/resources/d29412c45a99cc89cec6ceb4706f15a0.png)

And this [blog](https://www.magnetforensics.com/blog/artifact-profile-whatsapp-messenger/) tell us which artifact to get to read WhatsApp messages

![46d08b9a46dfe855793d0861a75fb993.png](/resources/46d08b9a46dfe855793d0861a75fb993.png)

![dd83eaf2eb1056a6001f9d8dc3c9d6ca.png](/resources/dd83eaf2eb1056a6001f9d8dc3c9d6ca.png)

Export database file and open with DB Browser for SQLite or WhatsApp viewer, we can see that a phishing link was sent which is a download link to a document file

```
http://appIe.com/IPhone-Winners.doc
```

> Q4: Multiple streams contain macros in the document. Provide the number of the highest stream.

![70c5e4b5e68bf0d0a09f10169f695e1a.png](/resources/70c5e4b5e68bf0d0a09f10169f695e1a.png)

From previous question, we know what file that being downloaded and it will be inside Downloads folder

![015099782ff725f939f98a54c8c66d62.png](/resources/015099782ff725f939f98a54c8c66d62.png)

Export it and use oleid from oletools suite to find any malicious indicators (`python oleid.py IPhone-Winners.doc`) which you can see that there are VBA Macros embedded in this file

![a32a03ecb4472672037d7a3d4d813864.png](/resources/a32a03ecb4472672037d7a3d4d813864.png)

But to find the highest macro stream we need to use oledump from DidierSteven suite with this command `python oledump.py IPhone-Winners.doc`, now you can see that there are 2 objects embedded with macros and the highest one is 10
```
10
```

> Q5: The macro executed a program. Provide the program name?

![c0a22add93cf1dd57120f38c6a1381a1.png](/resources/c0a22add93cf1dd57120f38c6a1381a1.png)

You know the stream that has VBA macros now, you can use either oledump or olevba to dump them and for me I'd do with this `python olevba.py IPhone-Winners.doc`

You can see that first macro stream is just AutoExec for Document_Open and the malicious macro is in later stream which is obfuscated

![16c80ea4108173737f3c5b8ca6fe2f5a.png](/resources/16c80ea4108173737f3c5b8ca6fe2f5a.png)

It's not that hard to deobfuscate, you can see that it's using "Chr()" to change number inside () to a character which mean inside () is ASCII code so What we will do is to Remove "Chr(" and ")" and keep all the numbers

![bd41412e4f57ab3d34e64c745b1457a6.png](/resources/bd41412e4f57ab3d34e64c745b1457a6.png)

Then go to https://codebeautify.org/ascii-to-text and try making it sense, in the end we will see that it will be parsed to PowerShell so the IIIIIIIII variable is storing base64 encoding strings
```
PowerShell
```

> Q6: The macro downloaded a malicious file. Provide the full download URL.

![a39291fa7f022c366ee9165c39a4752e.png](/resources/a39291fa7f022c366ee9165c39a4752e.png)

We know its base64 so just decode it, the code mean to make a web request to specific url (same domain that was used to download maldoc which was sent via WhatsApp) to download an executable file and save it to Temp folder

```
http://appIe.com/Iphone.exe
```

> Q7: Where was the malicious file downloaded to? (Provide the full path)

![49b9e11dd347de84bb341802ad812c1b.png](/resources/49b9e11dd347de84bb341802ad812c1b.png)

From the base64 decoded code, we know it save to Temp folder

![7dda0ee4c98ef83293a3b50cc02453fb.png](/resources/7dda0ee4c98ef83293a3b50cc02453fb.png)

And it's still there
```
C:\Temp\IPhone.exe
```

> Q8: What is the name of the framework used to create the malware?

![3e0bb1d9aacea113a5034c7a87cc9113.png](/resources/3e0bb1d9aacea113a5034c7a87cc9113.png)

Export filehash and lets search it on VirusTotal to save time

![f73f9d1a75a843695e836a41a5b6855e.png](/resources/f73f9d1a75a843695e836a41a5b6855e.png)

Some vendors labeled this file as Meterpreter which is a shell made for Metasploit

![c85939ff331388d1df153a81fe00ad46.png](/resources/c85939ff331388d1df153a81fe00ad46.png)

On the Community Tab, some sandboxes even gave this file a name as Metasploit 
```
Metasploit
```

> Q9: What is the attacker's IP address?

![193bbbab7b0e5514101aca287bbc6db9.png](/resources/193bbbab7b0e5514101aca287bbc6db9.png)

Go to Behavior tab, There is 1 TCP that was connected with unusual port and this IP address is the attacker IP 

```
155.94.69.27
```

> Q10: The fake giveaway used a login page to collect user information. Provide the full URL of the login page?

![080a451077258936a5ef14330b05d94e.png](/resources/080a451077258936a5ef14330b05d94e.png)

There is Firefox browser on this browser which has a riched profile 
It means that this user used Firefox as his main browser so lets export this profile folder to investigate next

![4126bc4d3dad77d9fdc17b334c4b4d36.png](/resources/4126bc4d3dad77d9fdc17b334c4b4d36.png)

Use MZHistoryView from Nirsoft to parse `places.sqlite` which store firefox browser history 

![2776e17145729c65e7834eb64da85d97.png](/resources/2776e17145729c65e7834eb64da85d97.png)

There are several histories to `appIe.com` which is a phishing site we're familiar with 

```
http://appIe.competitions.com/login.php
```

> Q11: What is the password the user submitted to the login page?

Nirsoft has several password recovery tools and the one we will use to get FireFox password is PasswordFox

![04693f771c59b4d411aace932eb2dd47.png](/resources/04693f771c59b4d411aace932eb2dd47.png)

Select firefox profile folder then click Ok

![98b7ccc8d3c778b4974665ca09697cee.png](/resources/98b7ccc8d3c778b4974665ca09697cee.png)

We got user credential that user puts to phishing site
```
GacsriicUZMY4xiAF4yl
```

https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/phishy/

* * *
