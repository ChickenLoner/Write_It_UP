# [CyberDefenders - TeamSpy](https://cyberdefenders.org/blueteam-ctf-challenges/teamspy/)
## Table of Contents

- [Scenario](#scenario)
- [Questions](#questions)

* * *
## Scenario
An employee reported that his machine started to act strangely after receiving a suspicious email with a document file. The incident response team captured a couple of memory dumps from the suspected machines for further inspection. As a soc analyst, analyze the dumps and help the IR team figure out what happened!

**Category**: Endpoint Forensics

**Tool**:
- [Volatilty 2.6](https://www.volatilityfoundation.org/26)
- [OSTviewer](https://www.sysinfotools.com/recovery/ost-file-viewer.php)
- [OfficeMalScanner](http://www.reconstructer.org/)
- [VirusTotal](https://www.virustotal.com/gui/home/upload)
- [dotnetfiddle](https://dotnetfiddle.net/)

**Resources**:
- [http://www.reconstructer.org/papers/_Analyzing%20MSOffice%20malicious file%20with%20OfficeMalScanner.zip](http://www.reconstructer.org/papers/_Analyzing%20MSOffice%20malware%20with%20OfficeMalScanner.zip)
- https://github.com/volatilityfoundation/volatility/wiki/Command%20Reference
* * *
## Questions
> Q1: File->ecorpoffice What is the PID the malicious file is running under?

![46428d58f94fa506a9642580d1a91dd9.png](/resources/46428d58f94fa506a9642580d1a91dd9.png)

Lets start by determine which profile to use with kdbgscan and imageinfo plugin

![4fcb444b7590ee9af994fad16dfbb673.png](/resources/4fcb444b7590ee9af994fad16dfbb673.png)

After determined which profile to use, next We will use `vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 pstree` to display process tree from this memory dump, you can see that "SkypeC2AutoUpd" really caught my eyes here because of it names I would read it as "Skype Command and Control Auto Update"

![8413822dd3201f24415fda46b843792b.png](/resources/8413822dd3201f24415fda46b843792b.png)

So We will use malfind plugin to scan find all processes with PAGE_EXECUTE_READWRITE protection, this process also appeared on the result of this scan

![f6f51b8676d124730134df42211aead4.png](/resources/f6f51b8676d124730134df42211aead4.png)

I also used `vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 cmdline` to find command line argument from this process but I got full path instead, but after reviewing this path again its raise another flag given an exe file with executed from user temp directory 

![63f65a861f33bff3ae9dda0ccbaa608f.png](/resources/63f65a861f33bff3ae9dda0ccbaa608f.png)

We can also see that user from this system is called phillip price, an infamous character from Mr. Robot which is the theme of this lab

```
1364
```

> Q2: File->ecorpoffice What is the C2 server IP address?

![081f649b295b3feef3efa671373eef22.png](/resources/081f649b295b3feef3efa671373eef22.png)

Lets use `vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 netscan | grep "Skype"` to find all IP addresses established by this process, we can see that there are 2 IP addresses that return from this scan but the one that really stand out is `54.174.131.235` on port 80

![80754aa2f33f500f9c69f41333fcb51e.png](/resources/80754aa2f33f500f9c69f41333fcb51e.png)

This IP address owned by Amazon AWS and its the right answer for this question

```
54.174.131.235
```

> Q3: File->ecorpoffice What is the Teamviewer version abused by the malicious file?

I used filescan plugin with grep to seach for TeamViewer version but it didn't the right one 

![a1051212c10fc0079a9a759a34dcecf9.png](/resources/a1051212c10fc0079a9a759a34dcecf9.png)

But we know an IP address that malicious process connected to so I will use `strings win7ecorpoffice2010-36b02ed3.vmem | grep -i "54.174.131.235"` to find anything related to this IP address from memory dump directly, and after carefully review urls return from strings output, we can see that `tvrv` should represent TeamViewer Version and turn out I was right

```
0.2.2.2
```

> Q4: File->ecorpoffice What password did the malicious file use to enable remote access to the system?

![15853342772ca7d94dc6763f2477091c.png](/resources/15853342772ca7d94dc6763f2477091c.png)

We know that TeamViewer will need ID and Password for Remote Control and File Transfer but how could we got them?

Which lead us to another plugin called [editbox](https://github.com/bridgeythegeek/editbox) that can capture the TeamViewer ID and password by extracting the text from Windows Edit controls, which are commonly used for text boxes in applications

![aa05f444a8100cbf175d213c6ad64a2a.png](/resources/aa05f444a8100cbf175d213c6ad64a2a.png)

Lets use `vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 editbox` then we can see both ID (can answer Q8) and Password here

```
P59fS93m
```

> Q5: File->ecorpoffice What was the sender's email address that delivered the phishing email?

![86e18d041043b20b92f405e510c2df40.png](/resources/86e18d041043b20b92f405e510c2df40.png)

From previous pstree scan, we can see that OUTLOOK.EXE were running with PID 2692 so we might dump this process and use strings to catch email header or email from process memory dump directly 

![edee26b3f6190b18b4f0231582e8ba34.png](/resources/edee26b3f6190b18b4f0231582e8ba34.png)

lets dump memory of this process with `vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 memdump -p 2692 -D /tmp/ecorp/`

![9410462834e9ff710ccc0b0ebd7db5eb.png](/resources/9410462834e9ff710ccc0b0ebd7db5eb.png)

First I will use `strings /tmp/ecorp/2692.dmp | grep "Reply-To"` to find for "Reply-To" field in Email Header and it return this email address for us 

![67db1b679f12c95819625ccf7f679b5f.png](/resources/67db1b679f12c95819625ccf7f679b5f.png)

Or we can use `strings /tmp/ecorp/2692.dmp | grep -E -o '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'` to catch all emails from this memory dump, we know that phillip.price is a user from this machine which mean another email belongs to the attacker

```
karenmiles@t-online.de
```

> Q6: File->ecorpoffice What is the MD5 hash of the malicious document?

![14bc92bbfb1a5f4887906eeca25f1918.png](/resources/14bc92bbfb1a5f4887906eeca25f1918.png)

From outlook process memory dump, I used strings and grep to find for any `.doc` file reside from this dump and I found 5 files where downloaded to phillip's downloads folder

![c4c77b18eebc60734e8dde198ef1587d.png](/resources/c4c77b18eebc60734e8dde198ef1587d.png)

Next We will use `vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 filescan | grep "\.pst"` to scan for any pst (Personal Storage Table) files and it is a file format used to store copies of messages, calendar events, and other items within Microsoft software such as Microsoft Outlook.

I also used to find for `.ost` file but it returns nothing so we only have couple of pst to work here

![22da1fb42d0496692df1ea485caee0cf.png](/resources/22da1fb42d0496692df1ea485caee0cf.png)

Then let use `vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 dumpfiles -r pst$ -u -n -D /tmp/ecorp/` to dump file that match regex (all pst files), `-u` to relax safety constraints for more data and `-n` to extracted filename in output file path

![0a7b5521ae9e2831626e0d22c6abfbcc.png](/resources/0a7b5521ae9e2831626e0d22c6abfbcc.png)

Lets use `find . -type f -exec pffexport -m all -f all "{}" \;` which will find all PST and OST files used by Microsoft Outlook and use pffexport to extract data from these files and lastly we will have a directory that is an output from pffexport

![4164ea9729cf6bfe0bc22f385652bd19.png](/resources/4164ea9729cf6bfe0bc22f385652bd19.png)

Using tree, we can see how many files that were extracted and there is 1 doc attachment that we are looking for inside Message00011 

![fd7a990df24f3914dc5f03627875525a.png](/resources/fd7a990df24f3914dc5f03627875525a.png)

I checked email header again to confirm that this is an email sent from an attacker to philip which you can see that both email matched perfectly

![2ffda7993d7f95d647329015f98455e0.png](/resources/2ffda7993d7f95d647329015f98455e0.png)

This is how phillip fell for, an attacker fake ecorp invoice and sent this to phillip 

![60c82fb3c8ba36e405c1ae96ad9ae149.png](/resources/60c82fb3c8ba36e405c1ae96ad9ae149.png)

so we can use `md5sum` on this malicious document to calculate MD5 hash

```
c2dbf24a0dc7276a71dd0824647535c9
```

> Q7: File->ecorpoffice What is the bitcoin wallet address that ransomware was demanded?

![c7d9740d0db5f44ca042a239529347ec.png](/resources/c7d9740d0db5f44ca042a239529347ec.png)

There are many messages to look for but to reduce out time we will use `find . -type f -exec grep -l "Bitcoin" {} +` to find all files that has "Bitcoin" inside of it

As you can see that there are 4 files that have "Bitcoin" inside their contents but only 2 files that matter just in different format

![4bc17483c9ac5d8323843e3589364213.png](/resources/4bc17483c9ac5d8323843e3589364213.png)

I started with Message00010 from inbox first, which you can see its an email demands for ransom 

![721f7118c5e7ce0d2b7eef1daadea64a.png](/resources/721f7118c5e7ce0d2b7eef1daadea64a.png)

And judging from email sent, look like phillip had no clue about it

```
25UMDkGKBe484WSj5Qd8DhK6xkMUzQFydY
```

> Q8: File->ecorpoffice What is the ID given to the system by the malicious file for remote access?
```
528 812 561
```

> Q9: File->ecorpoffice What is the IPv4 address the actor last connected to the system with the remote access tool?



I used  to filter out strings result with any strings that look like legitimate IP address, even though its not perfect but we can manually pick out which are the legitimate IP addresses for us

2 IP addresses that started with 3 caught my eyes and and first one from above image is the correct answer (even though VirusTotal didn't flag it as malicious)

```
31.6.13.155
```

> Q10: File->ecorpoffice What Public Function in the word document returns the full command string that is eventually run on the system?

![be260c544d888666eea8d398f73140a0.png](/resources/be260c544d888666eea8d398f73140a0.png)

First, lets confirm if there is any malicious vba macro embbed with `oleid` then we can proceed with `olevba`

![41f8a1b0c5167119eba0b7a9cb5a40fd.png](/resources/41f8a1b0c5167119eba0b7a9cb5a40fd.png)

After used `olevba`, we can see that this function has suspicious long string inside and then deobfuscate it before return as string 

```
UsoJar
```

> Q11: File->ecorpwin7 What is the MD5 hash of the malicious document?

![db430a15f398d6d7d7d4d359d4c7657f.png](/resources/db430a15f398d6d7d7d4d359d4c7657f.png)

We need to determine which profile to use again with kdbgscan and imageinfo again on this memory dump

![4eb43ae8ee119956377a791925a79797.png](/resources/4eb43ae8ee119956377a791925a79797.png)

We suspected that this machine also receive malicious document via an email as an attachment but I'll use `vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 pstree` to scan for process first

Which we can see that OUTLOOK were running on this machine when it was captured for memory dump and not just that we can also see that rundll32 were running under svchost which are commonly see for malware that based on dll  

![e2fff0bbff62c3e5022ae9226a905123.png](/resources/e2fff0bbff62c3e5022ae9226a905123.png)

Lets use `vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 filescan | grep "\.pst"` to find for any ost and pst file, we didn't need to let it finish but to confirm that there is any pst or ost file stored on this machine

![9a2ab8df130123a73711ef8cc84d0c20.png](/resources/9a2ab8df130123a73711ef8cc84d0c20.png)

Then we can use `vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 dumpfiles -r pst$ -u -n -D /tmp/ecorp/` to dump all pst file once again.

![a1e0ffba5d05dd0f110d98bfc4bf0ea2.png](/resources/a1e0ffba5d05dd0f110d98bfc4bf0ea2.png)

its time for `find . -type f -exec pffexport -m all -f all "{}" \;` again

![30e25ec4da8803ecdc9458cdbdbd0777.png](/resources/30e25ec4da8803ecdc9458cdbdbd0777.png)

There is only 1 attachment here and its rtf file that infamous as an extension that was used by malware 

![36f6f3c29f56afb09d37cecbe2399b0e.png](/resources/36f6f3c29f56afb09d37cecbe2399b0e.png)

But for some reason this file couldn't be export using this method, as you can see that its empty 

![881288037cec34aeb70cd2df81fc9c81.png](/resources/881288037cec34aeb70cd2df81fc9c81.png)

So we have to dump it from memory dump, first let scan for offset first with `vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 filescan | grep "Important\_ECORP\_Lawsuit\_Washington\_Leak\.rtf"`

![1d137e1194b41b5daad0a63b32315e60.png](/resources/1d137e1194b41b5daad0a63b32315e60.png)

Then use `vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 dumpfiles -Q 0x000000007d6b3850 -u -n -D /tmp/ecorp/` to dump it out

![07648f5f8a594d92113657f9d59e0ed1.png](/resources/07648f5f8a594d92113657f9d59e0ed1.png)

But even if we generated MD5 hash from an exported file, we still couldn't get the right answer because there are some trailing null bytes at the end of this file

![627a1b8d5fd76fe2702c37f4c1696a42.png](/resources/627a1b8d5fd76fe2702c37f4c1696a42.png)

You can used HxD to remove all those trailing null byes but I will use `xxd -p file.None.0xfffffa80040b3260.Important_ECORP_Lawsuit_Washington_Leak.rtf.dat | sed '/000000000000000000000000000000000000000000000000000000000000/d' | sed '/0000000000000000000000000000000000000000000000000000/d' | sed 's/6131376136616631303365316533616437657d7d7d7d0000000000000000/6131376136616631303365316533616437657d7d7d7d/g' | xxd -r -p > Important_ECORP_Lawsuit_Washington_Leak.rtf` to remove them then we will get the correct hash to submit

Btw, special thanks to [ForensicKween](https://forensicskween.com/ctf/cyberdefenders/teamspy/) for this awesome command!

```
00e4136876bf4c1069ab9c4fe40ed56f
```

> Q12: File->ecorpwin7 What is the common name of the malicious file that gets loaded?"

Remember rundll32 process that we found using pstree plugin? Its time to investigate them

![9d84e34786b660f3783993a3f6563a9d.png](/resources/9d84e34786b660f3783993a3f6563a9d.png)

I used cmdline plugin to determine which file that rundll32 was processed and these 2 processes processed the same file.

![520e6bed7de2006412b9d1d7747c7e69.png](/resources/520e6bed7de2006412b9d1d7747c7e69.png)

Lets find its offset to dump with `vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 filescan | grep "test\.DLL"`

![723b09943ae4932f0c69c86abcc6d1ed.png](/resources/723b09943ae4932f0c69c86abcc6d1ed.png)

Drop it with `vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 dumpfiles -Q 0x000000007e3eed10 -n -D /tmp/ecorp/` then search it hash on VirusTotal

![21da19458fb81fc7475f778ce02e2bc2.png](/resources/21da19458fb81fc7475f778ce02e2bc2.png)

Some vendors recognized it as Korplug malware

![cc1df27ae5ce1a52a1b2d600562159fe.png](/resources/cc1df27ae5ce1a52a1b2d600562159fe.png)

Which is also know as PlugX

```
PlugX
```

> Q13: File->ecorpwin7 What password does the attacker use to stage the compressed file for exfil?

![439c22b1371dae828c97bce2d8080515.png](/resources/439c22b1371dae828c97bce2d8080515.png)

First, I'll use `vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 mftparser > mft.txt` to dump information inside MFT to a text file to search for compressed file later

![2f46f6d1a37c395059c4bbebe36b5069.png](/resources/2f46f6d1a37c395059c4bbebe36b5069.png)

Then I will use `grep -E "\.(zip|tar|gz|tgz|bz2|7z|rar|xz|Z|jar|war|ear|iso)$" mft.txt` to find all compressed files possible from MFT and you can see that there is a rar file inside ProgramData folder where malicious dll resides

![bf46da76a9476e9bea9406fbc1fc1f77.png](/resources/bf46da76a9476e9bea9406fbc1fc1f77.png)

Those dll might came from this rar file and it should be a password protected to avoid some anti virus solution so I will use `strings -el ecorpwin7-e73257c4.vmem | grep "reports.rar"` to find any command that extract content of this file with password

```
password1234
```

> Q14: File->ecorpwin7 What is the IP address of the c2 server for the malicious file?

![f4f176f6281c636e298ef9842f36b5c0.png](/resources/f4f176f6281c636e298ef9842f36b5c0.png)

Just use `vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 netscan` and look out for svchost process that is the parent process of rundll32 process which processed malicious dll file

![d96a240337dcd529201026b741400dad.png](/resources/d96a240337dcd529201026b741400dad.png)

I confirmed it by searching on VirusTotal, lucky me then there are enough information on Relations tab that it was dropped malicious exe file (foreshadow to my bonus section)

```
52.90.110.169
```

> Q15: File->ecorpwin7 What is the email address that sent the phishing email?

![267d3decbfd4ecb8a60b3288fdc9d128.png](/resources/267d3decbfd4ecb8a60b3288fdc9d128.png)

Go back to mail files that was processed with pffexport, inspect header of an email that sent malicious rtf file

```
lloydchung@allsafecybersec.com
```

> Q16: File->ecorpwin7 What is the name of the deb package the attacker staged to infect the E Coin Servers?

![1a6f16529f618aff9c01e4f1765be6a0.png](/resources/1a6f16529f618aff9c01e4f1765be6a0.png)

I will use `strings -el ecorpwin7-e73257c4.vmem | grep "\.deb"` to find all deb file from memory dump directly and you can see that there were an attempt to download `linuxav.deb` file and depackage

![0d68d82feb5012bf34e4e5aac5d0517e.png](/resources/0d68d82feb5012bf34e4e5aac5d0517e.png)

I didn't find this file from filescan plugin but found on MFT 

![996d2380aaca874c3ea9129fb61851d7.png](/resources/996d2380aaca874c3ea9129fb61851d7.png)

So I want to know more details of this file so I will use `cat mft.txt | grep -F 'av/linuxav.deb' -B 50` which show more content then regular grep command that only things we want, you can see that this deb file was downloaded by a shell script

![55c8de1a97400db57b7bc2c5582a8281.png](/resources/55c8de1a97400db57b7bc2c5582a8281.png)

I dump this shell script with `vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 mftparser -o 0x699e3c00 -D /tmp/ecorp/` then we can see that this script ensures necessary tools are in place and handles the download and extraction of a Debian package, setting up the environment for further configuration tasks.

```
linuxav.deb
```

https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/teamspy/


* * *
**Bonus** 

Investigate futher into malicious rtf file 

![b515dcb3b7e1bb5e10727cd54ebc5805.png](/resources/b515dcb3b7e1bb5e10727cd54ebc5805.png)

First, we know that rtf file is a malicious file and VirusTotal tells us CVE number that file used to exploit

![dd219a7154e5cea6369a2a412a534de8.png](/resources/dd219a7154e5cea6369a2a412a534de8.png)

Searching this CVE number, its a Stack Buffer Overflow vulnerabliity which mean there are shellcode inside this rtf file

![a549c19635ad3f8e019101929c070837.png](/resources/a549c19635ad3f8e019101929c070837.png)

I used CyberChef to convert content inside using From Hex then save output as file

![53dfdf30cd6f6512ae00b7cf65f30f0d.png](/resources/53dfdf30cd6f6512ae00b7cf65f30f0d.png)

To analyze shellcode, We will have to use scdbg (shellcode debugger) and don't forget to check FindSc then let it launch

![fc9c9fad87aec5ef6f8c1bffce6572db.png](/resources/fc9c9fad87aec5ef6f8c1bffce6572db.png)

We can see that there is a report to this domain on port 80

![07f4a81ee0f88d90eda7635a6252ce38.png](/resources/07f4a81ee0f88d90eda7635a6252ce38.png)

To download malicious exe file on this path

![b0e0ceff111d59804150253b16578dd4.png](/resources/b0e0ceff111d59804150253b16578dd4.png)

Named malicious file that will be downloaded to `ecorpav.exe`

![d089195f7244a4884da39a50a09f71eb.png](/resources/d089195f7244a4884da39a50a09f71eb.png)

After download, execute it then exit program

![3fa82306fbe49f55709d5a7651c63512.png](/resources/3fa82306fbe49f55709d5a7651c63512.png)

Now we know which exe that was downloaded and executed from C2, lets use `vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 filescan | grep "ecorpav\.exe"` to find its offset to dump

![023434af9bb4b7a7ee81d07dbd32f641.png](/resources/023434af9bb4b7a7ee81d07dbd32f641.png)

Dump it with `vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 dumpfiles -Q 0x000000007d6f8070 -n -D /tmp/ecorp/` then generate file hash to search on VirusTotal

![4a429a4dfbb1e720c765054007cae685.png](/resources/4a429a4dfbb1e720c765054007cae685.png)

There it is, its a Kogplug or PlugX malware which is another way to solve Q12

* * *