# [TryHackMe - DiskFiltration](https://tryhackme.com/room/diskfiltration)
![c66a4e3755f5c79b007baf33b409d1db.png](/resources/c66a4e3755f5c79b007baf33b409d1db.png)
***
![0d508149ed757bffe394069f402c9fb9.png](/resources/0d508149ed757bffe394069f402c9fb9.png)

Tech THM discovered their critical data had been leaked to the competitors. After an internal investigation, the company suspects Liam, a recently terminated employee who was working as a system engineer with Tech THM. This suspicion was raised as Liam had access to the leaked data in his company-provided workstation. He often worked late hours without clear justification for his extended presence. He was also caught roaming around the critical server room and taking pictures of the entry gate. Following these suspicions, Liam’s workstation (provided by the company) was investigated. The initial investigation suggests that an external entity was also helping Liam.

Let's use the knowledge we gained from the previous modules of this path to search for traces of Liam's activities.

>What is the serial number of the USB device Liam used for exfiltration? 

![c45b595c66c5b037ddb11cd27160ca64.png](/resources/c45b595c66c5b037ddb11cd27160ca64.png)

After started the machine, we can confirm that the sole evidence of this investigate is located on the "Disk For Analysis" and we can also confirm all the tools we have on this room from "Forensic Tools" folder which is located on the desktop as well.

![c32cbeb021ccbcc0de0cffeabbd03e7f.png](/resources/c32cbeb021ccbcc0de0cffeabbd03e7f.png)

Since this room already pre-analyzed disk image for us so we can just open the case once we opened Autopsy.

![a29784a5989b7838ef6ab03a6402a8d6.png](/resources/a29784a5989b7838ef6ab03a6402a8d6.png)

And now we can look at the "USB Device Attached" to get the serial number of the USB that already parsed out from SYSTEM registry hive (USBSTOR key) right here.

```
2651931097993496666	
```

>What is the profile name of the personal hotspot Liam used to evade network-level detection?

![cf6143295d70575fe6db39d3e91c1545.png](/resources/cf6143295d70575fe6db39d3e91c1545.png)

To find the network profile, we have to dig into SOFTWARE registry hive to inspect the `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` registry key which we can see that Liam used his iPhone for this operation as indicates by the ProfileName.

```
Liam's Iphone
```

>What is the name of the zip file Liam copied from the USB to the machine for exfiltration instructions?

![783100bdf03ece68700842b29e0752c7.png](/resources/783100bdf03ece68700842b29e0752c7.png)

Since we are dealing with User and Entity Behavior Analytics (UEBA) then I want to know what files that were accessed by the user which we can look at "Recent Documents" to find out that there is 1 suspicious pdf file was opened from suspicious folder and the text file opened from the document folder so we will have to look into it later and we also know that Liam was authenticated as Administrator during this operation so he had accessed to every sensitive files on this machine and even on the shares too (if local administrator was configured to be able to access those shares).

![20af61d6525a6fbda83a8fd88303fb31.png](/resources/20af61d6525a6fbda83a8fd88303fb31.png)

After navigated to Desktop of the Administrator user, we can see that this is a zip file located on this folder and it has the same name as the suspicious folder we found from "Recent Documents" so this is the file we are looking for.

```
Shadow_Plan.zip
```

>What is the password for this zip file?

![b35970b422aeae1d7110ba145a6f624e.png](/resources/b35970b422aeae1d7110ba145a6f624e.png)

![47d1bdeffb1868bf2b17b3b88769ce6d.png](/resources/47d1bdeffb1868bf2b17b3b88769ce6d.png)

Remember that we found `Pass.txt` from the Document folder of the Administrator so we can inspect it which I found that this password can be used to unzip the file so we got the right file!

```
Qwerty@123
```

>Time to reveal the external entity helping Liam! Who is the author of the PDF file stored in the zip file?

![3aab0556f7c3d74c14fd7d3663ead3ed.png](/resources/3aab0556f7c3d74c14fd7d3663ead3ed.png)

I moved all extracted files to the folder that stores the exiftool binary then used it on each file which I found that Henry is the author of this pdf from the metadata of pdf file.

![386a119ab2a82edd993e5b319c6b0344.png](/resources/386a119ab2a82edd993e5b319c6b0344.png)

Now we can open pdf file to see what Liam had been told which it aligns with everything we found and things we are going to find as well.

```
Henry
```

>What is the correct extension of the file that has no extension in the zip folder?

![a01572d69b7fcbd84aaaa35e1aea043a.png](/resources/a01572d69b7fcbd84aaaa35e1aea043a.png)

Upon using exiftool on `confidential` file which we can see that this file is actually an image file and we also found the hidden flag from the comment metadata as well.

```
png
```

>It looks like Liam searched for some files inside the file explorer. What are the names of these files? (alphabetical order)

![b8b85b7459f527641ea0fa10a269e428.png](/resources/b8b85b7459f527641ea0fa10a269e428.png)

When talking about "searching", we have 1 registry key that stores keyword that was used to search which is `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` so we will have to look into NTUSER.DAT registry hive of Administrator user and as you can see that there are 2 keywords stores in this key which matches the answer format of this question.

![127db6ccc10460d1bbbfe16692141000.png](/resources/127db6ccc10460d1bbbfe16692141000.png)

Here is another keyword and we can determine that Henry that instructed Liam was interesting in Financial situation of the company from both keywords .

```
Financial, Revenue
```

>What are the names of the folders that were present on the USB device? (alphabetical order)

![17cbd0471bcec12618c2d143054dbc3d.png](/resources/17cbd0471bcec12618c2d143054dbc3d.png)

We can go back to "Recent Documents" which we can see another 2 folders that were accessed on E drive which is the drive that was mapped to USB device.

ShellBags also store similar info as well so we can use this artifacts as an alternative of this.

```
Critical Data TECH THM, Exfiltration Plan
```

>The external entity didn't fully trust Liam for the exfiltration so they asked him to execute file_uploader.exe, through the instructions in PDF. When was this file last executed and how many times was it executed? (YYYY-MM-DD HH:MM:SS, number of execution times)

![5e2b85d6a29721677b12bb8c3ad8f460.png](/resources/5e2b85d6a29721677b12bb8c3ad8f460.png)

First, I used exiftool and this file which is not reveal any useful information beside this is likely to be the python compiled binary based on the icon.

![3c3db57d86a9c4c7539c157f31dff4c8.png](/resources/3c3db57d86a9c4c7539c157f31dff4c8.png)

There are several evidence of execution that can be used to find this answer but we can easily get it from "Run Programs" that already parsed prefetch files for us which we can see that the file was executed 2 times but somehow the 09 was accepted as an answer instead of 11.

```
2025-01-29 11:26:09, 2
```

>Liam received a hidden flag inside a file (in the zip folder) from the external entity helping him. What was that?

![745d90d4314a04c425ad109377b05aa1.png](/resources/745d90d4314a04c425ad109377b05aa1.png)
```
FLAGT{THM_TECH_DATA}
```

>It seems like Liam caused one last damage before leaving. When did Liam delete "Tax Records.docx"? (YYYY-MM-DD HH:MM:SS)

![d8a251da18f0810133f5279ec0ae17b7.png](/resources/d8a251da18f0810133f5279ec0ae17b7.png)

I didn't see any docx in Recycle Bin so I exported Usn Journal file out.

![0cd7b4b9a7acccaa622113f4972e7a09.png](/resources/0cd7b4b9a7acccaa622113f4972e7a09.png)

Then I used `MFTECmd.exe -f $UsnJrnl_$J --csv output` to parse the artefact.

![9318d9e24520df14f8bd3131d2b40cdb.png](/resources/9318d9e24520df14f8bd3131d2b40cdb.png)

Then after filter file **docx** extension and **File Delete** Update Reasons then we will have the value inside "Update Timestamp" field as the answer of this question.

```
2025-01-29 11:26:02
```

>Which social media site did Liam search for using his web browser? Likely to avoid suspicion, thinking somebody was watching him. (Full URL)

![481c359050e09ff68f0009dbfff913ad.png](/resources/481c359050e09ff68f0009dbfff913ad.png)

We can take a look at "Web History" which reveals that Liam accessed Facebook but only default page but not browse for any extra page.

```
https://www.facebook.com/
```

>What is the PowerShell command Liam executed as per the plan?

![0b56706b04cb066af44afab98d28eeec.png](/resources/0b56706b04cb066af44afab98d28eeec.png)

Lastly, we can see that the last objective is get all network shares and we know that Liam was using PowerShell so we can look into PowerShell ConsoleHost for PowerShell command executed by Administrator user.

![22a6bea6899c750d146f157a52d45ce9.png](/resources/22a6bea6899c750d146f157a52d45ce9.png)

Which we can see that the last record shows the PowerShell command used to list all network shares as planned. 

```
Get-WmiObject -Class Win32_Share | Select-Object Name, Path
```

![5d34a7b7ca17d1fc308f89869f318061.png](/resources/5d34a7b7ca17d1fc308f89869f318061.png)

And now we are done!
***