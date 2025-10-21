# [HackTheBox Sherlocks - Unsupervised](https://app.hackthebox.com/sherlocks/Unsupervised)
![023bc541bfd4e11c370d95208f7e3f5e.png](..//resources/023bc541bfd4e11c370d95208f7e3f5e.png)
## Scenario
The incident happened around 4:30 PM on Friday, "The Last day of the week" at the Accounts/Marketing department of "Finance XYZ" company. There weren't many people in the department, and the remaining were not paying much attention to their surroundings as they were getting ready to head home. After the weekend on Monday while reviewing the security cam footage member of an IT team saw "Eddie" a new intern in the Accounts/Marketing department, plugging a USB into an unauthorized computer (containing sensitive financial and marketing documents), interacting with computer and unplugging the USB before heading out. As the incident happened 2 days ago, and not having enough knowledge of what Eddie did the security team use caution while asking around and gathering intel to avoid causing suspicion. The only information they were able to find out was that Eddie had a "Toshiba" USB. You are provided with a partial image of the “unauthorized computer" as well as a list of important documents, to investigate what he did and if he stole something sensitive or not?

* * *

![051a82bd7af22b0b18a6c4ef9f069cd7.png](..//resources/051a82bd7af22b0b18a6c4ef9f069cd7.png)

We have 2 files extracted from the sherlock zip file, first is disk image file with ad1 extension and the second is a text file that contains informatiom about important files and folders but it was obfuscated

![71c4dbd9a436eb8679424da53d8ec866.png](..//resources/71c4dbd9a436eb8679424da53d8ec866.png)

Since the image file is ad1 so we have to use FTK imager to analyze this image file and we can see that there is only a single user folder on this machine and we also have SYSTEM and SOFTWARE hive as well.

>Task 1: Find out the time zone of victim PC. (UTC+xx:xx)

![f77dcf8d9dcea3616836196b79f8243f.png](..//resources/f77dcf8d9dcea3616836196b79f8243f.png)

First we can mount disk image or extract config folder with both registry hives to our machine.

![659bced44e14b9643965c1ad459fab1d.png](..//resources/659bced44e14b9643965c1ad459fab1d.png)

Now lets open SYSTEM hive with Registry Explorer and check out `ControlSet001\Control\TimeZoneInformation` key that was already bookmarked by default then we can see that the timezone of this PC is West Asia Standard Time.

![965c6f4de73b514e161d953c6dcc7709.png](..//resources/965c6f4de73b514e161d953c6dcc7709.png)

With a quick google search reveal the UTC time format and we can use this to answer this question right away.

```
UTC+05:00
```

>Task 2: Employees should be trained not to leave their accounts unlocked. What is the username of the logged in user?

![378a72dba2b3fd2c6938be84e38cd52c.png](..//resources/378a72dba2b3fd2c6938be84e38cd52c.png)

Normally I would look up SAM hive but there is none on this sherlock so the only user available to us on is MrManj, the author of this sherlock 😂

```
MrManj
```

>Task 3: How many USB storage devices were attached to this host in total?

![2ad58afffd63d356202f8f29b03d1def.png](..//resources/2ad58afffd63d356202f8f29b03d1def.png)

Going back to registry explorer, we can now look at USB key which we will see that on the "Device Description" field, we can filter with something like "USB Mass" or "Mass Storage" to get all USB storages devices attached to this host, or we can just filter for "USBSTOR" on the service field as well.

![4a222a309554f8e7c728ea72f0da2586.png](..//resources/4a222a309554f8e7c728ea72f0da2586.png)

Now we have total of 4 devices but then for some reason, the correct answer of this question is 3 so maybe "Mass Storage Device" could be the disk storage of C drive.

Then from the scenario, we also know that Eddie using "Toshiba" USB so Toshiba TransMemory might be the one that plugged into the machine and did something dirty so we will get last connected and last disconnected time to answer task 4 and 5 before proceeded to find out what happened during this time.

```
3
```

>Task 4: What is the attach timestamp for the USB in UTC?
```
2024-02-23 11:37:50
```

>Task 5: What is the detach timestamp for the USB in UTC?
```
2024-02-23 11:39:12
```

>Task 6: Which folder did he copy to the USB?

![fb36b20ecd09874486451bcc7f3c6fc3.png](..//resources/fb36b20ecd09874486451bcc7f3c6fc3.png)

Normally, I would check for ShellBags for UEBA but there is no `NTUser.dat` hive from this disk image file so the only option here is Jumplists right here.

![2a184f9d7e81637808f881495663926f.png](..//resources/2a184f9d7e81637808f881495663926f.png)

After exported it and use JumpLists Explorer to open it, we can see that there are 3 applications that JumpLists collected which are Windows Explorer, Libre Calc and Libre Writer.

Libre Calc is for xls file and Libre Writer is for docx file. which leaves us to Windows Explorer which is expected and as we can see that there are a folder with 2 sub-folders were opened from E drive and this drive is the USB storage drive of Eddie! and we can also see that 2 sub-folders of Work Documents are the copied of "Documents" folder of the author of this sherlock.

```
Documents
```

>Task 7: There were subfolders in the folder that was copied. What is the name of the first subfolder? (Alphabetically)
```
Business Proposals
```

>Task 8: Eddie opens some files after copying them to the USB. What is the name of the file with the .xlsx extension Eddie opens?

![55beae8f2f804a6effcfeb04ba976df2.png](..//resources/55beae8f2f804a6effcfeb04ba976df2.png)

For xlsx file, we have to take a look at files that were opened by Libre Calc and we can see that there is a single file xlsx opened from eddie flash drive.

```
Business Leads.xlsx
```

>Task 9: Eddie opens some files after copying them to the USB. What is the name of the file with the .docx extension Eddie opens?

![514326a90095cdf59634e3d055ee1a5d.png](..//resources/514326a90095cdf59634e3d055ee1a5d.png)

The same goes for docx file that was opened with Libre Writer right here.

```
Proposal Brnrdr ltd.docx
```

>Task 10: What was the volume name of the USB?

![8ae2f862e347875ea543fbd377252261.png](..//resources/8ae2f862e347875ea543fbd377252261.png)

Some might not know that when opened a file on USB storage, JumpLists also stores the volume name/label and serial number of that USB storage as well so what we need to do is to open the detailed of this file and we will see the answer of this question right here.

```
RVT-9J
```

>Task 11: What was the drive letter of the USB?

![3dcd27575ffcea6be7327b1e261149a2.png](..//resources/3dcd27575ffcea6be7327b1e261149a2.png)

E drive is only a single drive letter other than C and this is correct answer of this question as well.

```
E
```

>Task 12: I hope we can find some more evidence to tie this all together. What is Eddie's last name?

![c2a11f502e9c920f1bebcc40199eeb4c.png](..//resources/c2a11f502e9c920f1bebcc40199eeb4c.png)

There is no trace of Eddie on this machine beside his USB storage so how we could find out about this? well author of this sherlock already provides hint for us that "Sometimes, the smallest details in an image can reveal the biggest secrets." so the only source of image on disk image is "Thumbcache" which located at `C:\Users\[Username]\AppData\Local\Microsoft\Windows\Explorer`

![6f5f8d9ffd848ed1fe1456ba6dc8af1b.png](..//resources/6f5f8d9ffd848ed1fe1456ba6dc8af1b.png)
![7f06db443462252f06ed1238d151d5c0.png](..//resources/7f06db443462252f06ed1238d151d5c0.png)

So after exported it out, I used [Thumbcache viewer](https://thumbcacheviewer.github.io/) to open `thumbcache_256.db` file which reveal that author of this sherlock once opened an image of Eddie's resume/CV and its cached here.

```
Homer
```

>Task 13: There was an unbranded USB in the USB list, can you identify it's manufacturer’s name?

![a39ce9141976425bc4aa3158602776b3.png](..//resources/a39ce9141976425bc4aa3158602776b3.png)

From USB key, we know that DataTraveler belongs to Kingston and TransMemory belongs to Toshiba which leaves us with last one to figured out.

First we will have to dissect Vender ID and Product ID from key name of this device first.

![eb32fb5b1dfded27599a7c71fd798e8c.png](..//resources/eb32fb5b1dfded27599a7c71fd798e8c.png)

Now we have VenderID = 0x346D and ProductID = 0x5678 so we can use the following [website](https://the-sz.com/products/usbid/index.php?v=0x346D&p=0x5678&n=) to look up for this device and it reveals the manufacturer name of this product right here.

```
Shenzhen SanDiYiXin Electronic Co.,LTD
```

![23ab6bc12a24fdd72f47d94d110c70c8.png](..//resources/23ab6bc12a24fdd72f47d94d110c70c8.png)
https://labs.hackthebox.com/achievement/sherlock/1438364/874
* * *
