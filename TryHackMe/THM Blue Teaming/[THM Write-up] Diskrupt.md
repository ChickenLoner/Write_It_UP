# [TryHackMe - Diskrupt](https://tryhackme.com/room/diskrupt)
![7d31f280af47a8c9eb9538feedaace47.png](/resources/7d31f280af47a8c9eb9538feedaace47.png)
***
An underground research group, NexgEn e-Corps, has been working on a groundbreaking research paper on Quantum-Resistant Cryptography. The paper introduces a new encryption algorithm designed to resist quantum attacks. This research is a game-changer capable of securing global communications from quantum-powered adversaries.

Last night, the system sent an alert regarding the research paper being accessed from an unknown system on the network. The suspicion is on the newly joined intern Fatima, who has been seen around the research lab a few times.

She, being the insider with direct access to the laboratory resources, is suspected of stealing the research and attempting to erase all traces of her actions.

The forensics team has taken an image of her disk, but an unexpected system failure left behind fragments of critical evidence on her workstation and external storage devices.
![954cf47ec0d3dc5281d4768eb9aa99d6.png](/resources/954cf47ec0d3dc5281d4768eb9aa99d6.png)
The lab has provided you with a forensic image of Fatima's workstation's hard drive. Your task is to :
- Fix the damaged disk.
- Examine the partitions.
- Find evidence of access to sensitive research documents.
- If any files were deleted or tampered with.
- What are the hidden files on the disk.
- Carve out important files deleted from the disk.

>What are the corrupted bytes in the boot sector that caused the disk to be damaged?

![567843fbf7990046e6ae1ded7b42341c.png](/resources/567843fbf7990046e6ae1ded7b42341c.png)

After started the machine, we can see our evidence inside "Evidence" folder on the desktop and also FTK Imager and Autopsy icons as a tool for Disk image then we also have HxD as hexeditor and EZ Tools in case we need to parse some artifacts.

![2c46f482ff6c33ba1d42d28cb189eb2e.png](/resources/2c46f482ff6c33ba1d42d28cb189eb2e.png)

Since we already know that we got the correct disk image, then we can use HxD to open disk image which we can see that at 0x01FE and 0x01FF, instead of `55 AA` which is the Boot signature of Master Boot Record (MBR), we got AC BD instead so this is why FTK Imager does not catch this disk image.

```
ACBD
```

![0d615b053203a102cc543fcef426fba2.png](/resources/0d615b053203a102cc543fcef426fba2.png)

Now we can fix it and save the disk image.

![15c6fe928da8a99ac140910bf99e16a4.png](/resources/15c6fe928da8a99ac140910bf99e16a4.png)

Now FTK Imager finally recognized this disk image and properly read the disk partition and all the files inside the disk image.

Beside this, you can start import the image to Autopsy as well since we will need it to automatically craved file for us for the last question.

>What are the bytes representing the total sector of the second partition? (Little Endian)

![18edde249136bdb5e554c7986033a3b9.png](/resources/18edde249136bdb5e554c7986033a3b9.png)

We know that there are 2 partitions on this disk image from the FTK imager but we could also see this from FTK imager as well so here is the position of each partition on Hex editor
- 0x01BE first partition 
- 0x01CE second partition
- 0x01DE third partition (blank mean it does not exist)
- 0x01EE forth partition (blank mean it does not exist neither)

![52fef6ca16c1af917c73f34bdedca8d2.png](/resources/52fef6ca16c1af917c73f34bdedca8d2.png)

So we can copy bytes that represent second partition and separate to table like this then we can see the total of section of second partition from byte 12-15 for this line and we have to switch position a little bit to make it little-endian.

```
0x01387800
```

>What is the size of the first partition in GB? (up to 2 decimals e.g: 15.25)

![de7d41f9261ae7e3f63775f92aa3c83b.png](/resources/de7d41f9261ae7e3f63775f92aa3c83b.png)

Its time for the first partition, we will have to multiply number of section with sector size (normally 512 bytes) to get the size of this partition.

![58ee431bec3e0ff58466fa448779a4cb.png](/resources/58ee431bec3e0ff58466fa448779a4cb.png)

But I had a better idea, I let ChatGPT did the work for me which I told it to convert total bytes to GB as well.

```
30.23
```

>What is the size of the second partition in GB? (up to 2 decimals e.g: 15.25)

![caffb027aab08002749ae07ee16bd568.png](/resources/caffb027aab08002749ae07ee16bd568.png)

This time we got 9.77 has the size of second partition but the correct answer is 9.76 for some reasons.

```
9.76
```

>In the NTFS partition, when was the text file related to the password created on the system?

![466f8c2fc492864ae0c1793eca5dd903.png](/resources/466f8c2fc492864ae0c1793eca5dd903.png)

![351e2c52c9ff7d58833f234e55166b83.png](/resources/351e2c52c9ff7d58833f234e55166b83.png)

First, I exported Master File Table (MFT) from the table along with Usn Journal since both file stores record of files and their changes.

![40deda65315badf2df5539ea1d33a481.png](/resources/40deda65315badf2df5539ea1d33a481.png)

Then I parsed both file with `MFTECmd.exe -f $MFT --csv output` and `MFTECmd.exe -f $J --csv output` to get a nicely csv file that can be opened with Timeline Explorer, our favorite tool.

![a59b493208df3516f680058668fe2c07.png](/resources/a59b493208df3516f680058668fe2c07.png)

Then I started by looking at MFT record which reveals that `passwords.txt` which is the file we are looking for, was created on 2025-03-19 22:01:57.

```
2025-03-19 22:01:57
```

>What is the full name of the sensitive pdf document accessed on this disk?

![984a05f110273e0625dee24fd5e19791.png](/resources/984a05f110273e0625dee24fd5e19791.png)

I could not find any PDF file that resemble the answer format so I shifted my focus on Usn Journal and to my surprised! there are some records regarding of the pdf file that matches the answer format from Usn Journal and it just happened to be the one that we are looking for as well.

```
Quantum-Resistant Cryptographic Algorithms.pdf
```

>When this file was first found on this disk?

![a2cd51a7c90ef088d9bfcee1e9c25484.png](/resources/a2cd51a7c90ef088d9bfcee1e9c25484.png)

So we can take a look at the earliest Update Timestamp which is the timestamp that recorded the first appearance of this file this system.

```
2025-03-20 00:44:37
```

>What is the entry number of the directory in the Journal that was created and then deleted for exfiltration purposes on the disk?

![bf6174908be3a4077b734dd00e135960.png](/resources/bf6174908be3a4077b734dd00e135960.png)

After filter for the Directory as File Attribute, I found the `data exfil` is the one that really stand out as its name imply so I grabbed its entry number and submitted as the correct answer.

```
163896
```

>What is the starting offset of the first zip file found after the offset 4E7B00000?

![af8517c94dec4d7fbadbcb76c7615a5a.png](/resources/af8517c94dec4d7fbadbcb76c7615a5a.png)

![7857b2137f4234172259facc9744e2c2.png](/resources/7857b2137f4234172259facc9744e2c2.png)

Now its time for manual file craving via Hex Editor, I started by going to "Search" -> "Go to..." feature which I putted the offset that I want to jump to which will lead me to the offset 4E7B0000 and start to hunt from there as my starting point.

![98398f65205ca96693e2a97b1522094a.png](/resources/98398f65205ca96693e2a97b1522094a.png)

Now I went to "Search" -> "Find..." to filter for Zip file header (50 4B 03 04) and select the Search direction to "Forward" which should get us to the closest zip file behind the offset 4E7B00000.

![d6f027aa7ff73ed03f5e264e2ee6e7de.png](/resources/d6f027aa7ff73ed03f5e264e2ee6e7de.png)

Which we found the zip file that contains secret plan text file right here. 

```
4E7B0E000
```

>What is the ending offset of the zip file?

![7a51d20b808f03787c198e54f06c4714.png](/resources/7a51d20b808f03787c198e54f06c4714.png)

Now we are going to find the End of central directory record (EOCD) which has the signature = 50 4B 05 06 as shown in the image above.

![7dc2bb9b2e810db580f309b675aad729.png](/resources/7dc2bb9b2e810db580f309b675aad729.png)

But the offset 06 will not be the correct answer since there are many things following this signature as shown in the image above.

![7002916a8f360950c23f34b111b38f5c.png](/resources/7002916a8f360950c23f34b111b38f5c.png)

Noticed that I putted the red rectangle around the 16th offset and thats is the correct offset that we will have to append to get the correct answer of this question.

```
4E7B0E43D
```

>What is the flag hidden within the file inside the zip file?

![b27a0458798789e9fc6995aac2307a52.png](/resources/b27a0458798789e9fc6995aac2307a52.png)

I noticed that the file might be in FAT32 partition so I tested my luck by going to it on FTK Image and to my surprise! we can get a file of the file inside the zip file this way as well!

```
FLAG:{RECOVERED_SECRET_THM}
```

>In the FAT32 partition, a tool related to the disk wiping was installed and then deleted. Can you find the name of that executable?

![418a363b1cd0904b1502166d555768ab.png](/resources/418a363b1cd0904b1502166d555768ab.png)

I hope your Autopsy already finished ingesting because its time to use it! and we can see that it actually catches the deleted executable from the FAT32 partition and this executable is the correct answer of this question.

```
Diskwipe.exe
```

![cec604b95cabde570719279be71ecca3.png](/resources/cec604b95cabde570719279be71ecca3.png)

And now we are done!
***