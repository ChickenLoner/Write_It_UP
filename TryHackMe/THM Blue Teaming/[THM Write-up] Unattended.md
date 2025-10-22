# [TryHackMe - Unattended](https://tryhackme.com/r/room/unattended)
![15d873da8fa3dcfa082e95343b2a508b.png](/resources/15d873da8fa3dcfa082e95343b2a508b.png)
***
## Table of Contents

- [Snooping around](#snooping-around)
- [Can't simply open it](#cant-simply-open-it)
- [Sending it outside](#sending-it-outside)

***
Welcome to the team, kid. I have something for you to get your feet wet.
Our client has a newly hired employee who saw a suspicious-looking janitor exiting his office as he was about to return from lunch.

I want you to investigate if there was user activity while the user was away **between 12:05 PM to 12:45 PM on the 19th of November 2022**. If there are, figure out what files were accessed and exfiltrated externally.

You'll be accessing a live system, but use the disk image already exported to the `C:\Users\THM-RFedora\Desktop\kape-results\C` directory for your investigation. The link to the tools that you'll need is in `C:\Users\THM-RFedora\Desktop\tools` 

Finally, I want to remind you that you signed an NDA, so avoid viewing any files classified as top secret. I don't want us to get into trouble.
***
## Snooping around
Initial investigations reveal that someone accessed the user's computer during the previously specified timeframe.

Whoever this someone is, it is evident they already know what to search for. Hmm. Curious.

> What file type was searched for using the search bar in Windows Explorer?

![3a83bf3a6e8de181fb30d6d63fdf8075.png](/resources/3a83bf3a6e8de181fb30d6d63fdf8075.png)

After we deployed the machine, we have tools on the `C:\Tools` folder and evidence on the Kape result folder on the desktop. 

![36b01c9726c7659e4270f92094077f8b.png](/resources/36b01c9726c7659e4270f92094077f8b.png)

Speaking about Windows Search, we can inspect **WordWheelQuery** registry key from the only non-default user on this system with Registry Explorer tool.

![4fc8d9d451cc85af5a22131a75fcdc1d.png](/resources/4fc8d9d451cc85af5a22131a75fcdc1d.png)

Registry Explorer 1.6 is quite an old version but could still get a job done, we could see that on the first record from **WordWheelQuery** registry is ".pdf" which is the first keyword searched and the answer of this question.

```
.pdf
```

> What top-secret keyword was searched for using the search bar in Windows Explorer?

![d1c09dd3625bccfcf44683e45d7da306.png](/resources/d1c09dd3625bccfcf44683e45d7da306.png)

Inspecting the second record, reveal the second keyword that was searched with Windows Search. 

```
continental
```

* * *
## Can't simply open it
Not surprisingly, they quickly found what they are looking for in a matter of minutes.

Ha! They seem to have hit a snag! They needed something first before they could continue.

***Note**:  When using the Autopsy Tool, you can speed up the load times by only selecting "Recent Activity" when configuring the Ingest settings.*
![a58fb21e107ed72fc9ea429b4921b555.png](/resources/a58fb21e107ed72fc9ea429b4921b555.png)

>What is the name of the downloaded file to the Downloads folder?

![c03015b61abd0abeaeda0e84b8a7c11d.png](/resources/c03015b61abd0abeaeda0e84b8a7c11d.png)

We have to use Autopsy for this one so after create a new case, we have to specify the folder as our logical files like this then follow the guide provides to only select Recent Activity injest module to run.

![2429c020082f378ef1eefd60740b4045.png](/resources/2429c020082f378ef1eefd60740b4045.png)

Wait a while for the result which then we can look into "Web Downloads" to find which files were downloaded to user's download folder and we could see that user downloaded `continental.7z` which then downloaded the installer of 7zip, which mean the 7z is not installed on the system and user downloaded it to extract the file. 

```
7z2201-x64.exe
```

>When was the file from the previous question downloaded? (YYYY-MM-DD HH:MM:SS UTC)
```
2022-11-19 12:09:19 UTC
```

>Thanks to the previously downloaded file, a PNG file was opened. When was this file opened? (YYYY-MM-DD HH:MM:SS)

![ee09de1912830295d2708e949c32f63c.png](/resources/ee09de1912830295d2708e949c32f63c.png)

We have to go back to the Registry Explorer and inspect **RecentDocs** registry key which separate each file extenstion to each subkey so we can inspect **.png** sub key to find the only file that was opened by the user and the **Last write** timestamp of this registry is the timestamp that the file was opened.
 
![e70d166ed1e582990d15c54fd7f31a42.png](/resources/e70d166ed1e582990d15c54fd7f31a42.png)

We could even find the full path of this file on Autopsy like this.

```
2022-11-19 12:10:21
```

* * *
## Sending it outside
Uh oh. They've hit the jackpot and are now preparing to exfiltrate data outside the network.

There is no way to do it via USB. So what's their other option?

>A text file was created in the Desktop folder. How many times was this file opened?

![300c4d9c8116e28202cd5ca1eb59ba25.png](/resources/300c4d9c8116e28202cd5ca1eb59ba25.png)

We also have JumpLists as our evidence and from the shortcut file inside this folder, we can see that `launchcode` is likely to be that text file so we have to parse JumpLists to find out how many times this file was opened.

![8145f471c36a2ad29e739d0be49a4a85.png](/resources/8145f471c36a2ad29e739d0be49a4a85.png)

We can proceed with `JLECmd.exe -d C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent --csv output` command to parse all files inside JumpLists folder.

![eef34ed8aedc5c2f6c3874316e49042b.png](/resources/eef34ed8aedc5c2f6c3874316e49042b.png)

Now we should have 2 output files from **AutomaticDestinations** and **CustomDestinations**.

![c62dad25c64f332355f64e2630f66565.png](/resources/c62dad25c64f332355f64e2630f66565.png)

We don't have **Timeline Explorer** but we still have **EZViewer** so we could open **AutomaticDestinations** output file with it which we will see that the text file was opened 2 times from the interaction column.

```
2
```

>When was the text file from the previous question last modified? (MM/DD/YYYY HH:MM)

![c982523d0b8f7ddfd72aa8d2e4dd5abb.png](/resources/c982523d0b8f7ddfd72aa8d2e4dd5abb.png)

We have to get the value from LastModified column which we can see that the interaction timeline was align with the incident. 

```
11/19/2022 12:12
```

>The contents of the file were exfiltrated to pastebin.com. What is the generated URL of the exfiltrated data?

![b58fc99182e1ad3112ac51b158f84122.png](/resources/b58fc99182e1ad3112ac51b158f84122.png)

We will have to go back to Autopsy again to check "Web History" which we will see the pastebin URL that was accessed by user and the timeline also align within the incident timeframe as well.

```
https://pastebin.com/1FQASAav
```

>What is the string that was copied to the pastebin URL?

![5a2998ee7158db6a0640d851e9f7dbb5.png](/resources/5a2998ee7158db6a0640d851e9f7dbb5.png)

We can access this URL directly with our browser to get the content inside this URL.

```
ne7AIRhi3PdESy9RnOrN
```

![72fa51162058bc6ab3156e667aa31c6d.png](/resources/72fa51162058bc6ab3156e667aa31c6d.png)

And now we are done!
* * *