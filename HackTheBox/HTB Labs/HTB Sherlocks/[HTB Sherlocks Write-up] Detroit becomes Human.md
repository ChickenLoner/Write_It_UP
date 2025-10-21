# [HackTheBox Sherlocks - Detroit becomes Human](https://app.hackthebox.com/sherlocks/Detroit%20becomes%20Human)
Created: 12/08/2024 19:56
Last Updated: 13/08/2024 01:25
* * *

![3414b8fc291e3f87f5d22658b926ffef.png](..//resources/3414b8fc291e3f87f5d22658b926ffef.png)
**Scenario:**
Alonzo Spire is fascinated by AI after noticing the recent uptick in usage of AI tools to help aid in daily tasks. He came across a sponsored post on social media about an AI tool by Google. The post had a massive reach, and the Page which posted had 200k + followers. Without any second thought, he downloaded the tool provided via the Post. But after installing it he could not find the tool on his system which raised his suspicions. A DFIR analyst was notified of a possible incident on Forela's sysadmin machine. You are tasked to help the analyst in analysis to find the true source of this odd incident.

* * *
>Task 1: What is the full link of a social media post which is part of the malware campaign, and was unknowingly opened by Alonzo spire?

![f4b9b37ff414484d71378f9e8b1cb052.png](..//resources/f4b9b37ff414484d71378f9e8b1cb052.png)

We were given Microsoft Edge artefacts which mean we can only examine Edge's history file right here

![b39326da11e7e21006e10f6135905576.png](..//resources/b39326da11e7e21006e10f6135905576.png)

Go to `urls` then we can see that user visit facebook post about GEMINI which lead to download link of suspicious file

```
https://www.facebook.com/AI.ultra.new/posts/pfbid0BqpxXypMtY5dWGy2GDfpRD4cQRppdNEC9SSa72FmPVKqik9iWNa2mRkpx9xziAS1l
```

>Task 2: Can you confirm the timestamp in UTC when alonzo visited this post?

![f6fbdad0ccf1e258c74cc8f185d787d4.png](..//resources/f6fbdad0ccf1e258c74cc8f185d787d4.png)

We can copy timestamp of the history database to https://www.epochconverter.com/webkit which will convert 13355296200136503 to Tuesday, March 19, 2024 4:30:00 AM

```
2024-03-19 04:30:00
```

>Task 3: Alonzo downloaded a file on the system thinking it was an AI Assistant tool. What is name of the archive file downloaded?

![058a51dc2cacb4104c67d3a62f2f97be.png](..//resources/058a51dc2cacb4104c67d3a62f2f97be.png)

Go to `downloads` table and find name of a file that was downloaded and the destination path of that file

```
AI.Gemini Ultra For PC V1.0.1.rar
```

>Task 4: What was the full direct url from where the file was downloaded?

![edaed4dc1ccc354daaf2273be7be58ac.png](..//resources/edaed4dc1ccc354daaf2273be7be58ac.png)

We can go to `downloads_url_chains` which stores full direct url of the downloaded files and we already know that the last one is the one we are looking for

```
https://drive.usercontent.google.com/download?id=1z-SGnYJCPE0HA_Faz6N7mD5qf0E-A76H&export=download
```

>Task 5: Alonzo then proceeded to install the newly download app, thinking that its a legit AI tool. What is the true product version which was installed?

![2a1c20478830529b10b79eb1852b6439.png](..//resources/2a1c20478830529b10b79eb1852b6439.png)

I want to confirm if the installer is msi file or an exe file so I used `MFTECmd` to parse `$MFT` file

![bece7f63d8fb5076000628918e396931.png](..//resources/bece7f63d8fb5076000628918e396931.png)

Then put an output file to `Timeline Explorer`, then we can see that an installer is indeed msi file or Windows Installer file

![df9afbc534f015af8b969417c91106a6.png](..//resources/df9afbc534f015af8b969417c91106a6.png)

So we can proceed to use any registry lookup tool to examine Uninstall key which also stores version of this software and as you can see that version that was installed is so different with the version stated on the installer 

```
3.32.3
```

>Task 6: When was the malicious product/package successfully installed on the system?

![b2f9654e11d6e1db68c57746a19cfab4.png](..//resources/b2f9654e11d6e1db68c57746a19cfab4.png)

Go back to the result from `MFTECmd`, find the "last access" timestamp which is the timestamp indicating the installation was done at that time from this file

```
2024-03-19 04:31:33
```

>Task 7: The malware used a legitimate location to stage its file on the endpoint. Can you find out the Directory path of this location?

![fde9d60d0221fbab2eb5ac827d8a3946.png](..//resources/fde9d60d0221fbab2eb5ac827d8a3946.png)

I tried to find any legitimate directory around installation period then we can see that this path is very suspicious because there are some js files, cmd file and ps1 file on this directory but I still could not confirm yet

![1904ba2e73390b13bd144a2ba280b46d.png](..//resources/1904ba2e73390b13bd144a2ba280b46d.png)

I digged a little bit deeper then I finally found that a file that user downloaded is in Recycle Bin so we can get file hash on search it on public malware sandbox to find more clue about this

![071ec6ab8ac1b30ce05b1a7c078e4059.png](..//resources/071ec6ab8ac1b30ce05b1a7c078e4059.png)

Then on Recorded Future Triage, we could see that one of `ps1` file also stores malware configuration and it also confirmed the path used by this installer for staging

```
C:\Program Files (x86)\Google
```

>Task 8: The malware executed a command from a file. What is name of this file?

![bc4e8ed756b3e5b8f9f92e4cd72b8511.png](..//resources/bc4e8ed756b3e5b8f9f92e4cd72b8511.png)

From public malware sandbox report, we could see that `install.cmd` was executed first then which will executed `ru.ps1` with PowerShell 

![d78ec9f745845302e622cbe72d0a6eee.png](..//resources/d78ec9f745845302e622cbe72d0a6eee.png)

So how about we do not waste our precious artefact and use `PECmd` to parse prefetch folder to find the timestamp of both powershell and cmd to see if both were executed during installation period

![d2445f4241bc4f15d97a28b82f2c2106.png](..//resources/d2445f4241bc4f15d97a28b82f2c2106.png)

We know that installation ended at 04:31:33 so both executable files were execute during that period

![0bc8f7ef2ba302b1fbb3a586da623325.png](..//resources/0bc8f7ef2ba302b1fbb3a586da623325.png)

And we also confirmed that `install.cmd` was loaded with `cmd.exe`

```
INSTALL.CMD
```

>Task 9: What are the contents of the file from question 8? Remove whitespace to avoid format issues.

![b876406041badc6958cd3d63e9d30446.png](..//resources/b876406041badc6958cd3d63e9d30446.png)

We can go to public sandbox to recover all files we need but since `installer.cmd` is very small so we can calculate MFT offset and recover it directory from `$MFT` file (if you're playing this sherlock then you should already know how to calculate this offset but in case you didn't, then go play BFT sherlock)

![c66362a45a502a54dc2ac001dc5bf400.png](..//resources/c66362a45a502a54dc2ac001dc5bf400.png)

Then after we got the right offset, use "go to" to go straight to that record then we can see the content of this script which is a command to run `ps1` script in the background (not notify user) 

![ca8a1d4f26a1c68df368a399457d76fe.png](..//resources/ca8a1d4f26a1c68df368a399457d76fe.png)

To submit an answer, use CyberChef to remove whitespace for us

```
@echooffpowershell-ExecutionPolicyBypass-File"%~dp0nmmhkkegccagdldgiimedpic/ru.ps1"
```

>Task 10: What was the command executed from this file according to the logs?

![466f1f15280e50222d5ec99aa9e555f9.png](..//resources/466f1f15280e50222d5ec99aa9e555f9.png)

We can find this from PowerShell event log file

```
powershell -ExecutionPolicy Bypass -File C:\Program Files (x86)\Google\Install\nmmhkkegccagdldgiimedpic/ru.ps1
```

>Task 11: Under malware staging Directory, a js file resides which is very small in size.What is the hex offset for this file on the filesystem?

![ab8bb139ff21f3e1eef0b1fd05be9815.png](..//resources/ab8bb139ff21f3e1eef0b1fd05be9815.png)

There are 2 js files on this directory but the smaller one is `content.js` file

![267edae03cae4a0debd1d45b05cb7f6d.png](..//resources/267edae03cae4a0debd1d45b05cb7f6d.png)

calculate an offset to answer this task

```
3E90C00
```

>Task 12: Recover the contents of this js file so we can forward this to our RE/MA team for further analysis and understanding of this infection chain. To sanitize the payload, remove whitespaces.

![34d13c2ba9af8e012448c0dc6257aade.png](..//resources/34d13c2ba9af8e012448c0dc6257aade.png)

We can do this by go to the offset we just calculated from previous task, remove whitespace and fix some characters

![690b0a3a8627290fdbb73a1db8a4df1b.png](..//resources/690b0a3a8627290fdbb73a1db8a4df1b.png)

Or we can get hash from public report (in my case, recorded future triage)

![9df9d62c0924160fd180b2b98bf0f8fe.png](..//resources/9df9d62c0924160fd180b2b98bf0f8fe.png)

And search it on any.run public report and from here, we did not need to fix anything 

![13fd5305bbd8c98c6cd8030c96f3e632.png](..//resources/13fd5305bbd8c98c6cd8030c96f3e632.png)

just remove whitespace and submit this as an answer

```
varisContentScriptExecuted=localStorage.getItem('contentScriptExecuted');if(!isContentScriptExecuted){chrome.runtime.sendMessage({action:'executeFunction'},function(response){localStorage.setItem('contentScriptExecuted',true);});}
```

>Task 13: Upon seeing no AI Assistant app being run, alonzo tried searching it from file explorer. What keywords did he use to search?

![711eb6d9c31b393b4726707827941139.png](..//resources/711eb6d9c31b393b4726707827941139.png)

We did not have Windows Search artefact but we still have `NTUSER.DAT` so lets open it with any registry viewer you have and inspect `\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` key then we will see that this user searched for this tool at this specific time

```
Google Ai Gemini tool
```

>Task 14: When did alonzo searched it?
```
2024-03-19 04:32:11
```

>Task 15: After alonzo could not find any AI tool on the system, he became suspicious, contacted the security team and deleted the downloaded file. When was the file deleted by alonzo?

![92587bdf5a4d8ae83904cb0d8db2037b.png](..//resources/92587bdf5a4d8ae83904cb0d8db2037b.png)

For this one, we need [$I Parse](https://df-stream.com/recycle-bin-i-parser/) to parse content of $I file which contains deleted timestamp of retrospective item it was linked to

![a18fbcd6335de58a0a44ddfacad23c9b.png](..//resources/a18fbcd6335de58a0a44ddfacad23c9b.png)

We will have tsv (tab separated value) file as an output, and here is the one we're looking for

```
2024-03-19 04:34:16
```

>Task 16: Looking back at the starting point of this infection, please find the md5 hash of the malicious installer.
```
bf17d7f8dac7df58b37582cec39e609d
```

![48f2e1a82fa22727bbf7a97be3bb09f8.png](..//resources/48f2e1a82fa22727bbf7a97be3bb09f8.png)
https://labs.hackthebox.com/achievement/sherlock/1438364/697
* * *
