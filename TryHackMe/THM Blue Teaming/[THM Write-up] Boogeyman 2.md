# [TryHackMe - Boogeyman 2](https://tryhackme.com/room/boogeyman2)
![00ec137cdfaa46c434d0941eebf3d330.png](/resources/00ec137cdfaa46c434d0941eebf3d330.png)
***
## Spear Phishing Human Resources
**The Boogeyman is back!**
Maxine, a Human Resource Specialist working for Quick Logistics LLC, received an application from one of the open positions in the company. Unbeknownst to her, the attached resume was malicious and compromised her workstation.
![b105037603ccc32d7916cfac4d0dc082.png](/resources/b105037603ccc32d7916cfac4d0dc082.png)
The security team was able to flag some suspicious commands executed on the workstation of Maxine, which prompted the investigation. Given this, you are tasked to analyse and assess the impact of the compromise.

>What email was used to send the phishing email?

![a353abab17948d10e63d6abd5bcc3ce5.png](/resources/a353abab17948d10e63d6abd5bcc3ce5.png)

We can confirm both of our evidences on the `Artefacts` folder located on the desktop right here.

![9ff237009933b86bde1b9e8abecf5476.png](/resources/9ff237009933b86bde1b9e8abecf5476.png)

By examine the eml file (email sample), we can see that this file is quite massive (1398 lines) due to the file attachment being encoded with base64.

![ddb6a070cab2c2284f4ef7aec02d53e1.png](/resources/ddb6a070cab2c2284f4ef7aec02d53e1.png)

After some trial and error, I finally got a command to get the header path that leave out the base64 encoded attachment completely (`head Resume\ -\ Application\ for\ Junior\ IT\ Analyst\ Role.eml -n 272`) so we can copy these 272 lines to [MX Toolbox](https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx?huid=32e548e5-5233-4159-b21a-51312650a2a9) for email header analysis.

![f4f686ce0b78fff62add6e4a222e2580.png](/resources/f4f686ce0b78fff62add6e4a222e2580.png)

After analyzed it, we can get the sender email from the "From" header right here.

![21f30b9baf399184b7767d1bf8ffdbb1.png](/resources/21f30b9baf399184b7767d1bf8ffdbb1.png)

And just to be sure, we will also have to cross check with "Return-Path" header which we can see that the email from both headers are matches!

```
westaylor23@outlook.com
```

>What is the email of the victim employee?

![08512d8daccd53d9982920c9785383dc.png](/resources/08512d8daccd53d9982920c9785383dc.png)

We can get the victim email address from the "To" header right here.

```
maxine.beck@quicklogisticsorg.onmicrosoft.com
```

>What is the name of the attached malicious document?

![3d99b0e4542ba19b62a0b4d91eeda2b9.png](/resources/3d99b0e4542ba19b62a0b4d91eeda2b9.png)

After reading the email body, we can see that the attacker tried to trick whatever in the position of reviewing the resume to open malicious attachment which we can see the name of an attachment right here.

```
Resume_WesleyTaylor.doc
```

>What is the MD5 hash of the malicious attachment?

![81a3076955f0ed278d7ddf544ae4ba25.png](/resources/81a3076955f0ed278d7ddf544ae4ba25.png)

To actually get the file attachment without manually copy-pasta and place it to CyberChef, I have this `tail -n +273 Resume\ -\ Application\ for\ Junior\ IT\ Analyst\ Role.eml | head -n -3 `
 command to get all the attachment lines from an email. so what's next?
 
![3a7bd079335a34c8d1eef77217b7aa1e.png](/resources/3a7bd079335a34c8d1eef77217b7aa1e.png)

We could not just decode base64 directly with the previous command since it will trigger input error and the hash won't match the original file, So I came up with this `tail -n +273 "Resume - Application for Junior IT Analyst Role.eml" | head -n -3 | tr -d '\r\n' | base64 -d > Resume_WesleyTaylor.doc` command to remove Unix new line (`\n`) and carriage return of Windows line ending (`\r`) and decode it and pipe the raw output to a file, then we should have an attachment that has MD5 hash matches what the question want.

```
52c4384a0b9e248b95804352ebec6c5b
```

>What URL is used to download the stage 2 payload based on the
document's macro?

![896384960c20b504ebffcdd16fff99f0.png](/resources/896384960c20b504ebffcdd16fff99f0.png)

Since we have Microsoft Office Document attachment then we can proceed with `olevba` tool to extract macro out of the file which we can see that upon opening this file, it will download a file from file hosting server to `C:\ProgramData\update.js` and execute it with `wscript` so from an attachment of the file and the binary that will be used to execute the stage 2 payload that the stage 2 payload is an actual JavaScript file so we will have to extract it out later.

```
https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png
```

>What is the name of the process that executed the newly downloaded stage 2 payload?
```
wscript.exe
```

>What is the full file path of the malicious stage 2 payload?
```
C:\ProgramData\update.js
```

>What is the PID of the process that executed the stage 2 payload?

![27ec5a2dab9ec258ed888ddc8970713b.png](/resources/27ec5a2dab9ec258ed888ddc8970713b.png)

We can now proceed with the memory dump, I used `vol -f WKSTN-2961.raw windows.pstree` command to display process trees which we can see that `wscript.exe` was actually executed after MalDoc was opened from the Outlook and beside that we also found the stage 3 payload (`updater.exe`) from this process tree as well!

```
4260
```

>What is the parent PID of the process that executed the stage 2 payload?
```
1124
```

>What URL is used to download the malicious binary executed by the stage 2 payload?

![efff31ab73e1ce5d278de00c3b321275.png](/resources/efff31ab73e1ce5d278de00c3b321275.png)

Its time to extract the file out from the memory dump, Lets list all the files including its virtual address to a text file with `vol -f WKSTN-2961.raw windows.filescan > file.txt` then search for the file and its virtual address of the stage 2 payload but noticed that in the memory cache, the file was not found on the `C:\ProgramData\` folder but instead it was located on the INetCache folder instead and we also have the path of stage 3 payload and also the cache file of stage 3 payload on the INetCache folder as well.

![fb0f00d09c7c33423da807c47e72af95.png](/resources/fb0f00d09c7c33423da807c47e72af95.png)

Since we got the virtual address then we can proceed with `vol -f WKSTN-2961.raw windows.dumpfiles --virtaddr 0xe58f836edc60` to dump it from the memory dump.

![bb2e26a765a575107bb8c68de4ec92db.png](/resources/bb2e26a765a575107bb8c68de4ec92db.png)

Now we can read the content of the file we reveals that it will download stage 3 payload to `C:\Windows\Tasks` as we already found it from the filescan and pstree plugins but it also added this path to User Shell Folder for persistence before execute it and sleep/delay.

```
https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe
```

>What is the PID of the malicious process used to establish the C2 connection?

![962f7287f07ffe4272e0769de127202c.png](/resources/962f7287f07ffe4272e0769de127202c.png)

We can also cross check the result of `vol -f WKSTN-2961.raw windows.cmdline` command to find that the stage 3 payload was really executed from `C:\Windows\Tasks`

![b9ddac088ba2e708fa88c0170cc4bfc5.png](/resources/b9ddac088ba2e708fa88c0170cc4bfc5.png)

So we can confirm that this is really stage 3 from all the evidence that leads to it.

```
6216
```

>What is the full file path of the malicious process used to establish the C2 connection?
```
C:\Windows\Tasks\updater.exe
```

>What is the IP address and port of the C2 connection initiated by the malicious binary? (Format: IP address:port)

![6a051b4ffabd5ad726fd841fbc71c6e3.png](/resources/6a051b4ffabd5ad726fd841fbc71c6e3.png)

I tried to use netstat plugin but it did not work so I proceeded with `vol -f WKSTN-2961.raw windows.netscan > netscan.txt` to list all connection cached from the memory dump and grep for the stage 3 payload which reveals C2 address and port used by this binary.

```
128.199.95.189:8080
```

>What is the full file path of the malicious email attachment based on the memory dump?

![5802d44e72ce439732f8dd827f487f3b.png](/resources/5802d44e72ce439732f8dd827f487f3b.png)

Review the result of cmdline plugin again then we will see the full path of email attachment from Microsoft Word process right here.

```
C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc
```

>The attacker implanted a scheduled task right after establishing the c2 callback. What is the full command used by the attacker to maintain persistent access?

![49e1daafabb653d08f1c13b84de2c93a.png](/resources/49e1daafabb653d08f1c13b84de2c93a.png)

I tried to dump strings from conhost process that was a child of stage 3 payload which should contains most of command line from the stage 3 payload but I could not find the full command line after filtered for schedule task creation command so I ended up dumping strings from the whole memory dump with `strings WKSTN-2961.raw | grep schtasks` and then we can finally see that command that responsible for schedule task persistence creation right here which will execute PowerShell base64 command that reside in the registry every day at 9.

```
schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\"'
```

![e2b78b9ba439134f51870de7e15d44d9.png](/resources/e2b78b9ba439134f51870de7e15d44d9.png)

And now we are done!

***