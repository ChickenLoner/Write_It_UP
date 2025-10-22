# [TryHackMe - New Hire Old Artifacts](https://tryhackme.com/room/newhireoldartifacts)
![1555d39d23fcc08b2c93301f14e7c4b5.png](/resources/1555d39d23fcc08b2c93301f14e7c4b5.png)
***
You are a SOC Analyst for an MSSP (managed Security Service Provider) company called TryNotHackMe.

A newly acquired customer (Widget LLC) was recently onboarded with the managed Splunk service. The sensor is live, and all the endpoint events are now visible on TryNotHackMe's end. Widget LLC has some concerns with the endpoints in the Finance Dept, especially an endpoint for a recently hired Financial Analyst. The concern is that there was a period (December 2021) when the endpoint security product was turned off, but an official investigation was never conducted. 

Your manager has tasked you to sift through the events of Widget LLC's Splunk instance to see if there is anything that the customer needs to be alerted on. 

Happy Hunting!
***
![82f9c7fe74b4cadb2323743b21b39847.png](/resources/82f9c7fe74b4cadb2323743b21b39847.png)

Once we accessed to the Splunk web interface, we can use `index=*` query with all time preset to see the volumes of log we have which we have total of 27,378 events from 4 different log sources including Sysmon as well, with Sysmon present then we gonna use it for the rest of this investigation.

>A Web Browser Password Viewer executed on the infected machine. What is the name of the binary? Enter the full path.

![e88dbbf15548161c5030b2c4e08ddf09.png](/resources/e88dbbf15548161c5030b2c4e08ddf09.png)

I started off my using `index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1` query which listed all Process Creation event and this event ID will also logged the **OriginalFileName** of the executable file as well, as you can see that there is `ChromeCookiesView.exe` from NirSoft was executed on infected machine.

![4830a4713c4fa3c82ed3762b2915af89.png](/resources/4830a4713c4fa3c82ed3762b2915af89.png)

Then I scoped down the event with `index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 OriginalFileName="ChromeCookiesView.exe"` query and inspect the first event from this query which we can see that its really ChromeCookiesView from NirSoft and it was executed from Temp directory (another red flag that malware often dropped).

```
C:\Users\FINANC~1\AppData\Local\Temp\11111.exe
```

>What is listed as the company name?
```
NirSoft
```

>Another suspicious binary running from the same folder was executed on the workstation. What was the name of the binary? What is listed as its original filename? (**format: file.xyz,file.xyz**)

![2ff030f69cd7e0efa600adb4a2327355.png](/resources/2ff030f69cd7e0efa600adb4a2327355.png)

Next I reduced my scope of finding with `index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Temp  OriginalFileName!="-" | stats  count by OriginalFileName, Image` query that find for any Process Creation events with "Temp" string and **OriginalFileName** value is not null which we can see that beside ProcMon, there is another binary executed from the same folder of the same workstation.

![8baab13ba9e515f3f6252444d7193f82.png](/resources/8baab13ba9e515f3f6252444d7193f82.png)

I copied file hash and search it on VirusTotal

![a99504cb5673238c1c6f5238bbbfbaab.png](/resources/a99504cb5673238c1c6f5238bbbfbaab.png)

Then we can see that the [file](https://www.virustotal.com/gui/file/a798591090c33182526993e634f67fb09e69d243b82a042d26d63c0b9bfba47a/detection) we got is flagged as malicious by different 54 security vendors so look like we got the right file here.

```
IonicLarge.exe,PalitExplorer.exe
```

>The binary from the previous question made two outbound connections to a malicious IP address. What was the IP address? Enter the answer in a defang format.

![393f3503bb06684628d8b403b3652b90.png](/resources/393f3503bb06684628d8b403b3652b90.png)

Knowing the image, I used `index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 IonicLarge.exe` query and inspect different **DestinationIp** addresses that need some manual check.

![3c24e8a047e2a77e79be79f12c106403.png](/resources/3c24e8a047e2a77e79be79f12c106403.png)

After reviewing the result from previous query, we navigated back to the **Contacted IP addresses** section under the **Relations** tab. Here, we compared the results of our previous query to the list of IP addresses contacted by the binary flagged on VirusTotal. and then we identified two IP addresses flagged as malicious. However, the correct answer to this question is 2.56.59.42.

```
2[.]56[.]59[.]42
```

>The same binary made some change to a registry key. What was the key path?

![b4ae96f8c4d324b016c2585f47b65704.png](/resources/b4ae96f8c4d324b016c2585f47b65704.png)

To identify registry changes made by this binary, I queried Splunk with `index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 IonicLarge.exe`

This query filters for Sysmon Event ID 13, which logs registry modifications, specifically those made by IonicLarge.exe. The results revealed that most of the registry changes were related to Windows Defender settings which make it able to continue operates without being detected and quarantined .

```
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender
```

>Some processes were killed and the associated binaries were deleted. What were the names of the two binaries? (**format: file.xyz,file.xyz**)

![915be9a7433d9cf603d660978090975d.png](/resources/915be9a7433d9cf603d660978090975d.png)

When speaking about killing the process, `taskkill` is the binary that would come to mind so I queried with`index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 taskkill` which returned with commands that were used to kill 2 un-readable processes and we can see that it was executed via cmd and it will not just kill both processes but also delete them from infected system as well. 

```
WvmIOrcfsuILdX6SNwIRmGOJ.exe,phcIAmLJMAIMSa9j9MpgJo1m.exe
```

>The attacker ran several commands within a PowerShell session to change the behaviour of Windows Defender. What was the last command executed in the series of similar commands?

![2d1e8f98faae858a34c91e1334c28e6b.png](/resources/2d1e8f98faae858a34c91e1334c28e6b.png)

I used `index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 | sort by UtcTime
| table UtcTime, User, CommandLine` query to create a table that can be traced process creation events nicely which we can see that there are several commands with PowerShell to change Windows Defender settings as the question imply and the last command was executed at 2021-12-29 01:09:30 UTC

![69d72159a8dd2655feea8e74283520ff.png](/resources/69d72159a8dd2655feea8e74283520ff.png)

If we kept scrolling up to events before this happened, we could see that there is a massive command line execution at 2021-12-29 01:07:51 UTC which responsible for those PowerShell commands we found earlier.

```
powershell  WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147737394 ThreatIDDefaultAction_Actions=6 Force=True
```

>Based on the previous answer, what were the four IDs set by the attacker? Enter the answer in order of execution. (format: 1st,2nd,3rd,4th)

![9a38ca68617a386e26c5c8005c703d57.png](/resources/9a38ca68617a386e26c5c8005c703d57.png)

We can copy them directly from the command since it will be executed in order.

```
2147735503,2147737010,2147737007,2147737394
```

>Another malicious binary was executed on the infected workstation from another AppData location. What was the full path to the binary?

![4dea910dd7c77bd3edbca14491ce5297.png](/resources/4dea910dd7c77bd3edbca14491ce5297.png)

Before I resorted to do any advanced query, I started off with `index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" AppData` query and we can see that there is another binary got executed from AppData location which is not in Temp just like others we found earlier and its so weird that I didn't find Event ID 1 related to this binary at all.

![741b18790fba00f654b7d8780d253508.png](/resources/741b18790fba00f654b7d8780d253508.png)

So I searched for other event ID which I found that `11111.exe` which we know that its the **ChromeCookieViewer** from **NirSoft** actually accessed this process at 2021-12-29 01:09:50 UTC, 20 seconds after the latest PowerShell to tamper with Windows Defender was executed.

```
C:\Users\Finance01\AppData\Roaming\EasyCalc\EasyCalc.exe
```

>What were the DLLs that were loaded from the binary from the previous question? Enter the answers in alphabetical order. (format: file1.dll,file2.dll,file3.dll)

![4782a6c437feea06a925a230aa22c8e1.png](/resources/4782a6c437feea06a925a230aa22c8e1.png)

We can use `index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EasyCalc.exe EventCode=7` query to get all Loaded Library/Dll events related to this binary and despite 11 library were loaded, there are only 3 dll were loaded from the same location as the binary itself which are the correct answers of this question.

```
ffmpeg.dll,nw.dll,nw_elf.dll
```

![38d18123df37ac45433dbd9925a855e4.png](/resources/38d18123df37ac45433dbd9925a855e4.png)

There are a lot of weird things that could be explored on this room but since we completed the room, lets wrap it up here.
***