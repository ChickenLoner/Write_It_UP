# [HackTheBox Sherlocks - Nuts](https://app.hackthebox.com/sherlocks/Nuts)
![7571ccae44080db1a3654bf3734a6d57.png](..//resources/7571ccae44080db1a3654bf3734a6d57.png)
* * *
>Task 1: What action did Alex take to integrate the purported time-saving package into the deployment process? (provide the full command)

![621cbe8fd42d0c37729df5cbac2952b3.png](..//resources/621cbe8fd42d0c37729df5cbac2952b3.png)

After extracted archive file, I did not see sysmon log so I started exploring Administrator's user folder to find interesting files which leads me to [NuGet](https://www.nuget.org/) which is package manager for .NET and most package manager utilized PowerShell so my next objective is to find PowerShell command history located at `%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

![cc1092f00b2df7bd7517b3afbacf9cf8.png](..//resources/cc1092f00b2df7bd7517b3afbacf9cf8.png)

Here, we can see that user installed PublishIgnor package with PowerShell.

```
nuget install PublishIgnor -Version 1.0.11-beta
```

>Task 2: Identify the URL from which the package was downloaded.

![4eee22f4eb546938642771a30ce188f0.png](..//resources/4eee22f4eb546938642771a30ce188f0.png)

I used DB Browser for SQLite to open Chrome's History file which we can see that author of this sherlock did some self-promo here but there is also full url of the downloaded package here as well.

![485c8c652288ef1b682ffa930cbf125e.png](..//resources/485c8c652288ef1b682ffa930cbf125e.png)

To make our investigation a little bit easier, timeline is a key so lets convert visit time to UTC with [WebKit timestamp converter](https://www.epochconverter.com/webkit).

```
https://www.nuget.org/packages/PublishIgnor/
```

>Task 3: Who is the threat actor responsible for publishing the malicious package? (the name of the package publisher)

![24536b0820f90e67db1107b159472a11.png](..//resources/24536b0820f90e67db1107b159472a11.png)

Upon visiting package url, we could see the owner of this package (which is also author of this sherlock)

```
a1l4m
```

>Task 4: When did the attacker initiate the download of the package? Provide the timestamp in UTC format (YYYY-MM-DD HH:MM).

![336c6a59dc4d17983041687bb8dd0f8a.png](..//resources/336c6a59dc4d17983041687bb8dd0f8a.png)

I used MFTCmd.exe to parse `$MFT` file so we could use Master File Table record to identify timestamp that related files from this package was created on this system.

![fb224c54d901eac4d83bb567209aeb1d.png](..//resources/fb224c54d901eac4d83bb567209aeb1d.png)

We already know the name of package, package URL visited timestamp so the downloaded time had to happened after that which we can just search for `nuget` and it will land us with the these results.

```
2024-03-19 18:41
```

>Task 5: Despite restrictions, the attacker successfully uploaded the malicious file to the official site by altering one key detail. What is the modified package ID of the malicious package?

![c7578be3f500be967364e138b7c40a31.png](..//resources/c7578be3f500be967364e138b7c40a31.png)

We can get package ID of any package by inspecting nuspec file of each package and in this case, malicious package's nuspec file can be found here.

![5c79c159ca183278ab6cd342f3575d9a.png](..//resources/5c79c159ca183278ab6cd342f3575d9a.png)

nuspec stores metadata in xml format and we can get package ID from id tag right there.

```
PublishIgnor
```

>Task 6: Which deceptive technique did the attacker employ during the initial access phase to manipulate user perception? (technique name)

![87dd4a3693119efc999448dae320f8d4.png](..//resources/87dd4a3693119efc999448dae320f8d4.png)

At first I dug into `Windows PowerShell.evtx` to find anything suspicious and it leaded me to this file, we can see that this script will disable real time monitoring and scanning of mapped network drives then proceed to set Path environment variable to Microsoft Visual Studio and create it if that directory is not exist and then it will download file from C2 server and execute it.

I also did some search on NuGet exploitation and I found out that this script actually match malicious payload of from articles below 
- https://www.bleepingcomputer.com/news/security/hackers-target-net-developers-with-malicious-nuget-packages/
- https://jfrog.com/blog/impala-stealer-malicious-nuget-package-payload/

and after reviewing what happened then so this sherlock is about Impala stealer dropped from malicious NuGet package that got installed via typosquatting technique.

```
typosquatting
```

>Task 7: Determine the full path of the file within the package containing the malicious code.
```
C:\Users\Administrator\.nuget\packages\publishignor\1.0.11-beta\tools\init.ps1
```

>Task 8: When tampering with the system's security settings, what command did the attacker employ?
```
Set-MpPreference -DisableRealtimeMonitoring $true
```

>Task 9: Following the security settings alteration, the attacker downloaded a malicious file to ensure continued access to the system. Provide the SHA1 hash of this file.

![aaf1d6f3480db4486dcbe1154cf53661.png](..//resources/aaf1d6f3480db4486dcbe1154cf53661.png)

This one is a little bit tricky to find, I had to skip to Task 12 first to know that Microsoft Defender detected this payload revealing C2 framework that was utilized (Sliver).

![bc2913c707db221eb2f2ebb0d3dff00a.png](..//resources/bc2913c707db221eb2f2ebb0d3dff00a.png)

Then I went to Microsoft Defender directory to find relevant logs, Fortunately this log stores SHA1 of detected file as you can see right here.

```
57b7acf278968eaa53920603c62afd8b305f98bb
```

I also searched this hash on VirusTotal and Hybrid Analysis which result with no result so this file might be a custom payload made by author of this sherlock.

>Task 10: Identify the framework utilised by the malicious file for command and control communication.
```
Sliver
```

>Task 11: At what precise moment was the malicious file executed?

![860c519c0944c2bec909334dd6d7d1ae.png](..//resources/860c519c0944c2bec909334dd6d7d1ae.png)

I parsed prefetch folder and found that it was not logged last run time in Output csv file (Source Modified timestamp is not the answer of this task) so we have to check Timeline csv file instead

Notice that `whoami.exe` was executed after this payload so C2 connection might be successful and the attacker ran this command to confirm who is the one executed payload.

![0d933a9cd1f44a0f03e98ce7d1758b28.png](..//resources/0d933a9cd1f44a0f03e98ce7d1758b28.png)

I found the run time of this payload in Timeline csv file which was accepted as the answer of this question meaning that it is the actual run time of this payload.

```
2024-03-19 19:23:36
```

>Task 12: The attacker made a mistake and didn’t stop all the features of the security measures on the machine. When was the malicious file detected? Provide the timestamp in UTC.
```
2024-03-19 19:33:32
```

>Task 13: After establishing a connection with the C2 server, what was the first action taken by the attacker to enumerate the environment? Provide the name of the process.

We already found an answer of this question on task 11
```
whoami.exe
```

>Task 14: To ensure continued access to the compromised machine, the attacker created a scheduled task. What is the name of the created task?

![b2e89093b1d490ba21532b0572d53d13.png](..//resources/b2e89093b1d490ba21532b0572d53d13.png)

After navigated to Tasks directory, I noticed that there is one task that was modified after payload was executed.

![181fbc0d28a09b4b654a7f086f9a3d05.png](..//resources/181fbc0d28a09b4b654a7f086f9a3d05.png)

This task was set to disable real time monitoring so there is no doubt that this is the task created by the attacker

```
MicrosoftSystemDailyUpdates
```

>Task 15: When was the scheduled task created? Provide the timestamp in UTC.

![0f5573233f98aec80f18547ec8cdaa48.png](..//resources/0f5573233f98aec80f18547ec8cdaa48.png)

Right click to inspect property of this task, we can see the Modified timestamp that can be used to answer this task.

```
2024-03-19 19:24:05
```

>Task 16: Upon concluding the intrusion, the attacker left behind a specific file on the compromised host. What is the name of this file?

![6f6b22a34ed5690bb111f4f3a49e5bac.png](..//resources/6f6b22a34ed5690bb111f4f3a49e5bac.png)

After reviewing Prefetch Timeline csv again, I noticed another file was executed from `ProgramData` directory so I parsed Amcache hive to get SHA1 hash of this file.

![5c854d2b3ed12f4eb89700ced0367897.png](..//resources/5c854d2b3ed12f4eb89700ced0367897.png)

Here is the result hash from Amcacheparser, now we can use this hash to search on VirusTotal.

![37e6fe6b99b6a7cb3a05b246d46d0b96.png](..//resources/37e6fe6b99b6a7cb3a05b246d46d0b96.png)

![6d0a1ecace417eafa577ebfa02c8d751.png](..//resources/6d0a1ecace417eafa577ebfa02c8d751.png)

It is Impala stealer malware that we read from those articles!

```
file.exe
```

>Task 17: As an anti-forensics measure. The threat actor changed the file name after executing it. What is the new file name?

![bf19f9401783c247878863fa13479377.png](..//resources/bf19f9401783c247878863fa13479377.png)

I noticed `Updater.exe` file inside `ProgramData` directory which is weird so I calculated filehash and ...Sure enough, It is the new file name of `file.exe` 

```
Updater.exe
```

>Task 18: Identify the malware family associated with the file mentioned in the previous question (17).
```
Impala
```

>Task 19: When was the file dropped onto the system? Provide the timestamp in UTC.

![9a03e9133a7b44aa378fb39b8877c001.png](..//resources/9a03e9133a7b44aa378fb39b8877c001.png)

Back to Master File Table record, Search for this file and submit timestamp in "Created0x10" field.

```
2024-03-19 19:30:04
```

![d72e6f6c95b59bd3cc94155541e6d2d1.png](..//resources/d72e6f6c95b59bd3cc94155541e6d2d1.png)
https://labs.hackthebox.com/achievement/sherlock/1438364/752
* * *
