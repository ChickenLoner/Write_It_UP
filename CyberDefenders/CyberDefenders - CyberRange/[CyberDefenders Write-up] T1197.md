# [CyberDefenders - T1197](https://cyberdefenders.org/blueteam-ctf-challenges/t1197/)
## Scenario
Adversaries can exploit BITS (Background Intelligent Transfer Service) jobs to persistently execute code and carry out various background tasks. BITS is a COM-exposed, low-bandwidth file transfer mechanism used by applications such as updaters and messengers, allowing them to operate in the background without interfering with other networked applications.

In this incident, an employee received multiple alerts from Windows Defender indicating the presence of malicious files on their PC. As you arrive at the scene, your goal is to use SIEM to analyze the event logs from the suspicious machine and determine the nature of the events.

**Category**: Threat Hunting

**Tools**:
Splunk
ELK

* * *
## Questions
>Q1: What is the framework used to create the backdoors?

![7de39499f3b9fc0e25e8ef56812d0d7b.png](/resources/7de39499f3b9fc0e25e8ef56812d0d7b.png)

After deploying the Splunk instance in this lab, I reviewed all log sources ingested into the instance. I confirmed that Sysmon events are not available in this dataset. However, according to the scenario, the adversary established BITS job persistence. Since BITS generates its own operational logs and related entries can also appear in the Windows Security Log, I shifted focus to analyzing these two channels instead.

Query : `index="mitre-t1197" | stats count by winlog.channel`

![ba0e608fcea71617a2636a157ec34ff0.png](/resources/ba0e608fcea71617a2636a157ec34ff0.png)

Instead of Sysmon, with less telemetry, the Security log can also log process creation and its command line. There are 245 events recorded for Event ID 4688. so I'll take a look at it first

Query : `index="mitre-t1197" "winlog.channel"=Security | stats count by winlog.event_id`

![fbd9fc68aa2f55c1034efc828e6c290f.png](/resources/fbd9fc68aa2f55c1034efc828e6c290f.png)

We can see multiple `bitsadmin.exe` processes being spawned from `powershell.exe`, which is highly abnormal. This is typical behavior of a BITS job persistence configured to run continuously.

Query : `index="mitre-t1197" "winlog.channel"=Security winlog.event_id=4688 winlog.event_data.SubjectUserName=IEUser
| sort @timestamp
|  table @timestamp,winlog.event_data.ParentProcessName,winlog.event_data.NewProcessName`

![ce77f4762eff916f3ec39c47b3a2ec10.png](/resources/ce77f4762eff916f3ec39c47b3a2ec10.png)


We can see that on 2023-07-31 18:09, `powershell.exe` spawned `schtasks.exe`, indicating scheduled task persistence being created alongside the BITS job to maintain persistence. We also see `robocopy.exe` executed, which could suggest file transfer activity, but we wouldn’t know much more without additional artifacts and Sysmon.

![9384e7d63687b64ac9b7daa424a17beb.png](/resources/9384e7d63687b64ac9b7daa424a17beb.png)

But how are we supposed to know which framework was used for the backdoor? BITS job logs and Security logs alone aren’t enough to determine that. Luckily for us, we have Windows Defender logs. By querying Event ID 1117—which records when Defender detects malware and takes action—we found a total of 7 events. That’s quite a high number for this time span.

Query : `index="mitre-t1197" Defender  "winlog.channel"="Microsoft-Windows-Windows Defender/Operational"  "winlog.event_id"=1117 | sort @timestamp`

![5541c58cc9db553d2b819e6a7a305e81.png](/resources/5541c58cc9db553d2b819e6a7a305e81.png)

The first event related to the Metasploit framework is a file transferred via a BITS job. As we can see from the file path, when BITS transfers a file, it is initially created under the name `BITSXXXX.tmp` before being renamed to its original name once the transfer is complete.

![ad3603df323b8882d2fa0b4ba6ac6660.png](/resources/ad3603df323b8882d2fa0b4ba6ac6660.png)

This is also because of BITS job.

![f31bbda8e4e7191044bb285054b33abe.png](/resources/f31bbda8e4e7191044bb285054b33abe.png)


We can see that several of them were detected as Meterpreter payloads, which are generated using the Metasploit framework—and that’s the correct answer to this question.

```
metasploit
```

>Q2: What is the name of the scheduled task that the attacker tried to create?

![69581c1080d9a1ce883f0b874cbf0eda.png](/resources/69581c1080d9a1ce883f0b874cbf0eda.png)

As we noted earlier, there were several instances of `schtasks.exe` spawned by PowerShell. We can assume the first one was task creation, and the rest were repetitions of the task running. Filtering for Security Event ID 4698 (task creation), we can see that "eviltask" was configured to execute `C:\shell.cmd` every minute as the SYSTEM user.

Query : `index="mitre-t1197" "winlog.event_id"=4698  "winlog.event_data.SubjectUserName"=IEUser | sort -@timestamp`

```
Subject:
	Security ID:		S-1-5-21-321011808-3761883066-353627080-1000
	Account Name:		IEUser
	Account Domain:		MSEDGEWIN10
	Logon ID:		0x2FBBC

Task Information:
	Task Name: 		\eviltask
	Task Content: 		<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2023-07-31T11:23:20</Date>
    <Author>MSEDGEWIN10\IEUser</Author>
    <URI>\eviltask</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT1M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2023-07-31T11:23:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\shell.cmd</Command>
    </Exec>
  </Actions>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
</Task>
```

```
eviltask
```

>Q3: What is the LOLBAS used by the malicious actor to move the backdoors to the targeted machine?
```
bitsadmin.exe
```

>Q4: When was the first attempt made by the attacker to execute the LOLBAS?

![bff3e086d6cc76d5a049f6d8469187fa.png](/resources/bff3e086d6cc76d5a049f6d8469187fa.png)

Going back to our Event ID 4688 query and get timestamp of the first `bitsadmin.exe` spawned event here as the answer of this question.

```
2023-07-31 17:39
```

>Q5: What is the IP address of the attacker?

![824735dbeb44b92260497012738553c9.png](/resources/824735dbeb44b92260497012738553c9.png)

Now it’s time to look at the BITS Client event log. We can see that at least two BITS jobs were configured to download and execute a payload from 192.168.190.136

Query : `index="mitre-t1197"  "winlog.channel"="Microsoft-Windows-Bits-Client/Operational" | sort @timestamp`

![f84cd7661efcab09f159c480183439ab.png](/resources/f84cd7661efcab09f159c480183439ab.png)

We can also retrieve the names of these BITS jobs by querying this IP address, and we can see at least 6 events associated with it.

```
192.168.190.136
```

>Q6: When was the most recent file downloaded by the attacker to the targeted machine?

![ad02a31fc5961416e1cc4078a31464d0.png](/resources/ad02a31fc5961416e1cc4078a31464d0.png)

Look at the last event from previous query or adjusted query to `sort -@timestamp` to get the answer of this question and now we are done with this lab.

```
2023-07-31 18:16
```

https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/t1197/
* * *
