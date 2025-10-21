# [HackTheBox Sherlocks - OpSalwarKameez24-2: Magic-Show](https://app.hackthebox.com/sherlocks/OpSalwarKameez24-2:%20Magic-Show)
Created: 03/11/2024 14:50
Last Updated: 23/11/2024 17:13
* * *
![cdfbe1a6c9dd3998b7a6fe088687724c.png](..//resources/cdfbe1a6c9dd3998b7a6fe088687724c.png)

**Scenario:**
StoreD Technologies’ System Administrators have observed several machines on the network unexpectedly rebooting to apply Windows updates during working hours. According to the organization’s update policy, these updates should only occur overnight. As a member of StoreD Technologies’ incident response team, your task is to investigate whether this unusual activity is linked to an ongoing security incident. System logs and a memory dump from one of the affected Windows 11 machines have been collected to assist in your investigation.

* * *
>Task 1: At What time did the compromised account first authenticate to the workstation? (UTC)

![804e9dcbb47d10511ae696abf2f5438e.png](..//resources/804e9dcbb47d10511ae696abf2f5438e.png)

We got artifacts collected by KAPE and first thing I went to check is Windows event log to find useful log such as sysmon but unfortunately, we don't have sysmon on this sherlock. 

![9d6c02bc7570c88be06648264128bb44.png](..//resources/9d6c02bc7570c88be06648264128bb44.png)

I parsed many logs file such as **PowerShell** log, **Security** log and **Local Session Manager** log (I called it RDP incoming connection log) which I found this IP address had so many log on sessions with compromised system which turn out it is the answer of Task 4 so I came close to the actual timestamp but none of these timestamps is the timestamp that was asked on this task.

![8329653bb53d1449ae7b0f45db8c9e5b.png](..//resources/8329653bb53d1449ae7b0f45db8c9e5b.png)

So we have to get successful logon event timestamp from Security log right here.

```
2024-10-22 15:25:57
```

>Task 2: What protocol did the threat actor us to access the workstation?

![9d6c02bc7570c88be06648264128bb44.png](..//resources/9d6c02bc7570c88be06648264128bb44.png)
We already know that this IP address was found in Local Session log so the protocol that used to access this workstation is **Remote Desktop Protocol (RDP)**
```
rdp
```

>Task 3: What logon type was logged when the threat actor accessed the workstation?

![16dab27fff6a9cef95bb9a9f719db8fc.png](..//resources/16dab27fff6a9cef95bb9a9f719db8fc.png)
The logon type field indicates the kind of logon that occurred and when connected to any workstation with RDP, Windows will log **10** as logon type which is **RemoteInteractive** 
```
10
```

>Task 4: What was the IP address of the workstation the threat actor pivoted through to access the internal network?
```
10.10.0.81
```

>Task 5: At what time did the threat actor first attempt to bypass a feature of Windows Defender? (UTC)

Before searching on PowerShell event log I wanted to check for other artifacts that logged PowerShell command which is **PowerShell Console Log** and since we already knew that "**arjun.patel**" was the compromised user.

![6a73e09909a54d09cbfd55db4f75ce24.png](..//resources/6a73e09909a54d09cbfd55db4f75ce24.png)

So I dug into AppData folder of this user searching for console log and luckily for us that this log was also presented and we have commands to [bypass AMSI](https://gustavshen.medium.com/bypass-amsi-on-windows-11-75d231b2cac6) and commands to downloaded and executed [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) to enumerate workstation for potential privilege escalation from misconfiguration, now we know the command that can bypass AMSI then lets dive into PowerShell Event Log. 

![8f7ebaba03c29234569e68a24277a985.png](..//resources/8f7ebaba03c29234569e68a24277a985.png)

One thing to keep in mind that the system on this workstation was changed 2 times. 

![d1f9018c2c9ab320ca974613170506f3.png](..//resources/d1f9018c2c9ab320ca974613170506f3.png)

Now we will have to get the timestamp of bypass command right here.
```
2024-10-22 21:49:29
```

>Task 6: What is the name of the tool the threat actor used to enumerate the workstation for misconfigurations?
```
PowerUp
```

>Task 7: What is the name of the executable the threat actor used to elevate their privileges?

This one took me a while since I was not expected this at all and some of you will also ponder "is this really correct?"

![dba88ef9d75aa6a17acf7899128dd1f1.png](..//resources/dba88ef9d75aa6a17acf7899128dd1f1.png)

I found the answer of this task via **AppCompatCache** artifacts which reveal "**Light.exe**" was executed after bypassed AMSI but what is Light.exe?

Its a tool from [WiX Toolset](https://wixtoolset.org/) that used to create MSI file that can abuse [**AlwaysInstallElevated**](https://medium.com/@persecure/windows-privilege-escalation-alwaysinstallelevated-8e83f7d1bbc6) privilege which will install MSI as SYSTEM so if that MSI is reverse shell payload then it will be triggered as SYSTEM 

Now you probably think "wait... then the threat actor might use maliciosu msi file for privilege escalation right?" , well since this task is asking for "executable" so "Light.exe" that was used to create MSI file could count i guess?

```
Light.exe
```

*One thing you might also notice from the output of AppCompatCache is **mimikatz** was executed under "Chhupa" download folder which mean that the threat actor might create a new privileged user then use that account in "**Attack on Objective**" phase. 

>Task 8: At what time did the new user get created? (UTC)

![7c1eac532451b3aca953328c9fe03b5f.png](..//resources/7c1eac532451b3aca953328c9fe03b5f.png)
Go back to Security log, then we could see that user "Chhupa" was really created by the threat actor around this time.
```
2024-10-22 21:52:24
```

>Task 9: What was the SID of the user that created the new user?

![4a133152c71c3198a1b0fc5a3d9141c0.png](..//resources/4a133152c71c3198a1b0fc5a3d9141c0.png)
Then we could also noticed that this account was used to create the new user and this SID is [local system](https://system32.eventsentry.com/error/code/S-1-5-18) so the hypothesis about AlwaysInstallElevated is confirmed at this point.
```
S-1-5-18
```

>Task 10: What is the original name of the exploit binary the threat actor used to bypass several Windows security features?

![327db9085458a3893ac071976d06b540.png](..//resources/327db9085458a3893ac071976d06b540.png)

Since we already know that PowerShell Console Log of "arjun.patel" was acquired then "Chhupa" will have one too and then we will see a lot of commands related to security features check then, an executable on Desktop was executed with xml probably to bypass those security features which prevented `mimikatz` from execution.

Which made sense that after bypass those features then `mimikatz` was executed at the end. 

![79dc10d43207c17218ddb78afe2b3e19.png](..//resources/79dc10d43207c17218ddb78afe2b3e19.png)

So lets see how those features were bypassed on "Chhupa" Desktop, there are several files here so lets see what this `dd.exe` is

![936e609784357f3bce8067eddbba119d.png](..//resources/936e609784357f3bce8067eddbba119d.png)

After submitted its hash on [VirusTotal](https://www.virustotal.com/gui/file/c204dc4c06d97a3df65a36ece3ead1800cdc74f295e23f9fd58ed545e7f0a2a7/details), which we can see that this exe is [Windows Downdate](https://github.com/SafeBreach-Labs/WindowsDowndate) executable that can downgrade Windows Updates to vulnerable patch.

![0e1a3ff4c386299d81645ed76875b4e2.png](..//resources/0e1a3ff4c386299d81645ed76875b4e2.png)

Here is the original name of this executable.

```
windows_downdate.exe
```

>Task 11: What time did the threat actor first run the exploit? (UTC)

![6b2342ae00f40456df5d29d62ffc59dc.png](..//resources/6b2342ae00f40456df5d29d62ffc59dc.png)

We can use prefetch to find out most of exe execution timestamp. 

![a8fc6ca4c60e27fc26fa6aee480df4cb.png](..//resources/a8fc6ca4c60e27fc26fa6aee480df4cb.png)

Then we can see that the threat actor executed this exe several times but the first time that was executed is right here.

```
2024-10-22 22:31:43
```

>Task 12: Which account owns the files manipulated by the exploit?

![79dc10d43207c17218ddb78afe2b3e19.png](..//resources/79dc10d43207c17218ddb78afe2b3e19.png)

Windows Downdate need config file that telling an exe which file to downgrade so we will have to take a look at `config.xml.txt` 	

![cd741a54829f1f7fe8ce71164652987b.png](..//resources/cd741a54829f1f7fe8ce71164652987b.png)

Which we can see that it will downgrade `securekernel.exe`

![55730ef440379f6d8be1f6a4110a28fb.png](..//resources/55730ef440379f6d8be1f6a4110a28fb.png)

Which belong to **TrustedInstaller**

```
TrustedInstaller
```

>Task 13: The threat actor managed to exfiltrate some domain credentials, which Windows security feature did they bypass using the exploit?

![087a9f9e9278ac1443a164be68f105a7.png](..//resources/087a9f9e9278ac1443a164be68f105a7.png)

We know that the threat actor deployed `mimikatz` after downgrade Windows so lets find out which security feature has to be disabled to allow `mimikatz` to operate

![c35bef25a7e6535a2cc8ae6c5ceb3f09.png](..//resources/c35bef25a7e6535a2cc8ae6c5ceb3f09.png)

This is an easy one, because `mimikatz` can be used to dump credential so the feature that will be needed to bypass is **Credential Guard**

```
Credential Guard
```

>Task 14: What is the NT hash of the domain administrator compromised by the Threat Actor?

![acfd6943a061b15d31ac503ab4a8958d.png](..//resources/acfd6943a061b15d31ac503ab4a8958d.png)

Since we already have all registry hives then we could use secretdump with following command to dump MS Cache 2 of the domain administrator (`impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL`)

![9d022640f664df0529dd428bb809a338.png](..//resources/9d022640f664df0529dd428bb809a338.png)

Then use following command to crack it (`hashcat -m2100 hash.txt  /usr/share/wordlists/rockyou.txt --force --potfile-disable`)

![04aefad2ff3d51150c2df4da2ffe4758.png](..//resources/04aefad2ff3d51150c2df4da2ffe4758.png)

Then we will have plaintext password of the domain administrator.

![b5dbbe77f0b8b225f179c8428db5c8de.png](..//resources/b5dbbe77f0b8b225f179c8428db5c8de.png)

Use [NTLM hash generator](https://codebeautify.org/ntlm-hash-generator) to create NTLM hash of this password then we will have answer of this task.

```
AE974876D974ABD805A989EBEAD86846
```

>Task 15: What is the password set by the threat actor for their generated user?

![acfd6943a061b15d31ac503ab4a8958d.png](..//resources/acfd6943a061b15d31ac503ab4a8958d.png)
We already got NT hash of the threat actor generated user with `secretdump` but there is another way to obtain this hash by using **lsass** dump on the desktop of new created user 

![a0cc556eec666aa7c60d0d811daa7430.png](..//resources/a0cc556eec666aa7c60d0d811daa7430.png)

We can use `mimikatz` to dump lsass with following command in Kali Linux (`pypykatz lsa minidump lsass.DMP`)

![8a1096df327ec8363001b06af1833200.png](..//resources/8a1096df327ec8363001b06af1833200.png)

Once we got the hash then use [CrackStation](https://crackstation.net/) to find the plaintext then we will have password of this generated user and completed this sherlock!

```
Password123
```

![2c2fbdd973b082fbb9eb071aa7dc9fdf.png](..//resources/2c2fbdd973b082fbb9eb071aa7dc9fdf.png)
https://labs.hackthebox.com/achievement/sherlock/1438364/791
* * *
