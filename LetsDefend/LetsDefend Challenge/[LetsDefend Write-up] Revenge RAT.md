# [LetsDefend - Revenge RAT](https://app.letsdefend.io/challenge/revenge-rat)
Created: 30/07/2024 23:31
Last Updated: 02/08/2024 10:53
* * *
<div align=center>

**Revenge RAT**
![818e3ae6cad8e721cbc7a1845e917032.png](../../_resources/818e3ae6cad8e721cbc7a1845e917032.png)
</div>
An attack on a company employed a Remote Access Trojan (RAT) disguised in seemingly harmless files. The RAT infiltrated the network and operated as fileless malware.

DFIR analysts have extracted the malware. Now they need you to analyse the sample and uncover its secrets. By dissecting the binary, we can understand its behaviour, assess the damage, and devise a strategy to eradicate the threat, ensuring the organization's security.

**File Location**: C:\Users\LetsDefend\Desktop\ChallengeFile\sample.7z
**File Password**: infected
* * *
## Start Investigation
>What compiler is used for this sample?

![7a496d208e080fd79e1ed2928fd0df5a.png](../../_resources/7a496d208e080fd79e1ed2928fd0df5a.png)

We can use DIE to get an answer of this question like this, then we can see that this sample is .NET based malware so we can use .NET decompiler such as JetBrains dotPeek, dnSpy or ILSpy to decompile this sample and analyze code and behavior of this sample

```
VB.NET
```

>What is the mutex name checked by the malware at the start of execution?

![75e694d8b274ac62c105938aba9b98f9.png](../../_resources/75e694d8b274ac62c105938aba9b98f9.png)

This one can be easily obtained by searching sample hash on VirusTotal and go to Behavior tab which you can see that there is a mutex which this random string, and since we got our .NET decompiler then we can check if this one is really random string per host or a constant value for all hosts

![5379fecf9e7f81c115867a46a025608b.png](../../_resources/5379fecf9e7f81c115867a46a025608b.png)

After decompiled sample, go to `Lime` namespace and `Main()` function then we should see that this malware will sleep for 2500 millisec then proceed to create Mutex and will retrieve a name from `Config`

![7f42533b5cdbfba6c7a394ec8a2ebd0b.png](../../_resources/7f42533b5cdbfba6c7a394ec8a2ebd0b.png)

Followed to `Config` class, we can also see other information related to this malware such as C2 IP and port, ID that look like base64 encoded, Mutex name, key and etc.

```
c416f58db13c4
```

>What function was used to get information about the CPU?

![1a2ef3eb9d3c8d1abd961ca9f7e1b302.png](../../_resources/1a2ef3eb9d3c8d1abd961ca9f7e1b302.png)
Inside there is an `idGenerator` class within `Lime Helper` namespace that declares many functions to retrieve information on infected host and `GetCpu` is the one responsible for getting CPU information via registry key

```
GetCpu
```

>What key was used during the “SendInfo” function?

Remember `key` varible in `Config`?, we just have to confirm that `SendInfo` function really uses that key 

![9e48a5dc2703afe75c8e735ceeaf1a79.png](../../_resources/9e48a5dc2703afe75c8e735ceeaf1a79.png)

Which you can see that this function is under `IdGenerator` class and it retrieve `Config.key` to send information

![ad31c96f6da38d73eb7d52daed02e22c.png](../../_resources/ad31c96f6da38d73eb7d52daed02e22c.png)

Get the key and submit the answer 

```
Revenge-RAT
```

>What API was used by the malware to prevent the system from going to sleep?

![ac0a3d006a0d5e9aa33f5a1f962c6dd5.png](../../_resources/ac0a3d006a0d5e9aa33f5a1f962c6dd5.png)

We can also see that there is one class that responsible for prevent the system from going to sleep which is `PreventSleep` then after examined this class, We can see that [SetThreadExecutionState](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadexecutionstate) is used under `Run` function. 

![5013de78d3f46d27c3345e95cecf8a90.png](../../_resources/5013de78d3f46d27c3345e95cecf8a90.png)

its a Windows API that capable of doing this job  

```
SetThreadExecutionState
```

>What variable stores the volume name and the function that imported the "GetVolumeInformationA" api?

![b2deb8c985e4610b49fe0fd3a981a58c.png](../../_resources/b2deb8c985e4610b49fe0fd3a981a58c.png)
We can see that [GetVolumeInformationA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationa) is imported from `kernel32.dll` then `GVI` function will be responsible for storing each information retrieve by `GetVolumeInformationA` and `IP` stored volumn name
```
IP
```

>What function was used to retrieve information about installed video capture drivers?

![4d43011960e7baf0b6a1da5dbdc3fb5d.png](../../_resources/4d43011960e7baf0b6a1da5dbdc3fb5d.png)

We can that there are another dll imports and the one that related to video capture driver is `apicap32.dll` then let `capGetDriverDescription` function stores information about video capture driver found on infected system then we need to find implementation of this method 

![1fd047b38ae84950e4d13bb289a5df45.png](../../_resources/1fd047b38ae84950e4d13bb289a5df45.png)
Then we can see that `GetCamera` is the only function that called `capGetDriverDescription` hence the answer of this question

```
GetCamera
```

>What is the value of the ID after removing obfuscation?

![ea26924670c3ef1b5ad757b53d6f91a8.png](../../_resources/ea26924670c3ef1b5ad757b53d6f91a8.png)

Remember id varible? lets grab it and decode it

![23fe3f17e5f545ee61b488ef3d5ab5fc.png](../../_resources/23fe3f17e5f545ee61b488ef3d5ab5fc.png)
```
MR_ahmed
```

* * *
## Summary
On this challenge, we analyzed Revenge RAT malware that is a freely available remote access tool written in .NET and analyze what it could do to our system once it got executed

Here are useful resources if you want to learn more about this RAT
- https://perception-point.io/blog/revenge-rat-back-from-microsoft-excel-macros/
- https://attack.mitre.org/software/S0379/
<div align=center>

![37b7db512e1d03311197a692b7dc54da.png](../../_resources/37b7db512e1d03311197a692b7dc54da.png)
</div>

* * *
