# [LetsDefend - AstasiaLoader](https://app.letsdefend.io/challenge/astasialoader)
Created: 19/06/2024 10:45
Last Updated: 19/06/2024 11:46
* * *
<div align=center>

**AstasiaLoader**
![4ed4c2a341e9e176da529717d02eef5c.png](../../_resources/4ed4c2a341e9e176da529717d02eef5c-1.png)
</div>

In this challenge, participants will play the role of security analysts tasked with investigating a potential malware incident involving an employee who has encountered suspicious activity. The challenge focuses on analyzing the suspected malware and identifying its behavior, potential payload, and mitigation strategies.

**File Location**: C:\Users\LetsDefend\Desktop\ChallengeFile\sample.7z

**File Password**: infected

* * *
## Start Investigation
>What is the base address of the sample?
Answer Format: 0x000000

![4799ce19f31af777bb51559849f8c271.png](../../_resources/4799ce19f31af777bb51559849f8c271.png)

Open sample file on Detect It Easy then you will have both Base address and Entry point, and do not that this sample is .NET base so we will have to use JetBrains dotPeek or ILSpy

```
0x400000
```

>What is the entry point of the sample?
Answer Format: 0x000000

![cb4f34cff270f80b7b88790c04e07bcc.png](../../_resources/cb4f34cff270f80b7b88790c04e07bcc.png)
```
0x4aab56
```

>What is the sha256 hash of the sample?

![453d4db2f0ec2d540d319716039a9361.png](../../_resources/453d4db2f0ec2d540d319716039a9361.png)

Using HashCalc to calculate filehash of this sample file

```
9d1ba303d691bee165c66a698adba44419bc772182fb80c927ee1df3464f40f9
```

>What is the directory name that was created by malware?

![c3db5c9d1ec1adcfc337f8b5eae1b58c.png](../../_resources/c3db5c9d1ec1adcfc337f8b5eae1b58c.png)

Inside Form1 function, there is an attempt to create directory and then if a specific file in that folder exists then it will return indicating that it won't affect the same host twice.

```
Astasia
```

>What is the URL that is encoded by the malware?

![6f9c40c7aa79afaa6c598555977b6ab4.png](../../_resources/6f9c40c7aa79afaa6c598555977b6ab4.png)

There is an url belonged to github that will be encoded and decoded inside `VcSR9o` class 

![d2f3cd9f27aa62d9a5c4d9d0153432b2.png](../../_resources/d2f3cd9f27aa62d9a5c4d9d0153432b2.png)

Upon researching about this malware, I've learned that this `README.md` was used to store url that hosted for redline steader

```
https://raw.githubusercontent.com/newuploaders/newuploaders/main/README.md
```

>Using Thread.Sleep, how long does the code pause execution of the current thread? (in milliseconds)

![2eae3d83974216860f7f2613c8a58ae3.png](../../_resources/2eae3d83974216860f7f2613c8a58ae3.png)

There is a `Lg4dXD` function inside `VcSR9o` class that will send information collects by redline stealer to telegram bot then sleep for 2000 milliseconds before deleting redline stealer then sleep again and then append number `1` to a file created by this malware

```
2000
```

>What is the name of the malware?

![2926014d1cbe5aaf197bbdb9ec89151b.png](../../_resources/2926014d1cbe5aaf197bbdb9ec89151b.png)
```
AstasiaLoader
```

>What is the username of the attacker on Telegram?

![d93cc7c57c7e70b52c0fa0b62f320f6f.png](../../_resources/d93cc7c57c7e70b52c0fa0b62f320f6f.png)
```
@SkalaMmmvkusno
```

>What is the name of the file that is deleted by the malware?

![c09f014cd916915cf9ba11d3f747e3ec.png](../../_resources/c09f014cd916915cf9ba11d3f747e3ec.png)
![dc2274a5b5ff45a56bfed778546a9dcc.png](../../_resources/dc2274a5b5ff45a56bfed778546a9dcc.png)
```
infected.exe
```

>What is the name of the file that was checked by malware or not?

![e34c84bbe7525a7ebce09a69cab9bb30.png](../../_resources/e34c84bbe7525a7ebce09a69cab9bb30.png)
```
currentscript.txt
```

* * *
## Summary

On this challenge, We analyzed AstasiaLoader which is .NET based malware that will read URL from `README.md` hosted on github and will download redline stealer to exfiltrate sensitive data and send them to Telegram bot then it also will also delete redline stealer from your system after data exfiltration process is completed 

<div align=center>

![e7d4c55e70938dee94efc4971e08e3f3.png](../../_resources/e7d4c55e70938dee94efc4971e08e3f3.png)
</div>

* * *