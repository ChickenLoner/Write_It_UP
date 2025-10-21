# [LetsDefend - Remote Working](https://app.letsdefend.io/challenge/remote-working)
Created: 10/01/2024 14:05
Last Updated: 05/06/2024 20:12
* * *
<div align=center>

**Remote Working**

![c4cbf4faaa46c2052cb0a60639a3144e.png](../../_resources/c4cbf4faaa46c2052cb0a60639a3144e.png)
</div>
Analysis XLS File

File link: /root/Desktop/ChallengeFiles/ORDER_SHEET_SPEC.zip Password: infected

NOTE: Do not open on your local environment. It is a malicious file.
* * *
## Start Investigation
### VirusTotal
Uploaded sample xlsm file to [VirusTotal](https://www.virustotal.com/gui/file/7bcd31bd41686c32663c7cabf42b18c50399e3b3b4533fc2ff002d9f2e058813) 
<div align=center>

![d23c72fd53e4b1d42f85bd3bbe53f255.png](../../_resources/d23c72fd53e4b1d42f85bd3bbe53f255.png)
This file was flagged as malicious by **42** security vendor

![c7097c9149b848606ad782e5a3f24160.png](../../_resources/c7097c9149b848606ad782e5a3f24160.png)
Some security vendors labeled this file as a **Trojan**

![6c4ab1bce435c326bbf507e6dc7885fa.png](../../_resources/6c4ab1bce435c326bbf507e6dc7885fa.png)
It was created on `2020-02-01 18:28:07` UTC

![1ff726e737168a8c573e4994fc3bf02e.png](../../_resources/1ff726e737168a8c573e4994fc3bf02e.png)
Found **1** contacted URL that seem suspicious and might be a payload stage

![d9ce8b80bf8b61bf616c111573e69e6f.png](../../_resources/d9ce8b80bf8b61bf616c111573e69e6f.png)
It drop **3** files on the disk 
</div>

## Record Future Triage
Uploaded this file to [Triage](https://tria.ge/240112-ka134scear/behavioral1) 

<div align=center>

![0a42b265900ff0584429e09baa9c01fc.png](../../_resources/0a42b265900ff0584429e09baa9c01fc.png)
Once this file is opened, a child process is spawned and it was a cscript that tries to connect to make a network request to download an actual malware

![14948ed663935e239b0dc5405e2d9093.png](../../_resources/14948ed663935e239b0dc5405e2d9093.png)
</div>

* * *
> What is the date the file was created?
```
2020-02-01 18:28:07
```

> With what name is the file detected by Bitdefender antivirus?
```
Trojan.GenericKD.36266294
```

> How many files are dropped on the disk?
```
3
```

> What is the sha-256 hash of the file with emf extension it drops?
```
979dde2aed02f077c16ae53546c6df9eed40e8386d6db6fc36aee9f966d2cb82
```

> What is the exact url to which the relevant file goes to download spyware?
```
https://multiwaretecnologia.com.br/js/Podaliri4.exe
```
* * *
## Summary
This XLS File is a microsoft excel with VBA macro embedded. It is a stager that once it opened it tries to download an actual malware from a certain URL.
<div align=center>

![7b2066901059f845e4d2aefb7077c9bb.png](../../_resources/7b2066901059f845e4d2aefb7077c9bb.png)
Badge Acquired
</div>

* * *