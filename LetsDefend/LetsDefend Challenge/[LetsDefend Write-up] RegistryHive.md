# [LetsDefend - RegistryHive](https://app.letsdefend.io/challenge/registryhive)
Created: 21/03/2024 11:28
Last Updated: 22/03/2024 13:52
* * *
<div align=center>

**RegistryHive**
![1bc40668849fde91cf5fbd31c2b40611.png](../../_resources/1bc40668849fde91cf5fbd31c2b40611.png)
</div>
You're a forensics analyst and have a registry dump. Try to analyze the evidence and answer the questions.

Registry Files Location: C:\Users\LetsDefend\Desktop\RegistryHive\Regs
* * *
## Start Investigation
>What is the Computer name of this machine?

We got all the registry hives that needed to complete this challenge
![ba2b7e6843be4838b6d92914445edd4c.png](../../_resources/ba2b7e6843be4838b6d92914445edd4c.png)
There are 3 tools that we can used which are RegRipper 2.8 and 3 and lastly RegistryExplorer from EZ tools
![024b8da93023e32d7e7501f81d4d240a.png](../../_resources/024b8da93023e32d7e7501f81d4d240a.png)
I started by using RegRipper 3 with SYSTEM hive which hold system information
![7ef3f9a8dac8805506a3377bb8339490.png](../../_resources/7ef3f9a8dac8805506a3377bb8339490.png)
Search for ComputerName
![c5c12c43c057b2d604ae62c8ca6526cc.png](../../_resources/c5c12c43c057b2d604ae62c8ca6526cc.png)

```
DESKTOP-8K4U4R6
```

>What is the last shutdown time for this machine? <br>
Format: YYYY/MM/DD HH:MM:SS

Search by shutdown on the system hive output
![486f2baa4bbc3f2802364647f903d0f2.png](../../_resources/486f2baa4bbc3f2802364647f903d0f2.png)
```
2023-03-23 21:53:11
```

>What is the time zone name that the machine uses?

Search by timezone on the system hive output
![07594b051ca85eca5c63e3ca33358c5e.png](../../_resources/07594b051ca85eca5c63e3ca33358c5e.png)
```
Pacific Standard Time
```

>What is the IP address of the default gateway?

Search by gateway on the system hive output, We got only DHCP Default Gateway here
![09c69a75369872c5a14c3561ba84fb81.png](../../_resources/09c69a75369872c5a14c3561ba84fb81.png)
```
192.168.235.2
```

>What is the last login date for the user “Work”? <br>
Format: DD/MM/YYYY HH:MM:SS

Now move to SAM hive for user information
![1620896d9973270b0fa043e336cac28f.png](../../_resources/1620896d9973270b0fa043e336cac28f.png)
![e4db74ebbc242ab65ba88af42baf0cfe.png](../../_resources/e4db74ebbc242ab65ba88af42baf0cfe.png)

```
23/03/2023 21:53:29
```

>How many logins did the “Work” user have?

![72d1dc85e4690b6a120cb57d00bf991f.png](../../_resources/72d1dc85e4690b6a120cb57d00bf991f.png)
```
3
```

>What is the OS “ProductName”?

use Registry Explorer to load Software Hive then go to `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion` which hold information about Windows OS and Product
![2155f45bb469e7d3d5ba84b712f84846.png](../../_resources/2155f45bb469e7d3d5ba84b712f84846.png)
```
Windows 10 Pro
```

>What is the OS “BuildNumber”?

Still on `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
![292db90dd3711a107ade2fecc9174736.png](../../_resources/292db90dd3711a107ade2fecc9174736.png)
```
19043
```

>How many programs run on startup for any user?
 
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` registry holds information for programs that will be run on startup
![9f8c4f2d16956f57ad8ea0aa2ff73c06.png](../../_resources/9f8c4f2d16956f57ad8ea0aa2ff73c06.png)
```
2
```

>What is the last installed app?

`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall` registry holds this information despite it names 
![6eeb502c818b3f1503724344f787a446.png](../../_resources/6eeb502c818b3f1503724344f787a446.png)
```
xampp
```

>What is the “DefaultGatewayMac”?

Registry NetworkList holds this information, so just search for this
![d709695939e0237693ffbc2cbf25dc6f.png](../../_resources/d709695939e0237693ffbc2cbf25dc6f.png)
```
00-50-56-FD-27-94
```

>What is the Machine SID?

This question can obtained by using RegRipper 2.8 only, and the hive that hold this information is SECURITY Hive
![08c48c7b70cbea3d35a605d3a797c7cc.png](../../_resources/08c48c7b70cbea3d35a605d3a797c7cc.png)
![f47a18535ba6575eec8afe6d230f89eb.png](../../_resources/f47a18535ba6575eec8afe6d230f89eb.png)
```
S-1-5-21-1957816478-2793074591-1041990146
```

* * *
## Summary

This challenge was designed for user to practice registry analysis and find basic information about system from 4 registry hives.
<div align=center>

![ab9619c5073440a51c50d25cd57e0165.png](../../_resources/ab9619c5073440a51c50d25cd57e0165.png)
</div>

* * *
