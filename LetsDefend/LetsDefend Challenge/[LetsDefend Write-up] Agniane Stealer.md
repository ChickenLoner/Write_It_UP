# [LetsDefend - Agniane Stealer](https://app.letsdefend.io/challenge/agniane-stealer)
Created: 19/06/2024 12:04
Last Updated: 19/06/2024 15:16
* * *
<div align=center>

**Agniane Stealer**
![236cc9a939177905ede5b6d1bbd58646.png](../../_resources/236cc9a939177905ede5b6d1bbd58646.png)
</div>
SecureTech Solutions recently detected unusual activity on its employee workstations. Upon investigation, they found that sensitive customer information, including email addresses and passwords, has been compromised. The company suspects that a stealer malware might be responsible for the breach.

**File location**: /Desktop/ChallengeFile/stealer.7z/
**File Password**: infected
* * *
## Start Investigation
>What is the decode hostname that is used by the stealer?

![889ccde88c5679c4ae31ffe57b2bf3cf.png](../../_resources/889ccde88c5679c4ae31ffe57b2bf3cf.png)

First, we need to determine which debugger/decomplier we can use on this sample and as you can see that this sample is .NET based which mean we can use either Jetbrains dotPeek or ILSpy

![d88b5010d8988391629f7fb86dd2f9d0.png](../../_resources/d88b5010d8988391629f7fb86dd2f9d0.png)

When it comes to analyze code, we often start from Main() function and luckily for us that many variables incluing hostname are declared inside this function

![2f1a3bd65e1c0660a46a449696aa1dc5.png](../../_resources/2f1a3bd65e1c0660a46a449696aa1dc5.png)

It's base64 encoded, so we will have to decode it first

```
https://central-cee-doja.ru/
```

>What is the API used by the stealer to detect debuggers?

![e7e2d3b704843cc3ae1d3edbcb27f857.png](../../_resources/e7e2d3b704843cc3ae1d3edbcb27f857.png)

There is a function calls to `AntiAnalysis.Start()` inside `Main()` function which will lead us to `Start()` function within `AntiAnalysis` class

![52363c46a84a83ff95e62c4ed0adff73.png](../../_resources/52363c46a84a83ff95e62c4ed0adff73.png)

Then when we read this function, we can see that there is a method imported from `kernel32.dll` that used to determine if a debugger is presented or not

![c73b404543e262a7c97d092a18de9e44.png](../../_resources/c73b404543e262a7c97d092a18de9e44.png)

And here is an example on how this method is used inside of `Debugger()` function 

```
CheckRemoteDebuggerPresent
```

>What is the number of the process names that are used by stealer to detect 
malware analysts?

![1d01abb7ab4e4bd89148988e792b2145.png](../../_resources/1d01abb7ab4e4bd89148988e792b2145.png)

Following `Debugger()` function then we can see a list is declared and it consists of processes that are known for debugging and doing digital forensics

```
8
```

>What is the number of the functions that are used by the stealer as anti-analysis?

![58333fb2b2c841f38031baa0eb720313.png](../../_resources/58333fb2b2c841f38031baa0eb720313.png)

Inside `Start()` function, we can see that 5 functions are used to determine if this malware should exit or not 

```
5
```

>What is the first DLL name that was downloaded by the malware?

![1beb0c9b37aea729ea607fe730487f57.png](../../_resources/1beb0c9b37aea729ea607fe730487f57.png)

Go back to `Main()` function then you can see there is a function calls to `Downloads()` function within `DynamicLinkLibrary` class

![e40bfe7186c0a29eec7a9feef0f2451c.png](../../_resources/e40bfe7186c0a29eec7a9feef0f2451c.png)

Upon following to `DynamicLinkLibrary` then we can see all dlls that going to be downloaded by `Download()` function

```
SQLite.dll
```

>What is the name of the project advertised by the malware?

![e84909b3f4b07766b4a19cdbc1e520f4.png](../../_resources/e84909b3f4b07766b4a19cdbc1e520f4.png)

Agniane is known to be a made by Cinoshi project but if we want to find an answer by reading through code, we need to dig into `Archive.Compile()`

![7abb3d2057acc50bad6ebe8b483742d1.png](../../_resources/7abb3d2057acc50bad6ebe8b483742d1.png)

Here is where Cinoshi project was mentioned

```
Cinoshi
```

>What is the user of the bot in Telegram?

![2b716b1eb1edb15b3f0bd4b824fd4299.png](../../_resources/2b716b1eb1edb15b3f0bd4b824fd4299.png)

This telegram bot is used to receive all informations that collect by this malware

```
@agnianebot
```

>What is the first regex that is used by the malware to find tokens?

![5e57e197d603164b907bc9dc9ae54d63.png](../../_resources/5e57e197d603164b907bc9dc9ae54d63.png)

Inside `Compile()` function there is another function calls related to token which is `Discord.GetTokens()`

![384864203634e27ac71ae9f7b315d9f3.png](../../_resources/384864203634e27ac71ae9f7b315d9f3.png)

Follow it to the bottom of this code then we can see Regex that used to find tokens

```
[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_\\-]{27}
```

>What is the build version?

![ceba91620978b3d6dc5834ae70d07be8.png](../../_resources/ceba91620978b3d6dc5834ae70d07be8.png)

Go back to `Main()` function for this one
 
```
0.1.1 beta
```

>How many domains are targeted by the Stealer to collect passwords and login credentials?

![75f9e736c2cdfa391c4c1f596a8b6546.png](../../_resources/75f9e736c2cdfa391c4c1f596a8b6546.png)

Go back to `Compile()` function again then we can see there is a function calls related to domain here 

![342757387234ba51154db2279fc9ced0.png](../../_resources/342757387234ba51154db2279fc9ced0.png)

there are 4 domains that this malware tries to harvest credentials

```
4
```

>Which specific registry key is targeted by the malware to collect Hostname, username, and password information from all sessions of WinSCP?

![4eb0f98faf67907236ea24754bc21d73.png](../../_resources/4eb0f98faf67907236ea24754bc21d73.png)

Go to `WinSCP` class then you can see `GetCredentials()` function responsible for harvesting all sessions of WinSCP

```
Software\\Martin Prikryl\\WinSCP 2\\Sessions
```

>What is the file name that is used by the stealer to save the information about the system?

![f8d48f454ea4f5248d174b99b26c718e.png](../../_resources/f8d48f454ea4f5248d174b99b26c718e.png)

Inside `Compile()` function, there is a text file that was created to save all information about system here.

```
PC Information.txt
```

* * *
## Summary

On this challenge, we analyzed Agniane stealer which is an .NET infostealer malware based that has many capabilities including 
- Anti-debugging
- Harvesting browser cookies, telegram/steam/discord sessions, login credentials, WinSCP sessions, FileZilla credentials, Capturing screenshots, computer information, Cryptocurrency wallets/extensions and so on...
- Send data back to telegram bot 

Zscaler made very information blog about this malware [here](https://www.zscaler.com/blogs/security-research/agniane-stealer-dark-web-s-crypto-threat) 

<div align=center>

![9ed6a3015a9e06ef790c223b37dd5a21.png](../../_resources/9ed6a3015a9e06ef790c223b37dd5a21.png)
</div>

* * *
