# [LetsDefend - Java Shellcode](https://app.letsdefend.io/challenge/java-shellcode)
Created: 
Last Updated: 
* * *
You work as a security analyst for a cybersecurity firm that specializes in malware analysis. Recently, your team discovered a suspicious Java application being circulated in the wild. Initial analysis suggests that the application contains an obfuscated shellcode, indicating potential malicious intent. Your task is to analyze the Java application, identify the shellcode, and analyze it.

* * *
## Start Investigation
>What library is used to load native libraries into the code?

![196f29e0a8ecdc89382f6cf9271f47e9.png](/resources/196f29e0a8ecdc89382f6cf9271f47e9.png)

We only have 1 java archive file inside `ChallengeFile` folder, we also have bunch for tools that can be used to analyze malware but the one we will actually use for this challenge is JD Gui (Java Decompiler) 

![8ea84ade7da35e97d829135f1399ae14.png](/resources/8ea84ade7da35e97d829135f1399ae14.png)

After decompiled it, we can see the `ShellcodeLoader.class` under `asexploit` object which we can also see that this class responsible for loading shellcode into processes and the library that responsible for loading Windows native binaries (Win32 API) is [com.sun.jna.Native](https://java-native-access.github.io/jna/4.2.1/com/sun/jna/Native.html)

Which will load Windows API from `kernel32.dll` that have several functions that can be used for shellcode injection.

```
com.sun.jna.Native
```

>What system property is used to determine whether to target 32-bit or 64-bit processes?

![c449f3dd9b9b47ca0cc7386aecbf0843.png](/resources/c449f3dd9b9b47ca0cc7386aecbf0843.png)

Shellcode is defined within main function then it will pass to `loadShellcode` which will use [sun.arch.data.model](https://www.baeldung.com/java-detect-jvm-64-or-32-bit) property to identify architecture of JVM 

```
sun.arch.data.model
```

>How many x64 processes were targeted by the shellcode?

![982faf2218c6f5746ec479221194c870.png](/resources/982faf2218c6f5746ec479221194c870.png)

After retrieve an architecture from `sun.arch.data.model`, it will check if its 32-bit or 64-bit then it will retrieve list of processes to be injected retrospectively 
 
And 64-bit processes that were targeted are  
- `C:\\Windows\\System32\\rundll32.exe`
-  `C:\\Windows\\System32\\find.exe`
-  `C:\\Windows\\System32\\notepad.exe`
-  `C:\\Windows\\System32\\ARP.EXE`

In total of 4 processes

```
4
```

>Which API function loaded kernel32.dll?

![e618d16ca292b52522310f44aa7db158.png](/resources/e618d16ca292b52522310f44aa7db158.png)

We know that `kernel32.dll` is loaded via Native library but if we were to specific then it will be `loadLibrary`

![f6a448bb6ef8df76add993b2da9bd6f4.png](/resources/f6a448bb6ef8df76add993b2da9bd6f4.png)

And according to [this](https://java-native-access.github.io/jna/5.3.1/javadoc/com/sun/jna/Native.html) document, it already deprecated

```
loadLibrary
```

>What is the length of the shellcode?

![ae12cf8b63157a04ad2726c19f2419ac.png](/resources/ae12cf8b63157a04ad2726c19f2419ac.png)

This question is likely to ask for character length defined in `shelldode` variable 

![d8b4992e642df469dd52bc21a7fa5906.png](/resources/d8b4992e642df469dd52bc21a7fa5906.png)

Use CyberChef to count, which we can see that without convert it from Hex, the length of this shellcode is 386

```
386
```

>What is the API used to allocate a region of memory in the target process?

![b1602fca5dce123e488188eebf275d07.png](/resources/b1602fca5dce123e488188eebf275d07.png)

This malware used [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) to allocate a region of memory which is a common API that used for process injection.

```
VirtualAllocEx
```

>What API was used to write shellcode?

![411e29ab9b507ce66d985747c7e559a4.png](/resources/411e29ab9b507ce66d985747c7e559a4.png)

After allocated region of memory to be injected, then it will write shellcode to that region with [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)

```
WriteProcessMemory
```

>What API was used to execute the shellcode in the target process?

![5b0f21714a8f0b5f33e5a8f9e3bd9df7.png](/resources/5b0f21714a8f0b5f33e5a8f9e3bd9df7.png)

Then [CreatedRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) will execute the shellcode injected into memory as a thread

```
CreateRemoteThread
```
* * *
## Summary
On this investigation, we conducted static analysis of jar archive file that will loaded a shellcode into processes depended on different architectures and familiarized ourselves with Windows API that commonly used for process injection.

<div align=center>

![68bf3e51f4e69249caba3284f8b543cc.png](/resources/68bf3e51f4e69249caba3284f8b543cc.png)
https://app.letsdefend.io/my-rewards/detail/2fdfd6a1d36b4646bfeb6d4d95ab035a
</div>

* * *
