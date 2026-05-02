# [Blue Team Labs Online - Enter The Dragon](https://blueteamlabs.online/home/investigation/enter-the-dragon-6648ac42c1)

![bc12f7cf54acad8d70487ea2906742d9.png](/resources/bc12f7cf54acad8d70487ea2906742d9.png)

You have been tasked with performing static disassembly of the executable. Due to time constraints the only tool available is Ghidra.

>**Reverse Engineering**

>**Tags**: Ghidra T1547.001 T1622
* * *
**Scenario**
A customer has activated their incident response retainer following the discovery of a suspected malicious executable on one of their hosts. The executable was detected during routine Security Operation Centre (SOC) threat hunt activities. SOC analysts have performed basic static analysis of the executable but were unable to identify any Indicators of Compromise (IOCs).

You have been tasked with performing static disassembly of the executable. Due to time constraints the only tool available is Ghidra.
* * *
## Environment Awareness
### Evidence & Tool Discovery
![400adbefc558730112f0469d7726547f.png](/resources/400adbefc558730112f0469d7726547f.png)

On this investigation machine, we have a malware sample inside `Tools` folder on the desktop and we only have Ghidra and Cyberchef available so we will have to conduct static analyse this malware. 
 
***
## Investigation
>Q1) What is the MD5 of the executable? (Format: MD5)

![56cc1c298e067e199377a4813bccd56b.png](/resources/56cc1c298e067e199377a4813bccd56b.png)

Lets use Windows lolbin to generate file hash such as `certutil` with `certutil -hashfile EnterTheDragon.exe md5` then we will have MD5 hash of this file (we have to specify hash algorithm for `certutil` since it will generate SHA1 hash by default)

Alternative to this is a `Get-FileHash` cmdlet on PowerShell that you can use `Get-FileHash .\EnterTheDragon.exe -Algorithm MD5` to get MD5 hash of this file (we have to specify hash algorithm for `Get-FileHash` cmdlet since it will generate SHA256 hash by default)

<details>
  <summary>Answer</summary>
<pre><code>6932ff601d9b00fc59d773332518cbd0</code></pre>
</details>

>Q2) What is the image base? (Format: 0xYYYYYYYYY)

![f8394f33c3dff01c80c8462e59c0b816.png](/resources/f8394f33c3dff01c80c8462e59c0b816.png)

Lets import this file into Ghidra, First we need to run Ghidra but execute `ghidraRun.bat` script

![cd3d5e04ee7d491bad0ec9153e15ead9.png](/resources/cd3d5e04ee7d491bad0ec9153e15ead9.png)

Then we have to create "Non-Share Project" to work on Ghidra.

![3dd7d6f88ada13b03b9d27a6a8789e35.png](/resources/3dd7d6f88ada13b03b9d27a6a8789e35.png)

After created a project, its time to import the sample.

![8f248dc56b486c2bd61666eccefa7b7f.png](/resources/8f248dc56b486c2bd61666eccefa7b7f.png)

After imported a file, we will have "Import Results Summary" window shows up like this and we can see the minimum address of this file and it is where image base is located.

![55f831b32b0fdaa0398954cdcdd5e095.png](/resources/55f831b32b0fdaa0398954cdcdd5e095.png)

We can confirm this by open this file on Ghidra CodeBrowser

![3e1391da0cc0d58283c174a4d52f3992.png](/resources/3e1391da0cc0d58283c174a4d52f3992.png)

We will have to let Ghidra analyze this file first, just go with "Yes" and its default setting.

![1d0c41ab50c91dd36fcb1bb10d82a9e7.png](/resources/1d0c41ab50c91dd36fcb1bb10d82a9e7.png)

Now if we goes to "Header" which located at the minimum address of this executable, we can see that the image base address starts at MZ header which is a magic header for PE32 executable file.

<details>
  <summary>Answer</summary>
<pre><code>0x14000000</code></pre>
</details>

>Q3) What is the RVA offset of the Entry Point? (Hint: RVA is Virtual Address (VA) – ImageBase) (Format: 0xYYYY) 

The Entry Point is where the execution of a program begins so normally, a main function will be called by The Entry point 

![35e24e25ece25c86df63ac15b2efefe2.png](/resources/35e24e25ece25c86df63ac15b2efefe2.png)

After analyzed a file using Ghidra, it usually jump to The Entry Point but if we have to go back to this function then we have to expand "Funtions" inside "Symbol Tree" window then find `entry` function 

Which we can see that the address of this function on the binary is 0x14001f00 but RVA - Relative Virtual Address which is used to describe a memory offset if the base address (in this case 0x14000000) is unknown so if we remove the base address then we will have RVA address which is 0x1f00

<details>
  <summary>Answer</summary>
<pre><code>0x1f00</code></pre>
</details>

>Q4) What is the first function called from the entry point? (Format: __something_something_something)

![18ad477385d3546afa77c1b5ac6d279c.png](/resources/18ad477385d3546afa77c1b5ac6d279c.png)

We can see that before it calls main function, it will call [__security_init_cookie](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/security-init-cookie?view=msvc-170) first which will initializes the global security cookie used by the compiler for runtime checks. (to detect unexpected memory modifications by validating its integrity.)

<details>
  <summary>Answer</summary>
<pre><code>_security_init_cookie</code></pre>
</details>

>Q5) At what Virtual Address (VA) offset is IsDebuggerPresent() called? (Hint: VA is RVA + ImageBase) (Format: 0XYYYYYYYYY) 

![9de68e6ec6a80b2c366daa29ae257948.png](/resources/9de68e6ec6a80b2c366daa29ae257948.png)

IsDebuggerPresent() is a function that was imported from `kernal32.dll` so we can utilize Symbol Tree to find for this imported address of this function and type Ctrl + Shift + F to show reference to this function (normally a function call should be return if a function is called)

![1a282c4f1577821075ee418496715cef.png](/resources/1a282c4f1577821075ee418496715cef.png)

Then we can see the address that call for this function right here.

<details>
  <summary>Answer</summary>
<pre><code>0x1400024f8</code></pre>
</details>

>Q6) How many functions are imported from WININET.DLL? (Format: Number)

![a81ded79f0641f57bc5459b31169523c.png](/resources/a81ded79f0641f57bc5459b31169523c.png)

Utilized symbol tree, then we can see that there are 5 functions imported from `WININET.dll`

<details>
  <summary>Answer</summary>
<pre><code>5</code></pre>
</details>

>Q7) What security attribute (LPSECURITY_ATTRIBUTES) is used when the mutex object is created? (Hint: Look at the KERNEL32.DLL if you’re stuck) (Format: 0XY)

![89d2510c1b4adef6e2a7c9e04e08a9f7.png](/resources/89d2510c1b4adef6e2a7c9e04e08a9f7.png)

We can utilize "Show Reference" feature to find any function calls to [CreateMutexA()](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexa) function like this.

![a935e16e8d3a447069999797510de3ba.png](/resources/a935e16e8d3a447069999797510de3ba.png)

Then we can see that the first argument that pass to this function is LPSECURITY_ATTRIBUTES and it is set to 0x0 (null) indicates that default security settings are applied.

<details>
  <summary>Answer</summary>
<pre><code>0x0</code></pre>
</details>

>Q8) What is the name of the mutex object? (Format: String)

![00874b2a85750b81798417a1db943b95.png](/resources/00874b2a85750b81798417a1db943b95.png)

Name of the mutex is the third argument that pass to CreateMutexA function and from this sample, we have to concatenate these variables together.

![c419e7fe4b314d41926d9f27f5bf1ae0.png](/resources/c419e7fe4b314d41926d9f27f5bf1ae0.png)

Then we can see that "EnterTheDragon" will be the name of this mutex.

<details>
  <summary>Answer</summary>
<pre><code>EnterTheDragon</code></pre>
</details>

>Q9) Where does the sample copy itself to? (Hint: Look at the API-MS-WIN-CRT-STDIO-L 1-1-0.DLL if you’re stuck) (Format: C:\something\something.extension)

![1b858e6a620702c41b0c91fc04fa103b.png](/resources/1b858e6a620702c41b0c91fc04fa103b.png)

To save myself sometimes, I utilized "Defined Strings" feature to find any defined strings that look like a path and find its reference which we can see that we have 2 candidates right here. 

![aaf4027c74516c9727af2ccddfc55f42.png](/resources/aaf4027c74516c9727af2ccddfc55f42.png)

Which we can see that this path is where the sample will copy itself to.

<details>
  <summary>Answer</summary>
<pre><code>C:\\PerfLogs\\lee.exe</code></pre>
</details>

>Q10) What size is the buffer used to perform the file read operation? (Format: XXXX)

![9bf90de39fdb8fce33336b7323c8c343.png](/resources/9bf90de39fdb8fce33336b7323c8c343.png)

By tracing back the reference to fread() function, we can see that 1024 is a buffer sizes that used to perform file read operation by Fun_140001920() function

<details>
  <summary>Answer</summary>
<pre><code>1024</code></pre>
</details>

>Q11) What encoding is used to obfuscate the payload URL? (Hint: Look at the WININIT.DLL if you’re stuck) (Format: Encoding Method)

![0c0759575ac5f95185986db4771dcf2e.png](/resources/0c0759575ac5f95185986db4771dcf2e.png)

We can trace the reference to functions imported from WININIT.DLL then we can see that there is one string that look like it is encoded and we can see that it has = as padding indicates that it might be base64 encoded

![37ea329ee17837eeb12f7cd6c4c117dc.png](/resources/37ea329ee17837eeb12f7cd6c4c117dc.png)

We can confirm this hypothesis by use From Base64 operation on CyberChef which reveal pastebin url which proved this hypothesis to be true.

<details>
  <summary>Answer</summary>
<pre><code>base64</code></pre>
</details>

>Q12) What is the decoded URL? (Format: https://domain.tld/something)

![37ea329ee17837eeb12f7cd6c4c117dc.png](/resources/37ea329ee17837eeb12f7cd6c4c117dc.png)
<details>
  <summary>Answer</summary>
<pre><code>https://pastebin.com/AsasW19v</code></pre>
</details>

>Q13) What is the user agent used during the URL access request? (Hint: Look at the WININIT.DLL if you’re stuck) (Format: String)

![9aca707dcfb33ef8fa41bf439595db5d.png](/resources/9aca707dcfb33ef8fa41bf439595db5d.png)

The first argument pass to [InternetOpenW()](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenw) function is a user-agent the will be used to create a connection in the HTTP protocol.

![d2fe7b56bf31090a445f7620fff5aae5.png](/resources/d2fe7b56bf31090a445f7620fff5aae5.png)

For those who do not get "What is Boards Don't Hit Back?", here is an explaination.

<details>
  <summary>Answer</summary>
<pre><code>BoardsDontHitBack</code></pre>
</details>

>Q14) What is the registry path string used to establish persistence? (Hint: Start looking at the ADVAPI32.DLL if you’re stuck) (Format: HIVE\\path\\to\\key)

![d6722245e699cab815a4af0b236950ee.png](/resources/d6722245e699cab815a4af0b236950ee.png)

We can trace reference of [RegSetValueExA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa) to find the function calls and arguments pass to this function.

![16dff8d202c11da173d4ca213a457c7f.png](/resources/16dff8d202c11da173d4ca213a457c7f.png)

Then we can see that the sample will make itself persistence by adding a key to the infamous run registry key.

<details>
  <summary>Answer</summary>
<pre><code>SOFTWARE\\Microsoft\Windows\\CurrentVersion\\Run</code></pre>
</details>

>Q15) What is the name of the key that holds the persistence value? (Format: String)

![66dd9a3e2aedba0914bff9abca11b7f7.png](/resources/66dd9a3e2aedba0914bff9abca11b7f7.png)

And the value that of the key is "Bruce" which should come from "Bruce Lee"

<details>
  <summary>Answer</summary>
<pre><code>Bruce</code></pre>
</details>

![a8617f3f929e294bf0a4758da55521f5.png](/resources/a8617f3f929e294bf0a4758da55521f5.png)
https://blueteamlabs.online/achievement/share/52929/162
* * *
## Summary
A static malware analysis was conducted to analyze Bruce Lee theme malware which has many capabilities such as detecting debugger, creating a mutex, read files from the internet and create registry key for persistence.

### IOCs
- `6932ff601d9b00fc59d773332518cbd0`
- `https://pastebin.com/AsasW19v`
- `BoardsDontHitBack`
- `SOFTWARE\\Microsoft\Windows\\CurrentVersion\\Run\\Bruce`
* * *