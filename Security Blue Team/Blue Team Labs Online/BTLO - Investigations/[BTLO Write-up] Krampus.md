# [Blue Team Labs Online - Krampus](https://blueteamlabs.online/home/investigation/krampus-79226a7f4f)
<div align=center>

![0e56557eacd2950976c340843e705796.png](/_resources/0e56557eacd2950976c340843e705796.png)
</div>
FrostGuard is sendings its troops to the North Pole! Can you stop its advances?

>**Incident Response**

>**Tags**: SpeakEasy CyberChef Volatility T1105 T1036
* * *
**Scenario**
The North Pole is under attack. Santa’s network has been breached, and a rogue daemon named Krampus is suspected. Krampus has been recruiting disgruntled elves on a forum, sharing a malicious tool designed to control Santa’s systems.

Using a RAM dump from one of Santa’s helpers turned insider, recover their forum password, access the hidden site, and download the tool used in the attack. Analyze it to uncover the IP address of Krampus’s Command-and-Control (C2) server and stop the sabotage.

Can you expose Krampus and protect Santa’s operation?
* * *
## Environment Awareness
### Evidence Discovery
![0eb4e443897b364c97066195e1ceed1c.png](/_resources/0eb4e443897b364c97066195e1ceed1c.png)

We are only provides with memory dump inside `Investigation` directory on this investigation machine
***
### Tool Discovery
![f4f8aeffa5edbdb938aa8109bc9050de.png](/_resources/f4f8aeffa5edbdb938aa8109bc9050de.png)

This investigation room tagged with "SpeakEasy", "CyberChef" and "Volatility", lets find them to confirm its presence 

![aceaadb50895916a0139fb1dc509dd8e.png](/_resources/aceaadb50895916a0139fb1dc509dd8e.png)

CyberChef could be found at `/home/ubuntu/Desktop/Tools`.

![075077a8208c861b913e9ba030519b89.png](/_resources/075077a8208c861b913e9ba030519b89.png)

By using `which vol`, we can see that we have Volatility already installed on this system and its Volatility 3 version 2.4.0

![d45b015bc398731ed346048b62e3086f.png](/_resources/d45b015bc398731ed346048b62e3086f.png)

And lastly, with `which speakeasy` we can see that its also in `/usr/bin` ready to be executed which also telling us that we will have to use this tool to emulate payload that going to be obtained on this investigation.

***
## Investigation 
>Q1) What is the URL of the forum used by the insider? (Format: URL)

![3aaebc31942f6b92928760a1d974834e.png](/_resources/3aaebc31942f6b92928760a1d974834e.png)

After using volatility 3 with `windows.pstree` plugin, we can see several Google Chrome processes so my next strategy would be using `strings` to find any site related to "forum"

![4243cd12faa1c66afab33223ee9bd570.png](/_resources/4243cd12faa1c66afab33223ee9bd570.png)

Sure enough! `strings` worked on this one, we got the URL of this forum which can be accessed on investigation machine directly.

<details>
  <summary>Answer</summary>
<pre><code>http://undergroundforum.io/</code></pre>
</details>

>Q2) What is the username and password used to access the forum? (Format: Username, Password)

![3287a3ea5be54016d37c4511b85b90df.png](/_resources/3287a3ea5be54016d37c4511b85b90df.png)

Next I used `strings` with `grep username` and `grep forum` to find potential username related to the forum reside in memory which we can see that we actually got a username with this method and we can also see that "password" might be a really good string to catch next!

![cd5112d6c31cb6eaab0890a67a5d5817.png](/_resources/cd5112d6c31cb6eaab0890a67a5d5817.png)

utilized username we just found then we will eventually get a password of this user right here! (Do not forget to decode URL from `%40` to `@`)

<details>
  <summary>Answer</summary>
<pre><code>SnowHacker, Moon@2024</code></pre>
</details>

>Q3) After downloading the tool created by Krampus and analyzing the script, what is the value of qQnZFFhoGvbrgs? Note: To unzip the file use the password from the previous question. (Format: Value)

![df5d70ae1ca3f14029508ba06c7c6a62.png](/_resources/df5d70ae1ca3f14029508ba06c7c6a62.png)

After reading the content of `/etc/hosts`, we can see that the forum is hosting on this investigation machine but to make it consistency with the story as much as it could, we will just forget about it and go straight to this site directly.

![4cf0ececdb1c06ae48c783d203f37ff5.png](/_resources/4cf0ececdb1c06ae48c783d203f37ff5.png)

We have the URL and credential that can be used to access so lets use that credential to login and find out what inside this forum!

![f77182cea4aa8628000e22bc86c7ca78.png](/_resources/f77182cea4aa8628000e22bc86c7ca78.png)

Then we can see that user Krampus posted a download link for a tool so we will have to download and analyze it from now on.

![c9bfc91e52807dc63cae0a8daca38aae.png](/_resources/c9bfc91e52807dc63cae0a8daca38aae.png)

We got `1.zip` file and after extract it with password we obtained from previous question, then we got `1.hta` payload ready to be analyzed.

![99669da9c70363bf37f89e4a0d870bf9.png](/_resources/99669da9c70363bf37f89e4a0d870bf9.png)

Payload was obfuscated but we can still piece them together then we will have `WScript.Shell` that provides a set of useful utilities that greatly expand the range of tasks that can be performed with Windows PowerShell and COM which we can see that this payload will create an instance of the `WScript.Shell` COM object which will be used to execute malicious system command (as you can see `cmd.exe` will execute PowerShell command)

<details>
  <summary>Answer</summary>
<pre><code>WScript.Shell</code></pre>
</details>

>Q4) What method and scripting language are being used to run system commands and manipulate objects? (Format: Method, Scripting Language)

![76602a3ecb48bbab9d2bd2bc3e45400b.png](/_resources/76602a3ecb48bbab9d2bd2bc3e45400b.png)

After an instance was created, this script utilizes `run` method to execute `cmd.exe` which will execute "PowerShell". 
<details>
  <summary>Answer</summary>
<pre><code>run, powershell</code></pre>
</details>

>Q5) What encoding format is used in the file to obfuscate part of the PowerShell command? (Format: Encoding Format)

![039244f9c95f2e15d5a5247cd2d215d7.png](/_resources/039244f9c95f2e15d5a5247cd2d215d7.png)

We know its base64, but just in case we can use CyberChef to decode it which we can see that "From Base64" recipe was successfully decode this long string hence confirming its Base64 encoding.

<details>
  <summary>Answer</summary>
<pre><code>base64</code></pre>
</details>

>Q6) In the encoded script, which function is used to write specific bytes into allocated memory as part of the injection process? (Format: Function Name)

![d6635cc3e0f47355e070d5278196bbce.png](/_resources/d6635cc3e0f47355e070d5278196bbce.png)

Now lets analyze decoded output, it imports `kernel32.dll` then use several functions such as [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) to allocate space in memory then use [memset](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/memset-wmemset?view=msvc-170) from `msvcrt.dll` to write shellcode to allocated memory.

<details>
  <summary>Answer</summary>
<pre><code>memset</code></pre>
</details>

>Q7) What is the MD5 hash of the binary data obtained from the decoded shellcode? (Format: MD5)

![9092f29cbd8f6df6192521e472628c37.png](/_resources/9092f29cbd8f6df6192521e472628c37.png)

Here is the shellcode, lets copy it.

![9ea6ac9583894265659cc6f439e226ba.png](/_resources/9ea6ac9583894265659cc6f439e226ba.png)

Then convert "From Hex" to raw then calculate MD5 hash using "MD5" recipe to get an answer of this question
<details>
  <summary>Answer</summary>
<pre><code>9bdf69740670b8793c622a9a8fd5e4f1</code></pre>
</details>

>Q8) What IP address and port does the shellcode attempt to connect to when emulated with Speakeasy? (Format: IP:PORT)

![ed80c7136f99b77d62ba9f9c53b8a0ab.png](/_resources/ed80c7136f99b77d62ba9f9c53b8a0ab.png)

Remove "MD5" recipe from CyberChef then save file to our file system so can use [speakeasy](https://github.com/mandiant/speakeasy) to emulate Windows as debug shellcode with `speakeasy -t shell.bin -r -a x86` then we can see that this shellcode will create a connection to this specific IP address on port 443 (reverse shell connection)
<details>
  <summary>Answer</summary>
<pre><code>51.79.49.174:443</code></pre>
</details>

![b7a84f5e9e86a6ac256fc53108622228.png](/_resources/b7a84f5e9e86a6ac256fc53108622228.png)
https://blueteamlabs.online/achievement/share/52929/248
***
## IOCs
- `undergroundforum[.]io` (forum)
- `121863e286d5cba24e9d5193c2482a1d59202243ff265a3560c85882c3c009ea` (SHA1 of `1.zip`)
- `e114d6bc53b4a52049ed82798e4a405f6d49f54ae401539cb801c1cace90268b` (SHA1 of `1.hta`)
- `51[.]79[.]49[.]174`
- `9bdf69740670b8793c622a9a8fd5e4f1` (MD5 of shellcode)
* * *