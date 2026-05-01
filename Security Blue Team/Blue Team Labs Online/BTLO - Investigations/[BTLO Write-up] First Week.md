# [Blue Team Labs Online - First Week](https://blueteamlabs.online/home/investigation/first-week-13c31aa3ba)

![e565c53e8c27f70dee8633e46e7a551a.png](/resources/e565c53e8c27f70dee8633e46e7a551a.png)

You’ve been assigned to analyze an infected computer for a client whose PC has been compromised by a Ransomware group.

>**Reverse Engineering**

>**Tags**: John YARA CyberChef DiE PEStudio Text Editor OSINT dnSpy T1486 T1547.001
* * *
**Scenario**
You’ve been assigned to analyze an infected computer for a client whose PC has been compromised by a Ransomware group. The boss has given you the builder for the malware to make analysis easier but he has forgotten the password to the archive. Using your skills acquired over your first week, you must retrieve the builder and analyze the machine for any traces left behind by the suspicious group.
* * *
## Environment Awareness
![25a581a5a2e53f00f8721f43dc4ee263.png](/resources/25a581a5a2e53f00f8721f43dc4ee263.png)

As the scenario describes that we are investigating compromised computer and after the investigation machine was deployed, we can see the console popup with several access denied errors so lets leave this open for now and look for a tool that can view the command line of this `cmd.exe` process 

### Evidence & Tool Discovery
![c014d67369f8c5e2ea6187c25bc3f6e2.png](/resources/c014d67369f8c5e2ea6187c25bc3f6e2.png)

On the Desktop, we can see that the malware builder located inside `Sample` folder on the Desktop and we have several tools that will help us though out this investigation which are
- `CyberChef` : There is no explanation need for this awesome tools.
- `dnSpy` : Decompiler and debugger for .NET compiled binary which suggested that the ransomware builder and the ransomware are .NET compiled binaries.
- `John` The Ripper : Password cracking tool that we can use to crack the password of `Builder.zip` which we can also see that we have `rockyou.txt` wordlist to use with John.
- `SysinternalsSuite` : Awesome sysinternals suit that can definitely help us in any investigation especially dynamic analysis with `Sysmon`, `ProcMon`, `ProcExp` and `Autoruns`.
- `DIE` (Detect It Easy) : File type Identification tool which also have rich features that can help us determine compiler, packer, language of the compiled binary
- `pestudio` : Another Powerful tool that can be used to conduct static analysis of the malware.
- `RegJump` : Registry viewer tool for CLI
- `Visual Studio Code` : Powerful Text Editor.
- and Lastly, `YARA` that can help us find the malware by given characteristics (rule)

And before we start our investigation, lets use `ProcExp` (Process Explorer) to find out the reason why we got the error console hanging out at the start

![13e60f08ba87fde02383cfb0eb7e08b9.png](/resources/13e60f08ba87fde02383cfb0eb7e08b9.png)

We can see that this CMD process will execute `deactivate.bat` script and inside that script, it should have command that required Administrator permission to execute so lets find out what this script does

![a2e996a1a62a80cd1ce93f4e543b4c56.png](/resources/a2e996a1a62a80cd1ce93f4e543b4c56.png)

The script will disable most of security features on this machine.

![620faefea95a8b0a9cf98ec2f947a3f8.png](/resources/620faefea95a8b0a9cf98ec2f947a3f8.png)

This script was set to run with Run registry key so lets keep that in mind for now.

***
## Investigation
>Q1) Using your blue team skills, crack the password to the builder and identify the name of the malware which has infected the system (Format: Password, Malware Name)

![06cbec2e962eb1000ec0e155d8f46dab.png](/resources/06cbec2e962eb1000ec0e155d8f46dab.png)

First, we have to use `zip2john` to extract hash from the zip file then we can use that `john` to crack that hash.

Here is the command I utilized > `zip2john.exe C:\Users\BTLOTest\Desktop\Sample\Builder.zip > C:\Users\BTLOTest\Desktop\Sample\zip.john` which will save hash of the zip file into the `zip.john` file 

![a73d5a614b8a21f91fb6ab85b8d07829.png](/resources/a73d5a614b8a21f91fb6ab85b8d07829.png)

And now we can use `john.exe --wordlist=C:\Users\BTLOTest\Desktop\Tools\rockyou.txt C:\Users\BTLOTest\Desktop\Sample\zip.john` to crack the password of this zip, it gonna take a while so lets just be patience here.

![64c1633ee01e881a12e221cae5e6def6.png](/resources/64c1633ee01e881a12e221cae5e6def6.png)

After it cracked, we can use `john C:\Users\BTLOTest\Desktop\Sample\zip.john --show` to display the password that was cracked and now we can use this password to unzip the file. 

![12003d3773748ec65ed717282976168f.png](/resources/12003d3773748ec65ed717282976168f.png)

And there, we have `Chaos Ransomware Builder v5.2.exe` which is a ransomware builder for Chaos ransomware

![3c82bc43595e660a31996b4dbc26f2f7.png](/resources/3c82bc43595e660a31996b4dbc26f2f7.png)

This ransomware was resurfaced in 2021 and the threat actor behind this ransomware also gave up the decryption tool for the victims of this ransomware somehow.

<details>
  <summary>Answer</summary>
<pre><code>BTL0_C3_D4ve!, Chaos</code></pre>
</details>

>Q2) What is the default process that the malware masquerades as? How many extensions are included in the infection list? (Format: Process.ext, Number)

![cce8dfa7c9206cf4195f2972ee60b737.png](/resources/cce8dfa7c9206cf4195f2972ee60b737.png)

We can use `DIE` to determine the file type and the compiler which we can see that this builder is .NET compiled library so we can use `dnSpy` to decompile this file directly.

![020af9bb1c983049ddb218c2b674fce6.png](/resources/020af9bb1c983049ddb218c2b674fce6.png)

This ransomware also known as "Ryuk" so we can see many classes were named after this, Then we can see the `DefaultSettingValue` for the targeted extension list of this ransomware inside `Ryuk.Net.Properties` -> `Settings` right here.

![9752b8dedd98a7c4ade2bf658ffe0dfd.png](/resources/9752b8dedd98a7c4ade2bf658ffe0dfd.png)

We can copy these extension to CyberChef and then use `[A-Za-z\d/\-:.,_$%\x27"()<>= !\[\]{}@]{4,}` regular expression with Display Total to find out how many extensions are included here.

![f5b1b9fd70c9be977233377f6b466ce6.png](/resources/f5b1b9fd70c9be977233377f6b466ce6.png)

And we can execute this ransomware builder directly to find out the default process name of the ransomware that it gonna build then we can see that it will masquerades as `svchost.exe` which is a Windows native process that used to host Windows services.

<details>
  <summary>Answer</summary>
<pre><code>svchost.exe, 229</code></pre>
</details>

>Q3) A piece of malware is hidden somewhere on the system and you must develop your own custom Yara rule to detect and locate the sample. Provide the path to the file and the associated name (Format: X:\..\..\..\..\..\..\file.ext)

![ddf4197116c836313f8736bb6c52ce21.png](/resources/ddf4197116c836313f8736bb6c52ce21.png)

Lets build a ransomware sample from this builder first. 

![08849a43e0e5e73a627e47aac98836c4.png](/resources/08849a43e0e5e73a627e47aac98836c4.png)

Now we can find the characteristics of this ransomware to create YARA rule to find the hidden ransomware.

![933f929695401573977dd8d7c9b9610f.png](/resources/933f929695401573977dd8d7c9b9610f.png)

The ransomware sample is .NET compiled binary as expected so we can also decompile it on `dnSpy`.

![fc7167a94258ba4ed07cd5c29f4eda47.png](/resources/fc7167a94258ba4ed07cd5c29f4eda47.png)

Then after determined some strings so I created this simple YARA rule based on 3 strings and PE32 executable file type then use `.\yara64.exe -r .\gg.yar C:\ 2> null` to recursively find the hidden ransomware on this system then we finally have the path of this ransomware right here.

<details>
  <summary>Answer</summary>
<pre><code>C:\Users\BTLOTest\AppData\Mystery\UnleashMayhem.exe</code></pre>
</details>

>Q4) Find the Library and Linker which were used in the making of the malware (Format: Library(Name), Linker Used)

![6946b887232d8ba6f87a702906969c5c.png](/resources/6946b887232d8ba6f87a702906969c5c.png)

Its time to use `DIE` directly on this ransomware, as you can see that both Library and Linker are identical to the sample we just created on previous question.

<details>
  <summary>Answer</summary>
<pre><code>.NET(v4.0.30319), Microsoft Linker</code></pre>
</details>

>Q5) List the blacklisted functions in Alphabetical order. Also, enter the number of libraries which are imported by the malware (Format: BlackA, BlackB, BlackC, BlackD, Number)

![a288ec741d344f64d0b8b72d24480c50.png](/resources/a288ec741d344f64d0b8b72d24480c50.png)

We will have to utilize `pestudio` for this one, then we can see that this ransomware loaded 2 libraries file which are `mscoree.dll` and `user32.dll`

![0e21ca7a503de90dabcf5bcd97116bcc.png](/resources/0e21ca7a503de90dabcf5bcd97116bcc.png)

Then by going to "functions" section, we can see 5 functions are blacklists by pestudio but we will have to remove `commands` function from this list.

![e27780e4166a8c2f4c007824a531dc18.png](/resources/e27780e4166a8c2f4c007824a531dc18.png)

We can use CyberChef to sort these functions which will make our life a little bit easier.

<details>
  <summary>Answer</summary>
<pre><code>AddClipboardFormatListener, AES_Encrypt, set_UseShellExecute, SystemParametersInfo, 2</code></pre>
</details>

>Q6) AES encryption is used for small files, what is the number (in Bytes) in which it checks to see if the files are smaller than? With larger files, what is the character that they are overwritten with? (Format: Bytes, Character) 

![7b683c403098d3511e16da41251fce45.png](/resources/7b683c403098d3511e16da41251fce45.png)

After decompiled ransomware with `dnSpy` then we can go to `encryptDirectory` function which will use simply if else statement to determine the file size and if less then "1368709120L" then it will call `AES_Encrypt_Small` function to encrypt small files

![12ea817c03ea13402eb8d6c3a89a8b93.png](/resources/12ea817c03ea13402eb8d6c3a89a8b93.png)

This function will encrypted a file and overwritten the content of file with "?"

![71955d19b5a38f33acc4cdc2d261eeee.png](/resources/71955d19b5a38f33acc4cdc2d261eeee.png)

We can see the same line within `AES_Encrypt` and `AES_Encrypt_Large` too. 

<details>
  <summary>Answer</summary>
<pre><code>1368709120L, ?</code></pre>
</details>

>Q7) A method of persistence allows the author to persist across reboots. Name the location where the new value is created and give the value name (Format: Location\of\registry\key (make double slashes singular), Key Created)

![2d43c5d47226a9f08dd4aa3a3a517d8f.png](/resources/2d43c5d47226a9f08dd4aa3a3a517d8f.png)

`registryStartup` function is responsible for creating Run persistence registry key that will execute every login. 

<details>
  <summary>Answer</summary>
<pre><code>SOFTWARE\Microsoft\Windows\CurrentVersion\Run, Microsoft Store</code></pre>
</details>

>Q8) A ransom note is dropped to the user upon execution. What is the URL of their leak site and how much is the ransom demand? (Format: http://xxx.xxx, X.XXXXX XXX)

![375d32719b02b7cf69fc6cb46f24cca4.png](/resources/375d32719b02b7cf69fc6cb46f24cca4.png)

The configurations of this ransomware are defined here which also included message that will be saved in the ransomware and since this is the ransomware then its mean the ransomnote has to contain payment method and ransom amount for the victim to pay as we can see right here. 

<details>
  <summary>Answer</summary>
<pre><code>http://Cha0t1cEv1L.btlo, 0.24356 BTC</code></pre>
</details>

>Q9) Navigate to the Leak Site within the lab environment (adding :8080 to the end), and list the 3 victims who have had their data leaked by the APT group in the order of which they appear (Format: VictimA, VictimB, VictimC)

![a92239fc1a3213632059c944c659dc93.png](/resources/a92239fc1a3213632059c944c659dc93.png)

We can accessed the url we found from previous question from the investigation machine directly and then we can see that there are 3 victims are listed on this site.
<details>
  <summary>Answer</summary>
<pre><code>Smicrosoft, Smesla, Smacebook</code></pre>
</details>

>Q10) The malicious actor managed to create a persistence method before the computer was turned off. Enter the value created by the actor and the value data (Format: Value, ValueData (no quotes))

![ead191e8c4080c0d34ab99d6536902b8.png](/resources/ead191e8c4080c0d34ab99d6536902b8.png)

Now we know that there is a run persistence key before we start our investigation involving security features disabling and its appeared that this was created by the malicious actor/ransomware.

<details>
  <summary>Answer</summary>
<pre><code>Scripty, C:\ProgramData\USOShared\deactivate.bat</code></pre>
</details>

>Q11) What is the second last command executed by the persistence method? (Format: Full command)

![7a21105ec8f6d930914c47ebd36110a1.png](/resources/7a21105ec8f6d930914c47ebd36110a1.png)

The second last command is to remove SecurityHealth key and its associate with Windows Security Health Service (`SecurityHealthService.exe`), which monitors and reports the health status of  Windows system including Antivirus Status, Firewall Setting and Device Security.

<details>
  <summary>Answer</summary>
<pre><code>REG DELETE HKLM\software\microsoft\windows\currentversion\run /v SecurityHealth /f</code></pre>
</details>

>Q12) As of early 2022, a new variant of this ransomware has been released under a new name. Perform research into the ransomware to locate the new name that has been assigned to the latest variant (Format: NewName)

![dc3fbb56a6d8f0d51c74f0078c235206.png](/resources/dc3fbb56a6d8f0d51c74f0078c235206.png)

We know that Chaos ransomware was also called "Ryuk" but the other various of this ransomware is called "Yashma" which claims to be the 6th version of Chaos ransomware (v6.0)

<details>
  <summary>Answer</summary>
<pre><code>Yashma</code></pre>
</details>

![d651dc9e53d86b6309435603b5329bab.png](/resources/d651dc9e53d86b6309435603b5329bab.png)
https://blueteamlabs.online/achievement/share/52929/107
* * *