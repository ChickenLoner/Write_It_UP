# [Blue Team Labs Online - Heaven](https://blueteamlabs.online/home/investigation/heaven-5bed4c7457)

![185a02e4e8063abc21a05294b54589d4.png](/resources/185a02e4e8063abc21a05294b54589d4.png)

One fine day, watching your miserable life. A supreme power dropped a heavenly executable on your Desktop.

>Reverse Engineering

>**Tags**: x64Dbg dnSpy HxD DiE rtdump.py T1204.002 T1071.001
* * *
**Scenario**
One fine day, watching your miserable life. A supreme power dropped a heavenly executable on your Desktop. Please find the dropper and Heaven.exe on the Desktop. Find the way to Heaven by answering the questions.
* * *
## Environment Awareness
### Evidence & Tool Discovery
![dba066126bd96e15a19fc1790bfc9567.png](/resources/dba066126bd96e15a19fc1790bfc9567.png)

We have 2 samples within `Sample` folder located on the Desktop here and after reviewing these filename, `dropper` seem to be a dropper that will be used to drop `heaven.exe` on the target system.

we also have several tools that can be used for malware analysis such as
- Detect It Easy : A tool use for file type identification
- dnSpy : .NET decompiler
- HxD : Hex editor
- rtfdump : Tool from Didier Stevens suite that can be used to analyze RTF file
- x32dbg/x64dbg : Debugger for PE32 executable files
- CyberChef : The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis.

Now lets dive it!
***
## Investigation
>Q1) Submit the File Signature of dropper in Hex format (Format: XX XX XX XX XX XX)

![397b2fa7e70d7357a02686507790966a.png](/resources/397b2fa7e70d7357a02686507790966a.png)

We can use HxD to open `dropper` file which we can see that this file is the RTF file and we can copy these part to answer this question.

<details>
  <summary>Answer</summary>
<pre><code>7B 5C 72 74 66 31</code></pre>
</details>

>Q2) Submit the URL from where dropper is downloading the malicious executable (Format: http://domain.tld/path/to/file.exe)

![fd865a95976bacd64a7600d36a649d71.png](/resources/fd865a95976bacd64a7600d36a649d71.png)

Its time to utiized rtfdump, we can just run it with the dropper file without any argument to let it analyze objects within this file which we can see that object 10 contains objdata with a size of 2560 bytes so lets take a look what inside of it

![ba8f8407eab8b938959f4eb0056d6a85.png](/resources/ba8f8407eab8b938959f4eb0056d6a85.png)

We can use `-s 10` to specify object 10, `-d` for dump and `-H` for hex decode which we can see some a suspicious domain which in this object 

![bf19f39af96bdf99f0c23c5637d891ba.png](/resources/bf19f39af96bdf99f0c23c5637d891ba.png)

So lets remove `-H` and just dump as it hex and convert it in CyberChef which will make copy and paste a little bit easier

![d44078f0a8c46d431b504218b45461ae.png](/resources/d44078f0a8c46d431b504218b45461ae.png)

Then we will finally have the domain that this dropper will attempt to make a connection and download second payload (`heaven.exe`) here

<details>
  <summary>Answer</summary>
<pre><code>http://iamthesuprepowermyfriend.com/heaven.exe</code></pre>
</details>

>Q3) According to DiE, what is the name of the linker used in heaven.exe? (Format: Format: string(x.x)[string])

![a9ad87a893bb6b61f1b1aed96c58834b.png](/resources/a9ad87a893bb6b61f1b1aed96c58834b.png)

Now we can use DiE or Detect It Easy to identify the file type of second payload which we can see that it could not recognize known linker for this executable.

<details>
  <summary>Answer</summary>
<pre><code>unknown(8.0)[GUI32]</code></pre>
</details>

>Q4) Submit the BaseAddress and EntryPoint of heaven.exe (Format: BaseAddress, AddressOfEntryPoint)

![4de8cf86b9677423c14799c9ec46fd42.png](/resources/4de8cf86b9677423c14799c9ec46fd42.png)

We can see both Entry Point and Base Address of this executable right here.

<details>
  <summary>Answer</summary>
<pre><code>00400000, 00402e5e</code></pre>
</details>

>Q5) Submit the name of the software framework used by the malware author to create heaven.exe (Format: SoftwareFramework)

![d81227c4766617d389f2daba56f5aca5.png](/resources/d81227c4766617d389f2daba56f5aca5.png)

Take a look at Library which we can see that this malware was developed using .NET framework and one more thing to notice is its also packed with MPRESS so we will have to unpack it first before analyze it properly.

<details>
  <summary>Answer</summary>
<pre><code>.NET</code></pre>
</details>

>Q6) What is the C2 IP that Heaven.exe will communicate with? (Format: X.X.X.X)

![d1a7ba5c3ad4eaeb9a8736dd29e218fb.png](/resources/d1a7ba5c3ad4eaeb9a8736dd29e218fb.png)

Lets following [this](https://www.linkedin.com/pulse/unpacking-mpress-net-assembly-dnspy-breakpoint-alex-necula-mmi0f/) gold mine to unpack MPRESS .NET executable via dnSpy

![f51913b01405185cda7d41900b2c4840.png](/resources/f51913b01405185cda7d41900b2c4840.png)

First we have to find where the entrypoint will be invoked and we should be able to see this on line 28 inside `Main()`

![ebda786fffe2bdbab69daa35e9c92690.png](/resources/ebda786fffe2bdbab69daa35e9c92690.png)

Lets add breakpoint here.

![ec7fc60b8032785d63d068469034f3a7.png](/resources/ec7fc60b8032785d63d068469034f3a7.png)

Now we can debug this file and it will stop at the breakpoint we just added.

![6a0e4ba67f9707def983a4c44a90fc60.png](/resources/6a0e4ba67f9707def983a4c44a90fc60.png)

Now lets open Modules tab.

![75131217979928b2d3418f47856c78e6.png](/resources/75131217979928b2d3418f47856c78e6.png)

Save this unknown part which is unpacked executable file as a new file. 

![423eb1e1fd4e71301d3cded5db95025d.png](/resources/423eb1e1fd4e71301d3cded5db95025d.png)

Now we can see that there is no more packer then we should be able to decompiled it on dnSpy and find out the C2 IP address easily.

![09ba4dcc823728a56696b70a67329585.png](/resources/09ba4dcc823728a56696b70a67329585.png)

We can see that under A class, there is an A function that declares many variables including the IP address and port of C2 right here.

<details>
  <summary>Answer</summary>
<pre><code>5.2.69.50</code></pre>
</details>

![ff5830b39951091f2490af7e133ddbeb.png](/resources/ff5830b39951091f2490af7e133ddbeb.png)
https://blueteamlabs.online/achievement/share/52929/82
* * *