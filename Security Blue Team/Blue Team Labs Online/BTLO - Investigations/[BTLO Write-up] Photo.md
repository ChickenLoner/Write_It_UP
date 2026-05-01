# [Blue Team Labs Online - Photo](https://blueteamlabs.online/home/investigation/photograph-711f1f7a2d)

![b66d51dc7d209707e655e2cad19466e9.png](/resources/b66d51dc7d209707e655e2cad19466e9.png)

>Reverse Engineering

>**Tags**: Linux CLI jpegdump.py cyberchef T1505
* * *

**Scenario**
As part of researching different security control bypassing techniques, the red team provided 2 jpg samples to the blue team to study and understand the behavior.
* * *
## Investigation Submission
>Q1) S1: Submit the URL responsible to download the webshell (Format: http://domain.tld/filename.ext)

![afd9513f41ceca96e4f2b2bd6c99b556.png](/resources/afd9513f41ceca96e4f2b2bd6c99b556.png)

We got CyberChef and `jpegdump.py` from wrote by Didier Steven to analyze 2 samples so lets dig into S1 first. 

![b0c69547ca7442da6003cfdffbdd8151.png](/resources/b0c69547ca7442da6003cfdffbdd8151.png)

After using jpegdump with an image file, I noticed stream 3 with length = 4506 which is unusual for METADATA of an image file.

![eb6e30f99173f8225c3d9b9b3241da1f.png](/resources/eb6e30f99173f8225c3d9b9b3241da1f.png)

After dumping it with `python ../../jpegdump.py totamtoWithShell.jpg -s 3 -d`, we can see php script inside of it that will fetch content this C2 to `cshell.php` and `r57.php` that made me think that its probably use [r57](https://github.com/tennc/webshell/blob/master/php/PHPshell/%E3%80%90r57%E3%80%91/r57.php) webshell but thats not the right answer for Q3.

<details>
  <summary>Answer</summary>
<pre><code>http://c0deblocker.alterxp.org/sauce.txt</code></pre>
</details>

>Q2) S1: What is the scripting language observed in the downloaded webshell? (Format: Language Name Abbreviation)

![93625cfc40b0df7e606c28f5f7e8c74c.png](/resources/93625cfc40b0df7e606c28f5f7e8c74c.png)

We already know that its downloaded php script from C2 and we can even confirmed this once we opened it and one thing you might notice from this script look like it's obfuscated by [wormshell](https://wormshell.com/)

<details>
  <summary>Answer</summary>
<pre><code>php</code></pre>
</details>

>Q3) S1: The downloaded file was found to be a well known webshell. Submit the name of the webshell! (Format: WebshellName)

![92a07d246b61af8f357f2d3b818231b6.png](/resources/92a07d246b61af8f357f2d3b818231b6.png)

Its osint time since r57 is not the right answer and we found more similar script around the internal (P0wny is not the right answer)

![5fc842ccbe360b3643cbb45d6641196b.png](/resources/5fc842ccbe360b3643cbb45d6641196b.png)

We can confirm that we got a shell that encoded by wormshell since this php script is quite similar to the script we have.

![90c6d0a54039e88a92708076ed88728e.png](/resources/90c6d0a54039e88a92708076ed88728e.png)

After searching for a while, we finally got the right answer which is c99 webshell.
<details>
  <summary>Answer</summary>
<pre><code>c99</code></pre>
</details>

>Q4) S2: Submit the C2 server IP address and the port used for communication (Format: IP:Port)

![bf2ccf67d9158170483be1e33557cb51.png](/resources/bf2ccf67d9158170483be1e33557cb51.png)

Time to analyze S2 and after use jpegdump, we can see stream 29 has d (data size) = 26106 bytes which is not normal at all ! 

![8c0de9863388d59e2d03004ce55a8982.png](/resources/8c0de9863388d59e2d03004ce55a8982.png)

So I dumped it with `-s 29d -d` then we can see start with BEGIN CERTIFICATE but after searching on how to use jpegdump to dump malware then I found [this diary](https://isc.sans.edu/diary/29010) wrote by Didier Steven that tell me a different story.

![32b0c3b18b7bfe6435e2f51a47e51a21.png](/resources/32b0c3b18b7bfe6435e2f51a47e51a21.png)

So after decode with base64, we can see the header start with MZ so its definitely malware embedded inside this image file.

![2544f0c3275778de54571c00d4120d41.png](/resources/2544f0c3275778de54571c00d4120d41.png)

We don't have to analyze everything on linux CLI, lets do this on CyberChef

![832e48488be20b5bd56c0f224dadf0d6.png](/resources/832e48488be20b5bd56c0f224dadf0d6.png)

Remove null bytes then use "Extract IP Addresses" which will return C2 IP address for us right here.

![a8fe2df85ae449677bcce0cbb23babd4.png](/resources/a8fe2df85ae449677bcce0cbb23babd4.png)

Since we already got C2 IP address then we can use this to search it since it has to be closed with port and sure enough, we get C2 port right here.

<details>
  <summary>Answer</summary>
<pre><code>46.101.166.19,6667</code></pre>
</details>

>Q5) S2: What is the name of the Intel Corporation process observed in the sample? (Format: ProcessName)

![27d8b29b4da625b1b16199bc2f8016ca.png](/resources/27d8b29b4da625b1b16199bc2f8016ca.png)

We need a little bit of OSINT for this one since Intel has so many processes on Windows machine but the answer of this question is right here, after C2 address and port.

![b257d1984acc7d0a0bfa19d2cea92cef.png](/resources/b257d1984acc7d0a0bfa19d2cea92cef.png)

Its an Intel Graphics Tray Icon process for graphic settings.
<details>
  <summary>Answer</summary>
<pre><code>igfxTray</code></pre>
</details>

>Q6) S2: Submit the Original Filename of the embedded malware (Format: filename.ext)

![9d0a70e53e352092fa956bb3f11b58b7.png](/resources/9d0a70e53e352092fa956bb3f11b58b7.png)

We know that this is PE executable so we can use for `.exe` which we have this weird filename that is original filename of this file right here.
<details>
  <summary>Answer</summary>
<pre><code>vxtnt1tn.exe</code></pre>
</details>

![67dde6b1f14ba49b67b3927469c393ca.png](/resources/67dde6b1f14ba49b67b3927469c393ca.png)
https://blueteamlabs.online/achievement/share/52929/119
* * *