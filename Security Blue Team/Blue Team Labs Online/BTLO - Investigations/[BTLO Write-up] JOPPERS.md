# [Blue Team Labs Online - JOPPERS](https://blueteamlabs.online/home/investigation/joppers-5400eb1aee)

![d939dbc81af9fdb6ab101b38e09a2f95.png](/resources/d939dbc81af9fdb6ab101b38e09a2f95.png)

Being the Security Champion of your Development team, now it’s your turn to analyse, report and spread awareness.

>**Reverse Engineering**

>**Tags**: x64Db Javascript T1105
* * *
**Scenario**
After a rigorous work project that lasted 1 year, the developers were finally granted a long vacation. Before the vacation, the development team was hit by a spearphishing attack, with attachments being JavaScript files, which are commonly sent between internal and external developers on the project. Being the Security Champion of your Development team, now it’s your turn to analyse, report and spread awareness.
* * *
## Environment Awareness
### Evidence & Tool Discovery
![bbfa66492c0924c94d42d97ef8e12f9f.png](/resources/bbfa66492c0924c94d42d97ef8e12f9f.png)

There are 2 samples that we need to analyze on this machine and as we could see on the desktop the we only have x64dbg, Notepad++ and CyberChef as a tool for our disposal.

***
## Investigation 
>Q1) Sample 1 - What is the name of the Microsoft component invoked to download the malware? (Format: string.string) 

![1157928827b3186735e029c919b69ce2.png](/resources/1157928827b3186735e029c919b69ce2.png)

Once we opened the first sample, we can see that this is well obfuscated js file in a single line

![aba5bd358123cb277a8dcd6ffded634d.png](/resources/aba5bd358123cb277a8dcd6ffded634d.png)

We can use Javascript Beautify recipe on CyberChef to make it a little bit easier to read then we can replace the same file or save as new file.

![1c66fa5f5ecb1ac38d9a1b40d7f2163f.png](/resources/1c66fa5f5ecb1ac38d9a1b40d7f2163f.png)

After reviewing the code, I noticed that on the line 621, there is a variable being declared with this very long string and its likely to be a base64 string

![aafca7995fb4532e811316ccc7205126.png](/resources/aafca7995fb4532e811316ccc7205126.png)

Then I checked how this variable will be used which I found that it will pass to another function and the return value of that function will be executed with `Run` method

![41cce676a513b7dbe4e90e6d9a900671.png](/resources/41cce676a513b7dbe4e90e6d9a900671.png)

Knowing `Run` method will be used which mean `Wscript.Shell` object will also created to run shell command.

![97e40640f0e5d95a502f99d72dce69d3.png](/resources/97e40640f0e5d95a502f99d72dce69d3.png)

By following the function that will return the command to be executed then we could see this variable is created which is likely to be the initiator for decoding base64 string

![9f5648caabe86c504904274357fdccce.png](/resources/9f5648caabe86c504904274357fdccce.png)

So I used CyberChef with **From Base64** to decode it and sure enough, it is indeed command line encoded with base64 which will use PowerShell to download a file via [XMLHTTP](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms759148(v=vs.85)) object to Windows Temp folder then execute it.

<details>
  <summary>Answer</summary>
<pre><code>Msxml2.XMLHTTP</code></pre>
</details>

>Q2) Sample 1 - Submit the full URL from which the dropper downloads the malicious file (Format: http://domain.tld/path/to/file.extension?params)

![c40337753b1182263ef572056c724c1e.png](/resources/c40337753b1182263ef572056c724c1e.png)

Here is the URL that the dropper will download malicious executable file.

<details>
  <summary>Answer</summary>
<pre><code>http://qshalmxixkoew.ru/dokumemti/fez21.exe?rnd=21901</code></pre>
</details>

>Q3) Sample 1 - What is the name of the System folder where the malware is downloaded? (Format: FolderName)

![e21a7cb0b02a402c6b2635287e9753d1.png](/resources/e21a7cb0b02a402c6b2635287e9753d1.png)

From the `$path` variable, we could see that it initialized with `$env:temp + \2021.exe` which mean the file will be downloaded to `C:\Windows\Temp` folder as `2021.exe`  

<details>
  <summary>Answer</summary>
<pre><code>Temp</code></pre>
</details>

>Q4) Sample 1 - After being downloaded, the sample is saved to disk with a new name. What is it? (Format: filename.extension)
<details>
  <summary>Answer</summary>
<pre><code>2021.exe</code></pre>
</details>

>Q5) Sample 1 - What is the command responsible to execute the downloaded malware on the system? (Format: Command-Name)

![ec86c7683ba10c0351ee40e2b60f07d5.png](/resources/ec86c7683ba10c0351ee40e2b60f07d5.png)

Lastly, we can see that after it saved to file then its used `Start-Process` cmdlet to execute the file saved in `$path` variable.

<details>
  <summary>Answer</summary>
<pre><code>Start-Process</code></pre>
</details>

>Q6) Sample 2 - Submit the 3 domains that the dropper will download executables from, in alphabetical order (Format: ADomain.tld, BDomain.tld, CDomain.tld)

![6d4e2cf4ddb3a50bf8a8210d18fba92f.png](/resources/6d4e2cf4ddb3a50bf8a8210d18fba92f.png)

Sample 2 is also obfuscated in a single line so we could use the same approach as the first sample .

![dd29e933612427fb387812b09c1cdda0.png](/resources/dd29e933612427fb387812b09c1cdda0.png)

After beautified the script, I noticed that there are several concatenation of strings from many other variables to `j9` variable.

![b35b1acd35b0e6ddd6ecf5f3c8c14661.png](/resources/b35b1acd35b0e6ddd6ecf5f3c8c14661.png)

Then after concatenate all variables then it will pass to `n9` variable which is an `eval` function to execute code in `j9` variable.

![4d6949e30aba40bcfc7886e558fbac54.png](/resources/4d6949e30aba40bcfc7886e558fbac54.png)

Since we already know that `n9` is `eval` then we can debug `j9` variable in browser debugger directly.

![f28fc8ad711ddf8091c62968ff6dd7cb.png](/resources/f28fc8ad711ddf8091c62968ff6dd7cb.png)

Utilized **JavaScript Beautify** recipe again then we can see that this script will try to download malicious executable from one of these 3 domains.

<details>
  <summary>Answer</summary>
<pre><code>binrants.com, igewgadcyxroup.org, optrapidg.com </code></pre>
</details>

>Q7) Sample 2 - What is the name of the System folder where the malware is downloaded? (Format: FolderName)

![4fdb37b56bfd00b0f9d8608a8b4eb87e.png](/resources/4fdb37b56bfd00b0f9d8608a8b4eb87e.png)

The malicious executable will be downloaded to Windows Temp folder.

<details>
  <summary>Answer</summary>
<pre><code>Temp</code></pre>
</details>

>Q8) Sample 2 - As per the script, what are the first 10 characters of the urlparameter "id"? (Format: XXXXXXXXXX)

![0d9a935dc8d12475e56fd83bf8d7fb0e.png](/resources/0d9a935dc8d12475e56fd83bf8d7fb0e.png)

`id` parameter will come from `str` variable in the main script so lets go back to the main script.

![406b0704e495afe8469e43c855f06e31.png](/resources/406b0704e495afe8469e43c855f06e31.png)

Here is the `str` variable.

<details>
  <summary>Answer</summary>
<pre><code>5553515E0A</code></pre>
</details>

>Q9) Sample 2 - What are the 3 unique values appended to the url paramater "rnd"? (Format: value1, value2, value3)

From the previous script, we can see that parameter `rnd` is initialized with `506606 + n` and `n` variable come from the first for loop which will start from `n=1` to `n=3`
<details>
  <summary>Answer</summary>
<pre><code>5066061, 5066062, 5066063</code></pre>
</details>

>Q10) Sample 2 - Submit the unique names of the executables after being downloaded from the url, in ascending value order (Format: file1.exe, file2.exe, file3.exe)

![c5f6a3042982f10e3dfac8e739fdea03.png](/resources/c5f6a3042982f10e3dfac8e739fdea03.png)

The name of executable file is also implemented the same logic as `rnd` parameter which will initialized with `913966 + n + .exe`

<details>
  <summary>Answer</summary>
<pre><code>9139661.exe, 9139662.exe, 9139663.exe</code></pre>
</details>

![b0a7a229e4cf4b6f5f02a9bd9a14204b.png](/resources/b0a7a229e4cf4b6f5f02a9bd9a14204b.png)
https://blueteamlabs.online/achievement/share/52929/84
* * *