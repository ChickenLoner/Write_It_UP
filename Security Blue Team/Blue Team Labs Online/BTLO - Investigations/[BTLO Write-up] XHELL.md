# [Blue Team Labs Online - XHELL](https://blueteamlabs.online/home/investigation/xhell-56d3ba7a9b)

![d45feac7ae6b1cbed43461124a1a47c6.png](/resources/d45feac7ae6b1cbed43461124a1a47c6.png)

>**Reverse Engineering**

>**Tags**: Olevba TextEditor LibreOffice T1564
* * *
**Scenario**
As part of their regular job, ZYX Company employees need to deal with a lot of Excel files. One day, Thomas who is the Security Champion of the Finance Team received 2 Excel files that looked suspicious. Being a security-conscious individual, Thomas sent those files to the RE team for further examination.
* * *
## Environment Awareness
### Evidence Discovery
![f951a8516a0fd85fd2ef6893aeb307d1.png](/resources/f951a8516a0fd85fd2ef6893aeb307d1.png)

We have both xls samples inside `Sample` folder

***
### Tool Discovery and Preparation

![f00003deb526fa57e1bec0714ebe7591.png](/resources/f00003deb526fa57e1bec0714ebe7591.png)

We can see that we have oletools suite and LibreOffice available for us inside this machine so lets find them.

![dd48ddd16b8cae0561e1e9a219f92bd6.png](/resources/dd48ddd16b8cae0561e1e9a219f92bd6.png)

Look like all oletools are installed and located in `/usr/local/bin` directory and to make it easier to use then we can add this path to PATH variable with `export PATH=$PATH:/usr/local/bin`

Now we are ready for the investigation.

***
## Investigation
>Q1) S1: Submit the full url from which the sample is trying to download a new file?

![48e1be3a30e556a75e907ccbaa215665.png](/resources/48e1be3a30e556a75e907ccbaa215665.png)

By using `oleid s1.xls`, we can see that this file contains XLM macros which we will need to use `olevba` to analyse it next.

![dfe644085cdb0874957375653d478545.png](/resources/dfe644085cdb0874957375653d478545.png)

After using `olevba s1.xls`, we will see a lot of character defining via `CHAR()` and some formula to concatenate/combine them together.

![daf67725c6539f5a29cbffa8232fa4a3.png](/resources/daf67725c6539f5a29cbffa8232fa4a3.png)

Then we can also see the name of the hidden sheet on this file so to make our analysis easier, we can use LibreOffice to open it and unhide this sheet

![9c909cb31ea2035ff7b965bc0e004f53.png](/resources/9c909cb31ea2035ff7b965bc0e004f53.png)

To unhide the hidden sheet, we have to click "Show Sheet..."

![56dcdf30a67a3de57428d90ff7014699.png](/resources/56dcdf30a67a3de57428d90ff7014699.png)

Which we can see the hidden sheet right away so just select it and click "OK"

![15c6b19b0847d266eaf5f60c0c56be76.png](/resources/15c6b19b0847d266eaf5f60c0c56be76.png)

Now we should be able to access the hidden sheet (which is now not hidden)

![2e214ded02134f3e53cd644d82f9d203.png](/resources/2e214ded02134f3e53cd644d82f9d203.png)

We can see that each Columns (Horizontal) have their own formula and "BB3" appears to make it harder for us to concatenate and read them (Q2)

![bd42dde9eacc916dbb267476c80d1efa.png](/resources/bd42dde9eacc916dbb267476c80d1efa.png)

We can use Find and Replace feature to replace all "BB3" with blank like this

![74936d3e9a1f613321795eca6beeebb1.png](/resources/74936d3e9a1f613321795eca6beeebb1.png)

Now we should be able to use `=TEXTJOIN()` formula to concatenate all characters within a column like this.

![37638122e08cb832715f0f88bf29130b.png](/resources/37638122e08cb832715f0f88bf29130b.png)

Now apply the same formula (with adjusted range) then we can see that these XLM macro are designed to download a second payload from this url and executed it with `rundll32.exe` so we can assume that the second payload is DLL file. 

<details>
  <summary>Answer</summary>
<pre><code>https://cbbyezvsv.website/d2e33</code></pre>
</details>

>Q2) S1: Submit the String used by the malware author to confuse the analyst

![2e214ded02134f3e53cd644d82f9d203.png](/resources/2e214ded02134f3e53cd644d82f9d203.png)
<details>
  <summary>Answer</summary>
<pre><code>BB3</code></pre>
</details>

>Q3) S1: From the above URL, file is downloaded and saved in which location? Submit FilePath/filename.ext

![691c2d7458baf5be00a9778a274a7e73.png](/resources/691c2d7458baf5be00a9778a274a7e73.png)

A file was downloaded with [URLDownloadToFileA](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85)) API to download file from url to public user home folder

<details>
  <summary>Answer</summary>
<pre><code>c:\User\Public\c7cd6zl.html</code></pre>
</details>

>Q4) S1: Submit the name of the registry file observed

![5557cdc15b0f6dc5e87e6c83d60d7f70.png](/resources/5557cdc15b0f6dc5e87e6c83d60d7f70.png)

We can also see that this macro also utilizes `reg.exe` to export registry keys related to Excel's security settings into the file `C:\users\public\3.reg`

<details>
  <summary>Answer</summary>
<pre><code>3.reg</code></pre>
</details>

>Q5) S1: Submit the registry hive targeted by the sample. Submit the short notation of the registry hive as observed in the analysis

![f4dedb4ac3d926b5c5e77defeafe58ab.png](/resources/f4dedb4ac3d926b5c5e77defeafe58ab.png)
<details>
  <summary>Answer</summary>
<pre><code>HKCU</code></pre>
</details>

>Q6) S2: Submit the formula used to assemble the command to download the malware

![f97b88d51f8b3e55d5151c2157ea5a8f.png](/resources/f97b88d51f8b3e55d5151c2157ea5a8f.png)

Its time for the sample 2, after using `oleid s2.xls` then we can see that this sample also contains XLM macros. 

![be788554e6acbcf9cbcdae25e45117c9.png](/resources/be788554e6acbcf9cbcdae25e45117c9.png)

This time, look like all payload are already defined within a sheet and need just to concatenate before executed them. 

<details>
  <summary>Answer</summary>
<pre><code>=CONCATENATE(A31,A32,C30,A33,A34)</code></pre>
</details>

>Q7) S2: Which windows process is used to install the malware

![22e4e5a320b6abd3462d0b317a46c157.png](/resources/22e4e5a320b6abd3462d0b317a46c157.png)

Open sample 2 with LibreOffice then we can see that there is 1 hidden sheet within this file as well.

![5fab08433c3a7c6bdfc5eadc0c7faef6.png](/resources/5fab08433c3a7c6bdfc5eadc0c7faef6.png)

Go to Columns A that we already found some of these fields will be concatenated, grammar checking of LibreOffice also helps us identity hidden text within this sheet as well.

![c8b392c66bea4518927386675564951f.png](/resources/c8b392c66bea4518927386675564951f.png)

Change the color of these text, we can see that `msiexec.exe` will be utilized to fetch and download malicious file without user knowing (with quite mode) 

<details>
  <summary>Answer</summary>
<pre><code>msiexec.exe</code></pre>
</details>

>Q8) S2: Submit the URL from which malware is being downloaded

![656a091d0df33fb379fd889f87929d98.png](/resources/656a091d0df33fb379fd889f87929d98.png)
<details>
  <summary>Answer</summary>
<pre><code>http://186.129.214.13/rol2</code></pre>
</details>

![3cc2ff6a0cea40a7367502548cc05ed9.png](/resources/3cc2ff6a0cea40a7367502548cc05ed9.png)
https://blueteamlabs.online/achievement/share/52929/80
* * *