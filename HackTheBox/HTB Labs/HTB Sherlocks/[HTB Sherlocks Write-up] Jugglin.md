# [HackTheBox Sherlocks - Jugglin](https://app.hackthebox.com/sherlocks/Jugglin)
Created: 24/05/2024 19:50
Last Updated: 30/05/2024 23:55
* * *
![62015aff678a05edcd70dd4e1f3d1ec1.png](/resources/62015aff678a05edcd70dd4e1f3d1ec1.png)
**Scenario:**
Forela Corporation heavily depends on the utilisation of the Windows Subsystem for Linux (WSL), and currently, threat actors are leveraging this feature, taking advantage of its elusive nature that makes it difficult for defenders to detect. In response, the red team at Forela has executed a range of commands using WSL2 and shared API logs for analysis.

* * *
>Task 1: What was the initial command executed by the insider?

![ef9ceebdedb7193a21e0159dd5b2b087.png](/resources/ef9ceebdedb7193a21e0159dd5b2b087.png)
We got 2 apmx64 files, I've never seen this file before so Its time to do my research
![b744f9176de8f36ff1ef3c08b48b3617.png](/resources/b744f9176de8f36ff1ef3c08b48b3617.png)
According to [file-extension.org](https://www.file-extensions.org/apmx64-file-extension), these files could be opened with API Monitor and look like we gonna have to investigate API calls

And lucky for us, HackTheBox already posted a blog about [Tracking WSL Activity with API Hooking](https://www.hackthebox.com/blog/tracking-wsl-activity-with-api-hooking) so now we know what and where to look for

![e08bfbfa90e328076ee35575b81fa2c5.png](/resources/e08bfbfa90e328076ee35575b81fa2c5.png)
An answer of this question lied in `Attacker.apmx64`

<details>
  <summary>Answer</summary>
<pre><code>whoami</code></pre>
</details>

>Task 2: Which string function can be intercepted to monitor keystrokes by an insider?

Read the blog the answer this question

<details>
  <summary>Answer</summary>
<pre><code>RtlUnicodeToUTF8N, WideCharToMultiByte</code></pre>
</details>

>Task 3: Which Linux distribution the insider was interacting with?

![721cd8ddc56489591dbfc94ce552ac16.png](/resources/721cd8ddc56489591dbfc94ce552ac16.png)
Its kali linux

<details>
  <summary>Answer</summary>
<pre><code>kali</code></pre>
</details>

>Task 4: Which file did the insider access in order to read its contents?

To be honest, This question was merely a guess and it was correct

<details>
  <summary>Answer</summary>
<pre><code>flag.txt</code></pre>
</details>

>Task 5: Submit the first flag.

![bf6fcfda69167f2214e2706448bca288.png](/resources/bf6fcfda69167f2214e2706448bca288.png)

<details>
  <summary>Answer</summary>
<pre><code>HOOK_tH1$_apI_R7lUNIcoDet0utf8N</code></pre>
</details>

>Task 6: Which PowerShell module did the insider utilize to extract data from their machine?

<details>
  <summary>Answer</summary>
<pre><code>Invoke-WebRequest</code></pre>
</details>

>Task 7: Which string function can be intercepted to monitor the usage of Windows tools via WSL by an insider?

![2e07a46d2a89f5b720ee090eb7eba83a.png](/resources/2e07a46d2a89f5b720ee090eb7eba83a.png)

<details>
  <summary>Answer</summary>
<pre><code>RtlUTF8ToUnicodeN</code></pre>
</details>

>Task 8: The insider has also accessed 'confidential.txt'. Please provide the second flag for submission.

![38e5966e49eaf88db669a617d53a5c7a.png](/resources/38e5966e49eaf88db669a617d53a5c7a.png)
So now we know that an insider used powershell to upload confidential.txt to attacker's hosted website
![9c4a978e13e9ae5d87de170dd1d6dbef.png](/resources/9c4a978e13e9ae5d87de170dd1d6dbef.png)
At the end of API events, we will eventually obtain this flag 

<details>
  <summary>Answer</summary>
<pre><code>H0ok_ThIS_@PI_rtlutf8TounICOD3N</code></pre>
</details>

>Task 9: Which command executed by the attacker resulted in a 'not found' response?

![dc3ac7cd1f3ca3fc3b06608de1588bd2.png](/resources/dc3ac7cd1f3ca3fc3b06608de1588bd2.png)

<details>
  <summary>Answer</summary>
<pre><code>lsassy</code></pre>
</details>

>Task 10: Which link was utilized to download the 'lsassy' binary?

![b6a0d8a9d4c27c3fce6fec56d61ae909.png](/resources/b6a0d8a9d4c27c3fce6fec56d61ae909.png)
An attacker using wget to fetch this url

<details>
  <summary>Answer</summary>
<pre><code>http://3.6.165.8/lsassy</code></pre>
</details>

>Task 11: What is the SHA1 hash of victim 'user' ?

![76cfd3b0835669a7add4b2475da984b2.png](/resources/76cfd3b0835669a7add4b2475da984b2.png)
Find any WriteFile API then we finally see that user's masterkey was saved to keys.txt and his SHA1 was shown here too

<details>
  <summary>Answer</summary>
<pre><code>e8f97fba9104d1ea5047948e6dfb67facd9f5b73</code></pre>
</details>

>Task 12: When an attacker utilizes WSL2, which WIN32 API would you intercept to monitor its behavior?

<details>
  <summary>Answer</summary>
<pre><code>WriteFile</code></pre>
</details>

![72452f41f3a623572bbaeb8ccf88eeb3.png](/resources/72452f41f3a623572bbaeb8ccf88eeb3.png)
* * *
