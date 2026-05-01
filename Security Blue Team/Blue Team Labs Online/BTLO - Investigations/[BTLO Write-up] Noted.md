# [Blue Team Labs Online - Noted](https://blueteamlabs.online/home/investigation/noted-85b9143864)

![8e08e31f658e127d310fa425624a8170.png](/resources/8e08e31f658e127d310fa425624a8170.png)

A number of machines have been compromised that belong to employees in the Finance department. Find out how.

>Incident Response

>**Tags**: PowerShell OneNote Text Editor T1566.001
* * *
**Scenario**
A number of machines have been compromised that belong to employees in the Finance department. While other Responders are containing the threat, you've identified that the employees all received the same email. It's time to take a look at the attachment that came with it.
* * *
## Investigation Submission
>Q1) What is the SHA256 hash of the .One file? (Format: SHA256Hash)

![6cc8710fe7d36600a5b7c8c289ff5932.png](/resources/6cc8710fe7d36600a5b7c8c289ff5932.png)

We only have CyberChef and this OneNote file.

![4f3c817d381758f2f4b8411aa8bf4360.png](/resources/4f3c817d381758f2f4b8411aa8bf4360.png)

I used certutil to calculcate SHA256 hash of this file.

<details>
  <summary>Answer</summary>
<pre><code>25fd150cffed8ccc00726885ff01e2cf3ab22d4915498c483453c922f355b7e7</code></pre>
</details>

>Q2) What is the name of the malicious file contained within the .One file? (Format: filename.extension)

![da0bc3f42db18079cbef1596028bf354.png](/resources/da0bc3f42db18079cbef1596028bf354.png)

Lets open onenote file and see what file was embedded inside this file (not recommended open it directly outside the sandbox) then after hover our mouse on the this image, we would be able to see what file embedded inside this file.

The file named `hta.eno` appears suspicious because the extension may not represent the actual file type. It is likely that the filename has been manipulated using a technique called Right-To-Left Override (RTLO). RTLO is a Unicode control character (U+202E) used to reverse the order of subsequent characters, causing them to appear from right to left. This technique is often used to disguise the true file extension, making a potentially dangerous file appear harmless.

In this case, the real file extension is `.hta`, which denotes an HTML Application file that can execute code. (Q4)

<details>
  <summary>Answer</summary>
<pre><code>temphta.eno</code></pre>
</details>

>Q3) What is the file path of the file when it was added to the document? (Format: Drive:\path\to\file.ext)
<details>
  <summary>Answer</summary>
<pre><code>C:\Users\Administrator\Desktop\Onedrive\temphta.eno</code></pre>
</details>

>Q4) What is the actual file type of the embedded file? (Format: File Type Name (.ext))

![6323fabd13f2a9037fecc2b2d094d81b.png](/resources/6323fabd13f2a9037fecc2b2d094d81b.png)
We could confirm our hypothesis by open this one file on CyberChef then RTLO would not be able to manipulate the actual file type under this circumstance.

<details>
  <summary>Answer</summary>
<pre><code>HTML Application (.hta)</code></pre>
</details>

>Q5) What is the name of the first file downloaded and written to disk, and what is the full URL it's downloaded from? (Format: filename.extension, https://domain.tld/path/to/file.ext)

![1bc33ecf7dd59dfda7ccdb60bad4de92.png](/resources/1bc33ecf7dd59dfda7ccdb60bad4de92.png)

After opened onenote file on CyberChef we might notice that there are so many `AutoOpen` functions that will download another onenote file and batch script then execute them but which one will be executed first?

![cafdfef125efc015666540193832e605.png](/resources/cafdfef125efc015666540193832e605.png)

The answer of Q5 and Q6 come from the last `AutoOpen` function on this file right here.

<details>
  <summary>Answer</summary>
<pre><code>invoice.one, https://onenotegem.com/uploads/soft/one-templates/homework_assignments_elementary.one</code></pre>
</details>

>Q6) What is the name of the second file downloaded and written to disk, and what is the full URL it's downloaded from? (Format: filename.extension, https://domain.tld/path/to/file.ext)
<details>
  <summary>Answer</summary>
<pre><code>system32.bat, https://transfer.sh/AudGFk/1.bat</code></pre>
</details>

![b30676930bdbe21abe5f1f36ea7700a4.png](/resources/b30676930bdbe21abe5f1f36ea7700a4.png)
https://blueteamlabs.online/achievement/share/52929/133
* * *