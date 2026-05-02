# [Blue Team Labs Online - Basilisk PT 1](https://blueteamlabs.online/home/investigation/basilisk-pt-1-7bb956abae)

![4b84fe90571ee942c6c537c6f408f4fd.png](/resources/4b84fe90571ee942c6c537c6f408f4fd.png)

Delve into the captivating tale of Harry, a young explorer who dreams of the Basilisk and later finds himself face-to-face with its digital counterpart.

>**Reverse Engineering**

>**Tags**: BinTexT CFFExplorer PEiD ExeInfo PEView
* * *
**Scenario**
As night fell, and Harry’s eyelids grew heavy, the tale of the basilisk seeped into his dreams. In a quaint village nestled deep within the forest, an ancient prophecy whispered of a mythical creature called the Basilisk. It was said that whoever gazed into its eyes would turn to stone. One day, Harry, a curious young explorer, ventured into the woods, determined to uncover the truth. As the sun set, the basilisk emerged from the shadows, its piercing eyes reflecting the moonlight. Harry, intrigued yet cautious, embarked on a quest to understand the basilisk's mysterious powers and unravel the secrets hidden within the forest.

The village, the prophecy, and the basilisk dream came alive more often. Harry find himself standing amidst the busy office day, feeling the weight of the prophecy in the air.

Awakening with a sense of confusion, Harry delved deeper into his weird dream. Amidst the constant hum of his desire to figure out his dream and look for new challenges in his career, Harry stood as a beacon of knowledge, ready to face the challenges both mythical and digital. Suddenly, one of the respected cybersecurity firm, the role of a malware analyst/incident responder was open and this is an awaited role that Harry always wanted—a position promising to test his limits and push the boundaries of his understanding.

Having breezed through the initial interview, Harry stepped into the practical exam arena. The challenge was daunting: unravel and neutralize a nefarious malware strain named 'Basilisk' that had surreptitiously infiltrated a simulated corporate network. With determination in their eyes, Harry fearlessly immersed themselves in the task, drawing upon their profound understanding of Malware Analysis, forensic methodologies, and state-of-the-art threat intelligence.

As Harry dissected the intricate code of the Basilisk malware, a chilling realization crept in—the same Basilisk that kept reappearing in his dreams was the very malware he was now investigating. The lines between the mythical and the digital began to blur as Harry delved deeper, driven not only by the professional challenge but also by an inexplicable connection to the enigmatic creature from his dreams.

Harry's determination intensified. The Basilisk, once a mysterious entity in his subconscious, was now a tangible adversary in the digital realm. Could Harry decipher the Basilisk's secrets, expose its weakness, and emerge victorious in both the mythical and digital realms?
* * *
## Environment Awareness
### Evidence & Tool Discovery
![f16185c272b7d91d5bd3d3cb744c672b.png](/resources/f16185c272b7d91d5bd3d3cb744c672b.png)

There is a folder on the desktop that contains malware (
`Basilisk.bin`) and tools that can be used to conduct both static and dynamic analysis.

Tools that can be used for static analysis are
- bintext
- CFF Explorer
- exeinfo
- PEiD
- PEview

Tools that can be used for dynamic analysis are
- Process Hacker
- Process Explorer (procexp)
- Process Monitor (procmon)
- Regshot

***
## Investigation
>Q1) Using the BinTexT tool, Is there a string that is related to a malicious executable? (Format: filename.ext)

![c5bab025cc4d71b279c53b2b6b1cc9ae.png](/resources/c5bab025cc4d71b279c53b2b6b1cc9ae.png)

After scan this file with BinTexT, we could see this weird dll in one of strings which is the answer of this question.

<details>
  <summary>Answer</summary>
<pre><code>39upd.dll</code></pre>
</details>

>Q2) Using the ExeInfo tool, what Windows version does Basilisk used to target? Give the complete machine version. (Format: Machine Version)

![25c9224ef7f4f68b1ab56710ce61d718.png](/resources/25c9224ef7f4f68b1ab56710ce61d718.png)

Load the file in ExeInfo then click "PE" to display header info of this file which we can see that Basilisk target Windows NT 4.0 so we investigated 10-20 year old malware here.

<details>
  <summary>Answer</summary>
<pre><code>Win NT 4.0</code></pre>
</details>

>Q3) Using the PEiD, what is the Entry Point? What is the EP section? (Format: EntryPoint, EP section)

![2c4f1e95a2e3c69a3d970e2142de58a1.png](/resources/2c4f1e95a2e3c69a3d970e2142de58a1.png)

Load the file in PEiD then we should be able to see the Entry Point address and which is located in .text section

<details>
  <summary>Answer</summary>
<pre><code>00001000, .text</code></pre>
</details>

>Q4) Using the CFFExplorer tool, what is the Import Directory RVA Offset of Basilisk? What is the section? (Format: Offset, section)

![0853e8010c58fba71b632a50330392f5.png](/resources/0853e8010c58fba71b632a50330392f5.png)
Load the file in CFFExplorer then go to "Data Dirctories [x]" then we should be able to see Import Relative Virtual Address (RVA) Offset of Basilisk including section of this offset which we can see that it in .rdata meaning that its read-only data.
<details>
  <summary>Answer</summary>
<pre><code>00000138, .rdata</code></pre>
</details>

>Q5) Using the CFFExplorer tool, What DLL is responsible for executing “ShellExecuteA” API? (Format: filename.dll)

![0f48517b82066b6a5912cbe4a28cbbe7.png](/resources/0f48517b82066b6a5912cbe4a28cbbe7.png)

Go to "Import Directory" then click numbers after each Module to find out which module has "ShellExecuteA" API which we will find that `shell32.dll` has this API 

<details>
  <summary>Answer</summary>
<pre><code>shell32.dll</code></pre>
</details>

>Q6) Using the CFFExplorer tool, What DLL is responsible for executing registry related functions? What are these APIs? (Format: filename.dll - API1, API2, API3, API4)

![fe059835ce764f8c7fada871214e2c39.png](/resources/fe059835ce764f8c7fada871214e2c39.png)

Use the same method from previous question then we could see that `advapa32.dll` import these 4 registry related APIs.

<details>
  <summary>Answer</summary>
<pre><code>advapa32.dll - RegCloseKey, RegSetValueExA, RegOpenKeyExA, RegCreateKeyA</code></pre>
</details>

>Q7) Using the CFFExplorer tool, What are all the modules imported by Basilisk? (Format: Module1, Module2, Module3)

![3cebdd789558b72f2e2e2a807df036db.png](/resources/3cebdd789558b72f2e2e2a807df036db.png)
Basilisk import 3 modules as you can see from "Import Directory" in CFFExplorer
<details>
  <summary>Answer</summary>
<pre><code>kernel32.dll, advapi32.dll, shell32.dll</code></pre>
</details>

>Q8) Using the PEiD tool, Is Basilisk packed? What is the Entropy? (Format: Yes/No, X.XX)

![ddd311182ec1c0fadce37662df22c704.png](/resources/ddd311182ec1c0fadce37662df22c704.png)
Go back to PEiD and then click ">>" button to display "Extra Information" window then click ">" button at Entropy section then we should be able to see entropy of this file along with packed or unpacked verdict of PEiD. 
<details>
  <summary>Answer</summary>
<pre><code>No, 4.63</code></pre>
</details>

>Q9) What is the SHA256 hash value of the Basilisk? (Format: SHA256)

![047d39c320664481d523bc4edd3e45f9.png](/resources/047d39c320664481d523bc4edd3e45f9.png)
Lets use `certutil` to calculate SHA256 hash of this file 
<details>
  <summary>Answer</summary>
<pre><code>8dd96e84b444e5f9c0814f042dd1f679e20656354bc57f7b4a9439e66e426d66</code></pre>
</details>

>Q10) Using the PEView Tool, Can you identify when was Basilisk was made? (Format: YYYY/MM/DD XXX HH:MM:SS XXX)

![8b37116b462db71f9dd001d53966e2dc.png](/resources/8b37116b462db71f9dd001d53966e2dc.png)

Load the file in PEView then go to "IMAGE_FILE_HEADERS" under "IMAGE_NT_HEADERS" then we should be able to see time date stamp when this file was made.

<details>
  <summary>Answer</summary>
<pre><code>2008/10/10 Fri 15:49:18 UTC</code></pre>
</details>

![9ecab31eab0510b1cd926130fea14ad0.png](/resources/9ecab31eab0510b1cd926130fea14ad0.png)
https://blueteamlabs.online/achievement/share/52929/165
* * *