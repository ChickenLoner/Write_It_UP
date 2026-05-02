# [Blue Team Labs Online - Thumbs Up](https://blueteamlabs.online/home/investigation/thumbs-up-f8f5f74383)

![a3db9d6e2bdeb8b1fb36960ba52eb415.png](/resources/a3db9d6e2bdeb8b1fb36960ba52eb415.png)

A new superweapon concept art plans were leaked from a hungarian research center.

>Digital Forensics

>**Tags**: Thumbcache Viewer PowerShell Google Image Search
* * *
**Scenario**
A new superweapon concept art plans were leaked from a hungarian research center. Before our Operative Threat Hunter Team found the presumed guilty, he deleted all of the pictures/documents from his laptop.

All of the DFIR team members are working hard to get back the data, now you got a piece of the evidences to work on. Find related evidences and prove the original concept art plans was on this computer.
* * *
## Environment Awareness
### Evidence & Tool Discovery

![d88d72f634728d028f4ff1d27df3726f.png](/resources/d88d72f634728d028f4ff1d27df3726f.png)

We have a single folder on the desktop that we can use to solve this investigation and inside this folder, there are 3 more subfolders inside of it which contains thumbcache files, original concept art and thumbcache viewer that will be used to open thumbcache files.

***
## Investigation 
>Q1) How many entries are there in the iconcache_16.db?

![1d5a3ecd3645d6de0ea1ccfd89941680.png](/resources/1d5a3ecd3645d6de0ea1ccfd89941680.png)

After open `iconcache_16.db` in thumbcache viewer, we can see that there are total of 370 entries that recognized by thumbcache viewer

<details>
  <summary>Answer</summary>
<pre><code>370</code></pre>
</details>

>Q2) How many .db files are empty?

![7c787288e9a8ad9f76cf6938450c7007.png](/resources/7c787288e9a8ad9f76cf6938450c7007.png)

We can take a look at .db files inside Evidence folder which we can see that there are 3 db files with 1KB file size indicates that its not store any data but database structure.

<details>
  <summary>Answer</summary>
<pre><code>3</code></pre>
</details>

>Q3) Which vpn client was used to connect other computers securely?

![e69dba29355e9666e0315b1bec1f0ba2.png](/resources/e69dba29355e9666e0315b1bec1f0ba2.png)

After searching for a while then we will come across this icon at entry 119 and if you searched for this icon on Google then you will see that this is an icon of openvpn

<details>
  <summary>Answer</summary>
<pre><code>openvpn</code></pre>
</details>

>Q4) What is the name of the PDF reader they used?

![9fe492d6428a8bae9ead287a6ee6cac9.png](/resources/9fe492d6428a8bae9ead287a6ee6cac9.png)

Scroll down to entry 123 then we will see this icon 

![a618e90de52041a5ad4c7f04a83e2cc0.png](/resources/a618e90de52041a5ad4c7f04a83e2cc0.png)

Which is an icon of Javelin PDF Readers

<details>
  <summary>Answer</summary>
<pre><code>Javelin</code></pre>
</details>

>Q5) There are maps saved to plan the stealing operation. What is the name of the city where the research lab is (inside a hill)?

![6684fbb1a0ab7868244c058664b59851.png](/resources/6684fbb1a0ab7868244c058664b59851.png)

After browsing `thumbcache_1280.db`, we can see a map that was opened by user and this map leads to Zirc

<details>
  <summary>Answer</summary>
<pre><code>Zirc</code></pre>
</details>

>Q6) What was the operation name?

![50c7b37ec3cdc4c5681b572313393e44.png](/resources/50c7b37ec3cdc4c5681b572313393e44.png)

We can also see the name of the operation from `thumbcache_1280.db` as well which we can see that the silhouette really resembled concept art we have.  

<details>
  <summary>Answer</summary>
<pre><code>STEALTHTAURUS</code></pre>
</details>

>Q7) What is the first recognizable, 256px wide concept art picture's Cache Entry Hash? 

![3e6ec7b8f169159caa82cbc7d39c8880.png](/resources/3e6ec7b8f169159caa82cbc7d39c8880.png)

We can see all 3 of concept art within these thumbcache but the first recongizable one is this image that resembled `taurus03.jpg` file and we can copy value inside Cache Entry Hash field to answer this question

<details>
  <summary>Answer</summary>
<pre><code>8c6951f58d98fde9</code></pre>
</details>

>Q8) What is the md5 sum of the previously mentioned file?

![dace09ed85f9145b8fac7cce6fa6868d.png](/resources/dace09ed85f9145b8fac7cce6fa6868d.png)

We can right click and "Save Selected..." to save this cache image file to our desired location

![ceeaaa9d3f9cbd8281bf6e4aed748b15.png](/resources/ceeaaa9d3f9cbd8281bf6e4aed748b15.png)

Then we can use available tool such as `certutil` or `Get-FileHash` cmdlet to calculate MD5 hash of this file like this

<details>
  <summary>Answer</summary>
<pre><code>c8f2dc1db01247a38af6ba74edfd3a2c</code></pre>
</details>

![f37362784bcb2cb26afb8df231a8299c.png](/resources/f37362784bcb2cb26afb8df231a8299c.png)
https://blueteamlabs.online/achievement/share/52929/159
* * *