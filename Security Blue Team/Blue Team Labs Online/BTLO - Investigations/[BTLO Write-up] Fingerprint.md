# [Blue Team Labs Online - Fingerprint](https://blueteamlabs.online/home/investigation/fingerprint-f57322044b)

![2739024265e034ba1dc1640372a6f887.png](/resources/2739024265e034ba1dc1640372a6f887.png)

>**Security Operations**

>**Tags**: Wireshark Linux CLI T1046 T1608.001 T1059 T1041
* * *
**Scenario**
Analyze the network traffic to identify the C2 communication and fingerprint it using ja3.
* * *
## Environment Awareness
### Evidence & Tool Discovery
![fcef8b823aa728df2165aec8f6091ce7.png](/resources/fcef8b823aa728df2165aec8f6091ce7.png)

We have [pyJA3](https://github.com/salesforce/ja3/tree/master/python) script that will make JA3 fingerprint of provides pcap and a pcap file that we need to investigate but lets save JA3 for last Q and start with open PCAP file.
***
## Investigation
>Q1) What is the attacker IP that scanned the TCP ports? (Format: X.X.X.X)

![d7d3039daf87988801f359f29f2c0707.png](/resources/d7d3039daf87988801f359f29f2c0707.png)

After open pcap file then I started by open Conversation statistic and find for the highest packet sent between 2 IP addresses then I found that this conversation has the highest packet sent so lets take a look at their conversation.

![de53ecf162844d391aee1601aa55b3fa.png](/resources/de53ecf162844d391aee1601aa55b3fa.png)

Then we can see that an IP address 192.168.1.16 sent so many GET request to Web server hosting on 192.168.1.9 attempts to discover valid directories of this website.
<details>
  <summary>Answer</summary>
<pre><code>192.168.1.16</code></pre>
</details>

>Q2) What is the first file uploaded? (Format: filename.ext)

![696eefe143cf84d321e02d84427ae9e7.png](/resources/696eefe143cf84d321e02d84427ae9e7.png)

To find for any data sent to website such as authentication or file upload, we need to filter with `http.request.method=="POST"` for HTTP POST method then we will see several POST request to the same endpoint for bruteforcing attack to be authenticated.

![fce77526047dbb3bfde630d7a5218b1e.png](/resources/fce77526047dbb3bfde630d7a5218b1e.png)

Then after successfully authenticated, other POST request were sent to another endpoint which we can see that this time the attacker uploaded `shell.php` to the web server hence the answer of this question.

<details>
  <summary>Answer</summary>
<pre><code>shell.php</code></pre>
</details>

>Q3) What is the first command executed by the attacker? (Format: command)

![d104585f7b6b8f0d037744e1f59738cd.png](/resources/d104585f7b6b8f0d037744e1f59738cd.png)

Take a look at this webshell then we can see its a simple webshell that will execute system command passes to `cmd` variable.

![86d59a0b7a56c43841a26c0605e9f2ad.png](/resources/86d59a0b7a56c43841a26c0605e9f2ad.png)

So I made my filter precise to `shell.php` which we can see 3 commands where executed via this webshell from `touch test.txt` (create test.txt file), `dir` (list content on current directory for Windows) and lastly `pwd` (print working directory)

<details>
  <summary>Answer</summary>
<pre><code>touch test.txt</code></pre>
</details>

>Q4) What is the second file uploaded by the attacker? (Format: filename.ext)

![d8b0c7f869e1f11ce07557a3b7ab1189.png](/resources/d8b0c7f869e1f11ce07557a3b7ab1189.png)

Go back to the POST request, we can see that is another file was uploaded to web server and its `shell2.php` possibly reverse shell one.
<details>
  <summary>Answer</summary>
<pre><code>shell2.php</code></pre>
</details>

>Q5) What is the port that the attacker used for a reverse shell? (Format: port)

![8cce87bf68b147e32f8d558ee52bbc7c.png](/resources/8cce87bf68b147e32f8d558ee52bbc7c.png)

Take a look at the content inside this webshell, sure enough its a php reverse shell from pentestmonkey.
<details>
  <summary>Answer</summary>
<pre><code>1234</code></pre>
</details>

>Q6) What is the C2 URL where the malware is hosted? (Format: http://something:port/something)

![9400ccc1a9402a712bef40fb2fae218a.png](/resources/9400ccc1a9402a712bef40fb2fae218a.png)

We know that reverse shell will be connected back to 192.168.1.16 on port 1234 so we can just filter for `tcp.port == 1234` then we should be able to see the stream of reverse shell connection.

![7a8d2e65f5f6e31e643b459e680162ba.png](/resources/7a8d2e65f5f6e31e643b459e680162ba.png)

Once we followed this stream, the attacker executed several commands but ultimately downloaded malware with wget to `/tmp` directory (Q7) as shown in the image above.

<details>
  <summary>Answer</summary>
<pre><code>http://192.168.1.6:8965/myapp</code></pre>
</details>

>Q7) What is the location where the command is executed? (Format: /location)
<details>
  <summary>Answer</summary>
<pre><code>/tmp</code></pre>
</details>

>Q8) After the execution of malware, it connected to the C2 server. In order to share/hunt information related to this malware traffic, use the ja3 in the desktop and produce ja3 fingerprint of the malware traffic (Format: JA3 hash of malware traffic)

![53f458f80743dcd38148b86849d98f8a.png](/resources/53f458f80743dcd38148b86849d98f8a.png)

And after it was downloaded, the attacker executed it and look like it will establish connection to `https//192.168.1.6.443/` which we can't read the content since its encrypted so its time to use pyJA3 script. 

![6a369f6cb19f0c3f0baef4eef32c58bd.png](/resources/6a369f6cb19f0c3f0baef4eef32c58bd.png)

This script is easy to use, we can use `python ja3.py ../../fingerprint.pcap > ../../output.txt` which will pipe all output to a text file then use grep with C2 we found earlier to get JA3 fingerprint of this C2.

<details>
  <summary>Answer</summary>
<pre><code>4264590bacd8b2accb2021b7adb3b98e</code></pre>
</details>

![b6cd8959f5ee6e696c5911268f45bae0.png](/resources/b6cd8959f5ee6e696c5911268f45bae0.png)
https://blueteamlabs.online/achievement/share/52929/103
* * *