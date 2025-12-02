# [Blue Team Labs Online - The Walking Packets](https://blueteamlabs.online/home/investigation/the-walking-packets-f8cf5573cf)

![35ddb9b7d0c99338c503270835af604f.png](/resources/35ddb9b7d0c99338c503270835af604f.png)

>**Security Operations**

>**Tags**: Arkime PCAP CCTV
* * *

## Scenario
Zeta-9 operates a centralized surveillance platform that monitors laboratory activity and flags anomalies. Following the explosion in the laboratory facility, the company’s perimeter defenses recorded a firewall breach. 

In the hours after that detection (specifically between Wed Sep 24 00:00:00 UTC 2025 and Wed Sep 24 02:52:00 UTC 2025), Arkime captured a sequence of unusual events: atypical HTTP requests to the surveillance console. 

Using the Arkime network logs, reconstruct the attacker’s chain of actions. 

For this challenge, Arkime is available at: URL: `http://localhost:8005/sessions `

Credentials: admin / admin 

WARNING! Don’t forget to start the service first: `systemctl start arkimeviewer`

* * *
## Environment Awareness
### Evidence & Tool Discovery

![578cf4a92f59d1a882f3781f7b4605ad.png](/resources/578cf4a92f59d1a882f3781f7b4605ad.png)

When the initialization of the investigation machine complete, We can use `sudo systemctl start arkimeviewer` to start Arkime and as you can see that there is CyberChef folder and the Mission Brief file on the desktop as well but Mission Brief is not that important right now so lets focus on Arkime.

![cd5e67c40c596f1847894928d8beb5f8.png](/resources/cd5e67c40c596f1847894928d8beb5f8.png)

After start Arkime service, We can open the browser and go to `http://localhost:8005` which will prompt basic authentication for Arkime for us. we will have to put "admin" and "admin" here and login.

![9020a0caebf9fed53404df4f59b54cf0.png](/resources/9020a0caebf9fed53404df4f59b54cf0.png)

Now we should be able to access Arkime web interface on our web browser.

![b1436acc90f38f4d73674a20afe41535.png](/resources/b1436acc90f38f4d73674a20afe41535.png)

Lastly, we will need to reduce the scope as the scenario say "specifically between Wed Sep 24 00:00:00 UTC 2025 and Wed Sep 24 02:52:00 UTC 2025" and now we should have almost 400k entries from this time range which is quite a lot but now we shall start the investigation.

* * *
## Investigation
>Q1) What source IP address did the attacker use, and which application port was actively targeted?

![2c9482400dd765f0ff7a88b25569ec86.png](/resources/2c9482400dd765f0ff7a88b25569ec86.png)

First, I will check the SPIGraph to find how many IP and their connections to each other which I found that an IP address of 91.90.124.21 have insane amount of communication with 10.0.14.53 so I'll look at the communication between them to find if 91.90.124.21 is the IP address belong to the attacker.

![7cdf111fbf60a11bda6aa42757cb135c.png](/resources/7cdf111fbf60a11bda6aa42757cb135c.png)

First thing I noticed after filter for this IP address is the communication from 91.90.124.21 to storage console host with the internal IP address of 10.0.14.53 / external of 18.133.31.160 on port 3000

Filter: `ip.src == 91.90.124.21 && http.method == GET`

![2da2b86bfcd274b4e805293ee148b827.png](/resources/2da2b86bfcd274b4e805293ee148b827.png)

Further events reveal multiple SQL injection attempt from 91.90.124.21 to the storage console which is now confirmed that this IP address is belong to the threat actor.

Filter: `ip.src == 91.90.124.21 && http.method == GET && http.statuscode != 404 && http.statuscode != 400 `

<details>
  <summary>Answer</summary>
<pre><code>91.90.124.21, 3000</code></pre>
</details>

>Q2) What is the MD5 checksum of the HTTP body returned by the home page?

![f230f233e86d3a946ffc7510fd2698c9.png](/resources/f230f233e86d3a946ffc7510fd2698c9.png)

To find MD5 checksum of the HTTP body of home page, we can inspect the communication to the home page by the attacker and Arkime already have MD5 checksum of this HTTP body for us right here.

![4499f56b084e4e72858c73c684d314d4.png](/resources/4499f56b084e4e72858c73c684d314d4.png)

Then If we take a look at the content of this body, there is nothing too interesting here so by obtaining the body hash then we can use it to filter out this page to only focus on the successful attack of the threat actor.

<details>
  <summary>Answer</summary>
<pre><code>ca1d882d9b1aac5f04f39509ee17f001	</code></pre>
</details>

>Q3) Which HTTP path did the attacker call to enumerate stored objects?

![373edc50b040b7d3b58b62d21f343d10.png](/resources/373edc50b040b7d3b58b62d21f343d10.png)

After filtering out the all request that return with standard html body from previous question, it come down to only 3 entries which indicates that the threat actor successfully exploited SQL Injection vulnerability in the end and download object ID 6 from the storage console.

Filter: `ip.src == 91.90.124.21 && http.method == GET && http.statuscode != 404 && http.statuscode != 400 && http.md5 != ca1d882d9b1aac5f04f39509ee17f001`

![6197a3e6884f47251ccb5737a8c590ba.png](/resources/6197a3e6884f47251ccb5737a8c590ba.png)

We can see that the vulnerable endpoint is the `/search` path here and we can see that the result of this query it to return all objects hosting on this storage console.

<details>
  <summary>Answer</summary>
<pre><code>/search?</code></pre>
</details>

>Q4) What SQL injection payload was used to enumerate the object records?

![9c5aa219171e8ec5becd515a16b9d069.png](/resources/9c5aa219171e8ec5becd515a16b9d069.png)

We can use URL Decode recipe from CyberChef to decode the payload for this question.

<details>
  <summary>Answer</summary>
<pre><code>a' OR '1'='1</code></pre>
</details>

>Q5) Which account name was set as the owner in the uploaded files' metadata?

![1fcf033c4698c0356c983062cccb5b6f.png](/resources/1fcf033c4698c0356c983062cccb5b6f.png)

We can see that the owner of all files is Frankenstein Code which is the researcher that we will have to investigate his workstation on [Zeta-End](https://blueteamlabs.online/home/investigation/zeta-end-2a5b4e8c18) investigation

<details>
  <summary>Answer</summary>
<pre><code>Frankenstein Code</code></pre>
</details>

>Q6) Which filename metadata corresponds to the camera of interest (the file the attacker exfiltrated)?

![95deeea06a1dbcfb9c7764f6aa7a231f.png](/resources/95deeea06a1dbcfb9c7764f6aa7a231f.png)

After leaked all files on this storage console, the threat actor only request to download file with object id 6 which is `cam06_ai_monitor_securityincident.mp4` and we can see that the storage console is hosting file with minio on port 9000 

<details>
  <summary>Answer</summary>
<pre><code>cam06_ai_monitor_securityincident.mp4</code></pre>
</details>

>Q7) What is the exact S3 object key that was downloaded by the attacker?

![34b47be4a4b5a2817441e2879bb8e0b1.png](/resources/34b47be4a4b5a2817441e2879bb8e0b1.png)

Copy the value of this key here to answer this question. 

<details>
  <summary>Answer</summary>
<pre><code>uploads/525e1f476a399b2675777f6c2993aba1_cam06_ai_monitor_securityincident.mp4</code></pre>
</details>

>Q8) Which path and ID did the attacker call to obtain the presigned download URL?

![c71849f442687ac1ab42365836052056.png](/resources/c71849f442687ac1ab42365836052056.png)

<details>
  <summary>Answer</summary>
<pre><code>/download,6</code></pre>
</details>

>Q9) What User-Agent string did the attacker present when retrieving the file?

![947de32ac2f0ae937dd01a6bba3bd826.png](/resources/947de32ac2f0ae937dd01a6bba3bd826.png)

The user-agent string indicates that the threat actor operated this from WIndows workstation.

<details>
  <summary>Answer</summary>
<pre><code>Mozilla/5.0 (Windows NT; Windows NT 10.0; en-CA) WindowsPowerShell/5.1.26100.6584</code></pre>
</details>

>Q10) Based on the network evidence, what host:port did the attacker ultimately reach in order to retrieve the object from the storage service?

![2b2128f792a0b7b9c2f8d6af363f7e10.png](/resources/2b2128f792a0b7b9c2f8d6af363f7e10.png)

<details>
  <summary>Answer</summary>
<pre><code>minio:9000</code></pre>
</details>

>Q11) After downloading and watching the video, what credentials are visible in the recording?

To get the answer of this question, I have 2 paths which are both intended and unintended. Which I used unintended path to finish this investigation but I'll show you both and tell you the story of why I missed the first blood of this investigation XD

![c59c3080310b84a8b6ef081b614f736e.png](/resources/c59c3080310b84a8b6ef081b614f736e.png)
![2bc6f503457a86bee2bfb45e960182ab.png](/resources/2bc6f503457a86bee2bfb45e960182ab.png)

First if you are not aware, we are indeed in the storage console host that host minio insider the docker container

![6249777ec519c8a646a450ca10294be0.png](/resources/6249777ec519c8a646a450ca10294be0.png)

I'll show the Intended path first. to get the file, we will need to replicate what the threat actor was doing by request another download url (since the old one already expired)

![902e5a25ed4fb340940a9bb3c32382ed.png](/resources/902e5a25ed4fb340940a9bb3c32382ed.png)

We can access the storage website on port 3000 (yes I didn't know this, I just realized it after SOUFFLETRINITY  already took first blood)

![41990fec83f229d3c543b220fca5c5c5.png](/resources/41990fec83f229d3c543b220fca5c5c5.png)

By accessing the same url (`http://localhost:3000/download?id=6`), we will have another url that can be used to download the same video that threat actor downloaded.

![c6e3ecad62844e4e4d0916db14c952a6.png](/resources/c6e3ecad62844e4e4d0916db14c952a6.png)

In this video, lie the credential of operator39 user which is the local administrator of JUMPHOST user that we will be investigating on [The Headless Dead](https://blueteamlabs.online/home/investigation/the-headless-dead-f8e2c3f90b) investigation

<details>
  <summary>Answer</summary>
<pre><code>operator39:halloween2025</code></pre>
</details>

Now lets see what I was doing to complete the lab in the unintended path

![b6b217ae1fc5d96a7f5f65e754ebbace.png](/resources/b6b217ae1fc5d96a7f5f65e754ebbace.png)

First I check the minio on port 9000 which I don't have any credential to login yet.

![c6b2c1a23fbba51772380e1fbdecf807.png](/resources/c6b2c1a23fbba51772380e1fbdecf807.png)

First, I'll switch my user to root and list all docker container. now I have container ID of the one that host minio.

![23ddc60af6cf747c8f42bd7dfc885383.png](/resources/23ddc60af6cf747c8f42bd7dfc885383.png)

I access the container and look at the environment variable that often defined user credential here and now I have admin credential to access minio

![d0d0dfb61a352c63fc046c69a79dc73a.png](/resources/d0d0dfb61a352c63fc046c69a79dc73a.png)

I can now watch any video including easter egg put by SBT team.

https://blueteamlabs.online/achievement/share/52929/281
* * *