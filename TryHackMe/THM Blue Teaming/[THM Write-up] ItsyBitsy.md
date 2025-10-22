# [TryHackMe - ItsyBitsy](https://tryhackme.com/room/itsybitsy)
![c857f94abcff342c3b66ac6ac9c6354d.png](../../_resources/c857f94abcff342c3b66ac6ac9c6354d.png)
***
During normal SOC monitoring, Analyst John observed an alert on an IDS solution indicating a potential C2 communication from a user Browne from the HR department. A suspicious file was accessed containing a malicious pattern `THM:{ ________ }`. A week-long HTTP connection logs have been pulled to investigate. Due to limited resources, only the connection logs could be pulled out and are ingested into the `connection_logs` index in Kibana.

Our task in this room will be to examine the network connection logs of this user, find the link and the content of the file, and answer the questions.
***
![4eda8339a430cb8aac72519e56b703f3.png](../../_resources/4eda8339a430cb8aac72519e56b703f3.png)

After starting the machine, you can either launch the **AttackBox** or directly access the URL http://$IP/app/discover#/ if you're already connected to the TryHackMe VPN. This will take you to the **Discover** page in Elasticsearch/Kibana, where you can begin your investigation.

>How many events were returned for the month of March 2022?

![1d7d68ed854ee838a7330c861c01c5ba.png](../../_resources/1d7d68ed854ee838a7330c861c01c5ba.png)

In Kibana, we always need to specify time range and luckily for us that the room already provided the time range for us which we can specify the time range like this and click "Update".

![ff31552620730a46526bbfd7cd8899e5.png](../../_resources/ff31552620730a46526bbfd7cd8899e5.png)

Now we have total of 1482 events during March 2022 which is the answer of this question

```
1482
```

>What is the IP associated with the suspected user in the logs?

![d80d8dc77d615a291ed686731453e2a2.png](../../_resources/d80d8dc77d615a291ed686731453e2a2.png)

While investigating the connection logs, which appear to be web server logs, I focused on identifying any unusual values such as **URIs** or **IP addresses**. During the analysis, I noticed an interesting **user-agent string**: `bitsadmin`.

This user-agent is associated with **Bitsadmin**, a Windows "living-off-the-land" binary (LOLBin) that can be exploited to download files. This discovery might represent a straightforward indicator of suspicious activity—a "low-hanging fruit" in our investigation.

![34036ea1dc737943a3c6f0480ae07bc7.png](../../_resources/34036ea1dc737943a3c6f0480ae07bc7.png)

So we can query with `user-agent:bitsadmin` to get event with this user agent then we will have these 2 events sending from 192.166.65.54 to pastebin.com

```
192.166.65.54
```

>The user’s machine used a legit windows binary to download a file from the C2 server. What is the name of the binary?

![d2383ec5213834f1e47f19f470a5e29c.png](../../_resources/d2383ec5213834f1e47f19f470a5e29c.png)

Bitsadmin is the powerful Windows lolbin that can be used for downloading a file and execute it, more detailed about the abuse of this binary could be found in the Lolbas project right here
- https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/

```
bitsadmin
```

>The infected machine connected with a famous filesharing site in this period, which also acts as a C2 server used by the malware authors to communicate. What is the name of the filesharing site?

![c7db59d2064a344a2b01e8f9d86616ed.png](../../_resources/c7db59d2064a344a2b01e8f9d86616ed.png)
```
pastebin.com
```

>What is the full URL of the C2 to which the infected host is connected?

![f73e364032e9d44e4a7ca723e486793f.png](../../_resources/f73e364032e9d44e4a7ca723e486793f.png)
```
pastebin.com/yTg0Ah6a 
```

>A file was accessed on the filesharing site. What is the name of the file accessed?

![bf47ed5f1929998fccbbf7329e20e351.png](../../_resources/bf47ed5f1929998fccbbf7329e20e351.png)

Following the full URL —https://pastebin.com/yTg0Ah6a, We can see that this pastebin is hosting a secret file containing a flag which can be submitted to complete the room.

```
secret.txt
```

>The file contains a secret code with the format THM{_____}.
```
THM{SECRET__CODE}
```

![61061590c92e9699c2674812f39b8b29.png](../../_resources/61061590c92e9699c2674812f39b8b29.png)

And we are done!
***