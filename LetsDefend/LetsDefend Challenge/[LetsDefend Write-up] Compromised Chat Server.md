# [LetsDefend - Compromised Chat Server](https://app.letsdefend.io/challenge/compromised-chat-server)
Created: 17/09/2024 11:02
Last Updated: 17/09/2024 14:02
* * *
![a8fa28b0b454b62885422a01efcf7863.png](../../_resources/a8fa28b0b454b62885422a01efcf7863.png)
In the company, one of our teams uses Openfire, an XMPP-based chat server for their communications. Recently, the L1 analyst detected suspicious activity on the server, including abnormal login attempts and traffic spikes. Further investigation suggests a potential exploitation of CVE-2023-32315, a critical vulnerability in Openfire allowing remote code execution. To confirm this, the L1 analyst captured a packet capture (PCAP) of the server's network traffic. As an investigator, your task is to analyze the PCAP, identify any signs of compromise, and trace the attacker's actions.

File location: /root/Desktop/ChallengeFile/Challenge-File.zip
File Password: infected

* * *
## Understand the exploit
![f0075c6670a564e8321c0d42b04a9b3a.png](../../_resources/f0075c6670a564e8321c0d42b04a9b3a.png)
Before we start investigate this case, we might need to understand what CVE-2023-32315 really is so here is a [blog wrote by Jacob Baines](https://vulncheck.com/blog/openfire-cve-2023-32315) that would help us learn what happened when we exploited this CVE.

![07433fe1db08d094a5f803703045732c.png](../../_resources/07433fe1db08d094a5f803703045732c.png)
To put it simply, it start from a path traversal that will access `user-create.jsp` endpoint which responsible for user creation then create admin user and login as admin user to upload openfire plugin file (.jar file) that is actually a webshell which will allow threat actor to execute any arbitrary commands as desired.

Now we know what to look for then we can start our investigation.

## Start Investigation
>How many GET requests are there in total?

![d9bfa096b37967c2eb4c8700c084805f.png](../../_resources/d9bfa096b37967c2eb4c8700c084805f.png)

Since we were provided with pcap file then we can open it in Wireshark and use `http.request.method == "GET"` filter to display all HTTP GET request like this.

```
128
```

>What is the host value in the first HTTP packet?

![4c353d9ba41e6bc8236a68f98ba3217b.png](../../_resources/4c353d9ba41e6bc8236a68f98ba3217b.png)

Reduce our filter to `http` then inspect first HTTP request (packet number 29) to get Host value, we can see that vulnerable openfire was running on port 9090 of 192.168.18.155

```
192.168.18.155:9090
```

>What is the CSRF token value for the first login request?

![cc5c33d310e49c6282d342dd5d4e24e0.png](../../_resources/cc5c33d310e49c6282d342dd5d4e24e0.png)

This CSRF token will differentiate legitimate user from the threat actor so we can see that after filtered by HTTP POST request, IP 192.168.18.1 sent POST request to vulnerable openfire server which likely to be the legitimate user that set this server up.   

```
A2HxEJfAcs31PlD
```

>What is the password of the first user who logged in?

![817e1a9d910065b53e38c736d1feafb7.png](../../_resources/817e1a9d910065b53e38c736d1feafb7.png)

Inspect HTTP Form then we will have credential of legitimate admin of this openfire server.

```
adminnothere
```

>What is the first username that was created by the attacker?

![26c06900983001c367244e7935597ef7.png](../../_resources/26c06900983001c367244e7935597ef7.png)

We know that the threat actor has to create user with `user-create.jsp` so we can just search for that and the result shown 4 HTTP GET request to this endpoint and this is the first one request that was successfuly, here is the user that was created. 

```
umu6od
```

>How many user accounts did the attacker create?

![c0226f02588bbda7cf3809c1602c79b4.png](../../_resources/c0226f02588bbda7cf3809c1602c79b4.png)

There are 4 HTTP GET requests to this endpoint but not all of them are successful, as we can see that only 2 users were successfully created. 

![21db9bbff016005b526f12bde6ae78d2.png](../../_resources/21db9bbff016005b526f12bde6ae78d2.png)

Here is the second user that was created.

```
2
```

>What is the username that the attacker used to log in to the admin panel?

![e8ba3a52bb7a19a9ff8cb522fdfc7d55.png](../../_resources/e8ba3a52bb7a19a9ff8cb522fdfc7d55.png)

Scroll down for a bit from user account creation then we will see that second user that was created is the one that threat actor authenticated to openfire dashboard.

```
byvr3r
```

>What is the name of the plugin that the attacker uploaded?

![a7bb81896147804cf37d5dfc6645bc9e.png](../../_resources/a7bb81896147804cf37d5dfc6645bc9e.png)

We know that threat actor had to upload webshell in admin panel so we can inspect traffic to admin panel like this then we can see "application/java-archive" being uploaded.

![f9b1de04eef907d779938d60ebacd874.png](../../_resources/f9b1de04eef907d779938d60ebacd874.png)

```
openfire-management-tool-plugin.jar
```

>What is the first command executed by the user?

![9e37c88df7dfc2d86b01945b1040ef94.png](../../_resources/9e37c88df7dfc2d86b01945b1040ef94.png)

We know that it has to be a webshell so we have to find HTTP POST request sent to plugin path, which we can see that the threat actor successfully executed 2 commands and first command is `whoami`.

```
whoami
```

>What is the last command that the attacker used on the server?

![70b46b2aec72836c8f56f92615645a29.png](../../_resources/70b46b2aec72836c8f56f92615645a29.png)

The second command that was successfully executed is this netcat reverse shell command that will connect to the threat actor on port 8888 so our next step is to find that connection and find out which command is the latest command.

![504e0d732444153860e64d6d9f6d3350.png](../../_resources/504e0d732444153860e64d6d9f6d3350.png)

we can see that after the threat actor received reverse shell connection, the threat actor executed 3 commands and the last one is `uname -a` that will display OS name.

```
uname -a
```

* * *
## Summary
On this challenge, we learned about CVE-2023-32315 which is Openfire Path Traversal that can be escalated to RCE and by analyzing provided pcap file, we can see how it worked in practical.

<div align=center>

![65e564f08e8bf7a4537fc3f95b39291d.png](../../_resources/65e564f08e8bf7a4537fc3f95b39291d.png)
</div>

* * *
