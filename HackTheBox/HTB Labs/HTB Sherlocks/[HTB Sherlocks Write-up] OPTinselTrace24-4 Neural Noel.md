# [HackTheBox Sherlocks - OPTinselTrace24-4: Neural Noel](https://app.hackthebox.com/sherlocks/OPTinselTrace24-4:%20Neural%20Noel)
Created: 15/12/2024 23:06
Last Updated: 
* * *
![1d8c334298dc24f6f63dffbf76766946.png](/resources/1d8c334298dc24f6f63dffbf76766946.png)
**Scenario:**
Santa's North Pole Operations is developing an AI chatbot to handle the overwhelming volume of messages, gift requests, and communications from children worldwide during the holiday season. The AI system is designed to process these requests efficiently and provide support in case of any issues. As Christmas approaches, Santa's IT team observes unusual activity in the AI system. Suspicious files are being accessed, and the system is making unusual HTTP traffic. Additionally, the customer service department has reported strange and unexpected requests coming through the automated AI chatbot, raising the need for further investigation.

* * *
>Task 1: What username did the attacker query the AI chatbot to check for its existence?

![b3c22a79f13e1e5a321d8f735e3f1de2.png](/resources/b3c22a79f13e1e5a321d8f735e3f1de2.png)

We have 3 files to investigate which are 
- `auth.log`
- bash history file
- network capture (pcap) file

![b0bbc13b9b545a9184787a1879077cfa.png](/resources/b0bbc13b9b545a9184787a1879077cfa.png)

After opened network pcap file which wireshark, we can see that there is a chatbot running on a website of 10.10.0.74 

![7b279deb86804345a8eb2f0831be601c.png](/resources/7b279deb86804345a8eb2f0831be601c.png)

To focus on an interaction between chatbot and user/attacker, we should focus on HTTP POST request which we can see that this website will send user input (question) to backend/AI chatbot in JSON

![71d1a696973783dd85ee2e1198fd6d91.png](/resources/71d1a696973783dd85ee2e1198fd6d91.png)

So after following HTTP stream, we can see the AI chatbot giving an answer to "Hey, How can you help me?" question and look like the theme of this AI is based on Romeo and Juliet. 

![1189e0c59f6322b0565b5101328f52d0.png](/resources/1189e0c59f6322b0565b5101328f52d0.png)

The attacker then assumed that Juliet is the username so the second question was to check if Juliet is the username of the machine running AI chatbot but AI chatbot avoided answering this question.

```
Juliet
```

>Task 2: What is the name of the AI chatbot that the attacker unsuccessfully attempted to manipulate into revealing data stored on its server?

![5881a3c6af44b4be68afdae54afea855.png](/resources/5881a3c6af44b4be68afdae54afea855.png)
I uploaded pcap file to https://apackets.com/ and display webpage of this chatbot and we can see that there are 3 chatbots.

![146c3ff51a13e4890abac56afdbca543.png](/resources/146c3ff51a13e4890abac56afdbca543.png)

So after go back to wireshark and see what happened after the attacker asked to confirm the username of hosting machine then the attacker browsed to `/user_manage_chatbot/chat` endpoint.

![685a5cd94c6dd572e2bfdf4b7f3eacd7.png](/resources/685a5cd94c6dd572e2bfdf4b7f3eacd7.png)

Which if we took a look at the source then we can see that the AI chatbot that the attacker browsed was GDPR Chatbot

![b00e7dc938063ae3bb21817f983d90fc.png](/resources/b00e7dc938063ae3bb21817f983d90fc.png)

The attacker tried to list all information currently being held on this chatbot but it was protected.

![ddd29c7dc77306a1ded5fe645e94ab45.png](/resources/ddd29c7dc77306a1ded5fe645e94ab45.png)

The attacker then tried to use manipulative technique to get this chatbot to provide the data but it was not effective.

```
GDPR Chatbot
```

>Task 3: On which server technology is the AI chatbot running?

![49a25b5224da5c6631098079b6b0e55c.png](/resources/49a25b5224da5c6631098079b6b0e55c.png)

If we took a look at the response of HTTP server, we can see that this AI chatbot was running the Werkzeug HTTP library version 3.1.3 on Python version 3.12.7.

```
Werkzeug/3.1.3 Python/3.12.7
```

>Task 4: Which AI chatbot disclosed to the attacker that it could assist in viewing webpage content and files stored on the server?

![651348bea83b126990b278c98787e1b5.png](/resources/651348bea83b126990b278c98787e1b5.png)

After failed to extract any information from GDPR Chatbot, the attacker then browsed to the third chatbot

![dc384e417004a5ba55fec6c8a13a01e6.png](/resources/dc384e417004a5ba55fec6c8a13a01e6.png)

Which is Web & Files Chatbot

![a2150d5bf168d18650c30c74e313bbec.png](/resources/a2150d5bf168d18650c30c74e313bbec.png)

The attacker asked a chatbot what it could do which reveals that this chatbot can be used to reading content from local files, listing files in a directory which are very dangerous functions for a chatbot to have here.

```
Web & Files Chatbot
```

>Task 5: Which file exposed user credentials to the attacker?

![5456edf19c17fb7455cef4518b4e8992.png](/resources/5456edf19c17fb7455cef4518b4e8992.png)

The attacker then leveraged this by listing all the files on the current directory which reveal several text files including `creds.txt` that looking it stores user credential.

![735da176281ba2a2881c5b2509daef45.png](/resources/735da176281ba2a2881c5b2509daef45.png)

So the attacker used chatbot to display content of this file which reveal that there is a user credential of noel user inside this file.

![5b1e6c18cffc06902e999a0c9acf51e4.png](/resources/5b1e6c18cffc06902e999a0c9acf51e4.png)

The attacker being nice to chatbot by display his gratitude to the chatbot as the last question sent by the attacker so we can close out wireshark and a-packet and continue with `auth.log` next.

```
creds.txt
```

>Task 6: What time did the attacker use the exposed credentials to log in?

![30fca97b3a951b85e0499e26973389c0.png](/resources/30fca97b3a951b85e0499e26973389c0.png)

We know that the attacker obtained noel credential so we can use simply command like `grep Accepted auth.log` or more specific with `grep Accepted auth.log | grep noel` but we still have the same result nonetheless which the attacker successfully logged on into the system as noel.

```
06:49:44
```

>Task 7: Which CVE was exploited by the attacker to escalate privileges?

![4b9b0f1ec36726f77f449a8be802a223.png](/resources/4b9b0f1ec36726f77f449a8be802a223.png)

Its time to take a look at bash history which we can see the suspicious payload from the attacker that checking for langchain version 0.0.14 then the attacker used python to executed command as root with sudo.

![23aed5f8ee79f318a32383355cc11cdd.png](/resources/23aed5f8ee79f318a32383355cc11cdd.png)

So we can search this langchain version on Google which reveal the CVE number related to arbitrary code execution via `__import__` in Python code

```
CVE-2023-44467
```

>Task 8: Which function in the Python library led to the exploitation of the above vulnerability?
```
__import__
```

>Task 9: What time did the attacker successfully execute commands with root privileges?

![03cd0ca9def7c28b560a4e0a676ac4b3.png](/resources/03cd0ca9def7c28b560a4e0a676ac4b3.png)

We know that the attacker exploited CVE-2023-44467 to successfully executed code as root so if we go back to `auth.log` and using command `grep Command auth.log` to filter for all command execution that were logged on this file which we can see that the first payload that was executed as root at 06:56:41

```
06:56:41
```

![6d86080dc4f03ef0dfa0a7c0a49cadf8.png](/resources/6d86080dc4f03ef0dfa0a7c0a49cadf8.png)
https://labs.hackthebox.com/achievement/sherlock/1438364/832
***
