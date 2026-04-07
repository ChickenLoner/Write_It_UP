# [HackTheBox Sherlocks - OpTinselTrace-1](https://app.hackthebox.com/sherlocks/OpTinselTrace-1)

![2c828b466f1a819508b8cd7725725d9f.png](/resources/2c828b466f1a819508b8cd7725725d9f.png)

## Scenario
An elf named "Elfin" has been acting rather suspiciously lately. He's been working at odd hours and seems to be bypassing some of Santa's security protocols. Santa's network of intelligence elves has told Santa that the Grinch got a little bit too tipsy on egg nog and made mention of an insider elf! Santa is very busy with his naughty and nice list, so he’s put you in charge of figuring this one out. Please audit Elfin’s workstation and email communications. Please note - these Sherlocks are built to be completed sequentially and in order!

* * *
## Evidence Handling

![0305e2e309f66385e0e9d8fa3d8238f8.png](/resources/0305e2e309f66385e0e9d8fa3d8238f8.png)

In this sherlock, we are provided with 2 types of evidence which are the Triage data and live response from the workstation when collection tool was ran. (KAPE)

![8466fe0f865a55e39b5cebfd475a8e42.png](/resources/8466fe0f865a55e39b5cebfd475a8e42.png)

Inside the `TriageData`, we have quite a lot of artifacts that can be used to aid our investigate and it is quite generous of the author of this sherlock to leave MFT and USN Journal here as they can be very powerful to determine file operation on that Windows system in quite recent time 

![ed8e2291c2eb9a41f18a3dd539b31cb8.png](/resources/ed8e2291c2eb9a41f18a3dd539b31cb8.png)

Meanwhile inside `LiveResponse` folder, we can see that we have process information including its network connection when the collection tool was used so this might come in handy to identidy suspicious process and network activity as well.

Now let's start the investigation

## Investigation
>Task 1: What is the name of the email client that Elfin is using?

![7a5ac4d34cfcb02ef4779d0046708fc6.png](/resources/7a5ac4d34cfcb02ef4779d0046708fc6.png)

The scenario strongly suggest that the user Elfin is potentially be an insider threat so normally I would go to for UserAsset registry key, and JumpLists to find the latest file and executable ran by this user but this time, I open the `pstree.txt` from LiveResponse folder which I can see that there is `MailClient.exe` which is a process belong to eM Client running under `explorer.exe` and that's basically mean it was running by user (Elfin).

![88390a55f9dfb2da4683e4a5ec7afa2f.png](/resources/88390a55f9dfb2da4683e4a5ec7afa2f.png)

And by inspecting `AppData\Roaming` folder of Elfin user, we can see `eMClient` folder which contains files associated to eM Client, a email client used by Elfin user.

```
eM Client
```

>Task 2: What is the email the threat actor is using?

There are 2 main ways to solve this sherlock:
- First: Open each SQLite3 dabase that stores email messages
- Second: Download eM Client, replace whole `AppData\Roaming` and open it which should let us read all email in eM Client (more user friendly this way)

I will go with the second approach as it is more UI friendly for me to read and capture screenshot to put in this write-up.

![6722c590c2e117ffb8dc61c9c2a3cd0e.png](/resources/6722c590c2e117ffb8dc61c9c2a3cd0e.png)

First, I want to download the exact version of eM Client that Elfin user used so I opened one of the log files located inside `Logs` folder and we can see that on the user-agent, it is reveals that eM Client version installed on this workstation is 9.2.2157.0

![685db9d94d1f2f524dd58fb71b9ed1de.png](/resources/685db9d94d1f2f524dd58fb71b9ed1de.png)

With that information, we can now go to eM Client download for Windows and I don't want to download the latest version, I want old version so we can click "release history" to download old version of eM Client.

![a044fbf2043771290f9d1e1c8a2fb418.png](/resources/a044fbf2043771290f9d1e1c8a2fb418.png)

Inside this [release history](https://www.emclient.com/release-history?os=win) page, we can search for the specific version we want to download the installer and then install it.

After finishing the installation, replace `C:\Users\username\AppData\Roaming\eM Client` with the artifacts we have (entire folder)

![444731acd87f346398f7cbcc53b052bb.png](/resources/444731acd87f346398f7cbcc53b052bb.png)

Now when we open eM client, we should be able to read every email saved in SQLite3 database from Elfin workstation.

![4adde9abe31bbf64adcf9abdadcb092c.png](/resources/4adde9abe31bbf64adcf9abdadcb092c.png)

I started digging into each email to gather the context around Elfin circle, and we can see that Elfin was using "elfinbestelfxmas4eva@gmail.com" and he had a conversation with "Grinch Grincher" (definitelynotthegrinch@gmail) about some top secrets project and Elfin's boss.

![34c7991dd0ee2cb6acc3be929c4371d7.png](/resources/34c7991dd0ee2cb6acc3be929c4371d7.png)

Elfin even told "Grinch Grincher" that he has accessed to santas special binaries.

![f45ee13c152d7021dc71def1fec8f82b.png](/resources/f45ee13c152d7021dc71def1fec8f82b.png)

And look like Elfin ended up sending it to "Grinch Grincher" as well, it seem like Elfin was pissing off about his boss, Elfuttin so he offered "Grinch Grincher" the binary and even sent it to him. 

This is confirmed that whoever using "definitelynotthegrinch@gmail" is the threat actor which use social engineering tactic to Elfin and eventually got what they want.

I also noticed that the name was changed to "Wendy Elflower" as well

![c072327fc5ab5a5d7613cc5343387a27.png](/resources/c072327fc5ab5a5d7613cc5343387a27.png)

After Elfin sent the binary in zip file, the threat actor seem to ghost him (not replying to any message anymore)

![16316d4cf01421be9f0fe9ce095686c4.png](/resources/16316d4cf01421be9f0fe9ce095686c4.png)

I extracted the attachment from an email and we can see that Elfin sent `santa_deliveries` binary to the threat actor.

![a2edf6c74f8adc725850297294737e9b.png](/resources/a2edf6c74f8adc725850297294737e9b.png)

It is ELF binary and compiled with GCC so to understand what it does, we might need to decompile it.

![cadad8ff88274b7cd2ddc36feab36df2.png](/resources/cadad8ff88274b7cd2ddc36feab36df2.png)

I ran strings on the binary to get a rough idea of what it might do, and we can see that it contains credential of "elf-admin" and exposed S3 bucket so this binary might be used in an automation of Santa gift delivery process.

```
definitelynotthegrinch@gmail.com
```

>Task 3: When does the threat actor reach out to Elfin?

![875a23edde036904a9e8141efdf16127.png](/resources/875a23edde036904a9e8141efdf16127.png)

After determine who is the threat actor, We can go back to the first email sent to Elfin from the threat actor which we can see that at 2023-11-27 17:27:26, the threat actor still used the name "Grinch Grincher" to send email to Elfin.

The content of this email made it look like they have seen Elfin from the North Pole HQ, we can already see the inconsistency at the end that they introduced themselves as "Wendy Elflower" to Elfin.

```
2023-11-27 17:27:26
```

>Task 4: What is the name of Elfins boss?

![e2c7155de944358a471dab89ed59cccb.png](/resources/e2c7155de944358a471dab89ed59cccb.png)

Inside the inbox, we can see that Elfin also had conversion with his boss "elfuttin bigelf" using an email as well and from the tone of the boss message sent to Elfin, I think we can understand how Elfin had joined the dark side at the end.

```
elfuttin bigelf
```

>Task 5: What is the title of the email in which Elfin first mentions his access to Santas special files?

![b576da45e0557fbcc3aa1033aa5b99ef.png](/resources/b576da45e0557fbcc3aa1033aa5b99ef.png)

In one of the email, Elfin finally mentioned that he has access to some of santas special binaries to the threat actor after talking about work-related subject 

![f3195b64fa343e23ba1e61e01928ca56.png](/resources/f3195b64fa343e23ba1e61e01928ca56.png)

We can open the property of this email which we can see that it is a reply from the "Work" subject email sent by the threat actor to ask about the secret project that Elfin was working on.

```
Re: work
```

>Task 6: The threat actor changes their name, what is the new name + the date of the first email Elfin receives with it?

![33d9edcf245d71d5597f340a174cbb87.png](/resources/33d9edcf245d71d5597f340a174cbb87.png)

As we know that the threat actor used the different name on the email sender but introduced with the different name in the email body.

![87b66d38a9d5f43dd0d1c327584080fe.png](/resources/87b66d38a9d5f43dd0d1c327584080fe.png)

Which they finally changed in at 2023-11-28 10:00:21 when asking about special binaries that Elfin has access to.

```
wendy elflower, 2023-11-28 10:00:21
```

>Task 7: What is the name of the bar that Elfin offers to meet the threat actor at?

![27b03eaa77fd34d918ddaea2ac2d2f9d.png](/resources/27b03eaa77fd34d918ddaea2ac2d2f9d.png)

After knowing the existence of secret binary, the threat actor sent another mail to Elfin to question his work ethic, is is worth sacrificing his wellbeing for the work and they planed to have a meeting at SnowGlobe bar later.

```
SnowGlobe
```

>Task 8: When does Elfin offer to send the secret files to the actor?

![263069ed153a9dc162e127cd0a7b0584.png](/resources/263069ed153a9dc162e127cd0a7b0584.png)

After giving himself in for the rage, Elfin sent another mail to the threat actor which they hold him to tell them more about the secret project Elfin had been working on.

![eab697589f68a8f5d85efee15fc14589.png](/resources/eab697589f68a8f5d85efee15fc14589.png)

Elfin offered to send the binary to the threat actor which they agreed to let him send it to them

![220371a7644f316df3ba4fc55b63abba.png](/resources/220371a7644f316df3ba4fc55b63abba.png)

We can look at the email property (email header) to get the date header where the email was sent to the threat actor.

```
2023-11-28 16:56:13
```

>Task 9: What is the search string for the first suspicious google search from Elfin? (Format: string)

![a0aa071f7defa8b7e7be595643a1ccbc.png](/resources/a0aa071f7defa8b7e7be595643a1ccbc.png)

Now it is the time to look at the browser history and we can see that we have Google Chrome history for us here.

I used DB Browser for SQLite to open History file and use the following SQL Query to query url, title and datetime column from urls table and also convert datetime to UTC time and sort by last_visit_time 

```sql
SELECT
    url,
    title,
    datetime((last_visit_time / 1000000) - 11644473600, 'unixepoch') AS visit_time_utc
FROM urls
ORDER BY last_visit_time DESC;
```

![2ede303b9a994ceb4a82b5e71d69df2a.png](/resources/2ede303b9a994ceb4a82b5e71d69df2a.png)

The result shows that after sending binary to the threat actor, Elfin searched on Google about how to get around work security, delete emails and how to destroy companies using Google Chrome.

```
how to get around work security
```

>Task 10: What is the name of the author who wrote the article from the CIA field manual?

![b0f9a4be8de98e7687da2e071006c069.png](/resources/b0f9a4be8de98e7687da2e071006c069.png)

Elfin also accessed to CIA Manual about poor management can sabotage a workplace as well.

![c13bff422be5f8bf498c5a13682b9e58.png](/resources/c13bff422be5f8bf498c5a13682b9e58.png)

By following the URL, we can get the author who published this blog here.

```
Joost Minnaar
```

>Task 11: What is the name of Santas secret file that Elfin sent to the actor?

![628c9a13fb77fded830f300b77be72de.png](/resources/628c9a13fb77fded830f300b77be72de.png)

```
santa_deliveries.zip
```

>Task 12: According to the filesystem, what is the exact CreationTime of the secret file on Elfins host?

![e33da000e23395119c692ab3432fc559.png](/resources/e33da000e23395119c692ab3432fc559.png)

We also have the binary file which is located inside the top-secret folder here

There are 2 approaches that we can use to obtain answer of this question, let's go with the first approach first

![1ad045147506287dacc576773e097266.png](/resources/1ad045147506287dacc576773e097266.png)
![1c403653eda5cbc9d705005a948528d6.png](/resources/1c403653eda5cbc9d705005a948528d6.png)

The first approach is to use JumpLists explorer to parse jumplists and we can see that the binary was created at 2023-11-27 16:15:34 and the zip file was created at 2023-11-28 17:01:29 just right before it was sent to the threat actor according to `TargetCreationDate`

![7881eafaa328fcb6f588189a8ffd3697.png](/resources/7881eafaa328fcb6f588189a8ffd3697.png)

The second approach is obvious, we can either use MFT record or USN journal to find the answer which I will use my [Resident Reaper](https://github.com/ChickenLoner/ResidentReaper) tool to rapidly parsed both files together.

![560d412ac1c624bc36f2e79c59862953.png](/resources/560d412ac1c624bc36f2e79c59862953.png)

The Created0x01 column also contains the same timestamp we found from JumpLists so 2 different ways to approach the same conclusion

```
2023-11-28 17:01:29
```

>Task 13: What is the full directory name that Elfin stored the file in?
```
C:\Users\Elfin\AppData\Roaming\top-secret
```

>Task 14: Which country is Elfin trying to flee to after he exfiltrates the file?

![30b57c6c187e0c1fbf9f46982c5400b8.png](/resources/30b57c6c187e0c1fbf9f46982c5400b8.png)

Elfin did search on Google about flights to Greece afterward.

```
Greece
```

>Task 15: What is the email address of the apology letter the user (elfin) wrote out but didn’t send?

![e2ea59854f22736870abbe67e38b6b0a.png](/resources/e2ea59854f22736870abbe67e38b6b0a.png)

We can go look at the unfinished draft email which reveals an email address of the recipient that Elfin wanted to send his email to, which is a Santa Claus

```
santa.claus@gmail.com
```

>Task 16: The head elf PixelPeppermint has requested any passwords of Elfins to assist in the investigation down the line. What’s the windows password of Elfin’s host?

![134bc30db79462a7d9c32f5d094a2c54.png](/resources/134bc30db79462a7d9c32f5d094a2c54.png)
![038b9b5554eb436fc87655514a9f544b.png](/resources/038b9b5554eb436fc87655514a9f544b.png)

To recover Elfin password, we can use secretdump from impacket the dump NT hash of Elfin user like this.

Command: 
```powershell
python .\secretsdump.py -sam "C:\Users\chicken\Desktop\Samples\HackTheBox\Op\elfidence_collection\TriageData\C\Windows\system32\config\SAM" -system "C:\Users\chicken\Desktop\Samples\HackTheBox\Op\elfidence_collection\TriageData\C\Windows\system32\config\SYSTEM" LOCAL
```

![66f4276d770b209500d160980da8013c.png](/resources/66f4276d770b209500d160980da8013c.png)

And then use public rainbow table service like crackstation to look up for the plaintext password which we can finally recover the password that was used by Elfin on this workstation here.

```
Santaknowskungfu
```

![e68f9fae7d637c3db84b891092cc1a33.png](/resources/e68f9fae7d637c3db84b891092cc1a33.png)

A little bit of extra here, the `santa_deliveries` contains hardcoded credential of elf-admin as we already discovered in strings and also fetch a file from public S3 bucket to retrieve information about kids and gifts before logging into a text file. this will help us in the OpTinselTrace-2 investigation later!

![30e5379356274a2b6d52796bb170cf6b.png](/resources/30e5379356274a2b6d52796bb170cf6b.png)

https://labs.hackthebox.com/achievement/sherlock/1438364/577
* * *
