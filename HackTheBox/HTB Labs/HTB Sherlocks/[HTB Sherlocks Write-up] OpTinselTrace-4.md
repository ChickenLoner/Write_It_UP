# [HackTheBox Sherlocks - OpTinselTrace-4](https://app.hackthebox.com/sherlocks/OpTinselTrace-4)

![128773e9145da691c80fcfc0dd05fb63.png](/resources/128773e9145da691c80fcfc0dd05fb63.png)

## Scenario
Printers are important in Santa’s workshops, but we haven’t really tried to secure them! The Grinch and his team of elite hackers may try and use this against us! Please investigate using the packet capture provided! The printer server IP Address is 192.168.68.128 Please note - these Sherlocks are built to be completed sequentially and in order!

* * *
## Investigation

![cb2c037541bd5f392f86b1399fd1a827.png](/resources/cb2c037541bd5f392f86b1399fd1a827.png)

We have a single pcap file for this Sherlock so I will open it on Wireshark to investigate what happened to the printer.

![6c26ce23360d30b00b4a951f4ec91a59.png](/resources/6c26ce23360d30b00b4a951f4ec91a59.png)

After opened the file on WireShark, I opened Capture File Property to see how many packets it was captured during which timespan and we can see that it captured 3,897 packets in 18:45 minutes span from 2023-12-08 19:01:32 to 19:20:18

>Task 1: The performance of the network printer server has become sluggish, causing interruptions in the workflow at the North Pole workshop. Santa has directed us to generate a support request and examine the network data to pinpoint the source of the issue. He suspects that the Grinch and his group may be involved in this situation. Could you verify if there is an IP Address that is sending an excessive amount of traffic to the printer server?

![cf762000c3892de51c7459ee5a049528.png](/resources/cf762000c3892de51c7459ee5a049528.png)

Since we know the IP address of the printer so we can use that as a filter and open the Converstations statistics to see which IP address interacted with the printer which we can see that there is only a single IP address 172.17.79.133, interact with the printer

![e317451b09b91ab0218be277bfd75004.png](/resources/e317451b09b91ab0218be277bfd75004.png)

And we can see that this IP address might be the internal IP address assigned to Grinch and his team upon connected to the internal network via exfiltrated openvpn file from OpTinselTrace-2

```
172.17.79.133
```

>Task 2: Bytesparkle being the technical Lead, found traces of port scanning from the same IP identified in previous attack. Which port was then targeted for initial compromise of the printer?

![5373e48e33cd92b9c5995b2a4f600a66.png](/resources/5373e48e33cd92b9c5995b2a4f600a66.png)

The port scanning discovered 2 opened ports which are 22 for SSH and 9100 which is a standard TCP/IP Printing port which is normal considering it was scanning the printer 

![5ebbef7682dfde54cf9b5fe4d2143b9a.png](/resources/5ebbef7682dfde54cf9b5fe4d2143b9a.png)

And after finished scanning, the threat actor then connected to the printer to conduct their operation.

```
9100
```

>Task 3: What is the full name of printer running on the server?

![cda275616a564e0b41f9eccdea85b755.png](/resources/cda275616a564e0b41f9eccdea85b755.png)

By following the established connection, we can see that the first thing we can see is the PJL (Printer Job Language) which was created by Hewlett-Packard to control printer jobs and `@PJL INTO ID` reveals the printer name which is "NorthPole HP LaserJet 4200n".

```
NorthPole HP LaserJet 4200n
```

>Task 4: Grinch intercepted a list of nice and naughty children created by Santa. What was name of the second child on the nice list?

![9c45e15126b25fe4932e8140cf8ef81b.png](/resources/9c45e15126b25fe4932e8140cf8ef81b.png)

After connected to the printer, the threat actor used `FSDIRLIST` to list directories and files on the printer's internal storage and it is reveals 
- PJL
- PostScript
- saveDevice
- webServer
- Administration
and chrismas directory

![594daed1211c1b1dde2fab7031e53e80.png](/resources/594daed1211c1b1dde2fab7031e53e80.png)

The threat actor then dig down into `chrismas` until they found a list of nice kids of 2023 stored in text file and they use `FSUPLOAD` to read the file directly

After that they also found a list of naughty kids and read it as well.

```
Douglas Price
```

>Task 5: The Grinch obtained a print job instruction file intended for a printer used by an employee named Elfin. It appears that Santa and the North Pole management team have made the decision to dismiss Elfin. Could you please provide the word for word rationale behind the decision to terminate Elfin's employment?

![7b6a23994e1597b0f8e007dc91a380b4.png](/resources/7b6a23994e1597b0f8e007dc91a380b4.png)

Continue exploring, the threat actor discovered In progress save jobs of the the Elfin layoff notice in PCL (Print Command Language) contains plain text mixed with specific ASCII escape codes that instruct the printer on layout, fonts, and graphics.

in this file, we can see that Elfin was expulsed because of his action we investigated in OpTinselTrace-1

```
The addressed employee is confirmed to be working with grinch and team. According to Clause 69 , This calls for an immediate expulsion.
```

>Task 6: What was the name of the scheduled print job?

![271c8e2e5557aaeece20d8e22783b6aa.png](/resources/271c8e2e5557aaeece20d8e22783b6aa.png)

The first session ended after threat actor retrieved the content of Elfin layoff so we need to follow the second session after the first one terminated. 

![dd160375dd959e3a00e8268c98cbbc6a.png](/resources/dd160375dd959e3a00e8268c98cbbc6a.png)
![514501e4c37acf7cc71abfb4fe33aaac.png](/resources/514501e4c37acf7cc71abfb4fe33aaac.png)

On this second session, we can see that the threat actor discovered "MerryChristmas+BonusAnnouncment" scheduled job from `Announcment-25Dec.ps` (PostScript file) and we can see that this is the scheduled job to print a specific text on the Christmas day and annoucement of the bonus.

```
MerryChristmas+BonusAnnouncment
```

>Task 7: Amidst our ongoing analysis of the current packet capture, the situation has escalated alarmingly. Our security system has detected signs of post-exploitation activities on a highly critical server, which was supposed to be secure with SSH key-only access. This development has raised serious concerns within the security team. While Bytesparkle is investigating the breach, he speculated that this security incident might be connected to the earlier printer issue. Could you determine and provide the complete path of the file on the printer server that enabled the Grinch to laterally move to this critical server?

![f75faba888f78b27d05dc961562a53f2.png](/resources/f75faba888f78b27d05dc961562a53f2.png)
![1cdf138c4bb8fd461c71d99ba17eda3f.png](/resources/1cdf138c4bb8fd461c71d99ba17eda3f.png)

After discovery of postscript file, the threat actor also discover a backup SSH private key belongs to the "christmas.gifts" server within `/Administration/securitykeys/ssh_systems/`, this is the place that we would not expect any SSH key to be here in actual environment.

```
/Administration/securitykeys/ssh_systems/id_rsa
```

>Task 8: What is size of this file in bytes?

![e875abf92378e0134b3507cff91a5ef7.png](/resources/e875abf92378e0134b3507cff91a5ef7.png)

We can get the size of the private key here.

```
1914
```

>Task 9: What was the hostname of the other compromised critical server?
```
christmas.gifts
```

>Task 10: When did the Grinch attempt to delete a file from the printer? (UTC)

![4d1be3d552249b77db50a6b38d096bdd.png](/resources/4d1be3d552249b77db50a6b38d096bdd.png)
![d2aa113b98983359365ebeaf9c5c1003.png](/resources/d2aa113b98983359365ebeaf9c5c1003.png)

After retrieve the backup key, the threat actor started enumerate file path on the printer until the end of second session so we need to jump into another session.

![d78a95cb51b03eca89e76130b7312276.png](/resources/d78a95cb51b03eca89e76130b7312276.png)

We can search for `FSDELETE` command in PJL that is used to delete file or directory from printer's storage which we will see one at 2023-12-08 12:18:14, the threat actor attempted to delete a backup key from the printer but failed (the file still existed after issued FSDELETE)

```
2023-12-08 12:18:14
```

![8bcd0df148ecefb99bc1a2697592fcec.png](/resources/8bcd0df148ecefb99bc1a2697592fcec.png)

https://labs.hackthebox.com/achievement/sherlock/1438364/581
* * *
