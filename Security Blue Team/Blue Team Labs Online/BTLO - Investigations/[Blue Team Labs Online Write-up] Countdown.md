# [Blue Team Labs Online - Countdown](https://blueteamlabs.online/home/investigation/countdown-2c3cc56daf)
Created: 15/05/2024 08:53  
Last Updated: 15/05/2024 11:57
* * *
<div align="center">

![b0bcd731255ee9356a4aabc687cc2de1.png](../../../_resources/b0bcd731255ee9356a4aabc687cc2de1-1.png)
</div>

> In a race against time, can you investigate a laptop seized by law enforcement to identify if a bomb threat is real or a hoax?
> **Tags**: Autopsy, Window File Analyzer, WinPrefetchView, Jumplist Explorer, SQLite DB Browser, T1573
* * *

**Scenario**  
NYC Police received information that a gang of attackers has entered the city and are planning to detonate an explosive device. Law enforcement have begun investigating all leads to determine whether this is true or a hoax.

Persons of interest were taken into custody, and one additional suspect named ‘Zerry’ was detained while officers raided his house. During the search they found one laptop, collected the digital evidence, and sent it to NYC digital forensics division.

Police believe Zerry is directly associated with the gang and are analyzing his device to uncover any information about the potential attack.

Disclaimer: The story, all names, characters, and incidents portrayed in this challenge are fictitious and any relevance to real-world events is completely coincidental.

* * *

## Investigation Submission

> Verify the Disk Image. Submit SectorCount and MD5

![653249862f2aac978d040489ac6267c6.png](../../../_resources/653249862f2aac978d040489ac6267c6-1.png)  
Go to "Investigation Files" folder on the desktop, you will see 2 folders

Go to "Disk Image/Zerry", image file is there along with FTK log file which could be used to answer this question

```
25165824, 5c4e94315039f890e839d6992aeb6c58
```

> What is the decryption key of the online messenger app used by Zerry?

![18ab07e248c3e7a79c96babd4e0053ad.png](../../../_resources/18ab07e248c3e7a79c96babd4e0053ad-1.png)  
Go to "Countdown" folder, its a folder used for Autopsy, now we confirmed where `.aut` file is stored

![a19c882407dd26c1727ae16dcdd5d7f9.png](../../../_resources/a19c882407dd26c1727ae16dcdd5d7f9-1.png)  
Lets open Autopsy and click on "Open Recent Case", and Open aut file we found ealier

![59331c2af288191fbebcf05b99d2f0fa.png](../../../_resources/59331c2af288191fbebcf05b99d2f0fa-1.png)  
I checked for Image Summary first, I found that `SIGNAL.EXE` was listed on Recent Programs which mean user was using signal as an online messager app

I did some research about how to find signal decryption key on a file system and I found [this](https://www.bleepingcomputer.com/news/security/signal-desktop-leaves-message-decryption-key-in-plain-sight/)! which is a news from bleepingcomputer that report about Signal Desktop app store decryption key in plaintext and can be used to decrypted sqlite database to read outgoing messages that store on system.

![77add12c1a985ca65c1c8a0173cd3874.png](../../../_resources/77add12c1a985ca65c1c8a0173cd3874-1.png)  
Lets grab the artifact in `vol_vol3/Users/ZerryD/AppData/Roaming/Signal/config.json` and there you can see signal decryption raw key

```
c2a0e8d6f0853449cfcf4b75176c277535b3677de1bb59186b32f0dc6ed69998
```

> What is the registered phone number and profile name of Zerry in the messenger application used?

the news on bleeping article we found earlier also told us that we can use DB Browser for SQLite with decryption key to read content of sqlite database in `vol_vol3/Users/ZerryD💣🔥/AppData/Roaming/Signal/sql/db.sqlite`  
![03b5f3b3b313a6ac8655f2f51f42245c.png](../../../_resources/03b5f3b3b313a6ac8655f2f51f42245c-1.png)  
Tool avaliable in `~/Desktop/Investigation Files/Tools/SQLiteDatabaseBrowserPortable`  
![177fc613c236d7bdbb5e9c984a72450b.png](../../../_resources/177fc613c236d7bdbb5e9c984a72450b-1.png)  
Use `0xc2a0e8d6f0853449cfcf4b75176c277535b3677de1bb59186b32f0dc6ed69998` as raw key then click OK  
![267af952c51d449bbaf9758d913ef672.png](../../../_resources/267af952c51d449bbaf9758d913ef672-1.png)  
Go to "conversations" table then you will eventually find both info here

```
13026482364,ZerryThe🔥
```

> What is the email id found in the chat?

![4ce5bffe73c81fcf74917a08500a0175.png](../../../_resources/4ce5bffe73c81fcf74917a08500a0175-1.png)  
On the same database, go to "messages" table then you will find a conversation between 2 entities (Tom and Zerry kinda like Tom and Jerry but in infosec) here

After reviewing this conversation, an attacker used Tor to browse website and Eraser to securely delete sensitive data and he even provided an email address to receive a file from other entity.

```
eekurk@baybabes.com
```

> What is the filename(including extension) that is received as an attachment via email?

![0b6d9bf0787a478fb24076bc6aead1a7.png](../../../_resources/0b6d9bf0787a478fb24076bc6aead1a7-1.png)  
Since it was erased using Eraser so I don't expect it to be found on Recycle Bin  
![64076435377d58ca481d8145c5828075.png](../../../_resources/64076435377d58ca481d8145c5828075-1.png)  
But Recent Documents caught a shoutcut file for me and now we can see that it was an image file

```
⏳📅.png
```

> What is the Date and Time of the planned attack?

I assumed that Date and Time was stored in an image file but it was securely deleted

But there is 1 artifact that will cache all images thumbnail on Windows which is [Windows thumbnail cache](https://en.wikipedia.org/wiki/Windows_thumbnail_cache)  
Which should be located in `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`  
![a2f0b62f986b0bd0789cc2124aa1dd95.png](../../../_resources/a2f0b62f986b0bd0789cc2124aa1dd95-1.png)  
There is a tool available for this one (it also gave us a hint to solve this question)  
![bf3e00618632922f270440a765b82329.png](../../../_resources/bf3e00618632922f270440a765b82329-1.png)  
I exported them all and open it with Thumbcache Viewer, then find for png file

There are 2 png files and the first one (on the above image) is the right one, you can see that its 01-02-2021 0900 with a sun which mean AM

```
01-02-2021 9:00 AM
```

> What is the GPS location of the blast? The format is the same as found in the evidence . \[Hint: Encode(XX Degrees,XX Minutes, XX Seconds)\]

![ba18116488f51eca4c552cbb6b14353b.png](../../../_resources/ba18116488f51eca4c552cbb6b14353b-1.png)  
Location was mentioned in meeting  
![a6147fb06f2e2e53f6b1e68947dfcc2e.png](../../../_resources/a6147fb06f2e2e53f6b1e68947dfcc2e-1.png)  
I did search through Web History provided by Autopsy and found nothing then I found `rot13.com` from Tor Browser History, it could mean something?

Now i'm stuck but someone gave me a hint that when it comes to meeting, it possible that user will write a note somewhere on his system

And note software that came with Microsoft is sticky note and to my surprise, there is a blog that talk about sticky note artifact [here](https://forensafe.com/blogs/stickynotes.html ) 
Lets grab stickey note artifact on `C:\Users\%UserProfile%\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`  
![497f4280c0da82b99fc8daa6665cbf77.png](../../../_resources/497f4280c0da82b99fc8daa6665cbf77-1.png)  
We got this `\id=f92c091d-7161-4cce-8deb-b53438d8238c 40 qrterrf 45 zvahgrf 28.6776 frpbaqf A, 73 qrterrf 59 zvah`  weird looking text but it does look like a coordinate but need a little bit more decoding

Then ROT 13 we found eariler comes into play to decode it back to its original from
![4f22bba4831347c2e30afa8d2a7c385f.png](../../../_resources/4f22bba4831347c2e30afa8d2a7c385f-1.png)
There we go
```
40 degrees 45 minutes 28.6776 seconds N, 73 degrees 59 minutes 7.994 seconds W
```

![cfd940ef2e810e823f65f98e58bd63f9.png](../../../_resources/cfd940ef2e810e823f65f98e58bd63f9.png)
* * *