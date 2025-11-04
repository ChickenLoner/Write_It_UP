# เฉลยโจทย์ Digital Forensic ในกิจกรรม Hackloween 2025 CTF Event by SEC Playground

## Table of Contents

- [Forensics](#forensics)
  - [Hello Gh0st #1](#hello-gh0st-1)
  - [Hello Gh0st #2](#hello-gh0st-2)
  - [Something’s Wrong](#somethings-wrong)
  - [Email Analysis](#email-analysis)
  - [ExtractCredential](#extractcredential)
  - [Grurat#1](#grurat1)
  - [Grurat#2](#grurat2)
  - [Grurat#3](#grurat3)
  - [LumnaStealer](#lumnastealer)
  - [This is Halloween](#this-is-halloween)
- [Cryptography](#cryptography)
  - [Ransomware#1](#ransomware1)
  - [Ransomware#2](#ransomware2)

***
![9927f5e9dfb48247d6ac1b0a397b0d7c.png](/resources/9927f5e9dfb48247d6ac1b0a397b0d7c.png)

สวัสดีครับ Chicken0248 เจ้าเดิมมากับทีม Wowza กับการแข่ง CTF ของ SECPlayground เป็นครั้งสุดท้ายอย่างเป็นทางการของทีมเราครับ แต่นั่นไม่สำคัญ ใน blog นี้ผมจะมาเฉลยการทำโจทย์ในหมวด Digital Forensic ทั้งหมด ในการแข่งขัน Hackloween 2025 CTF by SECPlayground ครับ และแน่นอนว่าผมไม่ได้มาเฉลยอย่างเดียวแต่จะมาแชร์ Methodology ในฐานะ blue teamer คนนึงที่ชอบสายงาน Digital Forensic ครับ 

* * *
## Forensics
### Hello Gh0st #1 
![8078ad9631b4bfd42bc1d52dc186f03b.png](/resources/8078ad9631b4bfd42bc1d52dc186f03b.png)

The user received suspicious file from their mail box and reported to SOC team for investigation.

What is the flag in suspicious file (password:infected)

Flag Format: flag{...}
* * *

![d5078f9e8450c125d8cc34c857e0f689.png](/resources/d5078f9e8450c125d8cc34c857e0f689.png)

ในข้อนี้จะให้ไฟล์ pdf เรามาไฟล์นึง ซึ่งดูเหมือนจะเป็น PDF แท้ไม่ได้มีการปลอมแปลงมาจากการใช้โปรแกรม Detect It Easy เพื่อ check magic header และ signature อื่น ๆ ของไฟล์

![e8fd0e36c0c5ac0e8b2194d8ebfaf9fb.png](/resources/e8fd0e36c0c5ac0e8b2194d8ebfaf9fb.png)

โดยปกติแล้วไฟล์ PDF มักจะมี metadata ที่เกี่ยวข้องกับคนเซฟไฟล์ประเภทนี้เอาไว้ เช่นชื่อคนสร้างไฟล์มักจะอยู่ในส่วนของ Author ซึ่งเราสามารถใช้ exiftool ในการเช็ค metadata ได้และเราก็จะเห็นว่า flag ของข้อนี้อยู่ในส่วนของ Author และ Creator ของไฟล์นี้นั่นเอง ดังนั้นเวลาเราเซฟไฟล์อะไรส่งชาวบ้านเราไม่อยากให้จับได้ เช่นส่งพิกัดเที่ยวหนีเมียก็อย่าลืมไปลบ metadata ออกด้วยนะครับ เดี๋ยวซวยกันหมด

```
flag{Gh0st}
```

* * *
### Hello Gh0st #2 
![35049d10d142353b2dafcf331ba40fe5.png](/resources/35049d10d142353b2dafcf331ba40fe5.png)

When opened the file, what is the URL that PDF connected to? (password: infected)

Flag Format: hxxps[://]xxx[.]com/yyy
* * *
![4fa234541cd0af918250d267ef42e70c.png](/resources/4fa234541cd0af918250d267ef42e70c.png)

ในข้อนี้จะถามเราว่าตอนที่เราเปิดไฟล์ PDF จากข้อที่แล้ว PDF ไฟล์จะติดต่อหาใคร ซึ่งเราสามารถเอา hash ของไฟล์นี้ไปค้นใน [VirusTotal](https://www.virustotal.com/gui/file/e725a552ff1a97d045a9aaad8f888378435206390dbd100282073c270541172f/behavior) ได้เลย แล้วเราก็จะเห็นว่าตอนที่เราเปิดไฟล์นี้ Microsoft Edge browser ก็จะถูกเปิดเพื่อไปหน้าของ webhook ซึ่งในโลกแห่งความเป็นจริงนั้น Webhook สามารถใช้ในหลายกรณี ในกรณีแรกก็คือส่งข้อมูลกลับไปให้กับเจ้าของ hook เช่นเราสามารถสร้าง pdf นี้ให้ user กรอก username และ password ลงในฟอร์มแล้วเมื่อกด click ก็จะส่งข้อมูลนั้นกลับมาที่ webhook ซึ่งข้อดีของ webhook มีหลายอย่างมากและด้วยความง่ายต่อการใช้งานก็มักจะถูกนำไปใช้ในการขโมยข้อมูลเช่นกัน

![437a635e6664654913b83dbcc308e2bd.png](/resources/437a635e6664654913b83dbcc308e2bd.png)

flag format ในข้อนี้ให้เรา defang url โดยการ defang url นั้นจะทำให้เราไม่สามารถเผลอกด click เข้าถูก direct ไปยังเว็บไซต์นั้นได้นั่นเอง มักจะถูกใช้กันอย่างแพร่หลายในวงการนี้ในการแชร์ IoC (Indicator of Compromise)

```
hxxps[://]webhook[.]site/bb27db55-4d88-4914-a4c5-acd67fbdc347
```

* * *
### Something’s Wrong 
![95d20a5ea65005b638db595233389494.png](/resources/95d20a5ea65005b638db595233389494.png)

The team received an alert regarding abnormal activity on a user’s workstation. As a member of the Forensics team, your task is to analyze the incident and determine its root cause.

Flag Format: forensic{(Flag),(CVE),(AttackerIP)}

password for unzip: secplayground
***

![7724adc96305adbcd36378a30f8b5651.png](/resources/7724adc96305adbcd36378a30f8b5651.png)

ในข้อนี้จะให้โฟลเดอร์ Log ของ Windows มาให้เราทั้งโฟลเดอร์เลย ซึ่งปกติโฟลเดอร์นี้จะอยู่ใน path `C:\Windows\System32\winevt\Logs` ซึ่งจะเก็บไฟล์ Log ต่าง ๆ บน Windows เอาไว้ในรูปแบบของ evtx ไฟล์ 

และเมื่อเราได้โฟลเดอร์นี้มา อย่างแรกที่เราควรจะมองก็คือการหาว่าเราสามารถใช้ Log อะไรในการหาคำตอบของข้อนี้ และตัวแรกที่ควรหาเลยนั่นก็คือ Sysmon log ซึ่งมักจะไม่ค่อยได้ติดต่อกันซักเท่าไหร่ แต่ถ้ามีก็ jackpot

![d0fe9dcffa6bc5634aa4be23e9bc41f6.png](/resources/d0fe9dcffa6bc5634aa4be23e9bc41f6.png)

JACKPOT เฉย แต่เอาหละในเมื่อให้เรามาทั้งโฟลเดอร์แบบนี้ ผมก็จะ parse ทั้งโฟลเดอร์ด้วย EvtxECmd จาก Eric Zimmerman's Tools เพื่อให้ได้ไฟล์ CSV ไฟล์เดียวที่มี record ของทุก event ที่ถูกเก็บในแต่ละ evtx ไฟล์

Command: `EvtxECmd.exe -d "C:\Users\chicken\Desktop\Samples\CTF\EventLogs" --csv C:\Users\chicken\Desktop\Samples\CTF --csvf log_timeline.csv`

![31c0dbdbf25edfd9498f1eefd34d39d2.png](/resources/31c0dbdbf25edfd9498f1eefd34d39d2.png)

ซึ่งเมื่อได้ไฟล์ CSV มาแล้วผมก็จะเปิดไฟล์นี้ด้วย Timeline Explorer จาก Eric Zimmerman's Tools เช่นกัน และเนื่องจากเราพบว่ามี Sysmon log ให้เราดังนั้นผมก็ได้ filter ด้วย Event ID 1 เพื่อดูว่ามี process อะไรรันบ้างแล้วมีอะไรแปลก ๆ มารึเปล่า ซึ่งผมก็เอ๊ะทันทีที่เจอการติดตั้ง Notepad++ บนเครื่อง

ทำไมหนะเหรอ? เนื่องจากช่วงนี้ผมสร้างแลปบ่อยแล้วต้องมาหา TTP หรือ CVE เจ๋ง ๆ มาลอง PoC อยู่บ้าง และ 1 ในโปรแกรมที่ผมหยิบมา test ในช่วงนึงก็คือ Notepad++ นั่นเอง เนื่องจากมี CVE ออกมาค่อนข้างเยอะ (ที่เป็นมีมก็มี) แถมหลังจากติดตั้งเสร็จ `cmd.exe` ก็มีการรันขึ้นมาพร้อมกับผองเพื่อน command สำหรับทำ Situation Awareness บนเครื่องด้วยนั่นทำให้ผมนึกถึง CVE ตัวนึงที่พึ่งออกมาในปีนี้ครับ

![5e701e00e7ddd191b9a48f4a70891a97.png](/resources/5e701e00e7ddd191b9a48f4a70891a97.png)

ซึ่งนั่นก็คือ [CVE-2025-49144](https://github.com/b0ySie7e/Notepad-8.8.1_CVE-2025-49144) ที่เป็น Local privilege escalation ตัวนึงที่เราสามารถวางไฟล์ `regsvr32.exe` ในที่เดียวกับตัวติดตั้ง และเมื่อกดติดตั้งทาง program จะรัน command `regsvr32 /u /s "$INSTDIR\NppShell_01.dll"` ซึ่งไม่ได้เรียกใช้ `regsvr32.exe` จาก `C:\Windows\System32` โดยตรงและนั่นก็สามารถทำให้เกิดการ hijack ได้เนื่องจาก Windows จะ search ไฟล์ที่อยู่ใน path ปัจจุบันก่อนทำให้เกิดช่องโหว่นี้ขึ้นนั่นเอง

ต่อมาผมก็นำ hash ของ `regsvr32` ที่รันไป search ใน VirusTotal ดูเพื่อตรวจทะเบียนประวัติอาชญากรรม ซึ่งก็ไม่พบและนั่นทำให้คอนเฟิร์มได้ทันทีว่าไฟล์นี้ไม่ได้เป็นไฟล์ legitimate จาก Microsoft 

![8c36a33591c5ccaad7f8a8fab9177107.png](/resources/8c36a33591c5ccaad7f8a8fab9177107.png)

ต่อมาผมก็เปลี่ยน filter เป็น Event ID 3 เพื่อหายานแม่ของไฟล์นี้ โดยเราจะเห็นว่าไฟล์นี้มันอยู่ที่เดียวกับตัวติดตั้ง Notepad++ อีกทั้งมีการติดต่อไปที่ IP 192.168.1.104 อีกด้วย ซึ่งเราก็มั่นใจแล้วหละว่านี่เป็น reverse shell payload เพื่อ exploit CVE-2025-49144

![b9b7f0f9641c3f7784779f35430155c9.png](/resources/b9b7f0f9641c3f7784779f35430155c9.png)

ต่อมาเราจะมาโฟกัสกันตรงที่ command ที่รันหลังจากได้ reverse shell ซึ่งเราจะเห็นว่ามีการพยายาม echo base64 string ออกมาทีละนิด ซึ่งการ echo ครั้งแรกดูเหมือนจะทำมาหลอกเนื่องจากถ้าดูจาก pattern มันจะไปซํ้ากันกับ base64 string ใน 3-4 commands หลังจากนั้น ซึ่งเราจะตัดมันออกไปแล้วเอาเฉพาะส่วนล่างมาให้หมด

![e21dc65a3e68e62760732c4ece71441f.png](/resources/e21dc65a3e68e62760732c4ece71441f.png)

จากนั้นเราจะตัดเฉพาะส่วนของ command ออกให้เหลือแต่ base64 string เพียวๆมา decode แล้วเราก็จะได้ flag ส่วนแรกมาตอบแล้วก็จบกันไปกับข้อนี้ 

```
forensic{(1Al@@ba*st3r6CAtap#88D1ny_89),(CVE-2025-49144),(192.168.1.104)}
```

* * *
### Email Analysis 
![0dbea9b84a672af1081357ac277c279f.png](/resources/0dbea9b84a672af1081357ac277c279f.png)

We've intercepted a suspicious email that triggered our alarms, prompting us to save it as a .eml file for detailed analysis before taking any action. Can you track down the sender's IP address from the file?

Format: forensic{IP}

E.g. forensic{127.0.0.1}
***

![129aaadfee9c4f8fe6b03a6f3a0d10e6.png](/resources/129aaadfee9c4f8fe6b03a6f3a0d10e6.png)

ข้อนี้จะให้ eml ไฟล์มาซึ่งเป็น email message file ที่เก็บข้อมูลทั้งหมดเกี่ยวกับอีเมล์ฉนับนึงเอาไว้ ซึ่งเนื่องจากข้อนี้ให้เราหา IP ของผู้ส่ง ดังนั้นผมจะใช้ [Email Analyzer](https://mxtoolbox.com/EmailHeaders.aspx) จาก MXToolbox เพื่อจับแต่ละ header โดยอัตโนมัติให้เราดูแต่ละตัวได้ง่ายขึ้น

![29d07f5443f63d32578b49b9e0d86279.png](/resources/29d07f5443f63d32578b49b9e0d86279.png)

ซึ่งเราจะสามารถหา IP ของผู้ส่งได้จากหลาย header ซึ่งในกรณีนี้เราจะเห็นว่าอีเมล์ได้ส่งมาจาก info@edm.co.mz (160.19.190.18 ดูจากได้ SPF ที่ได้ให้มอบให้ IP นี้สามารถส่งในนามของ info@edm.co.mz domain ได้) ไปหา gmail ของ [Taipun](https://th.linkedin.com/in/taipun-bannasit) 

```
forensic{160.19.190.18}
```

* * *
### ExtractCredential 
![33c7c562d2ca499c9c91cf3559ebdde9.png](/resources/33c7c562d2ca499c9c91cf3559ebdde9.png)

We intercepted a suspicious file. Upon further analysis, we found that the malware is categorized as an infostealer and contains hardcoded credentials in the binary that can be extracted. Could you please identify the username and password?

Flag Format: forensic{username:password}
***

![d9a8a0d1ab1739c5f057ba0f3d9a9eb7.png](/resources/d9a8a0d1ab1739c5f057ba0f3d9a9eb7.png)

ในข้อนี้เราจะได้มัลแวร์ตัวนึงมาซึ่งดูจากชื่อของ Zip ไฟล์แล้วก็น่าจะบอกได้ทันทีว่านี่คือ VIP Keylogger ซึ่งเป็น keylogger ที่ถูกพบในช่วงปลายปี 2024 (อ้างอิง: https://www.forcepoint.com/blog/x-labs/vipkeylogger-infostealer-malware) ซึ่งดูแล้วน่าจะเป็นญาติกับ Snake Keylogger เนื่องจากมีหลาย ๆ อย่างที่เหมือนกัน ซึ่งนอกจากจะทำหน้าที่เป็น keylogger ได้แล้วยังทำหน้าที่ของ infostealer ในการส่งข้อมูลไปยัง telegram และ SMTP server ได้ด้วย โดยไฟล์ที่เราได้มาก็น่าจะเป็นไฟล์ .NET payload ของ VIP Keylogger ที่โหลดมาจาก MalwareBazaar ซึ่งมักจะเปลี่ยนชื่อไฟล์เป็น SHA256 ของ sample นั้น ๆ 

![5a80f11e1434ea8559df564190735ca2.png](/resources/5a80f11e1434ea8559df564190735ca2.png)

ผมใช้ Detect It Easy เพื่อดูยืนยันว่ามันเป็น .NET payload จริง ๆ ซึ่งก็เป็นตามนั้นแถมมีการ obfuscate อย่างน้อย 2 ชั้น ชั้นแรกน่าจะเป็น ConfuserEx เพื่อ obfuscate string ส่วนชั้นที่สองน่าจะ compile ณ runtime ซึ่งมันจะเสียเวลามากถ้าเราไปทางนี้ดังนั้นเราจะใช้พลังของ internet ในการหาคำตอบครับ

![2802b602d50bb6b6b44cd94ad94e4b76.png](/resources/2802b602d50bb6b6b44cd94ad94e4b76.png)

ขั้นแรกเราเอา SHA256 มา search ก่อนซึ่งเราจะเห็นได้เลยว่ามีหลาย malware sandbox เลยที่เคย analyze sample นี้

![8d59ca717632ff42f9aa75667c744f2c.png](/resources/8d59ca717632ff42f9aa75667c744f2c.png)

ซึ่งเราจะส่อง sandbox อะไรก็ได้ที่มันสามารถแกะ configuration ของมัลแวร์ตัวนี้ได้เช่น [VMRay](https://www.vmray.com/analyses/_mb/e724f7ec302b/report/overview.html) แล้วเราก็จะเห็นว่ามัลแวร์ตัวนี้มีการ hard-coded SMTP credential สำหรับใช้ exfiltrate ข้อมูล และส่งไปยัง isb@crescenttrack[.]com

![6900798f4816884567d66e477c9afa5f.png](/resources/6900798f4816884567d66e477c9afa5f.png)

ส่วนนี่จาก Recorded Future [Tria.ge](https://tria.ge/250820-xgl9raap4s) ซึ่งจะเห็นข้อมูล confg คล้าย ๆ กันแต่จะพบว่า VMRay ทำได้ดีกว่ามากในการหา Encryption type และ key ของมัลแวร์ตัวนี้

```
forensic{isb@crescenttrack.com:isb123}
```

![571dd41b3b628685dab742bb3438e4ad.png](/resources/571dd41b3b628685dab742bb3438e4ad.png)

เรามาดูกันอีกซักหน่อยใน any.run โดยเราจะเห็นว่าหลังจาก binary ตัวนี้ถูกรันก็จะมีการสร้าง Scheduled Task ที่ชื่อค่อนข้าง random แถมยังมีการ drop binary ที่เป็นชื่อเดียวกันด้วย 

![e9d04093fdc560fce390336b7eaf2f38.png](/resources/e9d04093fdc560fce390336b7eaf2f38.png)

เราจะเห็นว่ามีสองไฟล์ดรอปเมื่อไฟล์ตัวนี้รัน อันแรกเป็น executable file และอันที่สองก็คือ XML ไฟล์

![31e58c7b994c09d5a0be2cc990e8b977.png](/resources/31e58c7b994c09d5a0be2cc990e8b977.png)

XML file จะเป็น XML file ที่ใช้สำหรับ config scheduled task เพื่อให้รันไฟล์ EXE ที่ drop เมื่อ user logon

![5bd5aa5bc7be793cf729d121af78be15.png](/resources/5bd5aa5bc7be793cf729d121af78be15.png)

ส่วนไฟล์ EXE ที่ drop ก็คือตัว copy ของ VIP Keylogger ซึ่งดูได้จากค่า hash ที่เหมือนกัน

เอาหละจบข้อนี้กันก่อนแล้วไปดูข้อต่อไปกัน

* * *
### Grurat#1
![490096bb039121a415faa7fed343472e.png](/resources/490096bb039121a415faa7fed343472e.png)

During system monitoring, we observed that one internal client machine exhibited behavior consistent with malware infection, including outbound connections to unidentified destinations.

The Incident Response (IR) team performed an initial investigation on the client machine but did not find any obviously suspicious files aside from a set of image files stored on the device and one potentially suspicious .exe file. To perform a deeper analysis, the team has provided the network traffic capture (PCAP) from the affected machine along with the suspicious .exe file. We request your assistance in analyzing the provided network traffic and the .exe file to determine whether the client made contact with any C2 (Command-and-Control) servers, and if so, identify those endpoints.

Password file:infected

Format flag: forensic{...}
***
![be68e18860358a9f6db7ca0fc57aae33.png](/resources/be68e18860358a9f6db7ca0fc57aae33.png)

ในข้อนี้จะให้ไฟล์ pcap กับ malware ที่เป็น payload ที่จะ connect กลับไปหา C2 server เมื่อเรากดรัน ซึ่งถึงแม้ว่า C2 Server อาจจะไม่ได้เปิดอยู่ในตอนนี้แต่ก็ปลอดภัยไว้ก่อนดีกว่าครับ ถ้ากลัวเผลอไปกดรันเข้ามาจริง ๆ ก็ควรจะเปลี่ยน extension จาก exe เป็นอะไรก็ได้ที่ไม่ให้รันเช่น `.wowza`

![40aef1997c81f662c8aa21231e6de1f7.png](/resources/40aef1997c81f662c8aa21231e6de1f7.png)

![414aa112e7e0dbf5e301b9b668756730.png](/resources/414aa112e7e0dbf5e301b9b668756730.png)

โดย pcap ไฟล์จะเป็นการเก็บ traffic ที่เกิดขึ้นบนเครื่องเหยื่อตอนที่ payload นี้ถูกรันและติดต่อกับ C2 Server นั่นเอง ซึ่งเราจะเห็นว่าเกินกว่าครึ่งจะเป็น PNG ไฟล์ที่ส่งผ่าน HTTP protocol แต่เพื่อให้แน่ใจ เราต้องลองมาแกะ payload ตัวนี้ดู ซึ่งดูแล้วน่าจะเป็น payload ที่เขียนขึ้นมาด้วยภาษา Python และทำการ pack/compile เป็น exe ด้วย pyinstaller (สังเกตจากรูปไอคอนของไฟล์)

![f55b213c5acf46e1083ffb0d1d17223a.png](/resources/f55b213c5acf46e1083ffb0d1d17223a.png)

เมื่อเราใช้ Detect It Easy เพื่อตรวจประเภทของไฟล์ ก็จะพบว่าเป็น payload ที่ถูกเขียนด้วยภาษา python และใช้ pyinstaller pack ให้เป็น EXE จริง ๆ ไม่ติงนัง

![215e855665f90bf3277102a337cdb355.png](/resources/215e855665f90bf3277102a337cdb355.png)

ในเมื่อถูก pack ด้วย pyinstaller ดังนั้นเราจะสามารถใช้ PyInstaller Extractor หรือ pyinstxtractor ในการแตกไฟล์ออกมาได้ ซึ่งเราจะพบว่ามีทั้งหมด 128 ไฟล์ถูก pack มาเป็น EXE และมีหลาย entry point ที่น่าจะเป็นได้ ซึ่งที่ิดึงดูดความสนใจผมทันทีเลยนั่นก็คือ `client_random_update.pyc` ไฟล์ 

![834de863dcb69ef54491bf0264f79aad.png](/resources/834de863dcb69ef54491bf0264f79aad.png)

ทั้งอีกไฟล์ที่ถูกแกะมาก็จะมีไฟล์ที่ชื่อ `shellcode_runner.exe` ซึ่งเป็น exe ที่ถูก pack ด้วย pyinstaller เช่นกัน ซึ่งไฟล์นี้น่าจะเป็นตัวที่ใช้สำหรับการรัน shellcode ที่ส่งมาจาก C2 server แต่เรามาลอง decompile pyc ไฟล์ที่ผมเอ๊ะไว้เมื่อกี้ก่อนเพื่อดูว่ามันใช่อย่างที่ผมคิดรึเปล่า

![da2d958fdefd462883103963808b298e.png](/resources/da2d958fdefd462883103963808b298e.png)

เราสามารถ decompile pyc ไฟล์ได้หลายวิธี ซึ่งที่ผมจะใช้ก็คือ [PyLingual](https://pylingual.io/) ซึ่งไม่จำเป็นต้องติดตั้งแต่สามารถอัพโหลดไฟล์เพื่อให้ไป decompile บนเว็บได้เลย ซึ่งเมื่อเรา decompile เสร็จเราจะพบว่า `client_random_update.py` ก็คือไฟล์ที่ใช้ handle C2 communication ทั้งหมด โดยมีหลักการก็คือตอนที่เรารัน payload จากฝั่งของ client, payload จะส่ง beacon string “agent online” ไปหา C2 server (34.124.239.18) ที่ port 9000 และจะ operate ด้วย port 9000 ในการส่ง command ต่าง ๆ เช่น `getrunurl` เพื่อให้ client ดาวน์โหลดไฟล์ PNG จาก C2 Server ที่ซ่อน shellcode ใน section พิเศษ ( `stEg`) เอาไว้ ซึ่งตัว shellcode นี้ได้ถูก encode ด้วย Mahjong มาให้ client แกะแล้วรันด้วย `shellcode_runner.exe` ที่เราพึ่งเจอนั่นเอง 

เรายืนยันตัว C2 ได้แล้ว เรามาส่งคำตอบแล้วไปยังข้อต่อไปกันเลยดีกว่า

```
forensic{34.124.239.18}
```

* * *
### Grurat#2
While investigating network activity, the IR team detected anomalous behavior from a client machine inside the organization. After pulling the network traffic and examining files on the host, we discovered a large number of image files stored on the machine — preliminary evidence suggests that a secret key may be hidden inside some of those images.

Analyze the provided data (the accompanying .exe binary and/or the related PCAP) to identify the image file that actually contains the hidden secret key, and extract that key as plaintext.

Password file:infected

Format flag: forensic{...}
* * *
![f4388cc6086b850b996ae41c3af21936.png](/resources/f4388cc6086b850b996ae41c3af21936.png)

![330d3e557f3f8370142e556b8312492a.png](/resources/330d3e557f3f8370142e556b8312492a.png)

ข้อนี้จะให้เราหา secret key ออกมาจาก C2 communication ใน Wireshark ซึ่งการที่เราจะหา flag ถูกต้องได้นั้นก็ต้องถอด shellcode ที่ส่งจาก C2 server ไปหา client โดยตัว key นั้นจะมีอยู่สองแบบหลัก ๆ แบบแรกจะลงท้ายด้วย `FF` (FAKE Flag) โดยแบบนี้จะ generate random flag ขึ้นมาแล้วส่งกลับไปหา C2 ด้วยการ XOR ด้วย key → base64 encode → mahjong encodes → ฝังไว้ใน `stEg` chuck ใน PNG ไฟล์และอัพโหลดไปที่ `http://34.124.239.18/api/update.php` ด้วย POST request 

key แบบที่สองนั้นจะลงท้ายด้วย `RF` (REAL Flag) ก็จะมีวิธี encode/encrypt/ฝังข้อมูลในรูปแบบเดียวกันกับ fake flag แต่ข้อมูลที่ส่งกลับจะไม่ใช่ random แล้ว ซึ่งจะให้ client ดึง hostname กับ Windows version มาต่อกันเป็น flag เข้าสู่กระบวนการและส่งกลับไปยัง C2 

![ec0d1667187179213c471c27a073b465.png](/resources/ec0d1667187179213c471c27a073b465.png)

ซึ่งจะเห็นได้จาก traffic ใน Wireshark ซึ่งคนออกโจทย์ค่อนข้างจะใจดีเพราะว่าชื่อไฟล์ที่ถูกใช้รันจะสามารถแยก fake flag ออกจาก real flag ได้จากชื่อไฟล์

![0f218a47942c0695e8978503e93b844a.png](/resources/0f218a47942c0695e8978503e93b844a.png)

ซึ่งเมื่อเรารู้แล้วว่าทำงานยังไงก็จะต้องเขียน Script หรือให้ AI vibe code มันขึ้นมาเพื่อแกะ flag ที่เป็น Real flag แล้วเอาไป decrypt หา flag ที่ส่งกลับไปยัง C2 ซึ่งนี่ก็คือสคริปต์ที่ Claude เขียนมาให้ผมครับ → [SPG_Grurat_c2_parser.py](https://raw.githubusercontent.com/ChickenLoner/All_The_Scripties/refs/heads/main/SPG_Grurat_c2_parser.py)

![79b9887123e6f9afba158c7ba3d2dff6.png](/resources/79b9887123e6f9afba158c7ba3d2dff6.png)

โดยเราสามารถอ่านทำความเข้าใจสคริปต์และการทำงานของ C2 อีกครั้งผ่านลิงค์ที่ผม [Publish](https://claude.ai/public/artifacts/e1b42690-7eb8-4eea-b873-110937a33667) จาก Claude ได้เลยครับ ซึ่งเขียนมาค่อนข้างดีในแบบที่ผมไม่ต้องอธิบายอะไรเพิ่มเติมเลย

![bcf9ea4fb5b36bfdb40f045924edd519.png](/resources/bcf9ea4fb5b36bfdb40f045924edd519.png)

เมื่อรันสคริปต์เสร็จก็จะได้ flag ออกมาสำหรับเอาไปตอบข้อนี้และ Grurat#3 ได้เลย

```
forensic{niarRF}
```

* * *
### Grurat#3
![95843c7d0ae359172fc06e7c82f543d5.png](/resources/95843c7d0ae359172fc06e7c82f543d5.png)
Based on the data we obtained from the previous challenge, find the actual information that was sent back to the C2 server.

Password file:infected

Format flag: forensic{...}
* * *
![039d950d3cf1201e72b8de6371733f5f.png](/resources/039d950d3cf1201e72b8de6371733f5f.png)

ท้ายที่สุดผมก็ให้ Claude มันลองเขียน Write-up มาให้แล้ว ซึ่งเขียนออกมาได้ดีเลยครับ ลองไปอ่านกันได้ → [Claude Grurat Malware Analysis - CTF Write-up](https://claude.ai/public/artifacts/8c0795d1-47c8-47b4-b191-052e8293d7f6)

```
forensic{DESKTOP-P477C8C_10.0.19045}
```

* * *
### LumnaStealer 
![408ed0feaabb771f634c5162fa4d1d3a.png](/resources/408ed0feaabb771f634c5162fa4d1d3a.png)

We intercepted a suspicious file. Upon further analysis, we found that after executing this file, it launches PowerShell and uses the DownloadString function to connect to a C2 server. Could you identify the full C2 URL that the DownloadString function is connecting to?

Flag Format: forensic{URL}

***
![1610d194f55e321af4e7e05100ed21ef.png](/resources/1610d194f55e321af4e7e05100ed21ef.png)

ในข้อนี้เราจะได้ไฟล์ประเภท HTA (HTML Application) มาซึ่งเป็นไฟล์อีกประเภทที่สามารถรัน JScript และ VBScript ได้ และถ้าเราดูจากชื่อไฟล์แล้ว เราก็สามารถจะเดาได้ว่าไฟล์นี้น่าจะโหลดมาจาก [MalwareBazaar](https://bazaar.abuse.ch/) ซึ่งจะนำ SHA256 hash มาตั้งเป็นชื่อไฟล์

![718aacaed38b0ff19befeefe98f5ced0.png](/resources/718aacaed38b0ff19befeefe98f5ced0.png)

สิ่งแรกที่ผมจะทำแน่นอนแหละว่าไม่ใช่การอ่าน Script แต่เป็นการเอาชื่อไฟล์ที่เป็น SHA256 hash ไปค้นใน MalwareBazaar และเราจะได้ว่าไฟล์นี้ถูกจัดในอยู่ในกลุ่ม LummaStealer ซึ่งเป็น infostealer ที่มีชื่อเสียงและเป็นต้นตำหรับการแพร่กระจาย payload ด้วย FakeCaptcha (ClickFix)

ต่อมาเราสามารถมาค้นต่อได้ว่าไฟล์นี้มัน fetch payload ที่เป็นตัวของ LummaStealer ของแทร่ เนื่องจากไฟล์ที่เราได้มานั้นก็คือตัว Dropper ซึ่งก็คือตัวเปิด ซึ่งทีนี้เวลาตัวเปิดมันไปหาเรื่องชาวบ้านเขา มันก็ต้องเรียกลูกพี่มาช่วย ซึ่งเป็นท่าที่เอาไว้ใช้แพร่กระจายมัลแวร์ในสมัยนี้เนื่องจากถ้าลูกพี่ไปสู้ตั้งแต่แรกก้จะถูกตำรวจจับได้ง่ายเนื่องจากมีรอยสักและดูโหง่วเห้งแล้วยังไงก็ตัวอันตราย 

![dd12ed67a59aa34718cc4798074525a0.png](/resources/dd12ed67a59aa34718cc4798074525a0.png)

ซึ่งเราสามารถทำได้ด้วยการเข้า sandbox platform ต่าง ๆ เพื่อเข้าไปดูประวัติอาชญากรรมของลูกน้องตัวนี้ และเราก็จะเห็นว่าลูกน้องตัวนี้ได้มีการติดต่อไปที่ `n.kliphirofey.shop` ซึ่งอยู่ในฐานข้อมูลอาชญากรรมของหลาย ๆ ที่ดังนั้นก็ต้องเป็นตัวนี้แหละแต่เราก็ต้องไปหาว่าลูกพี่มันชื่ออะไรต่อ

![1a7c65f1afaf70fd1e4e2a85a78a538f.png](/resources/1a7c65f1afaf70fd1e4e2a85a78a538f.png)

ซึ่งถ้าเรามาดูตรง Process Tree หรือ เราก็จะเห็นว่าตัวลูกน้องใช้โทรศัพย์ยี่ห้อ PowerShell เพื่อเรียกลูกพี่ `Evang.xll` จาก `n.kliphirofey.shop` และนั่นก็เป็นคำตอบของข้อนี้นี่เอง เราจับโจรได้แล้ว

```
forensic{https://n.kliphirofey.shop/Evang.xll}
```

* * *
### This is Halloween 
![1a750b98e81303326c8df8c829516c18.png](/resources/1a750b98e81303326c8df8c829516c18.png)

You receive two unusually large image files. Hidden data is suspected inside. Analyze both images to recover the hidden content, reconstruct it into a single file, and decode it to obtain the final FLAG.

Flag Format: FLAG{.....}

Password for unzip: secplayground
* * *
![cbe369a55e804e235785f4782d868119.png](/resources/cbe369a55e804e235785f4782d868119.png)

ในข้อนี้จะให้รูปผีมาสองรูปครับ ดูแล้วน่าจะเป็น steganography ดังนั้นเราจะมาลองดูกันก่อนว่าไฟล์นี้มันซ่อนอะไรในระดับ metadata ของไฟล์นี้กันบ้าง 

![28f63c313440de6b59284a14e9432f9c.png](/resources/28f63c313440de6b59284a14e9432f9c.png)

เราสามารถใช้ exiftool ในการ check metadata ได้ซึ่งรูปแรกไม่มีอะไรน่าสนใจแต่รูปที่สองจะมีคำใบ้ให้ในส่วนของ Comment ซึ่งเราจะได้ marker ที่ใช้แยกส่วนของ hidden payload ที่อยู่ในรูปภาพทั้งสองมา ซึ่งถ้าให้คำใบ้มาแบบนี้แสดงว่าไม่ได้ใช้ steghide ปกติแต่น่าจะเป็นการฝั่งเข้าไปในระดับ bytes เลย ซึ่งเป็นท่าที่มัลแวร์ช่วงนี้ชอบใช้กันมาก

![5e31cd8a4c4b797d10e94937782f90bd.png](/resources/5e31cd8a4c4b797d10e94937782f90bd.png)

เมื่อเราใช้ Hex Editor เพื่อหา marker ที่เราได้จาก Comment มาเราก็จะเจอกับ PK header ในไฟล์แรก ซึ่่งบอกเราว่าไฟล์ที่ถูกฝังเป็นไฟล์ ZIP นั่นเอง

![f6ce6f4c95ed30dc493211b8b36631bb.png](/resources/f6ce6f4c95ed30dc493211b8b36631bb.png)

https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html

ซึ่งถ้าเราดูจากโครงสร้างไฟล์ของไฟล์ประเภท Zip (PKZip) เราก็จะสามารถรู้ได้ว่าไฟล์นี้เก็บอะไรบ้าง ดังนั้นผมจะเปิดไฟล์ที่สองใน Hexeditor เพื่อดูว่ามันมีไฟล์อะไรบ้างที่ถูกเก็บใน Zip ไฟล์นี้

![ad4617b98bcf3c98cd0aca43e1539366.png](/resources/ad4617b98bcf3c98cd0aca43e1539366.png)

ซึ่งเราก็จะเห็นว่ามีไฟล์ `flag.txt` ถูกเก็บไว้อยู่เพียงแค่ไฟล์เดียว ซึ่งสิ่งที่ผมจะทำก็คือการ copy bytes หลัง marker จากทั้งสองไฟล์ออกมาแล้วจับมารวมกัน (ใช้ ChatGPT ก็ได้นะ) 

![da336f9cd8d669ecf3a74e06f297a2c1.png](/resources/da336f9cd8d669ecf3a74e06f297a2c1.png)

ผมจะใช้ CyberChef ในการ convert จาก HEX กลับไปเป็น raw แล้วแตกไฟล์ดูซึ่งเราจะพบว่าข้อความใน `flag.txt` ดูเป็นภาษาฉิ่งฉ่อง Jk

![006dbb31340cc2c953b422138d5e27f9.png](/resources/006dbb31340cc2c953b422138d5e27f9.png)

แต่เราถ้าเราจำได้ ชื่อไฟล์ที่สองจะมีคำว่า 8000 อยู่ด้วย ซึ่งภาษาฉิ่งฉ่องนี้ดูเหมือน ROT8000 Cipher และ [Cipher Identiier](https://www.dcode.fr/cipher-identifier) จาก DCode ก็ให้คะแนน confidential สูงในตัวนี้

![47ec193edc53574b4a765ace1edd8a9b.png](/resources/47ec193edc53574b4a765ace1edd8a9b.png)

เราสามารถใช้ [ROT8000 Decoder](https://www.dcode.fr/rot8000-cipher) เพื่อ decode กลับเป็น flag ได้เลย

```
FLAG{howling_werepuppy_under_the_blood_moon}
```
* * *
แถม Cryptography ที่ดูเหมือน Digital Forensics ให้อีก 2 ข้อครับ

## Cryptography
### Ransomware#1
![ff07226256dee5481bbd6a1e49123ca8.png](/resources/ff07226256dee5481bbd6a1e49123ca8.png)
The team is trying to find a way to decrypt an important file but they can't. Can you please help me find a way to recover the file?

Flag Format: crypto{file1,file2}

password for unzip: secplayground
* * *
![a227ba2655ca4795f7295faedce2ca65.png](/resources/a227ba2655ca4795f7295faedce2ca65.png)

ในข้อนี้จะให้ไฟล์ zip ที่ถูก encrypt ด้วย ransomware ประเภทหนึ่ง นั่นก็คือ Phobos ransomware หรือ 8Base ransomware ซึ่งมารพร้อมกับ Ransomnote ที่ชี้ชัดเข้าไปอีกว่ามาเป็นลูกเต้าเหล่าใคร

![d9b3ea537b6710424cb0960447c10e8c.png](/resources/d9b3ea537b6710424cb0960447c10e8c.png)

ซึ่งในปี 2025 ที่ผ่านมาก็ได้มีตำรวจจากแดนอาทิตย์อุทัยได้ปล่อย [decryption tool](https://www.npa.go.jp/english/bureau/cyber/ransomdamagerecovery.html) สำหรับถอดรหัสไฟล์ที่ถูกเข้ารหัสด้วย Phobos/8Base ransomware ที่ถูก encrypt ด้วยนามสกุล .phobos, .8base, .elbie, .faust, และ .LIZARD และเราก็จะใช้ decryptor ตัวนี้นี่แหละในการถอดรหัสไฟล์ออกมา

![cba51790b4445571675c5d11343d0a13.png](/resources/cba51790b4445571675c5d11343d0a13.png)

เมื่อเรารัน decryptor กับไฟล์ที่ถูก encrypt ก็จะได้ไฟล์ zip กลับมาครับ

![1ea4058e57304d9691e68bbc379a88cf.png](/resources/1ea4058e57304d9691e68bbc379a88cf.png)

และใน zip ไฟล์นี้ยังมีอีกสองไฟล์ที่ถูกเข้ารหัส แต่ไม่ได้ถูกเข้ารหัสด้วย 8base แล้วดังนั้นเราจะต้องหาวิธีอื่นในการถอดรหัสเพื่อหาไฟล์จริงออกมา แต่ตอบเอา flag กันก่อน จากนั้นโจทย์ก็จะให้เราไปหาวิธีถอดรหัสไฟล์ทั้งสองไฟล์นี้ในข้อถัดไป

```
crypto{287354.enc,782396.enc}
```

* * *
### Ransomware#2
![48b6ee9aaca6e57de5807ce448d47500.png](/resources/48b6ee9aaca6e57de5807ce448d47500.png)
Decryption is not enough. The file remains broken. Can you help fix it?

Flag Format: crypto{flag}

password for unzip: secplayground
* * *
![31dae4a5956f7aa3e6b75aedea7937e7.png](/resources/31dae4a5956f7aa3e6b75aedea7937e7.png)

ในข้อนี้เราจำเป็นจะต้องกลับมาอ่าน ransomnote อีกทีซึ่งก็จะบอกว่า AES-128 ECB mode ได้ถูกใช้ในการเข้ารหัสไฟล์ในชั้นที่สองโดย Key นั้นจะถูก derive มาจาก unique ID หรือก็คือ EEBF306F-3483 นั่นเอง แต่เอ๊ะ นี่ไม่ใช่ ransomnote ที่ 8base ใช้กันหนิ ตัวนี้น่าจะเป็นสิงที่ทีมงานของ SEC Playground เพิ่มเข้ามาเองครับ

![19fe5ee50e36aae357da08f424e23486.png](/resources/19fe5ee50e36aae357da08f424e23486.png)

AES-128 ECB Mode ก็คือ symmetric key algorithm ซึ่งจะใช้ key เดียวในการเข้ารหัสและถอดรหัส โดย ECB Mode หรือ Electronic Code Block ก็เป็นโหมดในการที่พื้นฐานที่สุดในการเข้ารหัส/ถอดรหัสของ AES ซึงจะทำการแบ่ง plaintext ออกเป็น block และใช้ key ที่มีขนาด 128 bits (16 bytes) ในการเข้ารหัสหรือถอดรหัสข้อมูลทีละ block (block ละ 16 bytes) และด้วยความง่ายแบบนี้ทำให้ไม่จำเป็นต้องใช้ Initialize Vector หรือ IV ที่เรามักจะใช้กันในโหมด CBC  แต่ในขณะเดียวกันก็จะมีข้อเสียเยอะกว่าด้วยทำให้ไม่ค่อยปล่อยภัยถ้าเทียบกับโหมดอื่น ๆ ของ AES ซึ่งสิ่งที่เราจะทำก็คือการ derive 16 bytes ออกมาจาก EEBF306F-3483 แล้วนำมาถอดรหัสทีละ 16 bytes เพื่อให้ได้ไฟล์ดั้งเดิมกลับมานั่นเอง 

ผมก็ให้ ChatGPT เขียน script ให้เหมือนเดิม → [try_aes_ecb_recover.py](https://raw.githubusercontent.com/ChickenLoner/All_The_Scripties/refs/heads/main/try_aes_ecb_recover.py) โดยให้มันลองวิธีการ derive key หลาย ๆ แบบทั้ง raw, md, sha1, sha256 แล้วพอมัน detect magic header ก็ให้ output ไฟล์ออกมา

![cac93b6e906395143cf53e3f554c12a4.png](/resources/cac93b6e906395143cf53e3f554c12a4.png)

แต่หลังจากรันเราจะพบว่าไม่มีการตรวจพบ Magic Header เกิดขึ้น ทำไมหละ?

![7564238464edbc96198052f910be9f9c.png](/resources/7564238464edbc96198052f910be9f9c.png)

ผมใช้ออปชั่น `--force-write` ที่แถมเข้ามาในสคริปต์ให้ลอง write file ทั้งหมดออกมาดูเผื่อจะเจออะไร surprise

![1eb5a41d832dd3a1e0145bef6a2f7940.png](/resources/1eb5a41d832dd3a1e0145bef6a2f7940.png)

ผมไล่เปิดแต่ละไฟล์ด้วย Hex Editor จะพบว่า key ที่ถูกต้องนั้นจะถูก derive ด้วย MD5 hash ซึ่งเราจะได้ PDF ไฟล์กลับมาแต่ address ในตำแหน่ง 0x00000000 ถึง 0x00000000F ได้ถูก alter ออก ดังนั้นเราก็แค่ไปหาไฟล์ PDF จริง ๆ มาอ้างอิง byte ในตำแหน่งที่หายไปก็พอ

![30ee583ce21963f8c79fc9faaf7f9b8e.png](/resources/30ee583ce21963f8c79fc9faaf7f9b8e.png)

และด้วยการที่ผมแทนค่า addresss ในตำแหน่ง 0x00000000 ถึง 0x00000000F ด้วย `25 50 44 46 2D 31 2E 37 0D 25 E2 E3 CF D3 0D 0A` ก็จะได้ไฟล์ PDF ที่เราสามารถไปเปิดกับ PDF Viewer ได้แล้ว
 
![75c5159069763872a4fbde90d0563d98.png](/resources/75c5159069763872a4fbde90d0563d98.png)

หลังจากแก้ address ของทั้งสองไฟล์และเปิดดูก็จะพบว่า ทั้งสองไฟล์ก็จะมี base64 string อยู่ เราไปลอง decode กัน

![58d91b59f6cbed65a01a8881d288af68.png](/resources/58d91b59f6cbed65a01a8881d288af68.png)

เมื่อเรา decode ออกมาก็จะเจอกับ flag ในบรรทัดสุดท้ายครับ 

```
crypto{HeadlessHorseman}
```
* * *

ในส่วนของ Blog นี้ก็จบไปแล้วครับ ขอขอบคุณทีมงานสำหรับโจทย์ให้เล่นฆ่าเวลาครับ ไว้เจอกันในงานและโอกาสอื่น ๆ 
 peace ✌