# Thailand Cyber Top Talent 2024 OPEN [Qualifier] - Network/Forensics/Mobile - MaAowHa (มาเอาฮา) Team
## Table of Contents

- [Introduction](#introduction)
- [Networks](#networks)
  - [HTTP Mayhem (100)](#http-mayhem-100)
  - [Silent Whisper (100)](#silent-whisper-100)
  - [Encrypted C2 v2 (200)](#encrypted-c2-v2-200)
- [Digital Forensics](#digital-forensics)
  - [Easy1 (100)](#easy1-100)
  - [Easy2 (100)](#easy2-100)
  - [Cloudo (300)](#cloudo-300)
- [Mobile](#mobile)
  - [Easy - YouSeeMe (100)](#easy-youseeme-100)
  - [The Face THCTT24 (100)](#the-face-thctt24-100)
  - [Medium (200)](#medium-200)
  - [Click Click (200)](#click-click-200)

***
## Introduction
สวัสดีครับท่านผู้อ่านทุกท่าน ผม chicken0248 หัวหน้าทีม MaAowHa (มาเอาฮา) ได้รับหน้าที่เป็น Blue teamer ประจำทีมโดยอีกสองท่านคือ PL.0x00  (pentester) และ casperx (dev) เป็นสมาชิกทีม โดยทีมของเราจะเป็นการรวมตัวกันระหว่างผมที่ทำงานในหน่วยงานภาครัฐและเพื่อน ๆ อีกสองคนที่ทำงานในหน่วยงานเอกชน แล้วก็เป็นการแข่ง CTF เป็นทีมครั้งแรกของพวกเราหลังจากเรียนจบด้วย

![8c94c9bdb9cbd0dabf013db6a0e7ad1a.png](/resources/8c94c9bdb9cbd0dabf013db6a0e7ad1a.png)

ใน write-up นี้ผมได้เขียนถึงวิธีการ solve challenge ใน 3 หมวดหมู่ได้แก่ 
- Networks (ทำได้ 3 จาก 4 ข้อ)
- Digital Forensics (ทำได้ 3 จาก 4 ข้อ)
- Mobile Security (ทำได้ทุกข้อ)

So without further ado, Lets jump right in ครับ

***
## Networks
### HTTP Mayhem (100)
![c5b34cf9b222c9440248ba185e723a02.png](/resources/c5b34cf9b222c9440248ba185e723a02.png)
เกิดการถ่ายโอนไฟล์ที่น่าสงสัยผ่าน HTTP... มีการดักจับ Network Packet (PCAP) ในระหว่างเหตุการณ์นี้ ผู้โจมตีอาจซ่อนเนื้อหาที่เป็นอันตรายในไฟล์ที่ถูกส่ง คุณสามารถวิเคราะห์และค้นหาเนื้อหาที่ซ่อนอยู่ได้หรือไม่?
* * *
![4ecf4f728710c037ab413c4188ac883e.png](/resources/4ecf4f728710c037ab413c4188ac883e.png)
เมื่อเราโหลดไฟล์มาแล้วเปิดด้วย Wireshark ก็จะพบว่ามีการส่ง HTTP GET Request ไปขอไฟล์ 2 ไฟล์มาจาก server โดยไฟล์แรกก็คือ `evil_plan.txt` และไฟล์ที่สองก็คือ `image.png`

![ebec72ef1618f75596ba851b08c217af.png](/resources/ebec72ef1618f75596ba851b08c217af.png)

ไฟล์แรกจะเป็นสคริปต์เพื่อทำการ embed flag ลงใน LSB (Least Significent-Bit) ของไฟล์รูปภาพ ซึ่งเราก็น่าจะเรากันได้ว่าไฟล์รูปภาพนั้นมาจากไหน

![56cd3acca464b1095ccbd073782228a6.png](/resources/56cd3acca464b1095ccbd073782228a6.png)

ผมก็เลยให้ ChatGPT เขียนสคริปต์ให้เปิดไฟล์ภาพแล้ว ดึง LSB ออกมา เพื่อ decode แล้วจะออกมาเป็น flag อย่างที่เห็นครับ

```
THCTT24{82d27383f4ce66b375cfc48b60afcb30}
```
***
### Silent Whisper (100)
![32693a25aa9b7ee37b2ba70adb2da510.png](/resources/32693a25aa9b7ee37b2ba70adb2da510.png)
พบไฟล์การดักจับ Network Packet (PCAP) ที่มีการสนทนาลับ... แต่ผู้โจมตีได้ทิ้งเบาะแสเล็กๆ ซ่อนอยู่ใน Packet บางอย่าง ภารกิจของคุณคือการวิเคราะห์ไฟล์ PCAP เพื่อหา "กุญแจ" ที่ใช้เข้ารหัส และถอดรหัสข้อความที่ซ่อนอยู่ คุณพร้อมที่จะเปิดเผยความลับหรือไม่?

Flag Format : THCTT24{MD5}
***
![f6556842907378a5284e29513d01b171.png](/resources/f6556842907378a5284e29513d01b171.png)

แวปแรกเมื่อเราเปิดไฟล์โจทย์ด้วย Wireshark จะพบว่ามี packet SYN จำนวนมากไปยัง Port 2121 ของอีก IP

![137deb8342557625dc38c9d83848a027.png](/resources/137deb8342557625dc38c9d83848a027.png)

เมื่อเราเลือก follow TCP Stream ขึ้นมาซักตัวก็จะพบว่าเป็นการพยายาม authenticate ไปยัง Python FTP server ด้วย user เป็น `thctt24` และ password เป็น flag 

![0c6ea3b3d2f17a8e993ae0320099b6c7.png](/resources/0c6ea3b3d2f17a8e993ae0320099b6c7.png)

ซึ่งก็น่าจะเดาไม่ยากว่า flag ที่ถูกต้องจะทำให้ authenticate success โดย authentication successful บน FTP จะใช้ Status 230 Login Successful โดยนี่ก็คือ flag ของข้อนี้ครับ

```
THCTT24{e8de3a77e7c3ac4f45412c7a4d67d7f9}
```

***
### Encrypted C2 v2 (200)
![a7ac6318655c51ac545b225abd3200de.png](/resources/a7ac6318655c51ac545b225abd3200de.png)
ทีมเฝ้าระวังเครือข่าย ดักจับ Network Packet (PCAP) ที่น่าสงสัย... ดูเหมือนเป็นการสื่อสารที่เข้ารหัสระหว่างเซิร์ฟเวอร์แฮกเกอร์ (C2) และคอมพิวเตอร์เหยื่อที่ถูกแฮก เมื่อวิเคราะห์พบว่าข้อมูลถูกเข้ารหัส ภารกิจของคุณคือถอดรหัสการสื่อสารและดึงข้อความที่ซ่อนอยู่ คุณสามารถถอดการเข้ารหัสและเปิดเผยแผนการของผู้โจมตีได้หรือไม่?

Flag Format : THCTT24{MD5}
***
![8566b28b5ffe8199751976f6ae67d69e.png](/resources/8566b28b5ffe8199751976f6ae67d69e.png)

สิ่งแรกที่เราจะพบเมื่อเปิดไฟล์โจทย์ด้วย Wireshark ก็คือ HTTP POST ไปยัง //handshake endpoint ซึ่ง server ก็จะตอบกลับมาว่า "handshake received"

![fce2744a2d6d2ab54f44c2caba07fb79.png](/resources/fce2744a2d6d2ab54f44c2caba07fb79.png)

ซึ่งเมื่อเราลองมองดูสิ่งที่ส่งไปให้ server ก็จะรู้ได้ทันทีว่านี่ก็คือ wordlist นั่นเอง

![f0adb9ff38f2d7c1707a0a4245f8162b.png](/resources/f0adb9ff38f2d7c1707a0a4245f8162b.png)

โดยสิ่งที่เราจะนำมา decode ก็จะมาจาก //callback โดยผมก็ได้ให้ ChatGPT เขียนสคริป match แต่ละ word ใน cmd ให้

![f0e05b59f76242356e75684272b6454d.png](/resources/f0e05b59f76242356e75684272b6454d.png)

ผลลัพธ์ก็จะออกมาเป็นคำสั่งให้ echo flag ลงบน terminal นั่นเอง

```
THCTT24{a6fce95191fb92a5878235d1d6b85862}
```
***
## Digital Forensics
### Easy1 (100)
Format: THCTT24{md5()}
***
ข้อนี้จะเป็นข้อที่ไม่บอกอะไรเรามาเลย ดังนั้นสิ่งที่เราทำได้ก็คือสำรวจไฟล์ที่ได้รับมา

![409015f8c630e02dd6c5a3d40f29ba5c.png](/resources/409015f8c630e02dd6c5a3d40f29ba5c.png)

ซึ่งหลังจากแตกไฟล์ผมก็พบว่ามันเป็น Nested directories โดยจะมี `flag.txt` อยู่ทุก directory 

![4504df914e986852cf3c6c2ddb88e17d.png](/resources/4504df914e986852cf3c6c2ddb88e17d.png)

สิ่งแรกที่ผมทำก็คือใช้ `find` command เพื่ออ่าน flag ซึ่งผมก็เอ๊ะขึ้นมาว่าถ้า flag มัน identical กันเกือบทุกตัว มันก้ต้องมีตัวนึงแหละที่มัน unique, จึงเป็นสาเหตุให้ผมเพิ่ม `uniq` แล้วก็พบ flag ของจริงที่ซ๋อนอยู่

```
THCTT24{853cc79bcd99fd4b9688032b487c0724}
```

***
### Easy2 (100)
Format: THCTT24{md5()}
***
ข้อนี้ก็ยังไม่ให้คำอธิบายโจทย์มา ดังนั้นเราก็ต้องมาสำรวจไฟล์ที่ได้ตามเดิมครับ

![f9a5a381c91c0ddcf44bb3c03c314ac0.png](/resources/f9a5a381c91c0ddcf44bb3c03c314ac0.png)

สิ่งที่เราได้รับมาก็คือไฟล์ QR Code จำนวน 99 รูป ซึ่งผมก็ให้ ChatGPT เขียน python script ในการ parse QR Code เหล่านี้แล้ว print output ออกมาผ่าน terminal 

![8b13728b277dddc5111b2a8593e18e26.png](/resources/8b13728b277dddc5111b2a8593e18e26.png)

ซึ่งทุก ๆ ภาพก็จะได้เป็นข้อความเดียวกันก็คือ "Password is THCTT24" แต่ password ใช่กับอะไรหละ?

![f4466ef40178a9e673105ec7ce931325.png](/resources/f4466ef40178a9e673105ec7ce931325.png)

เนื่องจากเราได้ไฟล์ที่เป็น jpeg มา ซึ่งแน่นอนว่าเราก็ต้องลอง steghide กับทุกไฟล์ด้วย password ที่เราได้รับมาครับ ซึ่งนี่ก็คือ script ที่ผมใช้

![eeed1587ea6240db9df3078f361cf214.png](/resources/eeed1587ea6240db9df3078f361cf214.png)

หลังจากรันสคริปต์ก็จะพบว่าทุกไฟล์มี text file ซ่อนอยู่และทุกไฟล์เหมือนจะมี flag format หมดเลย

![ab716a804401102f917c67585b7f8a74.png](/resources/ab716a804401102f917c67585b7f8a74.png)

ผมก็เลยอ่านมันทุกไฟล์เลยแล้ว pipe ใส่ `uniq` ซึ่งจะเห็นว่าตรงกลางก็คือ flag ที่ถูกต้องเนื่องจากไม่ถูก REDACTED ตรงกลางนั่นเอง

```
THCTT24{6b569a1f0566088c354bdc3d57c19063}
```
***
### Cloudo (300)
TechCorp, a mid-sized technology company, has recently experienced a security incident. The company's SOC team has been alerted to suspicious activities on their server. As a Tier 1 SOC Analyst, you've been tasked with investigating the incident using the available server logs.

**The Situation**
On September 2024, TechCorp's monitoring systems detected an unusually high number of requests to their server. The server hosts a custom application, and an administrative backend. Initial AI analysis reports suggest that there might have been attempts to:
- Exploit SQL injection vulnerabilities
- Access sensitive files through Local File Inclusion (LFI)
- Bypass access controls to reach restricted areas of the application
- Enumerate and discover hidden directories and files
- N-day vulnerability.

The SOC team is concerned that these activities might be part of a larger, coordinated attack aimed at compromising TechCorp's systems and exfiltrating sensitive data.

**Your Mission**
As a Tier 1 SOC Analyst, your task is to analyze the provided log files and identify the nature and extent of the potential breach. You need to:

- Identify the IP address(es) of the potential attacker(s)
- Determine the types of attacks attempted

https://storage.googleapis.com/secplayground-event/thailandtoptalent2024/cloudo.zip

Password for unzip: THCTT24

Format of answer: THCTT24{threat-actor-ip_CVE-number} such as THCTT24{10.0.0.01_cve-2024-4087}
***
นี่ก็เป็นข้อยากอีกข้อเลยที่ถ้าหากเราเริ่มต้นไม่ถูกตั้งแต่แรก เราก็จะหาคำตอบไม่ได้เลยเพราะหลงอยู่ใน log จำนวนมหาศาลครับ โดยสิ่งแรกที่ผมทำเลยก็คือเปิด splunk enterprise instance จาก docker ขึ้นมาแล้ว โยน log file ทั้งสามเข้าไปเพื่อทำให้การ search ง่ายขึ้น

![df214d17755cb93e96bcf624deae0610.png](/resources/df214d17755cb93e96bcf624deae0610.png)

สิ่งแรกที่ผมเริ่มจับผิดสังเกตได้ก็คือ `userName` ใน CloudTrail log ที่มีชื่อว่า `MisconfiguredIAMRole` ซึ่งมีความเป็นไปได้ว่า threat actor จะเข้าถึง role ตัวนี้แล้วทำการเข้าถึง resources อื่น ๆ บน Cloud

![60c183665b7b02c82df5b511f380e24a.png](/resources/60c183665b7b02c82df5b511f380e24a.png)

ซึ่งเมื่อ query ด้วย splunk จะพบว่ามีเพียง IP เดียวที่เข้าถึง arn ตัวนี้

![1501f525ff5afee873cfc1b5d5f5564f.png](/resources/1501f525ff5afee873cfc1b5d5f5564f.png)

จากนั้นผมก็มาค้นหา IP นี้ต่อที่ `realistic_unified_app_logs.txt` และผมก็พบว่า IP นี้ได้ส่ง request ไปยัง endpoint แปลก ๆ ซึ่งดูเหมือนจะเป็นการ exploit vulnerability หนึ่ง

![c8c8a7b4fd9ce1ec0a1c57810ffcfceb.png](/resources/c8c8a7b4fd9ce1ec0a1c57810ffcfceb.png)

หลังจากหาใน google ซักพักนึงผมก็ไปเจอ write-up (https://m.freebuf.com/articles/web/410898.html) ของช่องโหว่ที่พูดถึง endpoint นี้ โดยช่องโหว่นั้นก็คือนั่นก็คือ CVE-2024-45507 ซึ่งเป็นช่องโหว่ Server-side request forgery (SSRF) และ Code Injection บน Apache OFBiz นั่นเอง 

แน่นอนว่าเรารู้ IP address ของ threat actor แล้ว ทาง CVE เราก็รู้แล้ว งั้นก็ submit เอาคะแนนได้เลยครับ

```
THCTT24{191.168.223.137_cve-2024-45507}
```
***
## Mobile 
### Easy - YouSeeMe (100)
***
ข้อนี้ผมไม่ได้ Capture ตัวโจทย์ไว้ขออภัยด้วยครับ แต่เราจะได้ `YouSeeMe.apk` มา ซึ่งเราก็ต้องเอาไป decompile ใน Java decomplier เช่น jadx ซึ่งผมก็ได้ใช้ java decomplier online (https://www.decompiler.com/) ในการ decompile ครับ

![fdf408be02f15d5068a28c3e51cd4020.png](/resources/fdf408be02f15d5068a28c3e51cd4020.png)

ก่อนผมเริ่ม decompile ผมลองหาดูก่อนว่ามันมีไฟล์น่าสนใจซ่อนอยู่ไหม ซึ่งผมก็เจอว่ามันมี `flag.txt` ซ่อนอยู่จริง ๆ 

![25b8158baccc53c8f24162cf908d84de.png](/resources/25b8158baccc53c8f24162cf908d84de.png)

แต่เมื่อทำการ decompile เข้าไปอ่านก็จะพบว่า content ของ flag จริง ๆ นั้น อยู่ใน Manifest ไฟล์

![91884de20bcc4021696570de0156b34b.png](/resources/91884de20bcc4021696570de0156b34b.png)

ซึ่งตัว Manifest ไฟล์ที่ว่าก็คือ `AndroidManifest.xml` นั่นเอง โดยเราจะพบ base64 encoded string อยู่ตรงนี้

![058795d323e6b4866aadef828fa0b886.png](/resources/058795d323e6b4866aadef828fa0b886.png)

เอาไป decode ก็จะได้ flag มา

```
THCTT24{e28c529638e6d58b73b19b66e0e3dc50}
```

***
### The Face THCTT24 (100)
แอปพลิเคชัน The Face THCTT24 ได้รวบรวมใบหน้าของบุคคลสำคัญที่คาดว่าท่านจะได้เจอในการแข่งขัน Thailand Cyber Top Talent 2024 แต่เดี๋ยวก่อนนะมีหน้าใครบางคนหายไป

หมายเหตุ รูปแบบของ Flag ที่เป็นคำตอบของข้อนี้คือ THCTT24{md5}
***
![13d58909597b60b01cfb6de183a8d23f.png](/resources/13d58909597b60b01cfb6de183a8d23f.png)

เมื่อเราทำการ decompile, สิ่งแรกที่ทำได้ก็คือทำความเข้าใจหลักการทำงานของ app ตัวนี้ครับ ซึ่งสามารถอ่านได้ใน path `TheFaceTHCTT24.apk\sources\com\example thefacethctt24\MainActivity.java` 

![d33ec4d4de71196b0501cf9b59e2da27.png](/resources/d33ec4d4de71196b0501cf9b59e2da27.png)

โดยสรุปก็คือ application นี้จะทำการสุ่มแสดงผลรูป 44 รูป แต่มีรูปนึงที่หายไปนั่นก็คือ pic32 นั่นเอง แต่เราจะไปหา pic32 ได้จากไหน? 

![f5dbdb521bf0c94302889b11bacfa2ff.png](/resources/f5dbdb521bf0c94302889b11bacfa2ff.png)

เราต้องไปที่ `resources\res\drawable` เพื่อหารูปนี้ครับ

![f2eda8d6495114ac522f98434ee56f77.png](/resources/f2eda8d6495114ac522f98434ee56f77.png)

เมื่อเราได้ภาพมา เราก็จะเห็นว่ามันมีข้อความที่เป็น flag แอบอยู่ใต้ภาพ

![02a543abe49c70adb7f7159013e6a391.png](/resources/02a543abe49c70adb7f7159013e6a391.png)

Inverse ให้ดูอ่านง่าย แล้วก็พิมพ์ออกมาเพื่อส่ง flag ครับ

```
THCTT24{832b77d7e6da7cf86e79f85cee1815ff}
```

*ข้อนี้เพื่อนผม PL.0x00 เป็นคนทำแล้วส่งรูปที่มันหายไปมาให้ผม ถามว่า "มันต้องทำ forensics อะไรป่าว ดูให้หน่อย" ซึ่งผมมอบแวบแรกก็เห็น flag เลย มีคนโดนเกรียนแบบนี้ไปแล้วกี่คนครับ :D 

***
### Medium (200)
***
ข้อนี้ผมลืม capture คำอธิบายโจทย์ ขออภัยด้วยครับ แต่เพื่อนผมเริ่มจากการหา string `flag` จากไฟล์ทั้งหมดเผื่อเจอ hardcoded flag

![871826a5a891f1bd2d029895062a4926.png](/resources/871826a5a891f1bd2d029895062a4926.png)

ซึ่งก็เจอจริง ๆ ครับ...

![1c1cef15e83fcef4a6ed6a6348850090.png](/resources/1c1cef15e83fcef4a6ed6a6348850090.png)

เข้าไปอ่าน content หรือเราจะ unzip apk ไฟล์โดยตรงเลยก็ได้

![9bbb024a548615b603ca2c8a2c6d9255.png](/resources/9bbb024a548615b603ca2c8a2c6d9255.png)

หลังจาก decode จาก hex ก็จะได้ค่า flag ออกมาครับ

```
THCTT24{4ae7e6c6a479587aecd90dc353205432}
```

***
### Click Click (200)
ก็แค่ใส่ข้อมูลให้ถูกต้องแล้วก็คลิก ถ้าโชคดีก็จะได้ Flag

หมายเหตุ รูปแบบของ Flag ที่เป็นคำตอบของข้อนี้คือ THCTT24{md5}
***
![e7661181bcc7435898a4d47eb2725089.png](/resources/e7661181bcc7435898a4d47eb2725089.png)

สิ่งแรกที่ผมทำในข้อนี้ก็คือการ decompile แล้วไปส่องหลักการทำงานของโปรแกรมซึ่งจะเห็นว่าเป็นการรับ input (flag) จาก user แล้วมาเช็คว่า flag ตรงกับที่คำนวณมาหรือไม่

![ca41219f3d4cbac5e1fa761bea3e41c3.png](/resources/ca41219f3d4cbac5e1fa761bea3e41c3.png)

ซึ่งตัว secret เราจะหาได้จาก `Message.java`

![0932608c488e14f269379ab7fd28bc2c.png](/resources/0932608c488e14f269379ab7fd28bc2c.png)

นี่คือหลักการทำงานคร่าว ๆ ของโปรแกรมครับ เรามี secret แล้ว เราแค่ต้องหา key ในการ XOR

![c5664e0da75ccc8a0b083311d4a2d567.png](/resources/c5664e0da75ccc8a0b083311d4a2d567.png)

ซึ่งผมเห็นหลาย ๆ คนพลาดข้อนี้ตรงที่ไปเจอตัวแปร key ใน `R.java` ซึ่งนั่นไม่ใช่ตัวแปร key จริง ๆ แต่เป็นการ reference ไปหา key ครับ ซึ่ง key จริง ๆ จะถูก define ในไฟล์ `strings.xml` 

![333c3db500b6a2e78c20c0f69dce858b.png](/resources/333c3db500b6a2e78c20c0f69dce858b.png)

ตรงนี้นั่นเอง

![66129639d3cdeeda9fd601b2de829e5c.png](/resources/66129639d3cdeeda9fd601b2de829e5c.png)

เขียน script ให้มันคำนวณหา flag มาให้ เท่านี้เราก็ solve ข้อนี้แล้วครับ

```
THCTT24{03d124a4d859594308785750540014c6}
```
***

จบกันไปแล้วครับกับ Write-up ของ 3 หมวดนี้ที่พวกผมทำได้ 
Digital Forensics ข้อ **Bad Company** จะให้หา file ที่ถูก transfer ออกไปโดยให้ VMWare image มา investigate ซึ่งเน็ตผมกากครับ ผมเลย gave up ไป

ส่วนข้อ Network ยากสุดก็จะเป็น Communication ที่ถูกเข้ารหัส ซึ่งไม่มีใครในฝั่ง OPEN ที่ solve โจทย์นี้ได้เลย ซึ่งผมก็หวังว่าทาง official จะปล่อย write-up ของข้อนี้ออกมาครับ

ส่วนในหมวดหมู่ของ Cryptography, Reverse Engineering และ Programming จะพยายามเขียนลงใน blog หน้าครับ วันนี้พอก่อนเพราะเพื่อนร่วมทีมเป็นคน solved โจทย์พวกนี้เกือบทั้งหมด ซึ่งผมมีส่วนร่วมแค่นิดเดียวเลยไม่สามารถปั่นให้เสร็จภายในวันนี้ได้

ขอบพระคุณผู้จัดงานและผู้เข้าแข่งขันทุก ๆ ท่านที่มอบความบันเทิงให้กับทีมของพวกเราครับ!!
***

