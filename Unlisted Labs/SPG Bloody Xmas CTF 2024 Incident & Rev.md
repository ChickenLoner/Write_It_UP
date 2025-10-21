# SEC Playground Bloody Xmas2024 CTF - [Incident & Rev - Wowza]
[toc]
***
![2849d1b54a7607881c6a9fb1bf98e0c4.png](/resources/2849d1b54a7607881c6a9fb1bf98e0c4.png)

สวัสดีปีใหม่ครับทุกท่าน วันนี้ chicken0248 มากับทีม Wowza ได้มีโอกาสได้เข้าร่วมการแข่งขัน CTF (คือความท้าทาย~) ของ SEC Playground ที่มีระยะเวลาการแข่งที่ยาวนานถึง 4 วัน ตั้งแต่วันที่ 25 - 28 Dec 2024 ซึ่งก็มีโจทย์ที่เยอะขึ้นให้เหมาะสมกับจำนวนวันที่เพิ่มขึ้น 

![48821b7b40de4754e99add96b1c6f597.png](/resources/48821b7b40de4754e99add96b1c6f597.png)

Event นี้จะมีทั้งหมด 6 หมวดโดยจะแบ่งเป็น
- Web Application Security 11 ข้อ (Easy: 7, Medium: 3, Hard: 1)
- Reverse Engineering 6 ข้อ (Easy: 5, Hard: 1)
- Log analysis 3 ข้อ (Easy หมดเลย)
- Digital Forensic 11 ข้อ (Easy: 5, Medium: 4, Hard: 2)
- Incident#1 8 ข้อ (Easy: 6, Medium: 1, Hard: 1)
- Cryptography 2 ข้อ (Easy หมดเลย)

ซึ่งเราจะเห็นว่าโจทย์ในรอบนี้มีสัดเส้นที่เน้นไปทาง Blue Team สูงมาก เพราะแค่ Digital Forensic ก็มีจำนวนโจทย์เท่ากับ Web App แล้ว 

และใน blog นี้ ผมจะมาเขียน write up ในหมวดของ Incident#1 และ Reverse Engineering ครับ เนื่องจากหมวด Digital Forensic ได้ตกลงกับพี่ MirthZ แล้วว่าให้แกเป็นคนเขียน 5 5 5

***
## Incident#1(All 8 solved)
![8e2e9e415ca00adb623e4f6255889117.png](/resources/8e2e9e415ca00adb623e4f6255889117.png)

ในหมวดนี้จะมีอยู่ทั้งหมด 8 ข้อเริ่มจาก Medium ที่เปิดมาก็ไม่ใช่ Blue team แล้ว (Incident แบบใดห์) ซึ่งผมขอข้ามการทำ write up ในส่วนของข้อแรกนะครับ เนื่องจาก not in my field of expertise

แต่ถึงยังงั้นเราก็ต้องการ password จาก **Phantom of the Network#1** เพื่อไปแตกไฟล์ที่เราโหลดจาก **Phantom of the Network#2** ซึ่งเราจะใช้ไฟล์นี้ได้จนถึงข้อสุดท้ายเลย

![618ef61d7263a1b987ae179212a2f6c8.png](/resources/618ef61d7263a1b987ae179212a2f6c8.png)

โดยในโจทย์แรกนั้นจะมี Website host อยู่บน 2 port นั่นก็คือ port 80 และ 8080 

![b3c84c580b598b7794d11dda1518d988.png](/resources/b3c84c580b598b7794d11dda1518d988.png)

ซึ่งเมื่อเราเข้าไปที่หน้า index ของเว็บไซต์ที่ host บน port 80 แล้ว view page source, เราก็จะพบกับ SHA256 สองตัวที่ถูก separate ด้วยเครื่องหมาย + 

![1bd022f39c3fd40d6477bcbc95a1bb2a.png](/resources/1bd022f39c3fd40d6477bcbc95a1bb2a.png)

แยก SHA256 สองตัวออกจากกัน จากนั้นก็ใช้ rainbow table เพื่อหา plaintext โดยเราจะได้ `xmas2024` โดยเราสามารถนำ password นี้มาแตกไฟล์ที่ได้จาก **Phantom of the Network#2** ได้เลย

### Phantom of the Network#2
![60174e3d4c62459354a84f83063ffe3d.png](/resources/60174e3d4c62459354a84f83063ffe3d.png)
ถ้าเราอ่านคำอธิบายโจทย์ข้อนี้ เราก็อาจจะเข้าใจไปว่าให้หาไฟล์ที่ดาวน์โหลดมาเป็นไฟล์แรก แต่จริง ๆ แล้วโจทย์ต้องการให้หา ใครเล่น CTF บน platform นี้ต้องทำใจเพราะคำอธิบายจะค่อนข้างมึน ๆ ฉะนั้นเราข้ามมาที่วิธี solve กันเลยดีกว่า

![5e88f6a0b69dd4af94771fd58c94416d.png](/resources/5e88f6a0b69dd4af94771fd58c94416d.png)

เมื่อแตกไฟล์แล้ว เราจะพบว่าไฟล์ที่เราได้มาก็คือไฟล์ที่ได้รับการเก็บจากโปรแกรม KAPE ซึ่งทาง secplayground ก็ค่อนข้างใจดีที่มีการ parse artifacts บางอย่างด้วย Module ภายใน KAPE มาให้เราแล้ว ซึ่งเราจะสามารถหาผลลัพธ์จากการ analyze  

![d00cdfa012a292522d7f22d439264b30.png](/resources/d00cdfa012a292522d7f22d439264b30.png)

โดยผลลัพธ์ทั้งหมดที่ถูก parse จะสามารถหาได้ภายในโฟลเดอร์ ModuleResult 

![f82565b3642335da294a51f732d2f67c.png](/resources/f82565b3642335da294a51f732d2f67c.png)

เมื่อเราเปิดไฟล์ `20241203083207_EvtxECmd_Output.csv` ซึ่งเป็นไฟล์ที่ถูก parse ด้วย EvtxECmd ในการ parse Windows event log เราจะพบว่า security event log ได้ถูก set audit policy ให้ทำการ log command line ของ process ด้วย ซึ่งเมื่อได้ค้นหาด้วย Cmdlet ของ PowerShell ที่เกี่ยวข้องกับการ fetch content จาก website อย่าง `Invoke-WebRequest` เราก็จะพบว่ามี PowerShell command ปริศนาที่ fetch content จาก `blogoss[.]fr` ก่อนจะถูก execute ด้วย `iex` หรือ `Invoke-Expression` Cmdlet

![0b023b9587d6092b11cb1861dbeebdaa.png](/resources/0b023b9587d6092b11cb1861dbeebdaa.png)

ต่อมาเมื่อเราเอา domain นี้มา search บน [any.run](https://app.any.run/submissions), เราจะพบหลาย report ที่มีคนเคยมา submit url ที่เราพบเอาไว้แล้ว ดังนั้นเลือกอันที่ชอบที่ชอบเพื่อเข้าไปอ่าน script กันเถอะ

![21f61e19996af3ff0349488f6d33d79e.png](/resources/21f61e19996af3ff0349488f6d33d79e.png)
https://app.any.run/tasks/e742b873-0cf5-4ac6-a22e-672437dda00b

ซึ่งเราจะพบว่านี่จะเป็นสคริปต์ PowerShell ที่จะดาวน์โหลด `makron.zip` จาก `fatcriminal[.]com` ไปยัง `C:\ProgramData` โดยตั้งชื่อ output file เป็น `pzk.zip` ซึ่งเป็น flag ของข้อนี้นั่นเอง

```
forensic{pzk.zip}
```

![c955d04108f8fc5659c03708fd99926a.png](/resources/c955d04108f8fc5659c03708fd99926a.png)

ซึ่งหลังจากโหลดไฟล์, script นี้จะ fetch content จาก `iplogger.co` เพื่อ log IP address ของเหยื่อที่ run script นี้ 

### Phantom of the Network#3
![c8998743a429480350185248867e110f.png](/resources/c8998743a429480350185248867e110f.png)

จากข้อที่แล้วเราพบว่า เมื่อ file ถูกดาวน์โหลดไปที่ `C:\ProgramData` ไฟล์zip ก็จะถูก decompress ด้วย `Expand-Archive` Cmdlet ไปยัง `C:\ProgramData\Extrac` ซึ่งก็เป็น flag ของข้อนี้ นั่นเอง

![8a80d70f97efa87cdeb50b53f2c09346.png](/resources/8a80d70f97efa87cdeb50b53f2c09346.png)

เมื่อเรากลับมาลองเช็คใน event log, เราก็จะพบว่า script นี้ถูก run จริง ๆ ไม่ติงนัง

```
forensic{C:\ProgramData\Extrac}
```

### Phantom of the Network#4
![e71f455aa03e00cfe066be00b270b83a.png](/resources/e71f455aa03e00cfe066be00b270b83a.png)

![11cc7bd4f406c78483e5845d33225df5.png](/resources/11cc7bd4f406c78483e5845d33225df5.png)

เราพบว่า `kokesh.exe` ก็คือไฟล์ที่ถูก decompress จาก `pzk.zip` แล้วก็ถูก run ซึ่งเมื่อเราเอาชื่อไฟล์นี้มาค้นใน [hybrid-analysis](https://hybrid-analysis.com/search?query=kokesh.exe), ซึ่งเราก็จะได้ SHA256 จากในหน้า search ทันทีโดยที่ไม่ต้องกดเข้าไปดูซัก report เลย

```
forensic{0e78733824c1cdf52b59dadf1fa5f8b4a7c59dcfdbaceb226eee23f6cd04ea46}
```

### Phantom of the Network#5
![491bf9006966209727d38e275c608108.png](/resources/491bf9006966209727d38e275c608108.png)

เราสามารถหาคำตอบของข้อนี้ได้หลายวิธีเนื่องจากเราได้ hash ของไฟล์มาแล้ว

![2559e666ca4ecb82da70ef0f3fc45322.png](/resources/2559e666ca4ecb82da70ef0f3fc45322.png)

วิธีแรกที่ง่ายที่สุดต่อจากข้อที่แล้วก็คือการกดเข้ามาส่อง [hybrid analysis ซัก report](https://hybrid-analysis.com/sample/0e78733824c1cdf52b59dadf1fa5f8b4a7c59dcfdbaceb226eee23f6cd04ea46/674ef47a8f48afceea0720c0) โดยในส่วนของ "**File Details**" ก็จะมีรายละเอียดต่าง ๆ ของไฟล์ที่ sandbox ตรวจสอบได้ ซึ่งนั่นก็รวมถึง original filename ของไฟล์นี้นั่นเอง

![612850922ccc0e15d0162c4e75462cb0.png](/resources/612850922ccc0e15d0162c4e75462cb0.png)

วิธีที่สองที่จะทำให้เราได้เบาะแสไปยังข้อที่ 7-8 ก็คือการนำ hash ไป search บน [VirusTotal](https://www.virustotal.com/gui/file/0e78733824c1cdf52b59dadf1fa5f8b4a7c59dcfdbaceb226eee23f6cd04ea46) ซึ่งนอกจากจะได้ original filename แล้ว เราก็ยังได้ชื่อ family ของ malware ซึ่งนั่นก็คือ Lumma Stealer นั่นเอง

```
forensic{net1.exe}
```

### Phantom of the Network#6
![b5187e7c98538ef2850a9e809e2c9a86.png](/resources/b5187e7c98538ef2850a9e809e2c9a86.png)

![ef315f06f6c5d772cd36527ab6093692.png](/resources/ef315f06f6c5d772cd36527ab6093692.png)

กลับมาที่ event log เราจะพบว่าหลังจาก lumma stealer ถูก run ก็ได้มี `msedge.exe` ซึ่งเป็น process ของ Microsoft Edge ถูก run ด้วย flag `--remote-debugging-port=9221` โดยเทคนิคนี้จะเป็นการ abuse remote debugging port ของ Chromium ทำให้ malware สามารถ bypass security check บางอย่างรวมถึงการ remote access มาที่เครื่องของเหยื่อด้วย (bind shell)

```
forensic{9221}
```

สำหรับคนที่สนใจเทคนิคนี้ แนะนำให้ตามไปที่ เว็บนี้เลย -> https://krptyk.com/2023/11/12/remotechromiumpwn/

### Phantom of the Network#7
![e9a111e67f027e266751311feae7d119.png](/resources/e9a111e67f027e266751311feae7d119.png)

ข้อนี้จะให้เราหา shortcut หรือปุ่มที่เรากดบนคีย์บอร์ดนั่นแหละ ซึ่งถ้าไม่รู้เช่นเห็นชาติตระกูลของมัลแวร์ก็อาจจะไปยากนิดนึง แต่เนื่องจากเรารู้ชาติตระกูลของมัลแวร์ตัวนี้เรียบร้อยแล้ว ซึ่ง lumma stealer ในช่วงหลายเดือนที่ผ่านมาค่อนข้างจะ popular ในหมู่ threat intelligence gatherer และ malware researcher เนื่องจากได้ทำการ deliver ด้วย Fake Captcha campaign 

![ee7f3f9cfb80715d74f60d32a1f94699.png](/resources/ee7f3f9cfb80715d74f60d32a1f94699.png)

ซึ่งเมื่อเรากลับมาที่ any.run เราก็จะพบว่ามี domain อีก domain ที่เรายังไม่ได้เข้าไปส่องนั่นก็คือ `fiare-activity[.]com`

![01e54eb9121e9483912c823d0ba24418.png](/resources/01e54eb9121e9483912c823d0ba24418.png)

เมื่อเรากดเข้าไปดูใน [report](https://app.any.run/tasks/35e092c1-097c-4f59-bf21-49889b93d122) ก็จะพบว่านี่เป็นการ deliver ด้วย Fake Captcha จริง ๆ โดยให้กดปุ่ม Windows + R จะเป็นการเปิด run box ขึ้นมา จากนั้นเมื่อกด Ctrl + V ก็จะเป็นการ paste PowerShell command ที่ถูก host อยู่บน website (ที่เราเจอใน event log) โดยจะแอบฝังเข้ามาใน clipboard ของ user แล้วเมื่อกด Enter ก็จะเป็นการ run command นั้นนั่นเอง

```
forensic{(Windows+R)+(Ctrl+V)+(Enter)} 
```

ถ้าสนใจ lab ที่ investigate เคสคล้าย ๆ กันนี้แนะนำให้เล่น [Pikaptcha sherlock](https://app.hackthebox.com/sherlocks/Pikaptcha) จาก HackTheBox เพื่อเรียนรู้วิธีการป้องกันและการ investigate ว่าจะเกิดอะไรขึ้นเมื่อ PowerShell command ถูก execute ผ่าน Run box 

### Phantom of the Network#8
![9e66973ee93f332d252df3948a82eb16.png](/resources/9e66973ee93f332d252df3948a82eb16.png)

![a96d0e10c4f2201c65f15eb0e1d5c227.png](/resources/a96d0e10c4f2201c65f15eb0e1d5c227.png)

เมื่อเรารู้แล้วว่าการ deliver fake captcha ก็จะต้องมาจาก Web Browser ดังนั้นเราก็จะต้องมาเปิด  Microsoft Edge History ไฟล์ของ cheese user ซึ่งเราจะพบการ redirect เริ่มต้นมาจาก `en1[.]savefrom[.]net` ซึ่งก็เป็นคำตอบของข้อนี้นี่เอง

```
forensic{en1.savefrom.net}
```

![1f12576438186838d0eb7b7825510331.png](/resources/1f12576438186838d0eb7b7825510331.png)
จบไปแล้วกับหมวดของ Incident#1 เราไปต่อที่ Reverse Engineering กันเลย
***
## Reverse Engineering (All 6 solved)
![f9ce08974d73d91f75b355996dee946b.png](/resources/f9ce08974d73d91f75b355996dee946b.png)

Reverse Engineer เป็นหมวดที่ผมไม่เคยคิดจะเขียน write-up มาก่อน แต่สาเหตุที่ทำให้ผมต้องมาเขียน write-up ในครั้งนี้นั้นเพราะมันไม่จำเป็นต้อง reverse เสมอไป, ทำ Threat Intel ก็หาคำตอบได้

### Secplaysomware#1
![aaed22965899395bf363fba0c4e64f1d.png](/resources/aaed22965899395bf363fba0c4e64f1d.png)

![28233478a4bc8a65513b4a77f7452aea.png](/resources/28233478a4bc8a65513b4a77f7452aea.png)

เรามาเริ่มกันที่ข้อแรกกันเลย ข้อนี้จะให้เราหา SHA256 hash ของ ransomware ที่เราโหลดมาจากโจทย์

![ee08c76937317792f8a1774b539106b2.png](/resources/ee08c76937317792f8a1774b539106b2.png)

โดยในข้อนี้เราต้องตอบ hash เป็น upper case (ตัวพิมพ์ใหญ่ให้หมด) ซึ่งถ้าเราเอาไปโยนใน VirusTotal หรือใช้ `certutil` หาค่า hash ก็จะต้องนำค่า hash ไป "to uppercase" แต่ถ้าเราใช้ `Get-FileHash` Cmdlet บน PowerShell, เราก็จะได้ SHA256 ที่เป็นตัว uppercase ทั้งหมดทันทีโดยที่ไม่ต้องไป convert

```
re{B8AF9CBD706C13F5E7F20573FF5F2894966C905835BD7C026B8C96F20E304C0B}
```

### Secplaysomware#2
![f3cd0cbab629d9ff0bbc3aa21d5f1d67.png](/resources/f3cd0cbab629d9ff0bbc3aa21d5f1d67.png)

![d3b693fb7a98e3fbcb053eb9afa2f0a7.png](/resources/d3b693fb7a98e3fbcb053eb9afa2f0a7.png)

ในข้อนี้ถ้าเราเอาไปโยนใส่ [VirusTotal](https://www.virustotal.com/gui/file/b8af9cbd706c13f5e7f20573ff5f2894966c905835bd7c026b8c96f20e304c0b) ก็จะเห็นได้ไม่ยากว่า ransomware ตัวนี้ถูกเขียนขึ้นมาโดยใช้ภาษางู (Python)

```
re{python}
```

### Secplaysomware#3
![59b3f62f1937ab98730cf1bded588532.png](/resources/59b3f62f1937ab98730cf1bded588532.png)

![3325fafdcd5278569bfb9a9d22702614.png](/resources/3325fafdcd5278569bfb9a9d22702614.png)

ในเมื่อเราใช้ VirusTotal ให้เป็นประโยชน์แล้วก็ต้องไปต่อให้สุด เราสามารถกดไปที่ [Behavior](https://www.virustotal.com/gui/file/b8af9cbd706c13f5e7f20573ff5f2894966c905835bd7c026b8c96f20e304c0b/behavior) เพื่ออ่านข้อมูลเพิ่มเติมเกี่ยวกับพฤติกรรมต่าง ๆ ของ ransomware ตัวนี้เมื่อถูก run บน Sandbox ซึ่งเราก็จะเห็นว่ามีไฟล์จำนวนมากมี `.qwerty` ต่อท้าย file extension เดิม และนั่นก็เป็นคำตอบของข้อนี้นี่เอง

```
re{qwerty}
```

### Secplaysomware#4
![1645af8cb068083e8d20960454c7d343.png](/resources/1645af8cb068083e8d20960454c7d343.png)

![fd79005c8f15bd1bef54671afcc9ad94.png](/resources/fd79005c8f15bd1bef54671afcc9ad94.png)

ต่อมาเราก็มาใช้ public sandbox ตัวอื่นให้เป็นประโยชน์อย่างเช่น [any.run](https://app.any.run/tasks/b380d742-869e-4ec3-ac36-308c6bef4682) ซึ่งเราจะเห็นว่า ransomnote ได้ถูกเปิดด้วย `notepad.exe` หลังจาก ransomware ถูกรัน ซึ่งชื่อของ ransomnote ก็คือคำตอบของข้อนี้นี่เอง

```
re{UNLOCK_README.txt}
```

### Secplaysomware#5
![4830c958db1a598543201aadfe263162.png](/resources/4830c958db1a598543201aadfe263162.png)

![be855a68ea28808d8102662671e86c65.png](/resources/be855a68ea28808d8102662671e86c65.png)

เรารู้ว่า ransomware ตัวนี้ถูกเขียนด้วย python ดังนั้นเราสามารถใช้ [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) ในการแตก pyc ไฟล์ออกมาจากตัว executable ได้ ซึ่งเมื่อเราแตกไฟล์ออกมาก็จะพบว่าเราจำเป็นต้องใช้ decompiler ที่ support Python 3.12 ในการ decompile ซึ่ง Uncompyle6 ซึ่งเป็น python decompiler ยอดฮิตก็ไม่ได้ support python version นี้

![762c3cf256618465283e233c93d7bbba.png](/resources/762c3cf256618465283e233c93d7bbba.png)

แต่มันก็ยังมี python online decompiler อย่าง [pylingual](https://pylingual.io/view_chimera?identifier=606efc45df0dbf657540fa4c250c8848510fd205a38f58e972befe2bc066b84a) อยู่ ซึ่ง support python 3.12 และสามารถ decompile `main.pyc` ออกมาแล้วพบกับ hard-coded IV ของ ransomware ตัวนี้ได้ภายใต้ JamCrypt class

```
re{secplaygroundgod}
```

### Hello World
![d0f5435dbcb75d4b7ccfab17a22b2cd3.png](/resources/d0f5435dbcb75d4b7ccfab17a22b2cd3.png)

![f811d5683eb5b054a186ed4ff445fdf6.png](/resources/f811d5683eb5b054a186ed4ff445fdf6.png)

ในข้อนี้เราจะได้ไฟล์ขนาด 10MB มา reverse ซึ่งค่อนข้างใหญ่และเมื่อเราโยนใส่ Detect It Easy มันก็จะ detect ว่าตัว executable ตัวนี้ถูกเขียนด้วยภาษา C หรือ C++ ตาม Compiler 

![9c89df001edc216e746b45604dc101df.png](/resources/9c89df001edc216e746b45604dc101df.png)

แต่เมื่อเราใช้ลองใช้ strings ใส่ดูจะพบว่าที่จริงแล้วธาตุแท้ของมันก็คือ .NET compiled executable ดี ๆ นี่เอง

ซึ่งจากนั้นเราจำเป็นต้องใช้ iLspy ในการ decompile executable ตัวนี้ เพราะว่า dnspy ไม่สามารถ detect ได้ว่าไฟล์ตัวนี้เป็น .NET compiled executable

![f19f65d44ba702e6598b4b1f455367d3.png](/resources/f19f65d44ba702e6598b4b1f455367d3.png)

เมื่อ decompile เสร็จแล้วเรียบร้อยแล้วก็เข้าไปยัง main function ของโปรแกรม ซึ่งเราก็จะเจอว่าโปรแกรมนี้เป็นโปรแกรมที่จะเช็ค key ผ่าน CheckKey function และใช้ DecryptFlag function ในการ retrieve ค่า flag ออกมาในกรณีที่ใส่ข้อมูล secret key ได้ถูกต้อง

![d6a7636dfe6d61a17f6bc6d37fb0667b.png](/resources/d6a7636dfe6d61a17f6bc6d37fb0667b.png)

ซึ่งใน DecryptFlag function ก็จะมีแค่การเอาค่า hard-coded secret key (`array`) มา XOR กับ xor key  (`array2`)

![d8dee68dcab26c098c5427552d591d41.png](/resources/d8dee68dcab26c098c5427552d591d41.png)

เมื่อ convert ตัว xor key ออกมา เราจะได้ค่า key คือ "SECP7AygroundP7@tf0rm"

![0bf67dfd596126c28cb1f75f9900d7c8.png](/resources/0bf67dfd596126c28cb1f75f9900d7c8.png)

จากนั้นเราสามารถเอา `array` มา convert แล้ว XOR กับ key ที่เราพึ่งได้มาก็จะได้ออกมาเป็น flag

```
re{Just_An_E3C_X0r_Cha77enG3}
```

![ffa35614a19a3f3fcd8d367ce1caa65d.png](/resources/ffa35614a19a3f3fcd8d367ce1caa65d.png)

จบไปแล้วครับกับหมวด Reverse Engineering ซึ่งเราก็จะเห็นได้ว่าใน 6 ข้อนี้ เราได้ reverse มาตอบจริง ๆ แค่ 2 ข้อเท่านั้น  
***
## Digital Forensic (10 of 11 Solved)
### Santa_Message

![1fc294e0c80c666d6abc1e483c8d2205.png](/resources/1fc294e0c80c666d6abc1e483c8d2205.png)

![f874d52cbd67e607af3fb6462eedfd75.png](/resources/f874d52cbd67e607af3fb6462eedfd75.png)

![09b585fab2820eb5396a1d0eea2cf169.png](/resources/09b585fab2820eb5396a1d0eea2cf169.png)
https://github.com/eye9997/Santa_message

https://github.com/itxKAE/Video-Steganography/blob/master/main-module/wav-steg.py

![2a91a91f31b55cd0f9f14865620b122e.png](/resources/2a91a91f31b55cd0f9f14865620b122e.png)

`python wav-steg.py -r -s santa_key_message.wav -n 1 -b 20 -o output.txt`

```
forensic{santa_2024}
```
***

![bf0564a53d2132de70df02655a36d7d1.png](/resources/bf0564a53d2132de70df02655a36d7d1.png)

![c5bf3a2e236f014e7811baaf034d8444.png](/resources/c5bf3a2e236f014e7811baaf034d8444.png)
```
forensic{https://github.com/taipun/Minecraft/blob/main/MinecraftCrack.exe}
```

![fa6f37df6fb9bca3d91bb98088beb36e.png](/resources/fa6f37df6fb9bca3d91bb98088beb36e.png)

![d614386f29267110bef1142b9b1bd8f3.png](/resources/d614386f29267110bef1142b9b1bd8f3.png)

https://www.virustotal.com/gui/file/d95c97c31a22087b257107bacfdd21c8cc076463e13863c927d4dd76ed0d1b72/behavior
```
forensic{20.188.121.243:9999}
```


![e62e41c0bd01d267136f526ae864d1c1.png](/resources/e62e41c0bd01d267136f526ae864d1c1.png)

![fec9a21fad75d7d45e613fed4a4168cb.png](/resources/fec9a21fad75d7d45e613fed4a4168cb.png)

https://tria.ge/240525-rat35afd95

![70ca8a9354a041a0da027a92d68c0881.png](/resources/70ca8a9354a041a0da027a92d68c0881.png)
```
forensic{-|S.S.S|-}
```

### malware infected

![73b57ccf2f24d9763c889604382b2377.png](/resources/73b57ccf2f24d9763c889604382b2377.png)


![4849c44b6439d9341454315bd0a93cc8.png](/resources/4849c44b6439d9341454315bd0a93cc8.png)

![2e51f1b875f404f474de736343372f29.png](/resources/2e51f1b875f404f474de736343372f29.png)

![073af8b345b9909f31d83e712a04ea84.png](/resources/073af8b345b9909f31d83e712a04ea84.png)

![9afbde00b13492a64703aa855b7851aa.png](/resources/9afbde00b13492a64703aa855b7851aa.png)

https://www.virustotal.com/gui/domain/bibpap.com/community

![9a93cd9f10884c6519ef7b5da91fb486.png](/resources/9a93cd9f10884c6519ef7b5da91fb486.png)

![bd47e6623b19501f738b27ea571afaa3.png](/resources/bd47e6623b19501f738b27ea571afaa3.png)
https://bazaar.abuse.ch/sample/008653065299f1e96ecd195fe23948cc3976210bc8d58ba0e1456db17270154d/

```
forensic{e5d7a2dd2aafaa4e55c303c3533a36be}
```

***
## Log Analysis (All 3 solved)
### Universal Share
![fa012d2048237a813f96508d9382e92c.png](/resources/fa012d2048237a813f96508d9382e92c.png)

![6f4d9237984dbb93b851e86494c2362a.png](/resources/6f4d9237984dbb93b851e86494c2362a.png)

![ecd15a5a171e36f2b4c69ee5ae25f909.png](/resources/ecd15a5a171e36f2b4c69ee5ae25f909.png)

```
forensic{117.154.101.223}
```
***

