# [LetsDefend - ImageStegano](https://app.letsdefend.io/challenge/imagestegano)
Created: 02/04/2024 11:05
Last Updated: 02/04/2024 12:21
* * *
<div align=center>

ImageStegano
![4a6632ae907c23563e0c9384ae03a9de.png](../../_resources/4a6632ae907c23563e0c9384ae03a9de.png)
</div>
We are certain that there is something malicious in this image, but we do not know what it is. So we need you to investigate it and see if you can find any evidence.

**File Location**: C:\Users\LetsDefend\Desktop\ChallengeFile\Im493.zip

**WSL Username**: letsdefend
**WSL Password**: letsdefend
* * *
## Start Investigation
>Who is the “Device Manufacturer” according to the metadata?

Lets start by checking what we have first
![5d83d301cb54c19ebf7119731b4b09e2.png](../../_resources/5d83d301cb54c19ebf7119731b4b09e2.png)
We got 2 hash calcalators and a PowerShell, there is no Exiftool which mean it will be presented on Ubuntu WSL
![df1dbe34f043959fdf7a3d95dab2d1f5.png](../../_resources/df1dbe34f043959fdf7a3d95dab2d1f5.png)
There it is
![9e29a986d7a6f8951016faaa064917b0.png](../../_resources/9e29a986d7a6f8951016faaa064917b0.png)
```
Hewlett-Packard
```

>What is the CMM Type?

![50eb7c78686d0c0850cd9e2ae59d024c.png](../../_resources/50eb7c78686d0c0850cd9e2ae59d024c.png)
```
Linotronic
```

>What is the tool that created the payload inside the image?

Just search Google for Powershell Steganography
![cc9e2750477b389dedee2505856d9fd9.png](../../_resources/cc9e2750477b389dedee2505856d9fd9.png)
This is a tool to encodes powershell script into a png file that we're looking for
```
Invoke-PSImage
```

>After decoding the payload, can you find out the function's name?

I took a hint and found that I needed to find a blog from hack 4 career website
![60e7e6fc5a02a2cc437f73d5303f175c.png](../../_resources/60e7e6fc5a02a2cc437f73d5303f175c.png)
I finally found it, this blog subject is [Malicious Image](https://www.mertsarica.com/malicious-image/)
![208af60e436f82848d49a72ad5a22df2.png](../../_resources/208af60e436f82848d49a72ad5a22df2.png)
After reading this blog, We finally got a link to a [python script](https://github.com/mertsarica/hack4career/blob/master/codes/psimage_decoder.py) that this editor wrote
![130b896eb3c56b85d828f83e3a4fdccc.png](../../_resources/130b896eb3c56b85d828f83e3a4fdccc.png)
After I executed it, It was too much data to look up
![af7ff79e9b5a9ca0a123f40bb66ec8f7.png](../../_resources/af7ff79e9b5a9ca0a123f40bb66ec8f7.png)
Then I piped result to a text file
![3124cb2fcffcf45ccd5a2bb9d9f5a139.png](../../_resources/3124cb2fcffcf45ccd5a2bb9d9f5a139.png)
Which we can see that the embbeded script is a mimikatz, a popular credential dumping tool.
```
Invoke-Mimikatz
```

>There are two hidden executables in the decoded payload. What is the sha256 hash of the 32-bit version of the executable?

![1491d4973699d8a236d7668c51b9ad16.png](../../_resources/1491d4973699d8a236d7668c51b9ad16.png)
I didn't know capability of this tool so I kept scrolling down to search for something and I found that this tool even calculated hash of executables embbeded in this image
![126f0da5a02fdeed26954b595d2fbc54.png](../../_resources/126f0da5a02fdeed26954b595d2fbc54.png)
So I searched a Virus keyword for VirusTotal which I found 32-bit version of mimikatz as expected
![1371ec9b1dbc742ec79d6e58bfe34cb7.png](../../_resources/1371ec9b1dbc742ec79d6e58bfe34cb7.png)
```
BE3414602121B6D23FC06EDB6BD01AD60B584485266120C242877BBD4F7C8059
```

* * *
## Summary
This challenge is about teaching us on steganography which can be used to hide malicious payload inside an image file.

Which we learned that Invoke-PSImage module can be used to create a payload inside image then we also learned that this is a tool to decode it from Hack 4 Career.
<div align=center>

![18fc31e7b426efe611e2e8ef6a991543.png](../../_resources/18fc31e7b426efe611e2e8ef6a991543.png)
</div>

* * *
