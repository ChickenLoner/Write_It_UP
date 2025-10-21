# CyberSpaceCTF 2024 - Memory - Forensics Challenge
![7b69ff048b07fa725b0c71407a1a3134.png](/resources/7b69ff048b07fa725b0c71407a1a3134.png)
I left the image of the flag in the desktop but somehow it disappeared, can you help me recover it?

https://drive.google.com/file/d/1OqrNosho2yYFSu05sNKamQ1VeQcDzRVn/view?usp=sharing

> Incase you cannot download using the link given above, [here](https://drive.google.com/file/d/1hGiy8z73YPDV5E0OnZYA-MJZ5WcBzskT/view?usp=sharing) is a mirror link.

**Author**: 47gg
* * *
This challenge is quite unique, We were provided with Windows Memory dump and tasked to restore a file from "Desktop" < which is a big hint right here so we wanted to use `mftparser` and `filescan` and attempt to restore that file from provided memory dump (if its still there).

![ceefd4ea91126d48698c8f130f7c76be.png](/resources/ceefd4ea91126d48698c8f130f7c76be.png)

First, lets get to know about system of this memory dump first with `file` and it telling us that this memory dump is MS Windows 64bit crash dump so I used Volatility 3 with `windows.info` plugin next to find OS version which helped me determine suitable profile for Volatility 2.

From this result, I finally decided which profile to use which is `--profile=Win10x64_18362`

![b5ca251aabe5c3491827b7d793f41612.png](/resources/b5ca251aabe5c3491827b7d793f41612.png)

I always started with `pstree` to show any suspicious processes that I might want to look deep into and from this result, I wanted to dig into is `notepad.exe` and `WINWORD.EXE` despite knowing that they probably not associated directly with flag image. 

![1469629af3552ef01d7176730439b927.png](/resources/1469629af3552ef01d7176730439b927.png)

I used `cmdline` plugin next to show command-line arguments of each process and from this result, it telling me that there is one more file on "Desktop" that I might want to look into.

![84ea597206832b6de44fd71b1af35723.png](/resources/84ea597206832b6de44fd71b1af35723.png)

I used `mftparser` plugin to dump master file table record to a text file and find for any files reside in "Desktop" folder. and look like `note.txt` is not containing any hint nor an actual flag for us.

![7b6bc6d8cdeffbc569aa7b529a14defe.png](/resources/7b6bc6d8cdeffbc569aa7b529a14defe.png)

But there is one particular file that made me think, I was on the right track which is `flag.enc` but I could not dump this file using `dumpfiles` plugin since `filescan` plugin could not find this file from this memory dump.

There is a hint from the file extension indicates that this file could be an image file I was looking for but it was encrypted with some algorithms. 

![b5f0b6c261a6ca20bd76e99ffdd789d2.png](/resources/b5f0b6c261a6ca20bd76e99ffdd789d2.png)

So I used `flag.enc` to search for anything from this memory dump which landed me with a powershell script responsible for encryption.

![2b0b37360927ac01051135c8e76f7e82.png](/resources/2b0b37360927ac01051135c8e76f7e82.png)

After reviewing this script, We can see that this script used AES CBC Mode to encrypt `flag.jpg` and stores ciphertext, encryption key and IV on environment variables and eventually deleted `flag.jpg`

![bcde09142ec6153a35c1aec7cac2d7c8.png](/resources/bcde09142ec6153a35c1aec7cac2d7c8.png)

I used `envars` plugin (of volatility 2) to get these variables but It did not print out full content of `ENCD` and it could not retrieve other 2 variables.

So I had to get these variable directly from memory dump. 

![984f132e8be7c7c892bfc1a4c38d61c9.png](/resources/984f132e8be7c7c892bfc1a4c38d61c9.png)

These 3 variables were declared together so I expected that at the end of `ENCD` should follow by `ENCK` and `ENCV`.

![71f4446a6ec10b5cb4ebd78f2e424a6d.png](/resources/71f4446a6ec10b5cb4ebd78f2e424a6d.png)

But when I tried to restore this image, it was corrupted and I had no way to solve so I went to sleep and forgot that this CTF was about to end.

![8c12d36ae6370837324a024580fa0f44.png](/resources/8c12d36ae6370837324a024580fa0f44.png)

A thought came in my mind after I woke up (CTF has ended already) that maybe DATA craving via HxD and volatility 2 are not work then how about volatility 3?

![2be850c62500a92335389a8681fcea59.png](/resources/2be850c62500a92335389a8681fcea59.png)

After I tried `vol3 -f mem.dmp windows.envars > envars.txt` with `grep "ENC" envars.txt` then I finally realized that sometimes I just need to calm down and explore which options I have before give up on anything.

![32eba328b42e805ac09178b4feb51326.png](/resources/32eba328b42e805ac09178b4feb51326.png)

So finally I got 3 variables from the same process (different process might have different ciphertext, key and IV) then came back to CyberChef to retrieve a flag. (too late, CTF already ended LOL)

![800029e294194ff103bf520888105fdf.png](/resources/800029e294194ff103bf520888105fdf.png)

Here is All Recipes I used on CyberChef.

I also read write-up wrote by other team after this and realized, every team used Volatility 3 to solve this challenge.

Which made me realized that I really need to know tools and their capabilities so I will not have to waste my time and hit the wall again.
***