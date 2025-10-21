# [MemLabs Lab 6 - The Reckoning](https://github.com/stuxnet999/MemLabs/tree/master/Lab%206)
Created: 14/07/2024 19:01
Last Updated: 27/08/2024 18:10
***
## Challenge Description
We received this memory dump from the Intelligence Bureau Department. They say this evidence might hold some secrets of the underworld gangster David Benjamin. This memory dump was taken from one of his workers whom the FBI busted earlier this week. Your job is to go through the memory dump and see if you can figure something out. FBI also says that David communicated with his workers via the internet so that might be a good place to start.

**Note**: This challenge is composed of 1 flag split into 2 parts.

The flag format for this lab is: **inctf{s0me_l33t_Str1ng}**

**Challenge file**: [MemLabs_Lab6](https://mega.nz/#!C0pjUKxI!LnedePAfsJvFgD-Uaa4-f1Tu0kl5bFDzW6Mn2Ng6pnM)
***
Finally! we are in the final lab of MemLabs, are you ready to tackle this? lets go!

![11b9c71bf25ae116fd9db78e1e76fe8e.png](../../_resources/11b9c71bf25ae116fd9db78e1e76fe8e.png)

After determined which profile to use with `vol.py -f MemoryDump_Lab6.raw imageinfo`, now we are ready to rock!

## Getting second half of a flag

![845da5db022971cefe01425d6da2a015.png](../../_resources/845da5db022971cefe01425d6da2a015.png)

Showing process tree should be my signature move at this point since I always start with `vol.py -f MemoryDump_Lab6.raw --profile=Win7SP1x64 pstree` after determined image profile, You could see a lot of processes here that totally outstanding which are WinRAR, chrome, cmd and firefox

![70bd8c8f20f42debce68b79858ec9917.png](../../_resources/70bd8c8f20f42debce68b79858ec9917.png)

Start with `vol.py -f MemoryDump_Lab6.raw --profile=Win7SP1x64 cmdline`, since most flag we got so far almost start from here and this is likely to be the case for this one too.

![3338553f72ac1106accf0728661c7720.png](../../_resources/3338553f72ac1106accf0728661c7720.png)

And now its time to dump it, first getting an offset with `vol.py -f MemoryDump_Lab6.raw --profile=Win7SP1x64 filescans > mem6_filescan.txt` then `vol.py -f MemoryDump_Lab6.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000005fcfc4b0 -D .` and lastly, change dumped filename to its original name.

![4cae078493f6d720c276266ef9506d98.png](../../_resources/4cae078493f6d720c276266ef9506d98.png)

Its always password-protected, my first instinct is to use first half of a flag as a password but then I realized..."wait.. how about cmd.exe process?"

![df98637d77a9f292c3ff9f441f88485c.png](../../_resources/df98637d77a9f292c3ff9f441f88485c.png)

So I used `vol.py -f MemoryDump_Lab6.raw --profile=Win7SP1x64 consoles` to show command history which you can see that Jaffa user was trying to list all environment variables with `env` command

![01ee4ac221a9836fa16686b5fe03f071.png](../../_resources/01ee4ac221a9836fa16686b5fe03f071.png)

So we can use `envars` plugin to find for anything remotely closed to password or a clue to password which will lead us to this `RAR password` variable that stores password for flag archive file.

![flag2.png](../../_resources/flag2.png)

Use password we obtained to get second half of a flag!

## Getting first half of a flag

![d8e3be1b26e648ec2f46014554c6bd80.png](../../_resources/d8e3be1b26e648ec2f46014554c6bd80.png)

We still have `chrome.exe` and `firefox.exe` left to explore so I started with `firefoxhistory` and got nothing but `chromehistory` has this url that stand out.

![8547b4927aa44872a1fa0b5f99674da1.png](../../_resources/8547b4927aa44872a1fa0b5f99674da1.png)

So lets visit it, and we can see that this pastebin contains another url and a hint which we do not know yet how this key will be used for but lets keep that in mind for now.

![648ea59219c56a30f09855f48a5bb55d.png](../../_resources/648ea59219c56a30f09855f48a5bb55d.png)

Upon visiting url stores in pastebin, its a google doc that contain Lorem ipsum paragraph so we might need to skim this to find anything that should not be here.

![e886bc53645a8d0c1052eecb38666a80.png](../../_resources/e886bc53645a8d0c1052eecb38666a80.png)

Which eventually lead us to Mega Drive which is locked by a key so now we need to find password to unlock it.

![8c91a62257aced0562f33a2771c6dd55.png](../../_resources/8c91a62257aced0562f33a2771c6dd55.png)

Since a key was sent with mail and it might be a gmail so I did not expect it to be found by any plugin so I used `strings` to search for "the key" which we can see that it worked!

![0237787a4453123e34f0d3ef2354715a.png](../../_resources/0237787a4453123e34f0d3ef2354715a.png)

Unlock mega with that key and download a flag.

![cc450e276fd75bcff083774b715d0615.png](../../_resources/cc450e276fd75bcff083774b715d0615.png)

But look like this file is corrupted so we might need to use hexeditor to fix it

![fd92aafc89db70130a12600e62b4ad77.png](../../_resources/fd92aafc89db70130a12600e62b4ad77.png)

I used HxD that pre-installed in Flare-VM and we can see that in IHDR chuck because it supposed to be IHDR not iHDR 

![2fa42bb50f6ded65ac384aa0353e0c87.png](../../_resources/2fa42bb50f6ded65ac384aa0353e0c87.png)

Compare to `flag2.png`, we can see which offset we need to fix.

![c09538089b698f0cb4d9f730478c8cbf.png](../../_resources/c09538089b698f0cb4d9f730478c8cbf.png)

Lets change 0x0000000C offset from 69(i) to 49(I) then save it, we should be able to view this image for now.

![d0d5d88cb62e3e230abc4109ba6983fe.png](../../_resources/d0d5d88cb62e3e230abc4109ba6983fe.png)

Now we have both path of a flag and solved this lab! And now we've completed all Labs in MemLabs!

## Lab 6 : Flags
```
inctf{thi5cH4LL3Ng3_!s_g0nn4_b3_?_aN_Am4zINg_!_i_gU3Ss???}
```
***