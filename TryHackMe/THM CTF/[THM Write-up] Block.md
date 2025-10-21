# [TryHackMe - Block](https://tryhackme.com/r/room/blockroom)
![3138c3081ab03a010d93ba4401508269.png](../../_resources/3138c3081ab03a010d93ba4401508269.png)
Encryption? What encryption?
***
Created: 17/08/2024 16:30
Last Updated: 17/08/2024 20:38
***
One of your junior system administrators forgot to deactivate two accounts from a pair of recently fired employees.
We believe these employees used the credentials they were given in order to access some of the many private files from our server, but we need concrete proof.
The junior system administrator only has a small network capture of the incident and a memory dump of the Local Security Authority Subsystem Service process.
Fortunately, for your company, that is all you need.

>What is the username of the first person who accessed our server?

![196b2ecc53421f55570153f2cf2f5205.png](../../_resources/196b2ecc53421f55570153f2cf2f5205.png)

We got lsass dump and a pcap file so we have to investigate this incident on Wireshark which you can see that the first SMB session was created for `WORKGROUP\mrealman` user and look like he tried to get something from client network share.

```
mrealman
```

>What is the password of the user in question 1?

![0dbf902d4daa10526d3638685580a430.png](../../_resources/0dbf902d4daa10526d3638685580a430.png)

Since we have lsass dump then we can use `pypykatz lsa minidump lsass.DMP` to get NT hash of all users logged on during the time that this process was dumped and here is the NT hash of `mrealman` user

![484bd61c68947ae9414874b8cac0ef19.png](../../_resources/484bd61c68947ae9414874b8cac0ef19.png)

We can use `john` or `hashcat` to crack it but I always try with CrackStation.net first and the result was not disappointing.

```
Blockbuster1
```

>What is the flag that the first user got access to?

We need to decrypt SMB3 if we want to retrieve a flag accessed by this user

![d8f0565927261987ebfd1cb795a09332.png](../../_resources/d8f0565927261987ebfd1cb795a09332.png)

I did some google search and found this [medium blog](https://medium.com/maverislabs/decrypting-smb3-traffic-with-just-a-pcap-absolutely-maybe-712ed23ff6a2) talking about generate random session key from 
- User’s password or NTLM hash 
- User’s domain
- User’s username
- NTProofStr
- Encrypted Session Key

And even provided us with a python script for it

We already know domain, username and password and what left are NTProofStr and Encrypted Session Key

![19a0d027bf26d590fd56ec28f48709d2.png](../../_resources/19a0d027bf26d590fd56ec28f48709d2.png)

Inspect packet 11 (Session Setup Request of the first user) then go to "SMB2 (Server Message Block Protocol version 2)" > "Session Setup Request (0x01)" > "Security Blob..." > "GSS-API..." > "Simple Protected Negotiation" > "NTLM Secure Service Provider" which you can obtain NTProofStr and Encrypted Session Key from here.

![047112bf30f96b4c01593220a7353138.png](../../_resources/047112bf30f96b4c01593220a7353138.png)

I asked ChatGPT for a little bit transformation from python 2 to python 3 (my kali can not installed pycryptodomex for python 2) but do not worry all functions are still the same

So we can proceed with `python3 random_session_key_calc_py3.py -u mrealman -d WORKGROUP -p Blockbuster1 -n 16e816dead16d4ca7d5d6dee4a015c14 -k fde53b54cb676b9bbf0fb1fbef384698` to get random session key.

![75e0d7b350606684d3aee55cb2e665e2.png](../../_resources/75e0d7b350606684d3aee55cb2e665e2.png)

Now what left is to get Session Id from here and swap endianness of it before import it.

![bdcbaac1529585dc67e62074c57fca69.png](../../_resources/bdcbaac1529585dc67e62074c57fca69.png)

We can do it manually or we can use Cyberchef, its a fair game 

Now these are both values we need to import to our Wireshark.
`4100000000100000:20a642c086ef74eee26277bf1d0cff8c`

![2171ddc712c2b05d9cd78b9458ef2e92.png](../../_resources/2171ddc712c2b05d9cd78b9458ef2e92.png)

Go to "Edit" > "Preferences" > "Protocols" > "SMB2" > "Secret Session Key for decryption" and "Edit..." to import our session and after click "OK", We should be able to export file that was accessed by the first user.

![beb8f1054caebc18a6cb5bde613197bc.png](../../_resources/beb8f1054caebc18a6cb5bde613197bc.png)

Go to "File" > "Export Objects" > "SMB..." then we can see that the SMB3 traffic of the first user are decrypted and we can export this csv file to get our flag

![a80216a063739a7b2560ffee363c73b8.png](../../_resources/a80216a063739a7b2560ffee363c73b8.png)

```
THM{SmB_DeCrypTing_who_Could_Have_Th0ughT}
```

Note: This is me after obtained a second flag of this challenge, turn out we can just go to "Edit" > "Preferences" > "Protocols" > "NTLMSSP" and insert NT Password then Wireshark will be able to decrypt SMB2 traffic for `mrealman` user just fine

![f45d254baccb4f6e41cf4c3f6db94fa3.png](../../_resources/f45d254baccb4f6e41cf4c3f6db94fa3.png)

![cd237e5fe7c8247355dbb63d8e16260d.png](../../_resources/cd237e5fe7c8247355dbb63d8e16260d.png)

>What is the username of the second person who accessed our server?

![d8e1ecb9ec5a9370d447032b2935c15f.png](../../_resources/d8e1ecb9ec5a9370d447032b2935c15f.png)

After we're done with the first user, the other user that accessed to client network share is this user

```
eshellstrop
```

>What is the hash of the user in question 4?

![a9c7ae7ec12827ed62d1ddec1d632325.png](../../_resources/a9c7ae7ec12827ed62d1ddec1d632325.png)

Lets look up for NT hash of this user from lsass dump again

![9f5dd0766f043dfadbf870e1c541b093.png](../../_resources/9f5dd0766f043dfadbf870e1c541b093.png)

This question does not need to submit password but I still tried it with Crackstation anyway which turns out there is no match for this hash on this site.

```
3f29138a04aadc19214e9c04028bf381
```

>What is the flag that the second user got access to?

After struggled for a while because I could not crack the hash, I found another [medium blog](https://medium.com/tenable-techblog/decrypt-encrypted-stub-data-in-wireshark-deb132c076e7) that changed everything! and turn out we can use Kerberos key (keytab file) to decrypt kerberos blobs which will also decrypt SMB3 traffic of that particular user and we do not even need to crack NT hash for it

![34e954d62792fce425d9fb92cd29cc32.png](../../_resources/34e954d62792fce425d9fb92cd29cc32.png)

Get a script to create Kerberos key [here](https://github.com/dirkjanm/forest-trust-tools/blob/master/keytab.py) then edit tuple inside `keys` list right here

![c8929cae1a3386cea6063ddb19c22373.png](../../_resources/c8929cae1a3386cea6063ddb19c22373.png)

Execute a script with `python3 keytab.py keytab.kt` then we will have keytab file ready to be imported

![809aebe912f90c3ac8a6082597df41f6.png](../../_resources/809aebe912f90c3ac8a6082597df41f6.png)

Go to "Edit" > "Preferences" > "Protocols" > "KRB5" then check for "Try to decrypt Kerberos blobs" and browse our keytab file then click Okay

![0e347f32bb5627229f93d7bb266ff992.png](../../_resources/0e347f32bb5627229f93d7bb266ff992.png)

After imported keytab file now we should be able to export another csv file that stores second flag.

![497b1524d123a5361f3d6e3b47059748.png](../../_resources/497b1524d123a5361f3d6e3b47059748.png)

```
THM{No_PasSw0Rd?_No_Pr0bl3m}
```

***