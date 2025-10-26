# [HackTheBox - Forgotten](https://app.hackthebox.com/machines/Forgotten)

![c29024c50375590e18ac6fe58b8d0b97.png](/resources/c29024c50375590e18ac6fe58b8d0b97.png)

## Table of Contents

- [Abstract](#abstract)
- [Enumeration](#enumeration)
- [LimeSurvey Installation](#limesurvey-installation)
- [Foothold on docker via Limesurvey plugin](#foothold-on-docker-via-limesurvey-plugin)
- [Foothold on Host with Limesurvey password in env](#foothold-on-host-with-limesurvey-password-in-env)
- [Privilege Escalation via share directory between container and host](#privilege-escalation-via-share-directory-between-container-and-host)

***
## Abstract
Forgotten is a vulnlab machine imported to HackTheBox as an Easy Linux box, I started with network enumeration with nmap, revealing this machine is a running SSH, 
a website on port 80.

I started with web enumeration which reveals LimeSurvey installation page so I setup mysql database to connect to the LimeSurvey to complete the installation then gaining the foothold to the docker container by deploying a plugin that contains PHP reverse shell in it.

I found the password of limeuser user from the environment variable of the docker container, allow me to become root inside the docker and also grant me the actual foothold on the box.

On the actual box, I found the share directory between host and docker container which allows me to create SUID bash binary to run on the host and finally root the box.

## Enumeration

I start my initial nmap scanning with `-sCV` flag right away since I don't expect much port to be running on Linux box which reveals SSH running on port 22 and a website running on port 80 but looking from the title, I will need to bruteforce directory to find other way in.

![296d00ae6ff9132b181e6cc7b94677f7.png](/resources/296d00ae6ff9132b181e6cc7b94677f7.png)

I use feroxbuster to quickly bruteforce directory and finally found "/survey" path.

```
feroxbuster -u http://forgotten.vl/
```
![5e4ce09c08e8c1aed918d6843392cf76.png](/resources/5e4ce09c08e8c1aed918d6843392cf76.png)

Upon visiting this path, I discover the Limesurvey Installer which I can finish the installation of Limesurvey of this box which can give me a foothold.

![b39c5110f947d3701dc60cfc28608b73.png](/resources/b39c5110f947d3701dc60cfc28608b73.png)

## LimeSurvey Installation

In the installation process, I can see that all minimum requirement already satisfied so in theory, I can proceed with this installation easily.

![23ef1ab1b20223929e9314f489df0242.png](/resources/23ef1ab1b20223929e9314f489df0242.png)

However, there is no mysql server or any database on the box so I will need to use mine to host the database of the Limesurvey.

![b3672d9ec10074d4de0fbd3e67ecd555.png](/resources/b3672d9ec10074d4de0fbd3e67ecd555.png)

They are 2 main ways to approach this, first is to use mysql on the kali linux directly and the second way is to use docker container which I will use docker container for this since its easier for me to clean up but will also take more time.

```
docker run --name limesurvey-mysql -e MYSQL_ROOT_PASSWORD=password -e MYSQL_DATABASE=limesurvey -e MYSQL_USER=limeuser -e MYSQL_PASSWORD=limepassword -p 3306:3306 -d mysql:latest
```
![ae551e173bd7025a9eaf4fcf4cc519a0.png](/resources/ae551e173bd7025a9eaf4fcf4cc519a0.png)

After mysql docker ready, I specify the database location, database user, database password and database name as already created with docker container.

![72790c0de193aa1f263310098971bc63.png](/resources/72790c0de193aa1f263310098971bc63.png)

Next is to populate the database, this will take a while.

![656983639b1fb473afca33a9763ba7d1.png](/resources/656983639b1fb473afca33a9763ba7d1.png)

Lastly, I will change the password of admin user and the installation process should finish in this step.

![fe5ebd80f4a582ea648907b1d9974f84.png](/resources/fe5ebd80f4a582ea648907b1d9974f84.png)

The Limesurvey installation complete so I will access to Administrator page and login with credential set in the previous step.

![4f677665ef1e82fb75f05ffea62626c3.png](/resources/4f677665ef1e82fb75f05ffea62626c3.png)

![9c2658593dd06c275d5e3e53b38a3bcd.png](/resources/9c2658593dd06c275d5e3e53b38a3bcd.png)

## Foothold on docker via Limesurvey plugin

Since I am now the admin of Limesurvey, I can import the plugin which embeded with PHP reverse shell payload which I will use the plugin sample from [Y1LD1R1M's GitHub repository](https://github.com/Y1LD1R1M-1337/Limesurvey-RCE)

Then I will use Pentest-monkey PHP reverse shell and create new zip and manual upload it as plugin.
```
cp /usr/share/webshells/php/php-reverse-shell.php .
zip shell.zip config.xml php-reverse-shell.php
```
![cd26f55621250cda8ae55d0ec3140dd8.png](/resources/cd26f55621250cda8ae55d0ec3140dd8.png)

To import the plugin, I will go the the "Plugins" settings with in the Configuration menu right here.

![e58dbef93cd7be45eb72bd68bb28a693.png](/resources/e58dbef93cd7be45eb72bd68bb28a693.png)

After visiting plugin manager page, I will upload it with this button.

![c001e275ecdf4e01fe7679907d9d7a24.png](/resources/c001e275ecdf4e01fe7679907d9d7a24.png)

There is a file upload limit here but our plugin is very small so it should be fine.

![08d68805f2de7d7b0aa7056c7ca369e0.png](/resources/08d68805f2de7d7b0aa7056c7ca369e0.png)

But after uploading the plugin, It could not be installed due to the compatibility of the plugin with Limesurvey.

![639466facb535fea95c8d54af8977722.png](/resources/639466facb535fea95c8d54af8977722.png)

This make me check the config file of this plugin again and I can see that I notice that this Limesurvey that was installed in this box is version 6 but in the config file on the plugin, only compatible with version 3,4 and 5.

![e1aad3c48c96ac41d4dd75d03a103d81.png](/resources/e1aad3c48c96ac41d4dd75d03a103d81.png)

![954cbe0a3e80668f2c0de7d7dede781a.png](/resources/954cbe0a3e80668f2c0de7d7dede781a.png)

So by adding this one simply line to make it compatible with Limesurvey version 6 then I should be able to upload and install the plugin without any problem.

![229ac3ae28f4abc7307cea999943e607.png](/resources/229ac3ae28f4abc7307cea999943e607.png)

There it is, I can now install the plugin and effective deploy my webshell.

![f096d627c1f082a1ef2b5ac514de833a.png](/resources/f096d627c1f082a1ef2b5ac514de833a.png)

Lastly, I setup my listener with penelope and trigger a webshell for reverse shell which successfully landed me a shell but look like this is a docker container so I need to find a way out.

```
curl http://forgotten.vl//survey/upload/plugins/Y1LD1R1M/php-reverse-shell.php
```
![7b4fb7edc9d1586ccd22180d296c6801.png](/resources/7b4fb7edc9d1586ccd22180d296c6801.png)

## Foothold on Host with Limesurvey password in env

After gaining access to the docker container, I use `env` command to display environment variable on this docker container which I found the password of limesurvey user inside this docker container which is a member of sudo group so basically, I have root privilege on the docker container now.

![b5b010e43ecb09c25698fe63df05ada0.png](/resources/b5b010e43ecb09c25698fe63df05ada0.png)

I also discover that I can use this credential to actually get the foothold on the host and loot user flag located on the home directory of this user. 

```
sshpass -p '5W5HN4K4GCXf9E' ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" limesvc@forgotten.vl
```
![3d4275f99ba37e8fa7c96b0859527159.png](/resources/3d4275f99ba37e8fa7c96b0859527159.png)

## Privilege Escalation via share directory between container and host

I try to find out if I can run sudo on the host since I already have password of "limesvc" user but look like I can not run any sudo with this user on host.

```
limesvc@forgotten:~$ sudo -l
[sudo] password for limesvc: 
Sorry, user limesvc may not run sudo on localhost.
```

However after keep exploring the host, I discover the limesurvey directory which was supposed to be inside the docker container.

![c5bdcec5f638c5f14cc18550a63d7496.png](/resources/c5bdcec5f638c5f14cc18550a63d7496.png)

All those files resembles all files in the webroot directory within the docker container which mean the `/opt/limesurvey` was mounted to `/var/www/html`. 

![b68e45b881d1123f5052a3bb71932a12.png](/resources/b68e45b881d1123f5052a3bb71932a12.png)

To confirm this, I create a file inside docker container and it is also appears on the host as well.

![6cba868186530dc5c010d13fff8a9cd0.png](/resources/6cba868186530dc5c010d13fff8a9cd0.png)

Knowing that I can abuse this to root the box, I stabilize my shell and check if I can really become root with sudo and sure enough, I can!

```
script -q /dev/null -c bash
sudo -l
```
![5f6b1c12476c6b7d1f19c3fe1a706e39.png](/resources/5f6b1c12476c6b7d1f19c3fe1a706e39.png)

Simply changing to root user on docker container and now I am ready.

```
sudo su
```
![e80f2276e7ab56394dfcce66b9fcedd0.png](/resources/e80f2276e7ab56394dfcce66b9fcedd0.png)

Inside docker container, I copy bash binary to share directory and give SUID to this binary as root which now I can become root on the host with this SUID bash binary.

```
cp /bin/bash .
chmod u+s bash
```
![5fe384f7c4edec643b379107d4602015.png](/resources/5fe384f7c4edec643b379107d4602015.png)

Now I run the SUID bash to become root and loot root flag to root the box :D

```
./bash -p
```
![2b813055b7fe724a2539071fd0508e52.png](/resources/2b813055b7fe724a2539071fd0508e52.png)

![d553f6bac890a5a7c23044b3297c19f0.png](/resources/d553f6bac890a5a7c23044b3297c19f0.png)

https://labs.hackthebox.com/achievement/machine/1438364/733
***