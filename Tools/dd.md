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

