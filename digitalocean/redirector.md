# Redirecting Traffic


### SSH Forwarding

SSH can be used to forward traffic multiple ways.  This tutorial will show it being used Dynamically and Remotely.

To forward remotely you will use -R, the syntax is `ssh root@IP -R 80:127.0.0.1:8080`   
This will open a remote listening port, a port on the machine you are ssh'ing to.   
It will forward any traffic that is sent to that port to your local machine, a port on the machine you used to ssh.   
In the above senario the port 80 will be listening on all interfaces on the machine and forward that traffic to the localhost port 8080.   

To forward Dynamically you will use -D, the syntax is `ssh root@IP -D 127.0.0.1:9050`   
This will open a listener port on your local machine, the machine you used to ssh.   
Any traffic that is sent to this port will then be forwarded to the remote machine to be sent out by that machine.
This is important because it utilizes a socks4 proxy that will forward any type of traffic.  It will even work with TLS.   

### Proxychains

Proxychains is a tool that will allow you to easily pass commands through a proxy.  The config file for proxychains is located at `/etc/proxychains.conf`.   
In the config file you just need to set the type of proxy, the ip of the proxy and the port of the proxy.  
```vim
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5  127.0.0.1 9050
```

The syntax for using proxychains is 
```bash
proxychains "command"
```   

### Tsocks

Tsocks is another tool to proxy commands from other tools.  The benefit of tsocks is that it will force UDP DNS requests to TCP allowing the proxy to handle web requests.  The config file for tsocks is at `/etc/tsocks.conf`   
In the config file you will need to modify server, server_type, and server_port fields.   
```vim
server = 127.0.0.1
# Server type defaults to 4 so we need to specify it as 5 for this one
server_type = 5
# The port defaults to 1080 but I've stated it here for clarity 
server_port = 9050
```   
The syntax for using proxychains is   
 ```bash
 tsocks "command"
```


### Redirecting with SSH

In the following senario we will combine the above examples to hit a webserver.   
We will simultaneously create a dynamic and remote forwarding tunnel to complete this with the following command.   
```
ssh root@IP -R 80:127.0.0.1:8080 -D 127.0.0.1:9050
```   
We will then use Proxychains to grab the webpage through the tunnel.   
```
proxychains curl 127.0.0.1:80
```   
This will push commands through the Dynamic tunnel onto the sshed box where it will hit the remote tunnel and come back to ssh'ing box on 8080 where it will hit the open webserver.   

![alt text](https://github.com/vipertooth/Notes/blob/master/digitalocean/tunneling_proxychains.png)
