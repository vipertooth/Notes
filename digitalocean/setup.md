# Server Setup

First you need to create an account at [Digital Ocean](https://www.digitalocean.com/ "Digital Ocean's Homepage")   

Then once you have logged into Digital Ocean click + New Project in top Left corner of the screen.

![alt text](https://github.com/vipertooth/Notes/blob/master/digitalocean/create_project.png)   


You will then use the following settings in Digital Ocean project creation. Note that you will want to use Yubikey SSH for security.  Creating a regular ssh account will suffice for learning purposes. 

![alt text](https://github.com/vipertooth/Notes/blob/master/digitalocean/setup_project.png)

To add your SSH key you will copy and paste it into the text box that is opened when you click on New SSH Key.

![alt text](https://github.com/vipertooth/Notes/blob/master/digitalocean/ssh_key_creation_or_input.png)

You can also Enable backups for $1.00 a month if you do not want to worry about resetting this system up.

![alt text](https://github.com/vipertooth/Notes/blob/master/digitalocean/enable_backups.png)

Once your server is up and running you will get a email from Digital Ocean. You will then click on your newly created project and click on the name of the ubuntu server that was created this will bring you to a new screen where you will click on Access to get you public ip address to SSH in.

![alt text](https://github.com/vipertooth/Notes/blob/master/digitalocean/get_ip_address.png)

You should now be able to SSH into you server with a command like.    
```
ssh root@public_ip -i /ssh_key.pub
```

Now that you have access to a terminal on your Digital Ocean server, the first thing you will want to do is secure the box by doing the following.   
Resetting root password with 
```
passwd
```
Updating the box   
```
apt-get update
apt-get install tmux tmuxinator conntrack iptables-persistent iptstate
```
Configuation Changes   
Allow Remote Forwarding by modifying `/etc/ssh/sshd_config`   
```
GatewayPorts yes
```

## Setting up Iptables Rules   
```
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT ! -i lo --source 127.0.0/8 -j DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0/8 -j DROP
iptables -A OUTPUT -p udp -s PUBLIC_IP --dport 123 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -d PUBLIC_IP --sport 123 -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -s PUBLIC_IP --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -d PUBLIC_IP --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -s PUBLIC_IP --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -d PUBLIC_IP --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -s PUBLIC_IP --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -d PUBLIC_IP --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -I INPUT 5 -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
iptables -I INPUT 6 -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 15 -j DROP
iptables -I INPUT 7 -p tcp -d PUBLIC_IP --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -I OUTPUT 3 -p tcp -s PUBLIC_IP --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -A INPUT -j LOG --log-prefix "DROP INPUT IPv4: "
iptables -A OUTPUT -j LOG --log-prefix "DROP OUTPUT IPv4: "
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP
ip6tables -A INPUT -j LOG --log-prefix "DROP INPUT IPv6: "
ip6tables -A OUTPUT -j LOG --log-prefix "DROP OUTPUT IPv6: "
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
```

These new rules can be viewed with.   
```
iptables -L -n -v --line-numbers
```

The Log of all dropped requests can be viewed at`/var/log/syslog` using the tail command.   
```
tail -f /var/log/syslog
```

If any changes need to be made to Iptables it can be done using the iptables command or from the persistant rules file.   
```
vim /etc/iptables/rules.v4
vim /etc/iptables/rules.v6
```

Rules changed this way will need to be restored to the active overide the active rules with the following command.   
```
iptables-restore < /etc/iptables/rules.v4
ip6tables-restore < /etc/iptables/rules.v6
```
