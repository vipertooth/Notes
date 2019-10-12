```
nmap -A 10.10.10.0 -oN nmap/normalports.X
nmap -p- -A 10.10.10.0 -oN nmap/allports.X
nmap -p- -sV --script=vuln 10.10.10.0 -oN nmap/vuln.X
nmap -p- -sV --script=exploit 10.10.10.0 -oN nmap/exploit.X
```
