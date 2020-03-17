# Notes for GAWN

## Wifi Data Collection and Analysis

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

Set Regulatory Domain Settings(to use ranges outside legal in us)   
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

#### Airodmup-ng

Scan all channels   
`airodump-ng wlan0mon`

```bash
CH  6 ][ Elapsed: 18 s ][ 2020-03-16 20:58

 BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID

 14:59:C0:XX:XX:XX  -16        5        0    0   4  195  WPA2 CCMP   PSK  NETGEAR73
 16:59:C0:XX:XX:XX  -16        5        0    0   4  195  WPA2 CCMP   PSK  NETGEAR-Guest
```

Capture Handshake   
`airodump-ng -c 4 -d 16:59:C0:XX:XX:XX -w savefile wlan0mon`   

```bash
 CH  4 ][ Elapsed: 18 s ][ 2020-03-16 21:08 ][ WPA handshake: 16:59:C0:95:DB:06

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID

 16:59:C0:XX:XX:XX  -19  48       88        5    0   4  195  WPA2 CCMP   PSK  NETGEAR-Guest
```

Crack WPA2   
`aircrack-ng -w /usr/share/wordlists/rockyou.txt savefile.cap`   

```bash

                                 Aircrack-ng 1.2

      [00:00:00] 16/7120712 keys tested (1128.27 k/s)

      Time left: 1 hour, 45 minutes, 12 seconds                  0.00%

                           KEY FOUND! [ XXXXXXXX ]


      Master Key     : FD 3F 34 FD 32 6F 4D 16 DB 9B DA 5B B6 47 58 63
                       94 48 19 58 A5 42 E5 85 4F 3D CB BC 11 79 C9 74

      Transient Key  : 83 0F D3 B8 20 0C 22 AD 61 2D CD 1D 9E 40 05 AF
                       D6 EC CE 53 E7 0E D0 5D DA 23 46 BF 56 C0 0A 10
                       A3 47 7E 7B 32 9D 0D 61 62 1F D2 82 76 9F 55 29
                       F9 E1 E2 7C 59 85 4F C8 E5 4D F1 B9 8C 9D 00 A6

      EAPOL HMAC     : E7 2C 3E D2 EC F6 5E 1B E0 6C 68 B5 92 74 6C 0C
```


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
