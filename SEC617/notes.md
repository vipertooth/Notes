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
