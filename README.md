# Venom-MiTM
Venom is a multi-tool that can set up a MiTM and sniffs TLS requests to take advantage of SNI Leak and display all targets DNS traffic even if it is encrypted. 
As the SNI sniffing attack is currently the main one, it is not the only one. Venom can also be used as a: 

- MAC-Spoofer

- ARP Network Scanner (Host discovery)

- ARP-Poisoner

Venom can target a specific device or the entire network by choosing between the 2 attack modes => Sniper / Nuke respectively. (For SNI Sniffing and ARP-Poisoning) <br/>

This aims to be a future multi-tool capable of performing many different attacks and scans. As this is the first release, It mainly focuses on the SNI leak but I will be adding more and more options / attacks / scans to Venom as the time goes by. Feel free to participate and help if you wish ! :)

# Screenshots

<img src= "/IMGs/ASCII.png">
<img src= "/IMGs/arpscan.png">
<img src= "/IMGs/script_end.png">
<img src= "/IMGs/outputs.png">

# Installation

1. Install Python3 on your Device

2. ```pip3 install -r requirements.txt```

3. Enable IPv4 packet forwarding: ```sysctl -w net.ipv4.ip_forward=1```

4. Linux / MacOS: ```sudo python3 main.py --help```<br/>

# Instructions

Usage: ```sudo main.py [-h] [-n] [-s] [-ss SCAN_SPEED] [-ml] [-ir IP_RANGE] [-sni | -mac | -sc] [-iface IFACE]```

Ex. SNI Leak Sniffing (SNIPER MODE): ```sudo python3 main.py -sni --sniper -ml``` <br/>
*(Sniping mode selected + Mac Lookup when scanning for more details about the targets)*

Ex. SNI Leak Sniffing (NUKE MODE): ```sudo python3 main.py -sni --nuke -ss 3 -ml```<br/>
*(Nuke mode selected + Reducing ARP scan speed mode to be more precise + Mac Lookup when scanning)*

Ex. MAC Spoofing: ```sudo python3 main.py -mac -iface eth0```<br/>
*(MAC Spoofing mode selected + specifying wich iface to use)*

Ex. ARP Scanner: ```sudo python3 main.py -sc -ml```<br/>
*(Scanner mode selected + Mac Lookup)*

**Arguments List:**

- ```-h / --help```          => Shows / Explain all arguments utility

- ```-sni / --sni```         => SNI Leak Sniffing Attack (MiTM)

- ```-mac / --mac_spoofer``` => MAC Spoofing Attack

- ```-sc / --scan```         => ARP Scanning Only

- ```-s / --sniper```        => Sniper ARP Poisoning mode (Only with -sni)

- ```-n / --nuke```          => Nuke ARP Poisoning mode (Only with -sni)

- ```-ss / --scan_speed```   => ARP Scan Speed: 1 - 5 (Default: 4)

- ```-ml / --mac_lookup```   => Mac Lookup when ARP Scanning

- ```-ir / --ip_range```     => Targeted IP range (Default: 192.168.1.1/24)

- ```-iface / --iface```     => Iface used for Mac Spoofing (Default: eth0)

# Features (14/09/2023)

- ARP Scanning

- Scanning Speed Mode => 1(slowest) - 5(fastest).

- MiTM by ARP Poisoning

- MAC Spoofing

- MAC address Look-up

- Sniping Mode: Poison/Sniff only a specific device

- Nuke Mode: Poison/Sniff all available devices on the network

- Multiple clean Output files named by the IP of the target

# Coming Next

- Simple profiling

- Colors for the CLI Outputs

- Target Scanning for exploits

- Display Target Hostname [✅]

- MAC Spoofing [✅]

- Parsed Output file for each target [✅]

# Legal
 This software is designed to perform network security testing.<br/>
 The author is not responsible for any illegal use of these programs.<br/>
 I am not accountable for anything you get into.<br/>
 I am not accountable for any of your actions.<br/>
 This is 100% educational, please do not misuse this tool.
