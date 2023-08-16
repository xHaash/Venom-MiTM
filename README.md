# Venom-Sniffer
Venom is an ARP-Poisoner that sniffs TLS requests to take advantage of SNI Leak and display all targets DNS traffic even if it is encrypted. Venom can target a specific device or the entire network by choosing between the 2 attack modes => Sniper / Nuke respectively. <br/>

Venom aims to be a future complete tool capable of performing many different attacks and scans. As this is the first release, It only focuses on the SNI leak but I will be adding more and more options / attacks to the tool as the time goes by. Feel free to participate and help if you wish ! :)

# Screenshots

<img src= "/IMGs/ASCII.png">
<img src= "/IMGs/arpscan.png">
<img src= "/IMGs/script_end.png">
<img src= "/IMGs/outputs.png">

# Installation

1. Install Python3 on your Device

2. ```pip3 install -r requirements.txt```

3. Linux / MacOS: ```sudo python3 main.py --help```<br/>
   Windows: ```py main.py --help```

# Instructions

Usage: ```sudo python3 main.py [-n] [-s] [-ss SCAN_SPEED] [-ml] [-ir IP_RANGE]```

Ex. of Sniper Usage: ```sudo python3 main.py -s -ml``` 
*(Sniping mode selected + Mac Lookup when scanning to give more informations about the targets)*

Ex. of Nuke Usage: ```sudo python3 main.py -n -ss 3 -ml```
*(Nuke mode selected + Reducing ARP scan speed mode to be more precise + Mac Lookup when scanning)*

***Only Sniper or Nuke arg is required everything else is optional or has a default value.***

**Arguments List:**

- ```-h / --help```          => Shows / Explain all arguments utility

- ```-s / --sniper```        => Sniper attack mode

- ```-n / --nuke```          => Nuke attack mode

- ```-ss / --scan_speed```   => ARP Scan Speed: 1 - 5 (Default: 4)

- ```-ml / --mac_lookup```   => Mac Lookup when ARP Scanning

- ```-ir / --ip_range```     => Targeted IP range (Default: 192.168.1.1/24)

# Features (14/08/2022)

- ARP Scanning

- Scanning Speed Mode => 1(slowest) - 5(fastest).

- ARP Poisoning / Restoring

- MAC address Look-up

- Sniping Mode: Poison/Sniff only a specific device

- Nuke Mode: Poison/Sniff all available devices on the network

- Multiple clean Output files named by the IP of the target

# Coming Next

- Classic DNS Poisoning 

- Simple profiling

- Colors for the CLI Outputs

- Target Scanning for exploits

- All basics MiTM attacks

- Parsed Output file for each target [DONE]

# Legal
 This software is designed to perform network security testing.<br/>
 The author is not responsible for any illegal use of these programs.<br/>
 I am not accountable for anything you get into.<br/>
 I am not accountable for any of your actions.<br/>
 This is 100% educational, please do not misuse this tool.
