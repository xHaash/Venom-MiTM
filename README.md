# Venom-Sniffer
Venom is an ARP-Poisoner that sniffs TLS requests to take advantage of SNI Leak and display all targets DNS traffic even if it is encrypted. Venom can target a specific device or the entire network by choosing between the 2 attack modes => Sniper / Nuke respectively. <br/>

Venom aims to be a future complete tool capable of performing many different attacks and scans. As this is the first release, It only focuses on the SNI leak but I will be adding more and more options / attacks to the tool as the time goes by. Feel free to participate and help if you wish ! :)

For now, this script is made to show the information leak that remains in the TLS protocole and more specifically in the SNI extension.

# Screenshots


# Features (14/08/2022)

- Scanning Speed Mode => 1(slowest) - 5(fastest). Default value is 4 (better to let it like this as it is pretty precise and fast). You can change this value at l.16 in ```main.py``` if you feel the need to.

- ARP Poisoning / Restoring

- MAC address Look-up

- Sniping Mode: Poison/Sniff only a specific device

- Nuke Mode: Poison/Sniff all available devices

- Parsed Outputs in ```sni_output.txt```

# Installation

1. Install Python3 on your Device

2. ```pip3 install -r requirements.txt```

3. Linux / MacOS: ```sudo python3 main.py```<br/>
   Windows: ```py main.py```

# Coming Next

1. Classic DNS Poisoning 

2. Simple profiling

3. Colors for the CLI Outputs

4. Target Scanning for exploits

5. All basics MiTM attacks

6. Multiple Output files for each target

# Legal
 This software is designed to perform network security testing.<br/>
 The author is not responsible for any illegal use of these programs.<br/>
 I am not accountable for anything you get into.<br/>
 I am not accountable for any of your actions.<br/>
 This is 100% educational, please do not misuse this tool.
