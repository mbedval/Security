
### 8.1 SNIFFING OVERVIEW

#### What is SNIFFING ?
- Sniffing is the act of capturing (recording ) traffic flowing through a network
- It is the network equivalent of wiretapping
- Sniffing allows you to identification hosts, services, devices types, protocols, subnets, IP addresses, etc on the network.
- A good sniffer can capture nearly any protocol, even ones it does not recognize (for example Wireshark supports thousands of protocol)
- Encrypted packets can also be sniffed
	- You won't be able to read their contents unless you can decrypt them
	- Howevers you can still read:
		- Source and destination addresses and ports
		- SSID, authentication handshakes and initialization vectors for wireless networks
		- VPN handshakes information
- Two condition must be met for sniffing to be effective.
	- Sniffer interface must be in promiscuous mode
	- Traffic to be captured must be forwarded to, pass by the sniffers interface
		- You need to be on a shared segment such as a hub or Wi-Fi Channel
		- You can spoof the switch into copying frames out your switchports

#### HOW SNIFFING WORKS
- The sniffing apps puts the device network interface in promiscuous mode
- The app starts capturing all traffic that reaches the interface, regardless of who it's destined for
- You can stop the capture at any time and
	- Filter the results based on protocol, port IP, Address or payload key word
	- Perform some analysis on the traffic.
	- Recreates entire TCP conversations
	- Recreate certain file types
	- Save the captured traffic in a .pcap' file for later analysis
	- Note: Windows needs the WinPcap driver to be able to put a NIC in promiscuous mode.

#### Network SNIFFING Threats
- Many organization do not put any restrictions on unused switch ports. Someone can plug in any device using an Ethernet cable
- Sniffing allows the attacker to:
	- Identify potential targets
		- hostnames, device types, IP Addresses, MAC addresses, Port, Protocols, services
	- capture credentials
	- Read private messages
	- Eavedrop on voice and video calls
	- recreate files
	- and more
#### Active and Passive SNIFFING
- Passive sniffing involves collecting packets as they pass by your network interface.
	- You don't transmit anything
	- You just promiscuously receive
- Active sniffing involves sending out multiple network probes to achieve with followings objectives
	- MAC flooding
	- DNS poisoning
	- ARP poisoning
	- DHCP attacks
	- Switch port stealing
	- Spoofing attacks
-
#### Additional Active SNOOFING Methods
- Port Spanning
	- Switch configuration that makes the switch send a copy of all frames from other ports to specific port
	- AKA scan port or port mirroing
	- Not all switches have the ability to do this
	- Modern switches sometimes don't allow span ports to send data -you can only listen 
- Network tap
	- Purpose-built hardware devices that sits in a network segment between two appliances (router, switch or firewall)
	- Allows you to capture all traffic passing through it.
	- Note: There are special devices which can be plugged to ethernet switch so that all traffic transfer though it.
#### SNIFFING Scenario
There was addition email sent without consent
Possible scene: 
1. If http was used instead of HTTPS , an attacker might have sniffed through network and sniffed credentials and logged webmail with his credentials
2. If outlook was used and he sent in clear text his SMTP Login could have be compromised
3. It is also possible that the additional emails had a spoofed source addresses. and victim received a looking mail from email which look like but is not sent from victims id.

#### LAWFUL Interception
- Legal interception of data communication between end-points
- Some jurisdictions like the US, require a court order
- For surveillance on traditional phone, VoIP, data , multi-service networks
- PRISM - System used by NSA to collect internet communications from various U.S internet companies

#### WIRETAPPING
Process of third-party monitoring of phone/internet conversations
Attackers connects a listening device to a circuit between two hosts/phones often covert.
Attack can monitor, access, intercept and record information
Type of Wiretapping:
	Active Wiretapping: Monitoring / reads and injects something into communications / traffic
	Passive Wiretapping : Only monitors / Reads / Records data

#### EAVEDROPPING
- Secretly listening to private conversations or communications
- Capture speech or telephone conversations
- Plant a sniffer on a network
- Secretly place a camera or microphone in a room
- Capture VoIP packets off the network and replay them
- Use a phone to record someone entering a password or PIN from across a room.
- Use a Wi-Fi pineapple or other Man-In-the-Middle device to capture wireless traffic.
- Use an IMSI-catcher man-in-the-middle (MITM) devices to intercept cell phone calls

#### Protocol Vulnerabilities
- Many protocols are transmitted in clear text (unencrypted)
- Vulnerabilities includes:
	- Disclosures of usernames, password, host names, IP addresses, sensitive daa
	- Keystrokes that provides user names / passwords.
	- Reconstructing / capturing files including documents, images, voice, video.
- TCP/IP Core Protocols Vulnerable to SNIFFING
	- ARP 
	- IGMP 
	- ICMP 
	- TCP Shows sequence numbers (usable in session hijacking)
	- TCP and UDP show open ports
	- IP (both versions) shows source and destinations addresses
	-  Note : All 6 of the core TCP/ IP protocols are clear text and vulnerable to sniffing.
	- 
#### VULNERABLE Layer 7 Protocols (TCP)
FTP

| Clear Version       | TCP Port | Encrypted Replacement                  | TCP Port            |
| ------------------- | -------- | -------------------------------------- | ------------------- |
| FTP                 | 21       | SFTP (part of SSH),  FTPS              | 22, 990             |
| Telnet              | 23       | SSH                                    | 22                  |
| SMTP                | 25       | SMTP / SSL or TLS                      | 587, 465 (previous) |
| DNS (zone transfer) | 53       | --                                     | --                  |
| HTTP                | 80       | HTTPS, SHTTP (not popular or obsolete) | 443                 |
| POP3                | 110      | POP/SSL or TLS                         | 995                 |
| NNTP                | 119      | NNTP / SSL or TLS                      | 563, 443            |
| SMBv1               | 139      | SMBv3                                  | 445                 |
| IMAP4               | 143      | IMAP / SSL or TLS                      | 993                 |
| LDAP                | 389      | LDAPS                                  | 683                 |
| SQL                 | 1433     | SQL / SSL or TLS                       | 1433                |

#### Vulnerable layer 7 Protocols (UDP)

| Clear Version                  | UDP Port                                     | Encrypted Replacement                                           | UDP Port |
| ------------------------------ | -------------------------------------------- | --------------------------------------------------------------- | -------- |
| SFTP                           | 69                                           | --                                                              | --       |
| SNMP v1 -2c                    | 161, 162                                     | SNMP v3                                                         | 161, 162 |
| NTP                            | 123                                          | (Best practises recommend adding authentication and encryption) | --       |
| DNS                            | 53                                           | DNSSEC recommended to add integrity to records                  | --       |
| IKE                            | 500                                          | --                                                              | --       |
| SIP                            | 5060, 200 Cisco Call manager                 | SIP-TLS                                                         | 5061     |
| RTSP (SIP competitor for CCTV) |                                              | --                                                              | --       |
| RTP                            | 5004, 9000, 6970 - 6999, IETF, 16384 - 32767 | STRP                                                            | 5004+    |
| RTCP                           |                                              | SRTCP                                                           | 5005     |
### 8.2 SNIFFING TOOLS

#### WHAT IS SNIFFER >
- SNIFFER is also known as Protocol / Packet Analyzer
- Records all network traffic that reaches its interface
- Cab be software or hardware based
- Depending on the product, can capture different layers 2 protocols on various media types
- Typically requires a driver to place the interface in promiscuous mode. Allows the sniffer to intake frames even if they are not destined for the sniffing machines.

#### 8.2.1 SOFTWARE PROTOCOL ANALYZER
##### 8.2.1.1 : Wireshark
- The most popular open source software-based sniffer
- Open source. Previously known as Etherreal
- Runs on both Nix and Windows environment
- Captures live traffic from any interface, on different types of media
	- Any protocol including raw packets that are unidentified
	- Follow and recreates entire TCP/HTTP Streams
	- Recreates captured files from raw packet hex data
- Has extensive filtering and search capabilities, and packets analysis features
- Can save, export and import packet captures (pcap files)
- With the correct driver, can capture radio and management headers from Wi-Fi
- Common available filters 
	- ! (arp or ICMP or DNS)
		- Filters out the noise from ARP, DNS and ICMP requests
		- ! is not logic will clears the information not in interest of inspections
	- tcp.port == 23
		- Look for the protocols ports using tcp.port
	- tcp.port == 21 || tcp.port == 20 
		- looking for TCP 21 or 20 which are used by FTP
	- id.addr == 10.0.0.165
		- Looks for specific ip address
	- id.addr == 192.168.1.99 && tcp.port == 23
		- Display telnet packets for a particular IP
	- IP.src == 192.168.1.99 && id.dst == 10.0.0.156
		- Display all packets exchanged from IP source to destination IP
	- http.request 
		- Display HTTP get Requests
	- tcp.port == 21
		- Display FTP packets (unenrypted file transfers)
	- tcp contains string
		- Display TCP Segments that contain the word string
	- tcp.flags == 0x16
		- Filters TCP requests with ACK flag set.

##### 8.2.1.2 TCPDUMP and WINDUMP
TCPDump is command line tool for sniffing traffic
Similar to wireshark but linux command line only
	It captures and displays traffic
	Sniffing passwords
	Intercepting any clear text transmissions
Syntax 
	tcpdump flag(s) interface
	`tcpdump -i eth1` puts the specified interface in listening mode
#WinDump is a windows version similar to tcpdum

> PCAP Analysis : You can analysis from PCAP files generated from wireshark, tcpdump, windump, etherpeek, etc, to analysis tool

##### 8.2.1.3 Example tools includes 
#TCPTrace, #PRTGNetworkMonitor #Wireshark #NetworkMiner





#### 8.2.2 HARDWARE PROTOCOL ANALYZER
- Equipment that captures signals to monitor network usage
- Does not alter traffic in cable segment
- Identifies malicious network traffic generated via hacking network software 
- Grabs data packets
- Decodes and analyzes packet content based on predetermined rules
- Able to view individual bytes of data in each packet passing through cable.
- Examples
	- Keysight N2X N5540A
	- Keysight E2960B
	- RADCOM PrismLite Protocol Analyzer
	- RADCOM Prism UltraLite Protocol Analyzer
	- FLUKE Networks OptiView XG Network Analyzer
	- FLUKE Networks OneTouch AT Network Assistant 


#### 8.2.3 Additional Sniffing Tools
- Solarwinds Deep packet inspection and anlysis Tool
- ManageEngine NetFlow Analyzer
- Paessler Packet Capture Tool
- Omnipeek Network Protocol Analyzer
- tshark
- NetworkMiner
- Fiddler
- Capsa

#### 8.2.4 SNIFFING TOOLS for Mobile Devices
- Wi.cap network sniffer pro
- FaceNiff
- Sniffer
- zAnti
- cSploit
- Packet Capture
- Debug Proxy
- WiFinspect
- tPacketCapture
- Android tcpDump
> Many mobile sniffer apps require root access (you will have to root or jailbreak your device)



###  8.3 ARP and MAC attacks


#### 8.3.1 MAC ADDRESS
- Physical address of an network interface card (NIC)
- AKA burned-in address
	- Set by the factory - cannot be changed in the NIC firmware
	- Some NIC drivers allow the OS to temporarily override it
- Used to identify a node at layer 2  on ethernet and wi-fi segments
	- An IP Packets must also include the source and destination MAC addresses
- MAC Spoofing
	- Deliberately change the MAC address of your NIC
	- Many OSes can use the NIC driver to temporarily overrides the MAC addresses
	- Used to 
		- Impersonate another machine
		- Bypass MAC-based access control restrictions
		- Spoof (fool) a switch
		- Example: Window Network property --> Advanced --> Network Address -- "CUSTOM VALUE" can be used to configure spoofing
- MAC Flooding
	- A common attack on a network switch 
	- The goal is to force a switch to behave like a hub
		- Forward all frames out all ports
		- The attacker can sniff any traffic
	- Intentionally overwhelming a switch with phony MAC addresses
	- Specially crafted Ethernet framing are rapidly sent into a switch port
	- Typically the frames have random spoofed MAC addresses
	- The switch will enter the spoofed MAC addresses into its MAC table
	- The MAC table fills and cannot take in any new MAC addresses
	- Vulnerable switches will then change into hub mode
		- They repeat any incoming frame out all ports
	- This allows the attacker to sniff from all nodes on the switch
	- Most Modern switches are not vulnerable
	- Objective to over load MAC Table with fake/spoofed MAC address
#### ADDRESS RESOLUTION PROTOCOL (ARP)
- A Core TCP/IP Protocol
- Maps MAC addresses to IP Addresses
	- In Ethernet and wifi , you cannot transmit a packet until the layer 2 header contains the source and destination MAC Addresses
- ARP Processes
	- Sender transmits an ARP request
	- Layer2 broardcast (FFFFFFFFFFFF)
	- Ask which MAC "OWNS" the specified IP Address
- All nodes on the same segment receive and process the request
- The owner sends an ARP reply
	- Layer 2 unicast
	- Affirms its own the IP Address
- The sender updates its ARP cache, mapping mac to IP
- Mapping must be refreshed periodically.

ARP SPOOFING
- Used for sniffing someone else's traffic
- Transmit spoofed ARP frames into the switch
	- Pretend to have the same MAC as the node(s) you want to eavesdrop on
	- The IP address is irrelevant, because the switch only deals in MAC addresses
- The switch will add the spoofed MAC to its table, associating it with your port. The Switch will actually have the same MAC associated with two switchports
- Any traffic destined for the other node will also be forwarded out your post
> Attacker can use the target's MAC address to fool the switch

#### ARP Poisoning
- The deliberate effort to corrupt another device's ARP Cache
- Send fake ARP replies that assoicate attacker's MAC with target's IP
- Used for man-in-the-middle attacks
	- Corrupt both sides of a conversation (client -server / sender -gateway)
	- Each node thinks the other has your MAC address
	- The two sides with unknowingly relay their conversation through you
> Attacker can use own MAC Address, but associate it with the target's IP Address, to fool other devices

### 8.4 NAME Resolution Poisoning

#### WINDOWS NAME RESOLUTION PROCESS
- Check if the destination is self
- Check if the name is currently in the DNS resolver cache
- Check if the name is in the `%systemroot%\system32\drivers\etc\hosts` file
- Query the DNS server
- Send an LLMNR multicast to 224.0.0.252 (IPv6 FF02: 1:3) UDP port 5355
- Send a NetBIOS name query broadcast to 255.255.255.255 UDP port 137

#### DNS POISONING
Most DNS servers allow dynamic updates
Attackers updates a DNS server with fake A record
	Destination name is the same
	IP address has been changed to the attackers IP
Server things update is legitimate
When Clients perform an A lookup, they are given the wrong IP Address
Can be performed against both internet and Intranet DNS servers

#### DNS CACHE POISONING
- False DNS records are inserted into a DNS server's cache
- The records are then given to clients and other DNS servers
- Most DNS servers query other servers to resolve host names
- One false record can propagate to many DNS servers and clients
- Digital Signatures and DNSSEC can help and should be implemented
	- In DNSSEC, a digital signature accompanies each DNS record to prove its authenticity and integrity
	- Reduce the threat of DNS positioning, spoofing and similar types of attacks
	- Clients that cannot utilize DNSSEC will ignore the signatures files
 - Example:
 -  Attacker inject fake DNS entry, due to which request for real website is routed to fake website instead of real server
- DNS Poisoning Tools
	- Ettercap
	- Bettercap
	- dnsspoof
- DEFEND against DNS spoofing
	- Test your DNS server for poisoning vulnerabilities at
		- www.dns-oarc.net/oarc/services/dnsentryopy
	- keep DNS servers patched
	- Configure clients to use your internal DNS server
		- as opposed to google - you can reduce the risk of DNS MITM
	- Hard-code DNS A records where practical (especially server A records)
	- Disallow anonymous updates to DNS
		- Client updates
		- Incoming zone transfers
	- Configure local DNS server against cache pollution
	- Implement IDS to watch for inappropriate update sources
	- Implement DNSSec

#### NETBIOS NAME RESOLUTION (NBNS)
- Pre-Windows 2000 clients and servers
- Name resolution was performed by querying Microsoft’s NetBIOS name
	- server WINS (aka NetBIOS over TCP Name Server)
- NetBIOS name resolution order (configurable)
	- Check local NetBIOS resolver cache (`nbtstat -c`)
	- Query WINS server (UDP 139)
	- Check local LMHOSTS file
	- Send NetBIOS broadcast message (UDP 137)
	- Check DNS resolver cache
	- Query DNS server
- Link-Local Multicast Name Resolution (LLMNR) replaced NetBIOS
	- Uses multicasting instead of broadcasting
	- Supports IPv4 and IPv6
	 
#### LLMNR / NBT-NS POISONING COUNTERMEASURES
- Disable LLMNR / NetBIOS name queries
- Require all client to use DNS
- Secure DNS against spoofing


### 8.5 Other Layers 2 Attacks
#### DHCP STARTVATION ATTACK
- A flood of fake DHCP discover messages with spoofed MAC addresses
- The DHCP server makes an offer to each of the fake clients
- All available IP addresses quickly become reserved for "potential" DHCP clients
- DHCP starvation is often accompanied by a rogue DHCP server and MITM attack

#### DHCP STARVATION TOOLs and MITIGATION
- Attack Tool Examples:
	- Yersenia
	- DHCPStarv
	- A variety of GitHub tools
- Mitigation
	- Switchport security (restricting the port to only allow one MAC address) may not help 
		- switches monitor nodes on their ports by examining source MAC addresses
	- The DHCP protocol does not use source MAC addresses to identify clients
		- it uses the DHCP Discover CHADDR field in the payload
	- You can cocnfigure DHCP snooping on the switch
		- Will block rogue DHCP servers
		- The verify mac-addresses parameter will also only allow client requests whose payload matches the actual source MAC in the frame
		- `ip dhcp snooping verify mac-address`

#### SPANNING-TREE PROTOCOL (STP)
- Switching loops are causd by uncontrolled redundant links
- Switching loops will almost instantly bring the networks segments to a standstill 
	- Links will be flooded with endlessly looping and repeating frames
	- The switch CPU utilization will shoot up to near 100%
	- The switch MAC table will become unstable by constant rapid changes
- Spanning-tree protocol (STP) eliminates switching loops in a switched network 
- Switches us it to identify redundant links
- The switches agree upon one switch becoming the primary point of reference (root bridge) for the entire network
- All redundant links to the root bridge are put in a blocked state to break any loops
- If a primary links goes down, then the redundant link will assume its place and start forwarding traffic.

#### STP ATTACKS
- The attacker can send spoofed root bridge message (BPDUs )to a switch, advertising a better link to the root bridge
- The switch will redirect traffic from its normal path to the attacker instead
- The attacker can then sniff the incoming traffic
- The attacker can also choose to discard the traffic or redirect it back into the network

#### STP ATTACK TOOLS and MITIGATIONS
- Tools
	- Scapy
	- Yersina
	- Various Github Projects
- Mitigation
	- Enable Root Guard on the switchports
	- `spanning-tree guard root`


#### VIRTUAL LAN (VLAN)
- A Logical grouping of switch ports
- Used to segregate end devices and their traffic based on various business criteria:
	- Location
	- Device type
	- Security Level
- Each VLAN becomes its own broadcast domain
	- Traffic cannot not leave that VLAN unless routed by a router / Layer 3 switch
	- Device can only communicate with other 
	- Generally, a switch access port ( that an end device is plugged into) can only belong to one VLAN at any one time.
- VLANs can extend across any number of switches on an ethernet or Wi-Fi network

#### VLAN HOPPING
- The illegal movement of traffic from one VLAN to another
- Traffic jumps over the VLAN "Barricade" and end up in another VLAN

#### COMMON VLAN HOPPING TECHNIQUES
- MAC flood a vulnerable switch 
	- When this occurs, the switch defaults to operating as a hub
	- Repeats all frame out all ports
	- VLANs become meaningless
	- This "fail open" method ensure the network can continue to operate, but it is security risk.
- Configure an attacker's NIC as a "trunk port"
	- Encourage the switch to negotiate a trunk link
	- All Traffic is then sent across that link to the attacker
-  Double-tagging
	- A frame header is specially crafted with two VLAN tags, one embedded inside another.
	- The outside tag must belong to the native (default) VLAN of the switch
	- The switch accepts the frame, discards the outer tag, reads the second tag, and then forwards the frame to that target VLAN

#### VLAN HOPPING COUNTERMEASURES 
- Patch / update switch operating system
- Shut down unused ports and put them in an unused VLAN
- Explicitly configure ports for end devices as "access ports"
- `switchport mode access`
- Disable Dynamic Trunking Protocol
	- An attacker will not be able to trick a switchport into establishing a trunk link with them
- Change the switch's native VLAN and ensure no port directly uses the native VLAN 
	- This prevents a switch from accepting double-tagging frames


### 8.6 SNIFFING COUNTER MEASURES

- Use encrypted version of protocols
- Requires HTTP strict Transport Security (HSTS) to prevent MITM downgrade attacks
- Prefer switches over hubs
- Configure port security on switches
- Consider using host-to-host (transport mode) VPNs
- Use strong encryption WPA3/2 for WI/FI
- Scan For NICs in Promiscuous mode
- Avoid public Wi-Fi Spots
- Check DNS logs for Reverse DNS lookups
	- By default sniffer will attempt to resolve IP addresses to names
- Ping suspected clients with the their correct IP the wrong MAC address
	- IF suspect accepts the packet, its interface is in promiscuous mode
	- A good indication of sniffing
- Use NMAP sniffer detection scripts
	- `nmap --script=sniffer-detect <target>`


#### PROMISCUOUS MODE DETECTION
- Transmit an ARP request with the fake broadcast address `FF:FF:FF:FF:FF:FE`
	- This will be blocked by all NIC's operating in normal mode
	- Will be allowed by NIC operating in promiscuous mode and thus it will respond to the message
- Promiscuous mode detection tools
	- PRomqryUI
	- Ifchk

#### ARP SPOOFING DETECTION
- Use tools like Xarp to identify ARP attacks
- Hard code ARP-IP mappings
- Implement IDS
- Use host-to-host VPNs

#### SWITCHPORT SECURITY
- Limit MAC addresses that are allowed to connect to a switchport
	- Hard -code a maximum number of MACs per port
	- Hard-code the Mac-to-port mapping in he switch's MAC table
		- Alternatively, allow sticky MAC learning, the switch enters the first MAC plugged into the port as the only permitted MAC
		- Better make sure you plug in an authorized device for the switch to learn
- Set rules for switchport security violations
	- The port shuts down
	- The port is quarantined
	- The violation is logged

#### ROGUE DEVICE DETECTION
- DHCP Snooping
	- Feature that can be enable on certain switches
	- Examines DHCP message exchanges passing through its ports
	- Detects and blocks 'DHCPOFFER' frames from untrusted / unknown sources
- Dynamics ARP inspection
	- Prevents malicious devices from poisoning their neighbors ARP caches
	- Rejects invalid and malicious ARP packets
	- Relies on DHCP snooping
- Best option
	- MAC address reporting from a source device like a router or a switch 
	- You would need a management system or inventory process to capture these addresses
	- You then identify the rogue devices, and the switchports they were discovered on
- Next Best option
	- Periodic ARP scanning to list active MAC addresses
	- Check output for rogue devices.

### 8.7 SNIFFING REVIEW
- Sniffing allows you to capture passwords, private messages, voice and video calls files and other sensitive data from the network
- A good sniffer can capture any protocol from a variety of media types
	- Should also be able to use multiple filters, follows TCP sessions, recreate captured files from raw hex data, provide analysis and save and load captures files.
- Sniffing is successful when desired traffic passes a NIC in promiscuous mode.
- ARP poisoning redirects local LAN segment traffic to the attacker's MAC address.
- MAC flooding forces a vulnerable switch to behave like a hub and flood all frames out all ports
	- useful for VLAN hopping or when ARP poisoning is not desirable
- MAC spoofing changes the MAC address of your device's MIC
- Use DNS cache poisoning and other name resolution exploits to redirect targets when ARP poisoning isn't practical
	- Including when credential harvesting from another subnet
- Be careful when poisoning ARP and DNS caches as it could cause a denial-of-service for regular users.


