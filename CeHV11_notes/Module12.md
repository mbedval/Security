IDS = Intrusion Detection Systems

### 12.1 Types of IDS
- Network-based Intrusion Detection Systems
	- NIDS  (Network Intrusion Detection)
		- A NIDS is a passive monitoring system
		- Network traffic is examine as its passes by an IDS sensor
		- The traffic is compared to a rule set
		- If the traffic matches a rule it is logged
			- Optionally trigger an alert
		- Tools
			#SolarWinds #Bro #OSSEC #Snort #Suricata #SecurityOnion #OpenWips-Ng #SAGAN #McAfeeNetworkSecurityPlatform #PaloAltoNetwork ``
	- NIPS (Network Intrusion Preventions)
		- A NIPS is an active monitoring and control system
		- A network packet comes from Internet and passes through Firewall
		- The packet is no match the packet is sent to the switch and into enterprise network
		- If there is a match
			- An alarm sent and logged
			- The packet is sent through anomaly detection and stateful protocol analysis
			- Connection from the source are cut
			- The packet is dropped
	- Black Box on network in promiscuous mode
	- Detects malicious activity on the network
	- Does not detect anything going on in host
- Host-Based Intrusion Detection Systems
	- HIDS / HIPS
		- Only Activities inside the host are monitored
			- File activity
			- Processes
			- Logons
			- Priviledged Actions
			- User Account changes
			- Software installation/Deletion
		- Host-based IDS/ IPS does not monitor network activity
			- Port and vulnerability scans, denial-of-service attacks against the host
		- HIDS logs suspicious activities
		- HIPS prevents suspicious activities
		- Tools
			#solarwindsLogAndEventManager #ManageEngineLog360 #OSSEC #SAMHAIN #FAIL2BAN #AIDE #SAGAN #SECURITYONION #SPLUNK #SymanticEndPointProtection
	- Audits for events on a specific host
	- Requires overhead to monitor every system event
	- Only Detects activity inside the host
	- Does not detect anything happening on the network

> NIDS Vs HIDS
> In NIDS `IDSSystem ` and Host have 2 direction info exchange while In `HostBasedIDS` Hosts info is collected by `IDSServer`

> Placement for NIDS, NIPS, HIDS, and HIPS 
> NIPS can support Firewall for monitoring and preventing any call coming from Internet
> NIDS can be in network to detect intrusion
> HIPS will be deployed as Web HIPS, DNS HIPS, E-Email HIPS
> 

#### INDICATOR OF NETWORK INTRUSION
- Ongoing probes of services on your network
- Unusual Locations Connecting to you network
- Ongoing remote Login attempts
- Unauthorized data exfilteration
- Hosts with unexpected outbound connections
- Outbound connections to unusual destination ports

#### ONDICATOR OF SYSTEM INTRUSION
- New /Unfamiliar files or program detected
- Unfamiliar files names
- Files that are missing
- File permission changed
- Files sizes changed unexpectedly
- Rogue files not on master list of signed files
- Incomplete/short logs
- Logs that are missing / have incorrect permissions
- Random data in log files that might cause DoS or Service crash
- Slow performance of the system
- Graphic displays / text messages that are unusual
- Alternation to system software/ configuration files
- System crashes / reboots
- Processes that are unfamiliar

#### Ways to Detect INTRUSIONS
- Signature-based
	- Can only known attacks for which a signature has previously been created
	- Must regularly download signatures from the vendor
	- Is a risk for false negatives
	- More commonly used by IDS
- Anomaly-based
	- Can identify unknown attacks
	- Must pre-create a baseline of normal network traffic
		- Capture network traffic for about two weeks
		- Analyze protocols and usage statistics to identify "normal"
	- Is a risk of false positives
	- more commonly used by IPS
- Protocol Anomaly Detections
	- Users models to determines anomalies in how TCP/IP Specification are deployed

#### IDS Component
- Activity is monitored , and logged in Audit Records 
- It is processed by Audit Data Preprocessor
- ==Detection Engine== will match activity attributes from ==Detection Model==
- ==Decision Enginer== will take decision from ==Decision Table== 

#### IDS Results
True Positive :  Real attack and identified 
True Negative :  No Attack and no False  incident
False Positive : No Attack but Incident reported
False Negative : There is attack but could be IDS unable to detect it as feel everything is OK

#### WI-FI IPS
- Wireless intrusion prevention system
- Monitors the radio spectrum for the presence of unauthorised access points (intrusion detection)
- Can automatically implement countermeasures
- The WIPS system uses wireless access points as sensors
- Management software is installed on a server to collect, analyze and aggregate Wi-Fi events

#### WIPS Deployment Models
- The AP perform WIPS functions part the time. Alternates between WIPS and its regular network connectivity functions
- The AP has dedicated WIPs functionality built into it
- Performs network connectivity and WIPS functions at the same time
- The WIPS is deployed through dedicated sensors instead of the APs.

#### WIPS EXAMPLE PRODUCTS
- Open WIPS-NG
- AirTight WIPS
- HP RFProtect
- CISCO Adaptive Wireless IPS
- FLuke Networks AirMagnets Enterprise
- HP Mobility Security IDS/IPS
- Zebra Technologies AirDefense
- WatchGuard
- WiFi Intruder Detector Pro
- WiFi Inspector

### 12.2 SNORT

SNORT 
- Popular open source NIDS
- Runs in Linux or Windows
- You can create your own custom rules
- Will not Block the connection or drop the packet
- Evaluates the entire packet against all alert rules 
- Logs any matches it finds
- Allows packet to continue onward to its destination
- SNORT CONFIGURATION FILE (snort.conf) 
	- ==path_to_conf_file== : `/etc/snort/` (linux )  and `c:\snort\etc` (windows)
- SNORT MODES
	- Packet Sniffer: 
		- `snort -v`
		- SNORT's Packet sniffer mode means the software will read IP packets then display them to the user on its console
	- Packet Logger: 
		- `snort -l`
		- In Packet logger mode, SNORT will log all IP packets that visit the network
		- The network admin can then see who visited their network and gain insight into the OS and Protocols they were using
	- NIDS (Network Intrusion and Prevent Detection System)
		- `snort -A or snort -c <path_to_conf_file>`
		- In NIDS Mode, SNORT will only log packets that are considered malicious
		- It Does this using the preset characteristics of malicious packets, which are defined in its rules
		- The action that SNORT takes is also defined in the rules the network admin sets out
- Testing SNORT
	- Test snort Configuration and rules; check if there is any errors without starting up:
		`snort -i 4 -l c:\snort\log -c c:\snort\etc\snort.conf -T`
	- `-i t --> interface specifier , in case is interface 4`
	- `-c  --> for logging `
	- `-T only for testing, this prevent snort from start up; essentially to check if there is any error and if the rules `
- Starting SNORT
	- `-A : Set alert mode : fast, full, console, test or none`
	- `-b Log packets in tcpdump format (much faster)`
	- `-B <mask \\Obfuscate IP address in alerts and packet dumps using CIDR mask`
	- `-c <rule> \\Use rules files`
	- `-C Print \\out payloads with character data only (no hex)`
	- `-l specifies the logging directory`
	- `-i <interface number> specifies which interface SNORT should listen on`
	- `-K Logging mode ( pcap[default], ascii ,none)`
	- `-? Lists all switches and options and then exits`
-  SNORT RULES
	- Monitored protocols
		- TCP
		- UDP
		- ICMP
	- Rule Actions
		- Alert
		- Pass
		- Log
- Understanding SNORT RULES
	- A security analyst should be able to read Snort IDS rules and Pick out generic content such as:
		- The type of protocol covered by the signature
		- The port by analyzed
		- The direction of traffic flow
		- Rule Header {Action, Protocol, Source Address, Source Port, Direction, Destination Address, Destination Port}
		- Rule Option (msg: "ICMP ATTEMPT ATTACK": sid:1000005)
		- `alert icmp any any -> &HOME_NET any (msg:"ICMP Test"; sid:1000001; rev:1; classtype:ICMP-event;`
		- `alert tcp 192.168.x.x any -> &HOME_NET 21 (msg: "FTP Connection attempt"; sid:1000002; revL1  ` \\\\TCP alert in a source IP address 192.168.x.x with any port; HOME_NET destination on port 21 
		- `alert tcp $HOME_NET 21 -> any any (msg: "FTP failed login"; content: "Login or password incorrect"; sid:1000003; rev:1;)` \\\\TCP Alert in home_net PORT 21 (FTP) as a source, to any destination IP address and PORT:
		- `alert tcp !HOME_NET any -> $HOME_NET 31337 (msg : "BACKDOOR goging to the internal network port 31337` \\\\This alert about traffic that originated anywhere other than internal network going to the internal network port 31337
		- `alert tcp any any -> 192.168.10.5 443 (msg: "TCP SYNC FLOOD"; flags:!A; flow: stateless; detection_filter: tracl by_dst, count 70, seconds 10; sid:2000003;)` \\\\Detect TCP Syn flood
``` 
\\example
snort -i 4 -C :\snort\etc\snort.conf -l c:\Snort\log -K ascii
```

> Download snort and rules at https://www.snort.org/downloads 

### 12.3 SYSTEM LOGS
- Nearly all devices have a system log
	- Windows event viewer
	- Linux has many logs located in /var/log
	- Most Routers, switches , firewalls and other network devices have their own logs
- Log Event can be sent to a central syslog server 
	- on windows install syslog server's client software
	- On Linux, edit `/etc/syslog.conf` to point to the syslog server
Logs can also be queried by a SIEM or IDS

#### SYSTEM LOGGING CONSIDERATIONS
- System logs of hosts and network devices must be time-synchronized
- IDS and sysadmin must be able to cross-correleate events
- Logging can be resources intensive for the device
	- If you are about enable logging / OS auditing on a system for the first time, consider the impact of enabling the audit feature on system performance
#### SYSLOG
- Widely used standard for capture log messages from a variety of devices
	- Events are sent by devices to a centralized syslog server
	- Even if the attacker manages to delete logs on the compromised system, the syslog server has a copy
- Separates logging roles info;
	- Software that generates messages
	- The system that stores the messages
	- The software that analyzes the messages and create reports
- Messages include
	- time stamps event messages, severity, host IP addresses, diagnostics and more 
- Kiwi syslog server is a popular syslog product
- SYSlog Uses UDP 514


### 12.4 IDS Considerations

#### NIDS Considerations
- System clock of all monitored and monitoring devices must be synchronized
- Network sensors (taps ) must be strategically placed
	- Must have traffic pass their interface
	- Best Way is to configure port spanning (mirroring) on a switch
	- The switch copies all traffic to /from a particular port (where the server is connected) to the mirrored port

#### NIPS Considerations
- Provides defense-in-depth protection in addition to a firewall
	- It is not typically used as a replacement
	- A NIPS cannot handle the same heavy workload that a firewall can handle
- A false positive by a NIPS is more damaging than one by a NIDS 
	- Legitimate traffic will be denied
	- This may cause production problems
	- A NIPS usually has a smaller set of rules compared to a NIDS for this reason. Only the most trustworthy rules are used.
- A NIPS is not replacement for a NIDS
	- Many network use both a NIDS and a NIPS
	- To assist a NIPs, you can turn on the built-in auditing feature in the operating system.
	- Can slow system performance as well as take up a lot of disk space.

#### HIDS / HIPS Considerations
- Once installed, nearly impossible to uninstall, because this product replaces some OS components
- Can only detect activity happening within the OS, and cannot detect ping sweeps, port scans and non-intrusive vulnerability scans.
- Does not prevent intrusions or attacks
- Can be installed on network points such as routers or servers, but cannot monitor at the network level
- Does not filter incoming/ outgoing traffic based on rules, the way a firewall does, or a bandwidth monitor does.
- Is Most effective as a solution if it an forward events from individual hosts to a centralized log server, or even a cloud-based SIEM

#### TUNING IDS / IPS Security Alerts
- Some IDS / IPS products allow you to tune them for greater accuracy
- When tuning security alerts, attempt to tune to reduce false positives and false negatives
- General Tuning steps:
	- Identify potential locations for sensors
	- Apply an initital configuration
	- Monitor the sensor while tuning.
	- Analyze Alarms, Tune out False positives ,and implement signatures Tuning
	- Selectively implement Response Actions
		- IP Logging, TCP  resets, Shunning (Dynamically dropping / not allowing certain connections)
	- Update sensors with new signatures
- IDS Scenarios:
	- A bank stores and processes sensitive privacy information related to home loans, however auditing has never been enabled on the system. What is the first step that the bank should take before enabling the audit feature?
	- Ans: You must first determine the impact of enabling the audit feature

### 12.5 IDS Evasion
> There is no magic bullet for detecting and bypassing a firewalls or IDS system. What it requires is skill and experience

#### General IDS Evasion Techniques
- Use a proxy/Anonymizer to make the attack difficult to trace. 
- Spoofed source IP, source routing and source port manipulation
	- Make the packets seems to come from a trusted source
- Customize packets so they don't make any signatures
	- Append binary or text data
- IP fragmentation and session splicing
	- Send attack in small packets, making it difficult to determine overall attack signature
- Using character encoding in a URL to obfuscate a destination or intent
- Create confusion by flooding the network with decoys, DoS and false Positives.
- Encrypt incoming malicious traffic. An inside host will have to be able to decrypt
- Encrypt outgoing exfiltrated stolen data. Use a tool such as cryptcat to encrypt stolen data before you exfiltrate it out of the network
- Avoid scan types that an IDS will recognize
	- Stealth Scans
	- Other Scans with unusual TCP Flag combinations
	- Scans the go too fast
	- Scanning hosts in sequential order

#### TIMING Evasion
- A very slow scan will just appear as random noise to the IDS
- IT will fall below the threshold necessary to fire an alert
- Make sure addresses and ports are targeted in random order
- Scan using `nmaps -T 5` switch
- A SIEM is likely to detect a very slow whereas an IDS might not.


#### ID Address Decoys
- Generates Noise you can hide in
- Multiple IP addresses to be scanning a target simultaneously
- This makes it very difficult for the IDS or Sysadmin to a determine who the real attacker is 
- You can explicitly specify source addresses or allow the scanner to randomly generate addresses

#### INSERTION AND OBFUSCATION
- Insert Attack
	- Attacker forces the IDS to Process invalid packets
- Obfuscation
	- Encoding the attack packets in such a way that the target is able to decode them, but the IDS cannot.
		- Unicode : use unicode characters rather than ASCII so it doesn't match any signature.
		- Polymorphic code : Change the attack code so its doesn't match any IDS signature.
		- Encryption : Encrypt the attack code so it can't be read.
		- Path manipulated to cause signature mismatch.
#### FALSE POSITIVES and FRAGMENTS
- False positive generation events
	- Craft malicious packets designed to set off alarms
	- Attempt to distract / overwhelm the IDS and admin.
- Overlapping Fragments
	- Generate a bunch of tiny fragments overlapping TCP sequence numbers
- Fragmentations / Session Splicing
	- The pre-created endpoints must reassemble the packets
	- Use can use Whisker to perform this attack.

#### TCP FLAGS
- Desynchronization
	- Manipulate the TCP SYN Flag
	- Fool IDS into not paying attention to the sequence numbers of the illegitimate attack traffic
	- Give the IDS a false set of sequences to follow
- Invalid RST packets
	- Manipulate the RST flag to trick the IDS into ignoring the communication session with the target.
- Urgency Flag - URG
	- Manipulate the URG flag to cause the target and IDS to have different sets of packets
	- The IDS will processes ALL packets irrespective of the URG flag
	- The target will only processes URG traffic.

#### Pattern-Matching Attacks
- Polymorphic Shellcode
	- Blow up the pattern matching by constantly changing the shellcode
- ASCII Shellcode
	- Use ASCII characters to bypass pattern matching
- Application-Level Attacks
	- Taking advantages of the compression used to transfer large files and hide attacks in compressed data, as it cannot be examined by the IDS.

#### SESSION SPLICING
- Exploits IDSs that do not reconstruct sessions before performing pattern matching
- Fragments the attack across multiple packets
- No single packet triggers an alert
- IDS reassembly times out if fragments sit too long it its buffer
- #Whisker is popular tool for session splicing
	- Splits an HTTP request across multiple packets
		- Not true IP fragmentation
		- The Receiving webserver does not have to reassemble ip fragments
	- The target views the attack as a very slow incoming HTTP request
	- Example: Get/HTTP/1.0  is fragmented as [GE , T  , / , H, T ,TP, /1 , .0]
	- Whisker will put 1-3 characters in each packet
		- Depending on system and network speed
	- Resources
		https://packetstormsecurity.com/files/download/11002/whiskerids.html 
		https://dl.packetstormsecurity.net/papers/IDS/whiskerids.html

#### IDS EVASION TOOLS
- Stick
	- An IDS stress tool
	- Overwhelms a NIDS with so many alerts using valid signatures
	- The admin can not longer distinguish between false positives and legitimate alerts
	- Can cause some IDSes, including Snort, to turn themselves off
- #Snot 
	- Similar to stick
	- Attempts to randomize the sequence of rules or alerts generated so that a "snot generation" rule is not triggered by snort
	- Example : Snot -r snort.rules -s www.somerandomhost.org/24 -d somesnortuser.com -l 10
- #Fragroute
	- Packet fragmenter
- #Nessus and #Nikto
	- Vulnerability scanner with evasion capabilities
- #SSLproxy, #TOR
	- use proxies with encrypted traffic to evade detection
- #ADMMutate : creates scripts not recognizable by signature files
- #NIDSbench : Older Tool for fragmenting bits
- #Inundator : Flooding Tool
- IDS-Evasion
	- Multiple bash, powershell, and python scripts to evade snort
	- https://github.com/ahm3adhany/IDS-evasion

#### IDS / Firewall Evasion Tools
#Whisker #NMAP #HPING2 #HPING3 #CRYPTCAT #TrafficIQProfessional #TCP_Over_Dns #SnareAgentForWindows #AckCmd #YourFreedom #Tomahawk #AtelierWebFirewallTester #Freenet #GTunnel #HotspotShield #VPNOneClick

#### PACKET FRAGMENT GENERATOR
#Whisker  #colasoft #TamoSoftCommView #hping3 #MultiGnerator #NetInspect #OStinato #fping3 #NetScanToolsPro #pktgen #Packeth #PacketGenerator

### 12.6 FIREWALLS

- Acts As network choke pint
	- Traffic must flow through it
	- Unauthorized traffic (in or out) is blocked
- Can detect
	- Unauthorized protocols
	- Unauthorized source and destination IP Addresses
	- Unauthorized source and destination ports
	- unauthorized incoming connection attempts
	- Malicious Site URLs
	- Malicious payloads
> If you can reach a host using one port or protocol but not another, it means that a firewall is blocking certain traffic types.

#### Hardware Types
- Hardware-based
	- AKA firewall appliance
	- Separate device
	- Placed at the network edge, between the trusted, and untrusted networks
	- Block unauthorized traffic movement between the networks
- Software-based
	- Installed on a host
	- Prevent unauthorized traffic to /from the host itself.

#### PACKET FILTERING (STATELESS FIREWALL)
- Works at multiple OSI Layers
	- Layer 3 - IP Addresses
	- Layer 4 - Protocol
	- Layer 5 - Ports
- Can be a stateless firewall or a packet filtering router
- Every packet is compared to a rule set
- Firewall can permit or deny the packet
- Firewall can permit or deny the packet
- Rules may include
	- IP address of source and/or destination
	- Port number of source and/or destination
	- Protocol (IP, ICMP, IGMP, TCP, UDP)
- There is no memory of the packet before
- You will have to configure rules for every contingency
- Best when high performance is critical


#### STATEFULL FIREWALL
- Maintains a state table for every connection
- Disallows even outbound traffic if suspicious
- Tracks each connection
- Will notice if
	- There is no proper TCP handshake to start the connection
	- Any port suddenly changes
	- There are any other anomalies in the conversation
- Filters packets at the network and transport layers
- Evaluates packet content at the application layer
- Most modern firewall are stateful.

#### CIRCUIT LEVEL GATEWAY
- Works at the session Layer (Layer 5)
- Allows / disallows entires circuits (connections) as opposed to individual pakets
- Validates that TCP or UDP packets belong to an allowed connection
	- Examine TCP handshakes
	- Maintains a session state table
	- Makes IP spoofing more difficult
	- Compensates for UDP lack of source IP validation
- Typically host-based
	- Or a feature of a multi-layer firewall applicance

#### APPLICATION LEVEL GATEWAY
- Filters packets at the application layer (7) of OSI or Application Layer of TCP / IP
- Examine payloads and Application layers headers
	- Traffics is examined and filtered on application-specific commands
- If configured as a proxy:
	- Client session put on hold at the proxy.
	- Proxy fetches approved content for the client
	- Proxy caches the content against future requests.
	- Only Protocols supported by the proxy are serviced.
		- HTTP, HTTPS, SOCKS4, SOCKS5, and UdP
		- All other protocols are rejected. Or routed through packet filtering
	- Slowest performance, deepest packet inspection.
> Socks is layer 5 protocol, Connect client to proxy, Can forward TCP and UDP, optional Authentication.


#### UNIFIED THREAT MANAGEMENT (UTM)
- A device that combines multiple functions into a single piece of hardware including
- Firewall
- Anti-malware
- URL filter
- Spam / Phishing filter
- IDS / IPS
- VPN Server
- Data Loss Prevention (DLP)

#### 12.7 PACKET FILTERING RULES
#### 12.7.1 PACKET Filter
Different products have different rules syntax
- Typical rules elements includes:
	- Action
	- Protocol
	- Source IP
	- Source Port
	- Destination IP
	- Destination Port
	- Connection state
	- Interface
	- Traffic direction ( in or out of an interface)
- CISCO PACkET FILTERING RULE EXAMPLES
	- Disallow any source from pinging any destination `Deny ICMP any any`
	- Disallow any source from 192.168.1.0/24 from querying any DNS server `Deny UDP 192.168.1.0/24 any eq 53`
	- Only permit host 10.1.2.3 to use SSL / TLS connect to webserver 172.16.5.4 `Permit TCP host 10.1.2.3 172.16.5.4 eq 443`
	- Only permit the admin station 192.168.1.10 to SSH to a linux server 10.5.5.6 `Permit TCP host 192.168.1.100 10.5.5.6 eq 22`
	- Only permit host from subnet 10.0.0.0/24 to use the client TCP source port 5555 to connect to a gaming server 1.1.1.1 that listens on port 7777 `Permit TCP 10.0.0.0 0.0.0.255 eq 5555 host 1.1.1.1 eq 7777`
	- Disallow any host sending SNMP packets to 192.168.20.100 `Deny UDP any host 192.16820.100 eq 161`
- LINUX IP Table Rules Example
	- Block a specific IP Address
	- Block_THIS_IP="192.168.1.2"
	- iptables -A INPUT -s "$BLOCK_THIS IP" -j Drop
	- Allowing incoming SSH only from a specific Network
		- `iptables -A INPUT -i etho0 -p tcp -s 192.168.100.0/24 --dport 22 -m state --state NEW, ESTABLISHED -j ACCEPT`
		- `iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT`
#### FIREWALL RULES SCENARIOS
- You have been asked to review the firewall configuration to ensure that workstations in network 10.10.10.0/24 can only reach the bank web site 10.20.20.1 using https.
- Which rules satisfies the requirement??
	1. if (Source matches 10.10.10.0/24 and destination matches 10.20.20.1 and port matches 80/443 then permit)
	2. If (source matches 10.20.20.1 and destination matches 10.10.10.0/24 and port matches 443) then permit
	3. if (source matches 10.10.10.0 and destination matches 10.20.20.1 and port matches 443) then permit 
	4. if (source matches 10.10.10.0/24 and destination matches 10.20.20.1 and port matches 443) then permit 
	[Ans 4]


### 12.8 Firewalls Deployments
#### FIREWALL ARCHITECTURE
- Bastion host
	- A public-facing host
	- System that protects network resources from attack
	- Two interface : public and private
- Screened Subnet (DMZ)
	- External and Internal firewall, back-to-back
	- Does not allow access to private zone.
	- Let the public facing bastion host (typically a web server) take one for the team. Keep the application and database servers in the private network to protect them.
	- 
- Multi-homed Firewall
	- Firewall with two or more interface to further sub-divide the network based on security goals
	- Often has third interface that connects to a DMZ. Sometimes called a perimeter network
	- More complex to configure less expensive
- Outbound Traffic flow
	- Outbound connection = connection started from the private network
	- Inbound relies traffic flow  = Replies from the untrusted network are permitted. It both firewall are stateful. They will remember that an internal host started the session.
- Private-DMZ Traffic Flow 
	- An outbound connection can be from the trusted network to any untrusted network (internet or DMZ)
	- Replies : If the trusted network initiated the connection, response from the untrusted network is permitted back into the trusted network.
- DMZ-Internet Traffic Flow
	- An outbound connection can also be from the DMZ to the internet Both network are considered "untrusted" The DMZ will have some protections for its bastion hosts.
- Traffic Flow
	- Both a stateful and stateless firewall should be configured to permit responses
- Inbound connection Attempt
	- An inbound connection is one initiated from a (less) the connection was not started from the inside a stateless firewall should be configured to not accept any packet with just the TCP SYN flag raised and the ACK flag set to 0
- Inbound Connection to DMZ
	- If there is a bastion host offering a service to the internet, the outside firewall should be configured to permit incoming connections on that port
- Inbound connections to different PORTS
	- While the outside firewall will allow inbound connections to the DMZ the inside firewall is typically configured to allow NO inbound connections
- TRAFFIC FLOW
	- The exception is that you might have a host in the DMZ that needs to communicate with a host in the private network. The safest to allow this is to have an IPSEC VPN between the two. The inside firewall should have very strict rules that only allow the VPN, and only to a specific internal host.
	- > Note: IPSEC works at layers 3 and Layer 4. It does not care what the layer 2 protocol is. Nor does it care what the payload is.
- HOSTS that might need to communicate between DMZ and Private network
	- Web server front end - Database server back end
		- You could protect the internal financial database with a web server front end in the DMZ
	- Email spam filter  - Email Server
	- WebMail front end - Mailbox server back end

### 12.9 SPLIT DNS
#### SPLIT DNS
- You manage two separate DNS servers:
	- External (public) DNS
	- Internal (Private) DNS
- They should be separately managed with NO Communication between the servers
	- You will need to separately configure records for both
	- It is OK for both to have the same domain name
	- Internal hosts should be configured to only use the Internal DNS server.

#### SPLIT DNS - Public DNS Server
- Should be in the DMZ or hosted by a provider
- Public-facing services such as public website, spam filter/email relay, VPN server
- Only has records the general public will need access to
- TLD and parents DNS zones should delegate (point) down to your DNS on the Internet
- Should not have to perform any non-authoritative lookups
- Should not have to query other DNS servers for anything

#### 12.9.3 SPLIT DNS - Private DNS server
- Should be in the private network
- Has records that internal clients will need access to:
	- Active Directory
	- Internal resources
- Should be able to perform recursive queries or search the Internet DNS tree for clients needing public records
- Configure all internal clients to use the private DNS only.
- Have the private DNS go directly to an ISP DNS to do Internet name searches

### 12.10 Firewall Product Types

#### 12.10.1 
#Comodo #CiscoASA
#checkPint #UntangleNGFirewall #SonicWall #OnlineArmor #FortiGate #ManageEngine #Perimeter81 #TotalAV #ValutCore #PcProtect #Bitdefender #McAfee #ZoneAlarmPro #WindwosDefender #LinuxIpTables #LinuxUFW #CiscoPacketFilteringRouter 

#### 12.10.2 FIREWALL For Mobile
#AndroidFirewall #FirewallIP #MobiwolNoRootFirewall #AFWall #FirewallPlus #RootFirewall #AndroidFirewallGold #DroidFirewall #PrivacyShield #aFirewall #NoRootFirewall 



#### 12.10.3  Cloud Based IDS and Firewall Services
- IDSaas
	- Google Cloud IDS
	- AlienVault
	- Checkpoint
- FWaaS
	- Perimeter81
	- Fortinet
	- Zscaler
- 
