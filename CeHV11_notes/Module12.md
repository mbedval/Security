IDS = Intrusion Detection Systems

#### Types of IDS
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
	- 






