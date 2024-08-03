### 10.1 DOS CONCEPTs

#### What is Denial of services (DOS) ?
- A type of attack on a service that disrupts its normal function and prevents other users from accessing it
- Typically aimed at a website, but can attack whole networks, a specific server, or a
- specific application
- DoS can be achieved by:
	- Flooding the network or routers/switches with traffic (consuming all network bandwidth)
	- Consuming all of a server’s CPU, RAM or disk resources
	- Consuming all of a server’s permitted concurrent TCP connections
- DoS attacks can cause the following problems:
	- Ineffective services
	- Inaccessible services
	- Interruption of network traffic
	- Connection interference

#### DOS ATTACK  CATEGORIES

| Type                         | Description                                                                      |
| ---------------------------- | -------------------------------------------------------------------------------- |
| Volumetric attacks           | Designed to consume network bandwidth so authorized clients cannot connect       |
| Fragmentation Attacks        | Designed to keep a target busy with packet fragments that cannot be reassemebled |
| TCP State-Exhausttion Attack | Designed to consume connection state tables in network infrastructure components |
| Application Layer attacks    | Designed to consume app resource / service so they are not available to users    |
| Protocol Attacks             | Designed to abuse commonly used internet protocols                               |
| Multi-vector Attacks         | A combination of attack types                                                    |
> DoS attacks can have characteristic or more than on attack type

#### Distributed Denial-Of-Service (DDoS)
- Launched from numerous compromised devices
- There can be hundreds or even thousands of devices
- The compromised devices are typically organization and remotely controlled 
- Such computers are called zombies
- They are regionally located
- Often compromised machines themselves
- The C&C computers are in turn controlled by the attackers computer

> ATTACKER >> controls 'C&C servers' >> Controls 'Zombies' >> attacks Victim

#### 10.2 Volumetric Attacks
- The most popular type of DDoS attack
- Designed to consume network bandwidth so authorized clients cannot connect
- The volume of incoming traffic determines the efficiency of volume-based attack.
- The goal of volume-based attack is to saturate the websites bandwidth. This attack also has an impact on CPU utilization
- Bits Per seconds are used to quantify the bandwidth based attack
- Amplification is one of the strategies for transmitting a vast amount of data to a specific website.

- Packet Flood:
	- Send massive amount of TCP , UDP, ICMP, or random packet traffic to target, can include different TCP flag variants
- Botnet DDoS Attack
	- Service request flood
	- Attacker/ zombie group sets up / tear down TCP connections in an attempts to use a request is initiated on each connection
	- Flood of service requests overwhelms the target servers(s)
- Distributed Reflection DOS (DRDoS)
	- AKA spoofed attack
	- Uses multiple intermediary and secondary (victim) machines in the DDoS attack
	- Attack sends requests to intermediary hosts, which are redirected to secondary Machine then to target
	- Advantages includes
		- Target appears to be attacked by secondary machines
		- Results in an increase in attack bandwidth.
	- > >> Attcker >> Masters >>> Slaves >>> Reflectors >>> Victims
- SMURF ATTACK
	- A type of DRDoS
	- Large numbers of ICMP echo requests sent to intermediate devices
		- Source is spoofed so they are responded to the target
	- You could use hping3 to perform this attack
		- `hping3 -1 -c 1000 10.0.0.$i --fast -a <spoofed target>`
	- > > Note: IRC servers were historically the primary victims of SMURF attacks
	- Attacker >> Amplifers (responses are forwarded to the vicim) >> vitim
- ICMP Flood
	- Similar to Smurf but without the intermediate devices
	- Send ICMP Echo Packets with a spoofed address
	- Eventually reach limit of packets per second sent
	- Example you could use hping3 to perform an ICMP Flood
	- `hping3 -1 -flood --rand-source <target`
- FRAGGLE ATTACK
	- Same concept as Smurf Attack
	- UDP packets instead of ICMP (UDP flood attack)
	- `hping --flood --rand-source --upd -p <target>`
- HTTP Flood
	- Uses seemingly legitimate HTTP GET or POST requests to attack a web server
	- Does not require spoofing or malformed packets
	- Can consume a high amount of resources with a single request
	-  >> Botnet controller >> uses compromised Host(s) and attack with HTTP Get flood >> to server
- DNS Flood
	- Uses spoofed DNS queries to consume server Resources 
	- >> Attacker >> Uses Botnets >> send Spoofed DNS Queries to Open DNS Resolver >> Big DNS response to Target
- DNS Amplification Attack
	- Similar to Smurf or other amplification attacks
	- Multiple public DNS servers receive spoofed queries
	- They all respond to a single target to overwhelm it with UDP
	- >> attacker >> sends 64 bytes spoofed request to Open Resolver  
- NTP Amplification
	- Similar to Smurf and DNS amplification attacks
	- Multiple NTP queries are sent
	- The time servers all respond to a single target to overwhelm it with UDP
	- >>> Attacker >> BOT >> NTP SERVERS (S) >> Target Victim


### 10.3 FRAGMENTATION ATTACKs
- Designed to keep a target busy with packet fragments that cannot be reassembled 
- IP fragments are sent to a target
- Their fragment offsets overlap or otherwise cannot be ressembled
- The target's CPU is kept busy attempting to reassemble the packets
- Can result in system freezing or crash
- (Unfragmented part)  + (Fragment Part)
`(Link Layer Header + IPV6 Header )  + (Transport Header + Payload + Link Layer Trailer)`

#### 10.3.1 TEARDROP ATTACK
- An IP Fragmentation attack
- IP Fragments offset in the packet header overlap
- Fragmented Packet #1 
	- 20 Bytes (IP Header) + 800 Bytes (Data) = [Offset =0 , Length = 820, More Fragments =1]
- Fragmented Packets #2
	- 20 Bytes (IP Header) + 600 Bytes (Data) = [Offset = 800, Length 620, More Fragments = 0] (Note : Offset started too soon and overlaps with previous packet )
-
#### 10.3.2 TCP FRAGMENTATION ATTACK
- Similar to an IP Fragmentation attack, but for TCP
- Send the target TCP segments that have overlapping sequence numbers and cannot be reassembled
- Windows NT, Windows 95 , Linux version prior to Version 2.1.63 are most vulnerable

#### 10.3.3 UDP FRAGEMENTATION ATTACK
Send the target UDP fragments
When reassembled they are too large for the network's MTU

#### 10.3.4 PING OF DEATH
- Fragments ICMP messages
- Upon reassembles the ICMP packet is larger than the maximum allowable size
- Crashes the target
- >>> Attacker >> Maliciously ping of death ICMP packet fragments assemble to become larger than 65535 bytes >>> Target Victim
- Normal ICMP Maximum Packet Size is 65535 Bytes

### 10.4 STATE EXHAUSTION ATTACKS

#### 10.4.1 TCP STATE EXHAUSTION
- Attempts to consume all permitted connections
- Targets can include
	- Application servers/web serveres
	- Load Balancer
	- Firewalls


#### 10.4.2 SYNC FLOOD
- AKA Half-Open attack
- Send thousands of SYN packets to a target
- Source address is spoofed to non-existent devices
- The server replies with SYN/ACK to non-existent source
- No ACK is received to complete the handshake
- The server must wait to time out each connection
- Servers are usually configured to allow a limited number of concurrent connections
- All permitted connection are consumed
- Legitimate client requests are ignored
- >>> Attacker >> using Bot send Spoofed SYN PACKET >> to Target

#### 10.4.3 SS/TLS  EXHAUSTION
- Send garbage SSL/ TLS data to the server
- Server Runs out of resources attempting to process corrupt SSL handshakes
- Firewalls generally cannot distinguish between legitimate and phony SSL data

#### 10.4.4 DNS/NXDOMAIN FLOOD
- The attacker floods the DNS server with requests for invalid or non exists records
- The DNS server spends its time searching for something that doesn't exist
	- Instead of serving legitimate
- The result is that the cache on the DNS server gets filled with bad requests
	- Clients can't find the sites/servers they are looking for


### 10.5 APPLICATION LAYER ATTACKS

#### LAYER 7 ATTACKS 
- Abuse layer 7 protocols such as HTTP/ HTTPS , SNMP , SMB (Exploit weak code)
- Consume resource necessary for the application to run
	- Measured in requests per seconds (RPS)
- Slow rate, consume few network resources, but harmful to the target
- Imitate legitimate user activity
- Target File servers, web servers, web applications and specific web-based apps 
- Common attack examples
	- HTTP GET/POST attack
	- Slowloris or R.U.D.Y (Low and Slow) attack
		- Operates by utilizing partial HTTP requests
		- The attack functions by opening connections to a targeted web server. Keeps those connection open as long as it can.
		- The attacker first opens multiple connection to the targeted server. Sends multiple partial HTTP request headers
		- The Target opens a thread for each incoming request
		- Need to prevent the target from timing out the connections
			- The attacker periodically sends partial requests header to the targets
			- keeps the requests alive
			- In essence saying "I am still here, I m just slow, please wait for me"
		- The targeted server is never able to release any of the open partial connections. It remains waiting for the termination of the request
		- Once all the available connections are in use, the server will be unable to respond to additional requests made from regular traffics
		- Example >>> Nral
	- Malformed SMB requests : example Using `SMBdie` utility, target can be caused to a Blue Stop Screen (Blue screen of Death) on Windows
	- Malicious SQL queries that disrupts a database server
- 



### 10.6 OTHER ATTACKS

#### 10.6.1 PROTOCOL ATTACKS
- Rely on weakness in Internet communication protocols
- Because many of these protocols are in global use, changing how they work is complicated and very slow to roll out
- Their inherent complexity might introduce new flaws as the original flaws are fixed


#### 10.6.2 BGP HIJAKING
- A great example of a protocol that can become the basis of DDoS attack
- BGP is the routing protocol used on the Internet
- It is used by Internet routers to update each other on changing route conditions 
- It has very slow convergence
- If an attacker can send a false route update to a BGP router
	- Internet traffic could be misdirected or halted in certain areas.
- Example >>> Attacker sends fake BGP routing protocol updates to Internet routers
	- Internet routes now point to the wrong network.
	- REAL EVENT 
		- 2018 : 
			- Russian provider announced a number of IP prefixes (groups of IP addresses)
			- The Prefixes actually belong to route53 Amazon DNS Servers
			- Amazon DNS queries were hijacked so that DNS queries for myetherwallet.com went to servers the attackers controlled
			- Users attempting to log in the cryptocurrency site were redirected to fake site
			- Attackers stole approximately $152000 in cryptocurrency
		- 2008:
			- Pakistani government owned Pakistan telecom attempted to censor youtube within pakistan by updating its BGP routes for the website
			- New routes were announced its BGP routes for the website
			- New routes were announced to pakisthan telecom upstream providers and from there broadcast to the whole internet
			- Suddenly all web request for youtube were directed to pakisthan telecom
				- Result in an hour long outage of the website for almost the entire internet 
				- Overwhelmed the ISP


#### 10.6.3 LAND ATTACK
- Get a victim to try to start a session with itself
- Send a SYN packet to the target with a spoofed IP
- The Source and destination IP both belong to the target
- If vulnerable the target loops endlessly and crashes
- Attack: Echo request with destination and source IP address with same address, Victim echo reply to itself, and Resource of victim are consumed by the flood of DOS attack
- 

#### 10.6.4 PHLASHING
- A DoS attacjk that causes permanent damage to a system
- Modifies the firmware
- AKA "Bricking"
- Examples:
	- Send fraudulent firmware update to victim
	- Crash the BIOS
- 

#### 10.6.5 PEER-TO-PEER ATTACK
- Attacker causes clients to disconnect from peer-to-peer network and connect to a fake website
- Attacker uses DC++ protocol (Peer-to-peer file sharing) to exploit network flaws
- Attackers can launch huge DoS attacks which will compromise target websites


### 10.7 DOS/ DDOS Attack Tools

#### 10.7.1 DOS and DDOS Attack Tools
#LOIC (Low Orbit ION cannon), #HOIC (High Orbit ION Cannon) , #kaliSlowloris #Pyloris #HTTPUnbearableLoadKing #DDoSIM #OWASPHttpPost #Rudy #TorHammer #DAVOSET #GoldenEye #HULK #XOIC #Thc-ssl-Dos 
  
#LOIC 
- is window utility allowing to flood a target with TCP, UDP or HTTP requests
- Essentially a slowloris tool, but requires DDos to be effective

#HOIC 
- is more powerful version of LOIC
- Target TCP and UDP
- Can Open up to 256 Simultaneous attack sessions at once
	- Sends a continuous stream of junk traffic
#Rudy 
- R U Dead Yet ?
- DoS with HTTP Post Via Long-Form field submissions
- Similar to Slowloris attack
	- Sends more data
	- Header and body of a message
- Aims to keep a web server tied up
	- Submit form data at an absurdly slow pace
- Categorized as a low-and-slow attack
	- Focuses on creating a few drawn-out requests
- Used to attack web applications
	- Starves available sessions on the web server
	- Keeps the session alive
	- Uses never-ending POST transmissions
	- Sends arbitrarily Large Content-Length header value

### 10.8 DOS/ DDOS Countermeasures


#### 10.8.1 DDOS MITIGATION STRATEGIES
- '**Route**' traffic across multiple data centres
- '**Detect**' the fingerprint of an attack as it occurs
- **Response** : drop malicious traffic at the network edge
- **Adapt** : Use Machine learning to adapt to the attack pattern


#### 10.8.2 DDOS Management Strategies
When in the middle of an attack you can:
- Absorb attack
	- Increase capacity to absorb attack
	- Requires planning / additional resources
- Degrades Services
	- Stop all non-critical services until attack is over
- Shut Down Services
	- Shut down all service until attack is over

#### 10.8.3 DOS/ DDOS Countermeasures
- Good DoS / DDoS countermeasures can distinguish between legitimate and illegitimate traffic
- Use cloud-based anti DDoS to protect enterprise-level online services
- Increase bandwidth for all critical connections
- Filter traffic on upstream routers
- Rate-limit allowed connections
- Load Balance and cluster critical servers / Services
- Ensures routers are set to throttle incoming traffic to safe levels.
	- Throttling controls DoS traffic to minimize damage to servers
	- Throttling can be used to DDoS attacks to permit legitimate user traffic
- Ensure Software / protocol are up-to-date
- Patch system so they are no longer vulnerable to attacks that exploit software defects
- Scan machines to detect anomalous behavior
- Disable all insecure/ unused services
- Ensure kernel is kept-up-to-date
- Do not allow transmission packets that are addressed fraudulently at the ISP level
- Ensure firewall is configured to deny access by external ICMP traffic
- Ensure remote admin/connectivity testing is secure
- Ensure input validation is performed
- Do not Allowed data processed by attacker to be executed
- Ensure prevention of unnecessary functions
- Ensure prevention of return address overwritting

#### 10.8.4 Cloud-Based DDoS protection
- Most ISPs block all requests during DDoS Attack ( but unfortunately denies legitimate traffic)
- In-Cloud DDoS protection
	- During an attack all attack traffic is redirected to the provider
	- It is filtered and returned
	- Cloud-based solutions 
		- Cloudflare
		- Netsout

#### 10.8.5 Advanced ANTI-DDOS Appliances
#FortiDDoS #DDoSProtector #CiscoGuardXT #ArborPravail #NetFlowAnalyzer #SDLRegexFuzzer #WanGuardSensor #NetScalerApplicationFirewall #Incapsula #DefensePro #DOSarrest #AntiDDOSGuardian #DDoSDefend

#### 10.8.6 Techniques to Defend Against Botnets
- RFC 3704 Filtering
	- Strict Reverse Path Forwarding (Strict RPF)
	- Basically a Dynamic ACL
	- Ingress Filter
	- Denies Traffic with spoofed addresses 
	- Ensures that traffic is traceable to its correct source
- Real Time Black hole
	- Based on a manual trigger by an administrator
	- Internal routers in a ISP or other network propagate a route to a particular target to Null O
	- Route inside the network at any point will drop traffic destined for that target.
#### 10.8.7 POST Attack Forensics
- Develop new filtering techniques based on DDoS traffic patterns
- Determine source of DoS traffic by analyzing firewall, router , and IDS logs
- Analyze DoS traffic for certain characteristics
- Utilize DoS traffic characteristics and pattern analysis to update load-balancing/ throttling countermeasures

### 10.9 DoS / DDoS Review

- DoS is an attack on a computer / network that restricts / reduces / prevents system access
- Consumes all available resources such as network bandwidth, CPU , RAM disk space, Allowed connections
- A DDoS attack uses many compromised systems that attack a single target
- There are various categories for DoS /DDos techniques
	- Not all attacks involve large floods of traffic
	- Many attacks are designed for a specific target types
- A botnet is large network of compromized systems
	- They are managed by command and control servers
- DoS detection techniques rely on identifying / discriminating against illegitimate traffic
- You can use a DoS to stress-test a system
	- Be Careful as it will be disruptive








































