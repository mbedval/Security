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
	 

