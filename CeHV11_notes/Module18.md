### IOT Overview
#### WHAT is Intertnet Of Things (IoT)
- IoT can best be thought of as 
	- the process of connecting everyday objects an systems to network (internet)
	- Make all devices globally available and interactive
- Include devices from all sectos
- There are currently over 12 billion IoT devices connected to the Internet. In 2025 that number is expected to reach nearly 40 billion

#### IoT Application areas and Devices

| Service Sector               | Application Group                                                                          | Location                                                                                                                                                                                                                         | Devices                                                                                                                                     |
| ---------------------------- | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Buildings                    | - Commercial<br>- Industrial                                                               | Office<br>Education<br>Retail<br>Hospitality<br>Healthcare<br>Airports<br>stadium                                                                                                                                                | HVAC<br>Transport<br>Fire & Safety<br>Lighting<br>Security<br>Access                                                                        |
| Energy                       | - Supply /Demand <br>- Oil / GAS<br>- Alternative                                          | Power generators<br>Transportation &<br>Distribution<br>Low Voltage<br>Power Quality<br>Energy Management<br>Solar & Windmills<br>Electrochemical<br>Rigs, Derricks, pumps<br>Piplelines                                         | Turbines<br>Windmills<br>UPS<br>Batteries<br>Generators<br>Meters<br>Drills<br>Fuel Cells                                                   |
| Consumer and Home            | - Infrastructure<br>- Awareness & Safety<br>- Convenience & Entertainment                  | - Wiring, network access ,energy management<br>- Security / Alerts, Fire safety, Elderly Children, Power protection,<br>- HVAC / Climate , Lighting , Appliances Entertainment                                                   | Cameras, power system, e-readers dishwashers, desktop computer, washers / dryers, Meters, lights , TVs MP3 player, Gaming consoles, alarrms |
| Healthcare and Life sciences | - Care<br>- In Vivo / Home                                                                 | Hospital, ER / Mobile, PoC , Clinic Labs, Doctor's Office<br>Implants, Home monitoring systems<br>Drug discovery diagnostics , labs                                                                                              | MRI, PDAs , Implants , health monitors, Surgical Equipment, Pumps, Monitors, Telemedicine.                                                  |
| Transportation               | - Non-vehicular<br>- Vehicles<br>- Transporation Systems                                   | -Air, Rail, MArine<br>- Consumer, Commercial, construction, off-highway, <br>- Tools, traffic management, navigation                                                                                                             | - Vehicles, lights , ships , planes , signage, tools                                                                                        |
| Industrial                   | - Resource automation<br>- Fluid / Processes <br>- Converting / Discrete<br>- Distribution | - Mining, Irrigation agriculture, woodland<br>- Petrochemical, hydro, carbons, food, beverage<br>- Metal, papers, rubber/ plastic<br>- Metalworking<br>Electronics<br>Assembly / testing                                         | - Pumps, Valves, vats, conveyors, fabrication, assembly / packaging, vessels, tanks                                                         |
| Retail                       | - Specialty<br>- Hospitality<br>- Stores                                                   | - Fuel Stations, Gaming, Bowling, Cinemas, Discos, Special Events, <br>- Hotel restaurants, bars, cafes, clubs<br>Supermarkets, shopping centers, single site, distribution                                                      | - POS Terminals, Tags Cash Registers, Vending machines, Signs, Inventory Control                                                            |
| Security / Public Safety     | Surveillance<br>- Equipment<br>- Tracking<br>- Public Infrastructure                       | Radar / satellite<br>environmental, military, unmanned, fixed<br>Human, animal, postal, food, health, beverage<br>- Water treatment, Building, environmental equipment, personnel equipment, personnel, police, fire, regulatory | Tanks, fighter jets, battlefields, jeeps, cars, ambulance, homeland security, Environment and monitoring                                    |
| IT and Networks              | - Public<br>- Enterprise                                                                   | - SErvices, e-Commerce, data centers, Mobile carriers, ISPs                                                                                                                                                                      | Servers, storage, PCs , routers, switches , wireless access points, PBX                                                                     |
| Scientific                   | Research<br>Public health and safety inititiatives monitoring and analysis                 | - Closed Laboratory<br>- Outdoor (Earth) environment                                                                                                                                                                             | Oceanic atmospheric, and land condition sensors<br>- Animal trackers<br>- Lab environment sensors and actuators                             |
| Agriculture                  | - Precision Farming<br>- Livestock Monitoring<br>- Reduction of resource wastage           | - Farms<br>- Greenhouses<br>- Livestock areas                                                                                                                                                                                    | - Animal wearables<br>- Drones <br>- Soil, irrigation, Environmental sensors and actuators                                                  |

### 18.2 IoT INFRASTRUCTURE
#### IoT Architecture
- End Devices
	- Sensors, RFID tags, readers
	- Gather telemetery
- IoT gateway
	- Connects devices to the cloud
- Cloud Server/ Data Center
	- Connect through web services
	- Data processing and storage
	- Processed data transmitted back to the user
- Remote control
	- End user uses a mobile apps
	- Monitor, control, retrieve data, take an action.
	- User can be in a remote location.

#### IoT has no location or distance limits
- In IoT architecture , there is (theoretically ) no limitation of location or distance between two or more devices
	- Devices and components can be spread across the globe
	- There is, however, a practical consideration regarding bandwidth availability and latency

#### IoT Communication
- IoT Connectivity can be"
	- Wired or wireless, using just about any network transmission type
- Device-to-Device
	- Direct communication between two devices
- Device-to-Cloud
	- Communicates directly to a cloud service
- Device-to-Gateway
	- Communicats to a centralized gateway that gathers data and then sends it to an application server based in the cloud
- Back-End Data sharing
	- Scale devices to a cloud model
	- Allows for multiple devices to interact with one or more application servers
#### IoT Network Scopes
- PAN : IoT Wearables + Smartphones
- LAN : Wi-Fi Devices
- WAN : IoT Long Range Devices

 #### IOT COMMUNICATION , PROTOCOLS AND OSES
 - #ShortRangeWirelssCommunications
	 - Bluetooth low energy (BLE)
	 - Light-Fidelity (Li-Fi)
	 - NFC
	 - QR Codes
	 - Barcodes
	 - RFID
	 - Thread
	 - Wi-Fi
	 - Wi-Fi Direct
	 - Z-Wave
	 - ZigBee
	 - ANT
 - #MediumRangeWirelssCommunications
	 - Ha-Low
	 - LTE-Advanced
	 - 6LoWPAN
	 - QUIC
 - #LongRangeWirelssCommunicataion
	 - Low-power WAN (LPWAN)
		 - LoRaWAN
		 - Sigfox
		 - Neul
	 - Very small aperture Terminal (VSAT)
	 - Cellular
 - #WiredCommunications
	 - Ethernet 
	 - multimedia over Coax
	 - Power-Line Communication (PLC)
 - #IoTOperatingSystems
	 - RIOTOS
	 - ARM embedded OS
	 - RealSense OS X
	 - Nucleus RTOS
	 - Brillo
	 - Contiki
	 - Zephyr
	 - Ubuntu Core
	 - Integrity RTOS
	 - Apache Mynewt
	 - Windows 10 Iot Core
### 18.3 IoT Vulnerabilities and Threats
#### OWASP IoT top 10
##### 1 Weak guessable or hardcoded passwords
- Use of easily brute-forced, publicly available, or unchangeable credentials
- Incudes backdoors in firmware or client software that grants unauthorized access to deployed systems

##### 2 insecure network services
- Unneeded or insecure network services running on the device itself, especially those exposed to the internet
- Compromises the confidentiality, integrity / authenticity, or availability of information or allows unauthorized remote control

##### 3 insecure ecosystem interfaces
- Insecure web, backend API, cloud or mobile interfaces in the ecosystem outside of the device
- Allows compromise of the device or its related components
- Common issues include a lack of authentication / authorization , lacking or weak encryption and a lack of input and input filtering

##### 4 lack of secure update mechanism 
- Lack of ability to securely update the device
- Includes lack of firmware validation on device, lack of secure delivery (un-encrypted in transit)
- Lack of anti-rollback mechanisms
- Lack of notifications of security changes due to updates

##### 5 Use of insecure or outdated components 
- Use of deprecated or insecure software components / libraries that could allow the devices to the compromised
- This includes insecure customization of operating system platforms
- The Use of third-party software or hardware components from a compromised supply chain

##### 6 Insufficient privacy protection
- User's personal information stored on the device or in the ecosystem that is used insecurely, improperly, or without permission.

##### 7 Insecure Data Transfer and Storage
- Lack of encryption or access control of sensitive data anywhere within the ecosystem, including at rest, in transit, or during processing

##### 8 Insecure Default settings
- Lack of security support on devices deployed in production, including asset management, update management, secure decommissioning , systems monitoring , and response capabilities

##### 9 Lack of Device Management
- Devices or systems shipped with insecure default settings or lack the ability to make the system more secure by restricting operators from modifying configurations.

##### 10 Lack of physical hardening
- Lack of physical hardening measures, allowing potential attackers to gain sensitive information that can help in a future remote attack or take local control of the device.

#### IoT Threats
- Casino Lobby smart aquarium
- used as pivot to steal 10 GB of high roller data
- My friend Cayla Bluetooth-enabled interactive doll
	- Attackers take over its camera, mic and speaker
	- Banned in germany after high-profile incidents
- DDos Takes down home thermostats
	- Mirai botnet leaves residents without heat
	- 2 apt complexes, 2 weeks , freezing weather
- Baby monitor remote takeover
	- Attacker moves camera / views and speaks to child
	- 9 models reported from 2009 - 2022
- Jeep SUV remote control hijack
	- Weak password in firmware update
	- Made it speed up, slow down, and veer off the road
#### COMMON IoT Threats
- DDos : Devices join a botnet to perform DDoS against other targets
- Exploiting HVAC: 
	- Attackers uses shodan.io to find targets, the uses www.defpass.com to find default credentials
	- If the attacker can log in, they can send unauthorized commands to the HVAC system, possibly also breaching and IT network
		- Even though it is air-gapped from the IoT network
		- Use environment (temperature) changes to indicates binary data
- Rolling Code
	- Used to steal cars, The ability to join a key Fob's communication to the car, sniff the FoB's code and then create a subsequent code
	- Attacker uses rfcat-rolljam or RFCrack to perform the attack
- BlueBorne Attack
	- Attacks against Bluetooth devices
- Jamming 
	- Jams the signal between sender and receiver
- Remote Access using Backdoor
	- Attacker turns the IoT device into a backdoor to gain access into an organization network
- Remote Access using Telent
	- Obtain information shared between connected devices including hardware's and software's versions
- RootKit / Exploit Kits
	- Malicious Script exploit poorly patched vulnerability in an IoT devices
- MITM : Attacker pretends to be a legitimate sender
	- Attacker pretends to be a legitimate sender
	- intercepts and hijacks all communication between sender and receiver
- Replay
	- Attacker intercepts legitimate messages
	- Continuously resends the message to the target device to crash it or its service
- Forged malicious devices
	- Attacker replaces authentic IoT devices with malicious ones
	- Requires physical access to the network
- Side channel attack
	- Attacker observes the emission of signals (side- channels) to obtain information about encryption keys
- Sybil attack
	- Attacker uses multiple forged identities to creates the strong illusion of roadway traffic congestion
	- Affects communication between neighboring nodes and the network
	- Creates chaos and safety risks
- Client Impersonation
	- Attacker masquerades as a legitimate smart device / server
	- Performs unauthorized activities or accesses sensitive data
- SQL injection
	- Attacker performs SQL injection against vulnerable web or mobile apps
	- Gains access to the device or back end data
- Software-Denied Radio (SDR ) attack
	- Attacker uses a software-based radio to examine communication signals passing through an IoT network
	- Can send spam messages to interconnected devices
- Faults injection Attack
	- An attacker tries to introduce fault behavior in an IoT device. Exceeds operating temperature, voltage, frequency, etc.
	- Seeks to exploits faults to compromise device security
- Network pivoting
	- Attacker uses a malicious smart device to connect and gain access to a closed server
	- Uses that connection as a entry point to attack other normally unreachable devices.
- DNS rebinding Attack
	- Used to breach a private network by causing the victim's web browser to access computer at private IP addresses and return the results to the attacker

#### HOW AN ATTACKER PROFITS FROM A Compromised IoT device
Creates a botnet for use or rent
Sells compromised data
Perform malicious activities
Demands a ransom to unlock devices
Uses the device to steal a victim's identity, credit card information, or other data
Uses compromised CCTV cameras and baby monitors to snoop on or terrorize 
families

#### SCENARIO 
You are attending a cybersecurity conference and just watched a security researcher demonstrating the exploitation of web interface on a SCADA / ICS component
This caused the device to malfunction and be destroyed
You recognized that the same component is used through your company's manufacturing plants
What can be done to protect against this emergent threat?
Evaluate if the web interface must remain open for the system to function . If it isn't needed, block the web interface.

##### SCENARIO EXPLAINATION
The most immediate protection against this emergent threat would be to block the web interface from being accessible over the network
Before doing this, you must evaluate whether the interface needs to remain open for the system to function properly 
If it is not needed , you should block it to minimize the SCADA / ICS component's attack surface
Ideally, your SCADA /ICS component should already be logically or physically isolated from the enterprise network


### 18.4 IoT Hacking Methodology And Tools

#### IoT Hacking Methodology
- Take time to familiarize yourself with IoT technologies:
	- Architecture
	- Hardware
	- Physical Interfaces
	- Signaling
	- Network protocols
	- Device-Specific Operations
- Follow general hacking steps of reconnaisance, penetration and control
	- Keep in mind that there are many , many variation in IoT devices
	- Consider narrowing your focus to just a few IoT device types and use cases
- Expand attack approaches to include
	- Physical / environment attacks
	- Device -specific hardware and softwares 
	- Network communications
	- Control Instructions and Management Apps
	- Cloud Services

#### IOT HARDWARE ANALYSIS

- Soldering Equipment
	- Attach and detach hardware component to circuit boards, physical change circuit pathways.
- Microscope / Magnifying glass
	- Help improve soldering or tiny part handling preceision
- Communication interface (Such a a JTAG)
	- Connection to and Communicate with ICS devices
- Screwdrivers /tweezers
	- Open or disassembles devices, move jumpers and connections
- Signal Analyzer: Test the operation of chips pings
- Multimeter : Tests circuit voltage , current , resistance, continuity.
- Memory Programmer : Use to reprogram flash memory, EPROms / EeFROMS\
- OSCILLOSCOPE : Visually interpret along and digital signals

##### USE tools like 
- JTAG Dongle to connect to circuit boards
- Digital STorage Oscilloscope to view signals 
- RF analyzers
- Firmware analyzers

##### JTAGULATOR
Open source hadware hacking tool, Used to identify on-chip debug (OCD) interfaces on unfamiliar hardware.
Provides chip-level control of a target device. Extract program code or data, modify memory contents, or affect device operation on-the-fly
##### IoT Spectrum Analysis Example
Use Dongles such as #FunCube #Airspy #HackRF #RTL-SDR 
Along with #Gqrx spectrum analyzer

#### FIRMWARE AND OS ANALYSIS
See if the firmware is cryptographycially signed and has an update mechanism
Use tools such as 
#IoTInspector #BinWalk #FirmwareModKit #FirmwareAnalysisToolkit #FirmalyzerEnterprise

#### CHIP WHISPHER NANO FAULT INJECTOR
- Inject glitches into any embedded hardware
- Gain access to the clock or input power of the device

#### DeBuggers / DisAssemeblers
GDB : Linux debugger attacker can use to understqnd the process of on-chip executions
#OpenOCD : Allows attackers to remote to the chip they want examine using #GNUProjectDebugger (TCP 333) or TElnet (23)
#BinWalk : SCan and Examine firmware binaries and images
#Fritzing : Assists attackers in designing electronic diagrams and circuits
#Radare2 : Portable framework to analyze and reverse engineer binaries
OllyDBG, IDA Pro : A code disassembling tool to examine binaries

#### IoT RECON
#### IoT Device RECONNAISSANCE TOOLS
#Shodan #censys #Thingful #googleDorks #z-wave-sniffer #cloudSharkProtocolAnalyzer #UbiqueProtocolAnalyzer #Wireshark #Multipaging #nmap 
```
// scanning TCP ports of a specific device
nmap -n -Pn -sS -pT:0-65525 -v -A -oX <target>

//Scan TCP and UDP ports of a specific device :
nmap -n -Pn -sSU -pT: 0-65535 -V -A -oX <target>

// Scan using IPv6
nmap -6 -n -Pn -sSU -pT:0-65535 -v -A -oX <target>

```

#### SCAN FOR DEVICE WITH DEFAULT CREDENTIALS
- Use IoTSeeker to scan a network
	- Search for specific IoT devices types
	- Checks to see if the devices are using default, factory set credentials
	- AVailable on GitHub
```
/user/rapid7/freetools> perl iotscanner.pl <target>
```


#### IoT Device VUlnerability Scanners
Nmap #multiPingStornFuzzer #Metasploit #IoTSploit #IoTSeeker #BitDefenderHomeScanner #Firmalyzer #IoTInspector #RIoTVulnerabilitySCanner #IoTInspector #RIoTVulnerabilitySCanner #Foren6 #6LoWPAN passive sniffer / scanner

##### RETINA IoT (RIoT) Vulnerability Scanner
- Identifies at-risk devices
- Pinpoints make and model
- Looks for open ports and backdoors, default credentials

#### WIRELESS PROTOCOL TESTING
Attempt to perform replay and MITM attacks
Attempt to gain unauthorized network access
See if you can connect using
	#ZigBee #BluetoothLE #6LoWPAN 
Try to fuzz test the device
Use tool such as :
	#UbiqualprotocolAnalyzer
	#PerytonsProtocolAnalyzer
	#Wireshark
	#SOAPUIPro
	#AttifyZigbee
	#Z3Sec
	

#### MOBILE APP TESTING
Attempt to penetrate mobile apps that connect with the IoT device
Try to access storage, and bypass authentication and authorization
Use tools such as 
	X-Ray
	Threat Scan
	Norton Halt exploit defender
	Shellshock Scanner - Zimperium
	Hackode
	BlueBorne
	EternalBlue Vulnerability Scanner
#### WEB APP TESTING

- Try typical attacks against a web app including buffer overflows, SQL injections bypassing authentication, XSS / XSRF code execution
- Use tools such as 
	- #SAUCELABSFunctionalTesting
	- #Powersploit
	- #KaliLinux
	- #WAFNinja
	- #Arachni 
#### CLOUD SERVICES TESTING
Try to gain unauthorized access to cloud services for the IoT device
Use tools such as
	#ZEPHYR
	#SOASTACLOUDTest
	#LoadStormPro
	#BlazeMeter
	#Nexpose
	
#### IoT Attacks
#HackRFOne
- Software defined radio
- Can transmit or receive radio signals from 1 Mhz to 6 Ghz
- Can be use for :
	- Spectrum analysis
	- BlueBorne attack
	- Replay
	- Fuzzing
	- Jamming

#### KILLERBEE AND ATTIFY ZIGBEE
- Attack Zigbee-enabled device
	- Create an Atmel RzRaven USB stick flashed with killerbee
	- Install attify zigbee
	- Attack
- KillerBee
	- Framework for attacking Zigbee 802.15.4 networks
	- https://github.com/riverloopsec/killerbee
- Attify Zigbee Framework
	- Gui front end for RzRaven
	- https://github.com/attify/attify-zigbee-framework
- Rolling CODE (ROLLJAM) Attack (i.e. car unlock )
	- Capture code from the remote
	- Crack the code
	- Guess the next code
	- Transmit the code to the car
	- `python RFCrack.py -i` //live replay
	- `python RFCrack.py -r -M MOD_2FSK -F 31435000`
- GATTACKER IoT MITM Example
	- Sniff and take over IoT devices

#### IoT Remote Access Attacks
- Use Telnet to gain remote access
- Use firmware Mod Kit to maintain access
- You can also compromise any system that normally  has access to the device
	- Such as a smartphone

#### NOTABLE IOT ATTACKS
##### 1 RIPPLE20
- Ripple20 Zero-Day Vulnerabilities in Treck TCP / IP Libraries
	- Popular IPv6 protocol implementation for embedded systems
	- Affected millions of devices in various industry sectors
- CVE-2020-11896
	- DNS Remote Code Execution Vulnerability
- CVE-2020-11987, CVE-2020-11901
- Inject shellcode on the device via ICMP tunneling
- Github lists 13 repositories related to Ripple20
##### 2 RUBE-GOLDBERG ATTACK
- Exploits a vulnerability known as "Devil's Ivy"
- CVE-2017-9765 
- AFfects over 250 camera models (mostly from AXIS)
- Start by performing a shodan search for AXIS
- The attacker can:
	- Factory reset the camera
	- Gain root access
	- Take over the device
- https://vimeo.com/225922694

##### 3 CLOUDPETS ATTACK
- Cloud-connecting children' toys can be turned into remote surveillance devices
- In 2017 an open MongoDB database was found with personal information hashed passwords and voice recording of messages by children and parents using CloudPets teddy toys
- Exploit: https://github.com/pdjstone/cloudpets-web-bluetooth
- GitHub Lists 10 more repos for cloudpets

##### 4 AMAZON ECHO

- Alexa vs Alexa full volume attack
- Attacker commands echo to say malicious instruction commands to itselfs
- Github list 3 Repos with exploits for Alexis

##### 5 TRENDNET WEBCAM
Multiple Vulnerabilities
- Remote Security ByPass
	- Search shodan for TrendNet Webcams
	- Append a string to the IP to access a hidden live stream
	- Example: `http://<target IP>/Anony/mjpg.cgi`
- Multiple buffer Overflows
	- Search `exploit-db` for "Trendnet"
##### 6 TESLA TBONE
- Zero-Click exploit for Tesla model 3 media control unit (MCU)
	- Exploits two vulnerabilities affecting connman. Internet connection manager for embedded devices
	- Remote code execution over Wi-Fi
- The Tesla automatically connects to the "Tesla Services" "Wi-Fi SSID"
	- Attacker used a drone to hover over the vehical 
	- Drone was running a Wi-Fi hotspot names "Tesla Service"
	- The car automatically connected
	- Attacker logged in using publicly available credentials
	- Took over the infotainment system
	- https://kunnamon.io/tbone/tbone-v1.0.redacted.pdf
##### 7  MIRAI BOTNET DDOS ATTACK
- Mirai first grew a large botnet
	- Performed large IP block scanning to find device with easy to crack  Credentials: Factory defaults, Susceptible to brute forcing
	- 50,000 infected devices (mostly CCTV Cameras)
	- Infections in 164 countries
- Then launched DDos attacks based on instructions received from a remote C&C
	- https://github.com/lestertang/mirai-botnet-source-code

### 18.5 IoT Hacking Countermeasures
#### DEFENDING AGAINST IoT HACKING
- Today there are no longer clearly defined network perimeters
- Attacks are just as likely to pivot off a trusted internal user (phishing - drive-by malware) than through external alone
- Defense in depth is not enough for IoT
- You must create a fabric of defense based on Zero-Trust and automation
	- Every connection and endpoint is considered a threat
	- Analyze activities in real-time
	- Automatically lock threat as they materialize
- Approach security as a unified , integrated, holistic system
- Create an asset inventory and map out all possible ingress and egress paths
- Determine if the IoT networks has its own (inappropriate / rogue ) internet gateway 
- Disable Guest and demo accounts if enabled
- Implement any existing lockout feature
- Implement the strongest available authentication mechanism. Prefer two way authentication with SHA and HMAC hashing
- Locate control system network and devices behind firewalls
- Isolates them from the business network
- Implement IDS / IPS on the network
- Implement end-to-end encryption using 
- USe VPNs when possible
- Only Allow trusted IP Address to access the device from the Internet
- Disable UPnP ports on routers
- Protect devices from physical tampering
- Patch vulnerabilities and update firmware if available
- Implement secure boot with cryptographic code signing when possible
- Monitor traffic on port 48101 as infected devices tend to use this port
- Ensure that a vehicle has only one identity
- Implement data privacy and protection as much as possible
- Implement data authentication, authenticity and encryption whenever possible.
- Use a CAPTCHA with account lockout to avoid brute forcing
- Use a trusted execution environment (TEE ) to secure sensitive information
- Validate code immediately before its use to reduce the risk of time-of-check to time-of-use (TOC-TOU) attacks
- Secure encryption keys in a secure Access Module (SAM) Trusted Platform Module (TPM) or hardware security Module (HSM)
- Disable WEbRTC in the browser to prevent disclosure of IP addresses
- USe ad blockers and non-trackable browser extensions to prevent web-based attacks on IoT devices.
- Consider using a SaaS platform Azure IoT Central to simplify IoT setup.

#### IOT SECURITY TOOLS
#SeaCat #DigiCertIoTSecuritySolution #PulseIoTSecurityPlatform #SymantecIoTSEcurity #GoogleCloudIoT #NEt-Shield #TrustWaveEndpointProtectionSuite #NSFOCUSADS #DARKTRACE #NODDOS #CISCO #IoTThreatDefense #AWSIoTDeviceDefendr #Zvelo0IoTSecuritySolution #CiscoUmbrella #CarWall #BAyshoreIndustrialCyberProtectionPlatform

### 18.6 OT Operational Technology Concepts

#### OPERATION TECHNOLOGY (OT)
IoT focused on industry operations
USed to monitor, run and control industrial process assets

#### ESSENTIAL OT Terminology
- Assets : 
	- Physical devices such as sensors, actuators , servers , workstations , network devices, programmable logic controller (PLCs)
	- Logical assets such as flow graphics, program logic, database, firmware, firewall rules
- Zones and Conduits
	- A network segregation technique
	- Isolates networks and assets into security zones to impose strong access control
- Industrial Network
	- A network of automated control systems
- Business Network
	- AKA Enterprise network
	- A "normal" IT network of system that provide information infrastructure for the business.
- Industrial Protocols
	- Protocols such as s7 (Proprietary) , CDA , SRTP and non-proprietary) Modbus , OPC, DNP3, CIP
	- Used to serial communication or over standard Ethernet
- Network Perimeter
	- Outermost boundary of a network zone.
- Electronic Security Perimeter
	- Boundary between secure and insecure zones
- Critical Infrastructure
	- A collection of physical or logical systems and assets
	- If it fails or is destroyed it would severely impact security, the economy or public health

#### COMPONENT OF OT
- SCADA : Supervisory Control and Data Acquisition (is the central code)
- Communicated via #DCS Distributed Control System #RTU Remote Terminal Unit #PLC Programmable Logic Controller
- #ICS Industrial Control Systems
- #IIoT Industrial IoT
- OT
#### IIoT
- A subset of the Larger IoT
- The use of IoT in industrial sectors and applications. Including rebotics, medical devices, and software-defined production processes
- Collect and share data between devices to make decisions without human interaction
- Strong focus on:
	- Machine-to-machine (M2M) communication
	- Big Data
	- Machine Learning
- Leverage cloud based serverless architecture for large scale analytics . Data from individual SCADA systems feed #IIoT
- #IIoT enables industries and enterprises to have better efficiency and reliability in their operations

#### EVOLUTION OF INDUSTRY TO IoT
industry 1.0 : manual production
industry 2.0 : Industry + electricity = MAss Production
industry 3.0 : Mass production + computerised manufactoring = #SCADA supervisor control and DAta acquisition : 
industry 4.0 : SCADA+ internet = IIoT

### 18.7 IT-OT CONVERGENCE
#### IoT Convergence
These two work together
- OT : Manufacturing Zone:
	- Mechanical Devices
	- SCADA
	- DCS
	- PLCs
	- RTUs
- IT Enterprise Zone
	- Cloud 
	- internet
	- Networks
	- Storage and Data Processing
	- SQL, JAVA , Python, etc.

##### ENTERPRISE ZONE
- IT Systems:
	- Technologies and Protocols: DCOM, DDE, FTP/ SFTP , GC-SRTP, IPv4, IPv6, OPC , TCP/IP, Wi-Fi
- Level-5 Enterprise Network
	- Business-to-Business (B2B)
	- Business-to-Customer (B2C)
	- Accumulates data from subsystems at individual plats
	- Aggregates inventory and overall production status
- Level 4 - Business Logistics Systems
	- IT systems that support production
	- Application, file and database servers
	- Supervising systems
	- Email Systems
##### Manufacturing Zone
- OT System
- Level-3 Operating Systems / Site Operations
	- Technologies and protocols - CC-Link, DDE , G-SRTP , HSCP , ICCP , MODBUS, NTP , Profinet, SuiteLink , Tase-2 , TCP/IP
- Level-2 : Control Systems / Area Supervisory Controls
	- Technologies and Protocols
		- 6LoWPAN, CC-Link, DNP3, DNS / DNSSEC , FT, HART-IP, IEC 60870-5-101 , IPv4 / IPv6 , ISA, OPA, OPC, NTP, SOAP, TCP/IP
- Level-1 : Basic Controls / Intelligent Devices
	- Technologies and Protocols
		- BACnet, Ethrecat, CANOpen, Crimson v3, DeviceNet, GE-SRTP, Zigbee, ISA/IEC 624423, MELSEC-Q, MODBUS, NIAGARA FOX, Omron Fins, PCWorx, Profibus, Profinet, Sercos II, S7 , WiMax

#### PROTECTING OT FROM IT
- Enterprise and manufacturing zones are often connected via ethernet
- A standalone , unconnected ("islanded") OT system is inherently safer from outside threats that one connected to an etnerprise IT system(s). Nearly all enterprise network have external connectivity
- An intermittently connected OT System can be a good compromise.
	- It is only at risk when it is connected
	- Connections should be on a need-basis such as for downloading updates or limited-time remote access
- The most common external connectivity into the OT environment is 3rd party connections from vendors. Their risk becomes your risk

### 18.8 OT Components
#### #ICS Industrial Control System
- Collection of different types of control systems such as :
	- #SCADA #DCS #BPCS #SIS #HMI #PLCs #RTU #IED
- #ICS is extensively used in 
	- Electricity production and distribution
	- Water supply and waste water treatment
	- oil and natural gas supply
	- Chemical and pharmaceutical production
	- Pulp and paper
	- food and beverages
- #PlantFirewall controll the Network Switch to trigger Process A , B C
- ICS COnfiguration
	- ICS System are configured in one or three modes
		- Open Loop : Output of the system depends on the preconfigured settings
		- Closed Loop : The out always has an effect on the input to acquire the desired objective.
		- Manual Mode: The system is totally under the control of humans
#### #SCADA Supervisory Control And Data Acquisition
- A subset of ICS
- A centralized supervisory control system. Provides central supervision over a variety of proprietary systems
- Used for controlling and monitoring: 
	- Industrial facilities and infrastructures
	- Multiple process inputs and outputs
- Integrates data acquisition with data transmission and Human MAchine Interface #HMI Software
	- HNI-Touch Screen operator control
	- RTU (Remote Terminal Unit) Suitable for wider geogrphical telemetry; transmits telemetry data from field instruments directly to master control systems
	- PLC (Programmable Logic Controller) Can autonomously locally execute simple logic processes without involving the supervisory computer
- In the past , depended on "security through obscurity"
- Now largely uses web technologies for human system interaction

#### #PLC Programmable Logic Controller
- A small , solid-state control computer
- Controls a local process autonomously
- You can customize its instructions to perform a specific task
- Has a CPU module, and power supply module, and I/O modules
- Connects to other components via:
	- RS-232 serial cables
	- Modbus RTU serial cables
	- Ethernet TCP/IP
	- Modbus TCP/IP
	- Profinet
- PLC Architecture
	- Input Sensors : Switches, smart devices
	- Processing Unit : CPU/Memory/Communication 
	- Output Section: : Motor starters, Lights valves, Smart devices
- Remote PLC Example:
	- WebScreen/Mobile Device connected to webserver via Internet
	- WebServer than contolling Programmable controller FP7
	- This controller than using Modbus TCP/ on Ethernet or by Modbus RTU via Serial communication
#### #HMI Human-Machine Interface
Any interface or dashboard that connects a person to a machine
Typically a touch screen used in an industrial process
HMIs communicate with Programmable Logic Controller (PLCs ) and input/ Output sensors
They get and displays information for users to view
They can send commands
HMI screens can be used for:
	A single function like monitoring and tracking
	Performing more sophisticated operations like switching machines off or increasing production speed

#### #RTU Remote Terminal Unit
- AKa Remote Telemetry or telecontrol unit
- Microprocessor-based device
- Typically installed in a remote location as part of a large system
- Monitor and controls field devices
	- Valves, actuators, sensor , and more
- Connects to a distributed control system or SCADA
- Transmits telemetry data to a master system
- Uses messages from the master supervisory system to control connected objects
#### #RTU vs #PLC 
similar but not the same
PLC and RTU have many overlapping functionality

| PLC                                                                  | RTU                                            |
| -------------------------------------------------------------------- | ---------------------------------------------- |
| Used for putput control of device like valves, pumps motors etc      | Genrelly not used for output control           |
| Wired connectivity                                                   | Wireless connectivity                          |
| Local use                                                            | Wider geographical telemetry                   |
| Might have built-in display<br>Connection to SCADA not a requirement | No built in display must be connected to SCADA |
| Cheaper                                                              | More expensive                                 |

#### #DCS Distributed Control System
- A highly engineered large-scale control system
- Often used to perform industry-specific tasks
- Contains a centralized supervisory control unit
- Used to control
	- Multiple local controller
	- Thousands of I/O points
	- Various other field devices
- Operates using a centralized supervisory control loop (SCADA , MTU*)
	- Connects a group of localized controller (RTU/ PLC)
	- Executes the overall tasks required for the entire production process
	- Used to control production systems spread within the same geographical location
- For industry-specific tasks
- Large, complex, distributed processes such as:
	- Chemicals manufacturing nuclear plants, oils refineries, water and sewage treatments plants, electric power generation, automobile and pharmaceutical manufacturing
- It can have Main Supervisory control server and Redundancy Server to control Process A/B/C having PLC/RTU example
	- Process A: Having `Temperature` sensor at PLC1 to operate `Boiler`
	- Process B: Having `Transmitter` at PLC2 to operate the `control valves`
	- Process C: Having Pumps at PLC3 to operate the `motor`
> Master terminal Unit - The heart of the SCADA system

#### ADDITIONAL COMPONENTS
#### #BPCS Basic Process Control System
- Responsible for process control and monitoring of the industrial infrastructure
- Responds to input signals from the process and associated equipment
- Generates output signals that make the process and equipment operate as required
- Commonly used in feedback loops such as:
	- Temperature control
	- Batch control
	- Pressure control
	- Flow Control
	- Feedback and Feed-forward controls for chemical, oil and gas, and food and beverage
- BPCS Closed Loop Architecture
	- Set values on error flag to controller
	- Controller signals to Final Control Element. 
	- Process variable signal to Transmitter via  (i.e Temparature flow) via primary element (i.e. Transducer) 
	- This transmitter than set the process variable
#### #SIS SAFETY INSTRUMENTED SYSTEM
- Automated control system designed to safeguard the manufacturing environment
- Automatically shuts down the sytem in case of a hazardous incident . Overrides the BPCS
- Part of risk management strategy

#### THE COMPLETE PICTURE
1. ==IT==: Corporate DMZ, COrporate ENTERPRISE SYSTEM, OPERATION DMZ
2. ==OT==: SUPERVISORY CONTROL, Basic Control, Sensors and Equipment under control

### 18.9 OT Vulnerabilities
#### OT 's' Biggest Security challenge
- ICS and SCADA system are difficult to retrofit with modern security
- Most were developed many years before security standards were established and integrated into their design
- Many of these older systems data back to the in 1970s and are still in use today
- Over time, these systems were incorporated into the organization TCP/ IP data networks : This provides a huge exploitation area by penetration tester and attackers alike
- Many ICS and SCADA vendors are slow to implement security measures
- Because they cannot be easily retrofitted with the newer security requirements
- For ecample, some ICS/SCADA systems use a proprietary operating ssytem
- More Modern ICS /SCADA operates using a version of Windows
- However, many still use Windows XP , making them much more vulnerable since they cannot be upgraded to windows 10 without hardware replacement
- ICS and SCADA systems should ALWAYS be isolated from production networks and segmented into their own logical network (VLANs)

#### OT CHALLENGES\
- LAck of Visibility
- Plaintext / weak passwords
- Network complexity
- Legacy technology
- Lack of antivirus protection
- Lack of skilled security professionals
- Rapid pace of change
- Outdated Systems
- Haphazard modernization
- Insecure connections
- Usage of rogue devices
- Convergence with IT
- Organization challenges
- Unique production networks / proprietary software
- Vulnerable communication protocols
- Remote Management Protocols


#### COMMON #OT Vulnerabilities

| Vulnerability                                                         | Description                                                                                                                                                                                                                                                                                                       |
| --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Publicly Accessible OT Systems                                        | - OT System that are directly connected to the Internet of the convenience of vendor maintenance<br>- OT Systems not protected by modern security controls<br>- Ability to perform password brute-forcing or probe OT systems to disable or disrupt their functions                                               |
| Insecure Remote Connections                                           | Corporate network use jump boxes to establish remote connectivity to the ICS / SCADA network<br>Attacker exploit vulnerabilities in those jump boxes                                                                                                                                                              |
| Missing Security Updates                                              | Outdated software versions lead to increased risk and provide a path for attackers to compromise a system.                                                                                                                                                                                                        |
| Weak PAsswords                                                        | Use of default usernames and passwords for OT systems                                                                                                                                                                                                                                                             |
| Insecure Firewall configuration                                       | - Misconfigured access rules allow unnecessary connection between IT and OT networks<br>Support teams allow excessive permissions to the management interfaces on the firewalls<br>- Insecure firewalls propagate security threats to the OT network<br>                                                          |
| OT Systems Placed withing the corporate IT network                    | - Corporate systems are interconnected with the OT network to access operational data or export data to third-part management systems<br>- OT systems such as control stations and reporting servers are placed within the IT network<br>- Ability to use compromised IT systems to gain access to the OT network |
| Insufficient Security for corporate IT network from OT systems        | - Attacks can also originate from OT systems, then pivoting to the corporate network                                                                                                                                                                                                                              |
| Lack of Segmentation within OT networks                               | - Several OT networks have a flat and unsegmented configuration which assumes all system have equal importance and functions<br>- Compromise of a single device may expose the entire OT network                                                                                                                  |
| Lack of Encryption and Authentication for Wireless OT networks        | - Wi-Fi and other radio equipement in OT networks use insecure or outdated security protocols <br>- Attackers can sniff, bypass authentication, and take over RF communications                                                                                                                                   |
| Unrestricted of encryption and Authentication for wireless OT network | - OT network allow direct outbound network connections to support patching and maintenance from a remote location<br>- Increase risk of malware, command-and-control, and other remote attacks                                                                                                                    |
#### WELL-KNOWN IMFAMOUS OT ATTACKs In History
###### 1 Colonial Pipeline (2021)
- Ransomeware attack halted petroleum pipeline operations
- Shuttered gas stations and grounded some commercial flights in 17 States for a week
##### 2 casino Database Accessed via fish tank (2018)
- Attackers used an IoT-Connected fish tank thermostate to exfiltrate information from the casion's High Roller database
##### 3 some Water Company (2016)
- Attackers accessed the water district's valve and flow control applicatin
- They reprogrammed PLCs to alter the number of chemical entering the water supply, affecting water treatment and production capabilities
- This caused water supply recovery times to increase

##### 4 Ukraine Power Grid (2016, 2015)
- Attackers repurposed Blackenergy3 (MS office macro malware)
- Corrupted Human MAchine interfaces
- Caused monitoring stations to abruptly go blind and breakers to trip in 30 substations 
- Shut off electricity to approximately 225K customers

##### 5 German Steel Mill (2014)
- Attackers gained access to the business network of the steel plant
- They pivoted from that into the production network
- It caused many failures of individual control systems
- Ultimately prevented a blast furnace from shutting down in a controlled manner 
- caused extensive damage to the plant

##### 6 New York Dam (2013)
- Attackers gained access to a SCADA system that was connected to the Internet via a Cellular modem

##### 7 Target Stores (2013)
- Attackers broke into a third-party that maintained target stores HVAC control system
- This gave them access to the business network
- They uploaded malicious credit card stealing software to cash registers across Target's chains of stores
##### 8 Night Dragon (2010)
- Targeted global oil, energy , and petrochemical companies
- Attackers collected data from SCADA systems

##### 9 Stuxnet (2010)
- A complex worm that damaged as many as one-fifth of the nuclear power centrifuges in Iran, 
- First known threat to specifically target SCADA systems in order to control networks
- Infected servers using windows SMB Vulnerability
- Attacked SIEMENS PLC controllers
- Copied itself into Step 7 projects to sabotage code on the PLCs

### 18.10 OT ATTACK METHODOLOGY AND TOOLS

#### OT ATTACK METHODOLOGY
- Operational Technology is a very large tent encompassing a broad spectrum of device types, protocols, connectivity and processes
- OT offer many vectors for attack
	- Internet facing IoT devices
	- It-OT connection
	- Diverse ICS platforms
	- Extended SCADA networking architecture
	- Physical hardware
	- Proprietary protocols
	- Un-remediated vulnerabilities in legacy systems
	- Human Social Engineering

#### ICS / SCADA Attack Tools
- ICS Exploitation Framework / ICSPLOIT : Test for PLC and ICS software vulnerabilities
- PLCinject : used to inject code into PLCs
- MODBUS Penetration Testing Framework (SMOD) : A full-featured framework for penetesting the ModBus (PCL Data communicatins) protocol
- #Moki Linux: A customized version of Kali Linux geared towards ICS/ SCADA penetesting professionals
- #Sixnet-tools: Tool for exploiting sixnet RTUs
- Note: all of the above available on github
- mgtget : Perl script for making modbus trascation from the command line
- SCADA shutdown Tool : PLC hacking tool, Fuzz , Scan and run remote commands
- Modbus-cli : Read and manipulate Modbus register values
- Visit exploit.kitploit.com for additional ics/scada exploits
- #Metasploit : has over 200 ICS and SCADA scanners and exploits
- #SearchSploit : has over 64 SCADA / ICS exploits

#### #OT RECONNAISSANCE
#shadon #SearchDiggity #KamerkaGui #RedPoint #s7Scan #SCADAPASS #PLCScan #nmap 
```
// Scan well-knwon ICS / SCADA ports:
nmap -Pn -sT --scan-delay 1s --max-parallelism 1 -p 80, 102, 443, 502, 530, 593, 789, 1089-1091, 1962, 2222, 2404, 4000, 4840, 4843, 4911, 9600, 19999, 20000, 20547, 34962-34964, 34980, 44818, 46823, 46824, 55000-55002 <target IP>

//identify HMI Systems
nmap -Pn -St -p 46824 <target IP>

//Scan Siemens SIMATIC PLCs:
nmap -Pn -St -p 102 --Script w7-info <target IP>

// Scan Modbus Devices:
nmap -Pn -sT -p 502 --Script modbus-discover <target IP>

// Scan BACnet Devices:
nmap -Pn -sU -o 47808 --script bacnet-info <target IP>

// Scan Ethernet/ IP Devices
nmap -Pn -sU -p 44828 --script enip-info <target IP>

//Scan niagra fox devices
nmap -Pn -sT -p 1911, 4911 --script fox-info <target IP>

//scan ProConOS Devices
nmap -Pn -sT -p 20547 --script proconos-info <target IP>

//Scan OMRON PLC Devices:
nmap -Pn -sT -p 9600 --script omron-info <target IP>

//SCAN PCWorx Devices:
nmap -Pn -sT -p 1962 --script pcworx <target IP>


```

#### SNIFFER / VULNERABILITY SCANNERS
- #Skybox : 
	- Detailed path analysis across OT-IT networks
	- Provides insight into vulnerablilities attack vectors
- #nessus : Vulnerabilities scanner
- #Nework Miner , Wireshark : Passive sniffers
- #GrassMarlin : ICS /SCADA passive network topology mapper
- SmartRF PAcket sniffer: 
	- Uses the CC13xx an cc26 xx family of captures devices
	- Display over-the-air packets of zigbee, Easylink, BLE 
- #Cyberx : IoT / ICS vulnerability Scanner
- 


#### COMMON PLC TCP PORTS BY PRODUCT
- Allen Bradley - Newer Rockwell PLC : 44818
- Allen Bradely - Older Rockwell PLCs : TCP
- BECKHOFF Embedded PC : 48898
- C-More HMI programming : 9999
- Danfoss ECL APEX : 5050
- FATEK FB Series : 500
- GE FANUS SERIES 90-30 : 18245
- GE SRTP Uses TCP Ports 18245 and 18246
- GE QuickPanels Use TCP port : 57176
- HITACHI EHV SEries 3004
- KEYENCE KV 5000 8501
- Korenix 6550 : 502
- Koyo Ethernet : 28784
- LS GLOFA FENet : 2004
- LS XGB FENet : 2004
- LS XGK FEnet : 2004
- Memobus (Yaskawa MP Series Controller) : 502
- Mitsubishi FX : 1025
- Mitsubishi FX3u (Ethernet) : 5001
- Mitsubishi MELSEC-Q  (Ethernet ) : 4999
- Mitsubishi MR-MQ100 (Ethernet) : 4999
- Mitsubishi QJ71E71 (Ethernet) : 5002
- MODBUS TCP / IP (Ethernet) : 502
- MODBUS Server (ModBus RTU Slave) : 502
- OMRON PCC : 9600
- Panasonic FP (Ethernet) : 9094
- Panasonic FP2 (Ethernet) : 8500
- Parker Drives Using MODBUS TCP/IP (Ethernet): 502
- RED Lion HMIs 789
- SAIA S-BUS (Ethernet) : 5050
- SChelecher XCX 300 : 20547
- Simemens S5 Protocol Uses TCP port : 102
- Toshiba Series PLCs uses Modbus Port : 502
- Unitronics Socket1 - TCP : 20256
- Unitronics Socket2 - TCP Slave : 502
- UnitronicsSW Socket3 - TCP Slave 20257
- WAGo CODESYS - TCP :2455
- YAMAHA NETWORK BOARD ETHERNET RCX SEries use telnet port :23
- YASKAWA MP Series Ethernet : 10000
- YASKAWA MP2300Siec : 44818
- YASKAWA SMC 3010 Ethernet : 23
- YOkogawa FA-M3 (Ethernet): 12289


#### #OT PENETRATION AND CONTROL

- OT is subject to all IoT attacks, an many of the dame attacks on regular IT network
- Spear phishing
- Unauthorized access
- Password cracking
- malware / trojan / bots
- Protocol Abuse
- Potential Destruction of Resources
- Denial-of-Service
- Side-channel attacks
- Hardware-specific attacks
#### #OT Attack tools
- MITRE ATT&CK lists 79 techniques for attacking ICS [link](https://attack.mitre.org/techniques/ics)
- Metasploit lists 72 modules to attack ICS/SCADA. 18 exploits with a rank of great or excellent
- Github lists about a dozen ICS/SCADA/PLC /RTU exploits
- Exploit-DB lists 25 verified SCADA exploits
- Shodan.io returns 2700+ results for ICS , 1300+ results for SCADA


#### OT FILELESS MALEWARE
- MegaCortext
	- Fileless OT ransomeware
	- Distributed by QakBot (QBot) . Emotet, or Reitspoof trojan
	- Uses psExec to execute malicious commands
- Other File less OT Malware
	- Disruptionware
	- LockerGoga
	- Triton
	- Olymptoc Destroyer
	- SamSam
	- Shamoon3
	- VPNFilter
	- Havex
#### #HMI ATTACKS
- HMI is the local control station a human operator uses to manage a particular ICS/ SCADA devices
- OS is typically {Windows IoT core, Linux Core}
- It is especially subject to:
	- Memory corruption
	- Credential Management
	- Lack of authentication / Authorization
	- Insecure Defaults
	- Code Injection

#### #PLC Attack
- PLC Rootkit Attack
- PLC code tampering
- Payload sabotage attacks
- Worms and Trojan such as 
	- PLC Blaster 
		- Siemens s7 PLCs
		- TC 102
	- Stuxnet
		- Considered the first cyber weapon
		- Destroys uranium enrichment centrifuges by causing them to spin erratically
		- Targeted attack causing extensive damage to Iran's nuclear program
		- [link](https://github.com/loneicewolf/Stuxnet-source)
	
#### SIDE-CHANNEL ATTACKS
Timing Analysis , Power Analysis 
- Input Ciphertext , 
- Use of Side Channel Information like {Power consumption, Electromagnetic Radiation, Injection of faults, Acoustic Sounds} ==> Side Channel Analysis ==> Output plaintext

#### #RTU Attacks
- Direct dial to RTU modems
	- Most have default or no authentications
	- Most will identify themselves on answer
	- Attacker can then research and use its commands
		- Attacker can then research and use its commands
	- Target Modbus communications
		- Crafted #modbus / TCP packet exceeding MTU of 260 bytes can cause DoS
		- Clear text makes it easy to sniff
	- Target update packages

#### CRITICAL #RTU ATTACK EXAMPLES
CVE-02019-14931
	Unauthenticated remote OS Command Injection
	Complete CIA comprosmise
	Mitsubishi Electric ME-RTU devices through 2.02
	INEA ME-RTU devices through 30.
	CVSS 10.0
CVE-2017-12739
	Unauthenticated RCE
	Siemens SICAM RTUs SM-2556 COM Modules
	Integrated Web Werver (port 80 / TCP) of affected devices could allow unauthenticated remote attackers to execute arbitrary code on the affected device
	CVSS 10.0

#### #RF Control Hacking
- Radio frequency (RF) protocol are often used to control
- Used for simple operation such as turning on a motor (drills), lifting a load (cranes) , or maneuvering a heavy-duty vehical
- They are fixed codes that can be sniffed and replayed
- CVE-2018-17935, CVE-2018-19023: Authentication Bypass by capture-Replay CVSS 801
#### #RF Remote Control Attack Types
- Replay attack
- Command Injection / Command Spoofing
- Abusing Emergency Stop (E-Stop)
	- An attacker can replay emergency stop commands indefinitely to engage a persistent denial-of-service condition
	- Its also possible for an attacker to turn a machine back on, even though the operator issued and emergency stop
- Re-pairing with malicious RF controller
- Cloning a remote controller
- Malicious Reprogramming Attack
- DDoS
- RF Remote Control Example 
	- Attacker Record the Command from Transmitter
	- Captures the data and processed for commands
	- Attacker than Transmit recorded command to misuse it.
#### #Requack
- Practical POC for RF Control Attacks
- Batter-powered, pocket-sized embedded device for remote access
- Attacker against temporary physical access to the facility
- Hides device in an inconspicuous place
- Device must be in RF range of the machines
- Device is remote controlled by the attacker
- Built by TrendMicro Researchers (2019)

### 18.11 #OT Hacking Counter Measures
#### #UEBA USER and Entity Behavior Analysis
- ICS, SCADA and IoT devices often run proprietary , inaccessible  or uncatchable operating systems
- Traditionally tools used to detect the presence of malicious cyber activity in normal enterprise networks will not function properly
- User and entity behavior analytics (UEBA) is best suited to detect and classify known-good behavior from these systems to create as baseline
	- Once a known-good baseline is established, deviations can be detected and analyzed
	- May be heavily dependent on artificial intelligence and machine learning
	- May also have higher false-positive rate
- UEBA is now evolving into Extended Detection and Response (XDR)
- Tools include
- Rapid7 InsightIDR
- Splunk
- Aruba IntroSpect
#### CONSIDERATION FOR APPLYING ANTIVIRUS UPDATES AND PATCHING
- A SCADA workstation might be isolated from the internet
- infections are often caused by removal media
- Once the system is cleaned, and anti-malware solution will need to be manually updated to ensure it has the latest virus definitions
- The same goes for applying security patches
- Without the latest virus definitions or patches, the system can easily become re-infected
#### ICS / SCADA Protection Recommendations
As recommended by the US Department of Energy , CISA , NSA and FBI:
- Isolate ICS / SCADA systems and networks from corporate and Internet networks
	- Use Strong perimeter controls
	- Limit any communications entering or leaving ICS / SCADA perimeters
- Enforce multifactor authentication for all remote access to ICS networks and device whenever possible
- Have a cyber incident response plan. Exercise it regularly with stakeholders in IT, Cybersecurity and Operations
- Change all passwords to ICS/ SCADA devices and systems on a consistent schedule
- Ensure Open Platform Communications / Unified Architecture (OPC UA) Security is correctly configured
	- Application authentication enabled
	- Explicit trust lists
- Ensures the OPC UA certificate private keys and user passwords are stored securely
- Maintain known-good offline backups for faster recovery upon a disruptive attack. Conduct hashing and integrity checks on firmware and controller configuration files to ensure backup validity
- Li9mit ICS/ SCADA systems network connections to only specifically allowed management and engineering workstations
- Robustly protect management systems by configuring:
	- Device guard
	- Credential Guard
	- Hypervisor code integrity (HVCI)
- Install Endpoint Detection and Response (EDR) solutions on these subnets
- Ensure Strong anti-virus file reputation settings are configured
- Implement robust log collection and retention from ICS / SCADA systems and management subnets.
- Leverage a continuous OT monitoring solution to alert on malicious indicators and behaviors
	- Watch internal systems and communications for known hostile actions and lateral movement
	- For enhanced network visibility to potentially identify abnormal traffic, consider using CISA's open source industrial control system network protocol parsers (ICSNPP)
- Ensure all applications are only installed when necessary for operations
- Enforce principle of least privilege, Only use admin accounts when required for tasks, such as installing software updates.
- Investigate symptoms of denial of service or connection severing
	- These exhibit as delays in communications processing, loss of function requiring a reboot, and delayed actions to operator comments as signs of potential malicious activity
- Monitor systems for loading of unusual drivers, especially for #ASROck driver if no ASRock driver is normally used on the system

#### #OT Security Best Practices
- Implement a dedicated VPN gateway or jump host, within the enterprise DMZ.
	- This should be the only access point into the plant environment for remote users
	- Remote access should never be enabled by default
- Implement a default "deny all" access policy across the external-to-internal communication boundary
- Establish remote access multi-factor authentication #MFA were possible
- Implement enhanced logging and monitoring
	- across the IT / OT boundary
	- For any highly critical assets within the OT environment
	- This helps you identify traffic from rogue device that may have gained access to the OT network.
- Implement network micro-segmentation
	- Physical air-gapping
	- Separate VLANs for distinct groups of assets
	- Reduces the risk ofr wide-scale compromise

#### IDS / IPS for OT
- ICS / SCADA machine utilize very specific commands to control equipment
- You could set up strict IDS / IPS rules to detect and prevent unknown types of actions from being allowed to occur
- Tools include:
	- #SPLUNK #AlienVaultSIEM #Dragos #McAfee #SecurityOnion #Nessus 
#### OT Security Tools
- Indegy Industrial Cybersecurity Suite
- Tenable Industrial Security
- Flowmon
- Singtel
- Forecount
- PA-220R
#### IOT/ OT Monitoring TOOLS
- (Princeton) IoT inspector
	- Open source tool to watch network interactions of your SOHO / Home IoT devices
	- Currently under major revision -re launch slated for spring 2023
	- https://inspector.engineering.nyu.edu
- #Domotz : remote monitoring and management
- #Splunk Industrial for IoT : Monitoring and problem root cause analysis
- #Datadog IoT Monitoring : Performance and security monitoring
- #TeamView IoT : Remote Monitoring and management
- #AWS IoT Device Management : Cloud-based IoT monitoring and Management

#### OT Security Organizations
- Operations Technology Cybersecurity Alliance (www.otcsalliance.org)
- Operational Technology Information Sharing and analysis Center (www.otisac.org)
- International Operation Technology Security Association ( #iosta)

### 18.12 IOT AND OT HACKING REVIEW
- The internet of Things refers to everyday devices that 
	- can connect to a network to transmit data
	- are not considered transitional computers
- IoT devices can use a very wide range of networking protocols and transmission types. Most use some form of wireless communication (Bluetooth, Cellular, ZigBee, Z-Wave, Wi-Fi)
- The vast majority of IoT devices are:
	- purpose built for a specific task
	- Smaller with few security task
- IoT devices may or may not use IP addresses . They may use MAC addresses or some other identifier
- IoT hacking can include:
	- Physically or logically attacking the device itself
	- Intercepting, modifying, spoofing or replaying its transmissions
	- Attacking the phone / web / router app that it connects to 
	- Connecting to unsecured devices that are directly exposed to the internet
- OT is subset of IoT
	- IT is the hardware and software, OT attacks tend to focus or industrial control systems (ICS and SCADA)
	- OT attacks an not only shut down company equipment that affect only a company, but some equipment can be connected to and affect human life
- Both IoT and OT present a new , uncharted frontier in cyber security
- OT uses security zones to keep the business IT network separate from the manufacturing / industrial network
	- Ideally there should be no connection between the two
	- Attackers can compromise either network , and then pivot to the other network
- OT components include IIoT , ICS , SCADA , DCS , RTU , PLC , BPCS and SIS 
- OT's biggest challenge is that ICS and SCADA systems are difficult to retrofit with modern security
- OT countermeasures should include all the typical ones used to protect IoT and IT , as well as OT device-specific vulnerability


	- 

	- Mo

- 



- 

- 





