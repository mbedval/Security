### 16.1 WIRELESS CONCEPTS
#### WIRELESS LAN #WAN
- LAN based on wireless radio technologies
- Wi-Fi is the most common implementation
- Adds security risks because the network is "unbounded"

#### Advantages 
- Fast, easy installation
- Easy connectivity where cables can't easily be used
- Connectivity from anywhere, so long as you are in range of an access point
- Seamlessly extends a wired LAN
- Makes it easy to offer free Internet for worker and guest

##### Disadvantages
- The unbounded nature of radio makes security a greater concern than in  wired network
- A single access point can become overwhelmed by too many client requests
- Enhancement may need new wireless access points and /or wireless cards
- Wi-Fie networks can be disrupted by electromagnetic and radio frequency interference

#### ISM BAND
- Industrial, Scientific and Medical Band
- Collection of frequency range for various uses
- Devices need not be licensed
- Transmission power must not exceed 1 watt
- Wi-Fi uses the 2.4 GHz, 5GHz and 6 GHZ bands
- Electromagnetic frequency Scale
	- 902-928 MHz (26 MHz) : 
	- 2.4-2.4835 GHz (83.5MHz) [IEEE 802.11] 
	- 5 GHz HyperLan1 and HyperLan2 [IEEE 802.11]


#### SERVICE SET IDENTIFIER #SSID
- The friendly name given to the wireless network
- Need not be unique
- Can be hidden (not advertised)
	- You can still connect to the WLAN if you know the SSID
	- You'll have to manually enter the SSID

#### BASIC SERVICE SET #BSS 
- Simple WLAN with one:
	- Wireless access point
	- SSID (AP advertises itself)
	- Channel
	- BSSID (MAC Address of AP)
- Typically can accommodate up to 10 clients
- Usually an extension of the LAN
- Traffic might also be routed straight to the Internet.

#### EXTENDED SERVICE SET #ESS 

- Several interconnected BSSs acting as one
- APs that are physically close to each other will use different channels. Avoid interfering with each other
- All participating BSSs use the same SSID. To the client, the ESS appears as a single BSS

#### AUTHENTICATION MODES FOR WI-FI
- Open-system authentication process
	- No authentication
	- Clients must hav etheir own protection (such as firewall, anti-virus)
	- Often used for guest Wi-Fi
- Pre-shared key (PSK ) authentication process. Password is set of WAP and Clients
- Centralized Authentication
	- Authentication forwarded to a centralized server
	- Typically a RADIUS server
- 802.1x : 
	- WAP or switch forwards authentication to a centralized server.
	- Uses the extensible Authentication Protocol (EAP) to allow many authentication types.
	- An IEEE standard for port-based network access control
	- It provides an authentication mechanism to devices wishing to attach to a LAN or WLAN
	- It uses EAP to provide a wide range of authentication types.
	- The 802.1x process is as follows
		- The wireless client connects to the 802.1x enable access point
		- The access point places the client connection to hold
		- a browser opens to a captive portal
		- Either the client or the user authenticates
		- The AP forwards the authentication attempt to a RADIUS server
		- If the authentication is successful, the AP allows the client on the network
		- The client caches a short-term session token.
- #EAP (Extensible Authentication Protocol)
	- Used by 802.1x to allow for wide range of user and client authentication mechanisms including
		- Plain text passwords
		- Challenge-Handshakes (CHAP) / MS-CHAP / MS-CHAPv2 passwords
		- certificates, token, smartcards, authenticator apps
		- biometrics
- #RADIUS 
	- RADIUS is protocol that provides centralized authentication, authorization and accouting (AAA or Triple A) authentication
	- A RADIUS server usually serves as the back-end server in 802.1x authentication
	- 

### 16.2 WIFI SECURITY STANDARDS

#### WIRED EQUIVALENT PRIVACY #WEP
- 64.128 bit
- Rivest Cipher 4 (RC4) Stream Cipher Algorithm
- Pre-shared key #PSK 40 or 104 bits long
- Used a 24 bit Initialization Vector (IV ) to extend the key to 64 or 128 bits
- No digital signatures
- No sequences numbers
- Susceptible to replay attacks
- Short key = quick to crack
> Very old and unsecure


#### WI-FI PROTECTED ACCESS (WPA)
- Create to address the security problems of WEP, still uses RC4
- Included TKIP (Temporal Key Integrity Protocol) to change the key for every Packet.
- Initialization Vector (IV) is larger and an encrypted hash
- Every Packet gets a unique 128-bit encryption key
- Personal || WPA-PSK 
	- TKIP + PSK 
	- 64/128 bit RC4 MIC
- Enterprise | WPA-802.1x
	- TKIP + RADIUS
	- 64 - 128 bit RC4 MIC
	- Authenticates users individually with an authentication server (eg. RADIUS)
#### TEMPORAL KEY INTEGRITY PROTOCOL (TKIP)
- Change the encryption key for every packet
	- Combines the secret root key with the IV
- Prevent replays attacks : by adding sequence counter
- Protects against tampering: by implementing a 64 bit message Integrity Check
- TKIP has its own set of vulnerabilities
- Deprecated in the 802.11-2012 standard

#### WPA2 
- IEEE 802.11i
- CCMP replace TKIP, Large key with message authentication
- AES (Advanced Encryption Standard) replaced RC4
- Also comes in PSK or Enterprise (802.1x) modes.
- info: For the longest time WPA2 with AES encryption was the strongest Wi-Fi security type.

#### WAP3
- The Wi-Fi Alliance now requires all devices that wish to be certified to support WPA3
- Manadates the adoption of Protected Management Frames that protect against eavesdropping and forging
- Standardized 128-bit cryptographic suite and disallows obsolete security protocols
- Uses zero-knowledge proof
- No elements of the password are transmitted over the network
- Session key derived from the process
- QR codes can be used to gain network connection details
- Enterprise version has optional 192-bit security encryption and a 48-bit IV for better protection
- GCMP-Galois/ Counter Mode Protocol WPA3-Personal Uses CCMP-128 and AES-128


### 16.3 WIFI DISCOVERY TOOLS
- Wi-fi ADAPTER Requirements
- To be able to sniff and perform various Wi-Fi attacks your will need a wireless adapter with a good antenna and the correct drivers
- Windows :- #AirpCap (legacy) , #AirpCap 
- Linux :- `libpcap`
- if you laptop's Wi-Fi adapter doesn't support what you need, Get an External on such as 
	- Alfa AWUSO36NMHA
	- Alfa Long-Range Dual Band AC1200
- 
#### WIRELESS SNIFFERS
#kismet #wireshark #TCPDump #Airodump-ng #OmniPeek #Vericode #Monitis

#### Wireless Access point Discover Tools
#inSSIDer #NetSurveyor #Vistimbler #NetStumbler #WirelessMon #Kismet #KisMac #CommonView #WiFiHopper #WaveStumbler #iStumbler #WiFinder #Wellenreiter #AirCheckWifiTester #AirRaider2 #XirrusWiFiInspector #WiFiFinder #WeFi 


#KISMET 
 - Wireless network Detector, packet sniffer, and intrusion detection system (IDS)
 - Works with any wireless card supporting raw monitoring (rfmon) mode
 - Can sniff 802.11a, 802.11b, 802.11g and 802.11n traffic
 - Works on Linux , Mac and Windows 10 under the WSL framework
 - Commonly found on Linux computers
#### MOBILE WIRELSS DISCOVERY TOOLS
#WiFiFoFum-WiFi-Scanner  #WiFiManager #NetworkSignalInfo #OpenSignalMaps #Fing #OverlookWiFi

#### WARDRIVING TOOLS
#Airbase-ng #ApSniff #WiFiFoFum #MiniStumbler #WarLinux #MacStumbler #WiFi-Where #AirFart #AirTraf `802.11 NetworkDiscover Tools`


### 16.4 COMMON WIFI ATTACKS
#### WIRELESS Vs WIRED Exploits
- Most Wired exploits will also works against wi-fi wireless:
	- Sniffing: 
	- Spoofing 
	- MITM/Hijacking : 
	- De-authentication
	- DoS
- In addition, wireless devices have technology-specific vulnerabilities
- Wireless is inherited vulnerable

#### COMMON WIRELSS ATTACKS
- Sniffing: Use #Wireshark or other tools to passively sniff wireless traffic
	- Spoofing : Change the MAC (or other ) address of the attacker device to that a victim
- Rogue Access Point: 
	- Unauthorized  access point plugged into a wired one (can be accidental 
	- Tool for Rogue AP: Wi-Fi Pumpkin, Wi-Fi Pineapple)
- Evil Twin
	- Intentional rogue AP that is broadcasting the same (or very similar) SSID
	- Also known as a `mis-association` attack
	- Honeypot : faking a well-known hotspot with a rogue AP
	- KARMA Attack - Responding to, and impersonating, and SSID the client beacons for 
- Wi-Fi Phishing
	- Aka Wi-Fishing
	- Combination KARMA / EVI TWIN and login page `spoofer` for password capturing
- Ad Hoc Connection Attack:
	- Connecting directly to another phone via ad-hoc network
	- Requires social engineering - the other user has to accept connection
- De-authentication Attack:
	- The wireless client is knocked off the network by the attacker
	- Usually done to force the client to reauthenticate to the WAP
		- The attacker then captures packets from the client to perform other attacks
	- Can also be used for simple denial-of-service
- Replay Attack:
	- The high-speed repeated retransmission of the captured packet
	- Usually for the purpose of collecting key material from the access point
- DoS attack:
	- Use deauth, signal jamming, or ARP spoofing to perform denial-of-service
	- With a de-AUTH, you can have the users connect to your SP instead if it has the same name
	- Jammers are very dangerous as they are illegal.
- Password Cracking : WEP/ WPA/ WPA2 / WPS Cracking
#### Long Range Wi-Fi Antenna
- Highly directions YAGI
- Can snoop/attack up to several miles always
- 

#### DEAUTHENTICATION ATTACK #deauth
- In WEP networks use de-authentication to force a client to reconnect (and hopefully ARP) to the access point 
- In WPA/WPA2 networks, use deauthentication to capture the four-way handshake
	- Client must perform handshake when reconnecting
	- Capture PSK exchanged in handshake
	- Try cracking the PSK using
		- Hashcat, John-the-Ripper, aircrack-ng
	- Or Send the captured handshake to an online cracking service.
	- 

#### REPLAY ATTACK
- Capturing and re-transmitting a packet to force a response from the access point. Used to speed up the time an attack takes
- WEP Cracking: 
	- You capture an encrypted ARP packet
	- You replay it at high speed to the AP
	- The AP will respond with increase initialization Vectors (IVs) that each provide some key material
	- Once you have collected enough IVs, you can crack the Password.
- WPA-WPA Krack Attack:
	- When a client joins a network, it executes a 4-way handshake to negotiate a fresh encryption key.
	- It will install this key after receiving message3 of the 4-way handshake
	- Because message may be lost or dropped , the Access Point (AP) will retransmit message 3 if it did not receive an appropriate response as acknowledgment
	- An attacker can collect and replay retransmissions of message 3 of the 4-way handshake
	- Each time the client accepts the connection it reveals a small amount of key material
	- When enough of the key material has been captured , the key can be cracked

#### ROGUE ACCESS POINTS
##### EVIL TWIN ATTACK
- A type of attack where a rogue access point attempts to deceive users into believing that it is a legitimate access point
- A form of social engineering
- Often facilitated through DE authentication
- Attacker knocks client off real network
- Evil Twin should have a stronger signal be placed closer to the victim
	- It will appear about the legitimate AP in the Victim's list of available networks
- Client reconnects to rogue AP
- Can Launch all manner of attacks against connected victim. SSL downgrade / SSL Strip
- Sniffing traffic and capturing credentials

 ##### MITM / EVIl TWIN / WI-FI Phishing Tools
 #Wi-FiPineapple #Wi-FiPumpkin #SKA #SimpleKarmaAttack 

KARMA ATTACK
- A Variant of the evil twin attack
- Exploits the behavior of wireless client trying to connect to its preferred network
	- The client has a list of SSIDs it has connected to in the past 
	- The client beacons to determine if any of these SSIDs are withing range
	- The attacker answers the request. Pretends to be any SSID it hears in the client beacon
	- The user connects to the evil twin
- Karma Attack Tools
	- WiFiphisher : Rougue AP Framework
	- hostapd-mana - WIFI PINEAPPLE : Hardware Rogue AP
	- WIFI PINEAPPLE - Hardware Rogue AP
	- FruityWIFI - Multi Featured wireless audit tool for Raspberry PI or any Debian Based System

#### WIFIPHISHER
- Available in kali Linux
- Performs Wi-Fishing attacks
	- Jammer
	- MITM 
	- Spoofed Captive Portal

##### WI-FI SCENARIO 1
- You are conducting a wireless penetration test against an organization
- During your reconnaissance you discover that their network is known as "BigCorpWireless" has its SSID broadcast is enabled
- You configure your laptop to respond to requests for connection to "BigCorpWireless and park at the far end of the parking lot"
- At the end of the workday, as people get in their cars in the parking lot, you see numerous smartphones connecting to your laptop over WIFi
- `KARMA attack`
- You have configured your laptop rogue AP to automatically respond to the clients

##### WI-FI SCENARIO 2
- You are conducting a wireless penetration test against an organization 
- You have been monitoring the WPA2 encrypted network for almost an hour but have been usable to successfully capture a handshake
- What kind of attack can you perform to more quickly capture a handshake?
- `A De Authentication attakc`
- It would force the client to reauthenticate with new handshake to the AP


#### DENIAL of SERVICE
##### DENIAL-OF SERIVCE TOOLS
- `Airjack` : DoS and Packet Injector
- `Arcai Netcut` 

#### FREQUENCY JAMMING
- The simplest and crudest form of wireless attack
- Denial-of-service at the radio frequency level
- The wireless system and all of its clients are overwhelmed by a more powerful signal 
- Authorized signals get buried in noise


#### ARP SPOOFING TOOL - ARCAI NETCUT
-  A Very convenient and easy-to-use tool to manage wireless devices on your network
- Uses carefully controlled ARP spoofing to execute selective denial of service attacks
- An administrator can use it to control activity for a specific device including:
	- Bandwidth throttling
	- Kick device of network
	- Inject latency on wireless game controllers
- An attacker can use it to completely cut a device off of the wireless network
- Available for PC, MacOS and android
	- Limited free trial
	- Inexpensive paid subscription

#### WI-FI PASSWORD CRACKING
- Wi-FI password cracking has similarities and differences from other types of the password cracking
- Cannot be done offline - you can't just steal the account database
- You could perform a dictionary attack or capture the PSK through MITM
- The attacker captures packets that each contain a small amount of encryption key material
- When enough key material is captured, the packets can be sent to a password cracker


#### Wi-FI PASSWORD CRACKING TOOLS
- `Aircrack-ng`
	- Suite of tools for monitoring testing attacking and cracking WEP and WPA PSK passwords
	- Tools include : `Airmon-ng`, `airodump-ng`, `aireplay-ng`, `besside-n`, `airbase-ng` and many more
- `Beside-ng`:
	- Automatically discover and cracks WEP networks
	- Automatically captures WPA handshakes
- `Wifite`: 	- Automated WEP, WPA, and WPS cracking tool
- `WEPAttack`: 	- Web Dictionary cracker
- `Pyrit` : WPA/2 PSK brute force cracker
- `Airgeddon` : A script that simplifies Wi-Fi cracking, Request Aircrack-ng
- `Cain and Abel`:  Sniffer and password cracker
- `CoWPAtty` : WPA dictionary cracker
- `Fern WiFi Cracker` Automated WEP, WPA, WPS cracking, Has a nice GUI, Written in python bully, WPS brute forcer. Includes improvements over over `reaver`.
- Bully : WPS brute force with improvements over reaver and pixiewps
- `Reaver`: WPS brute forcer
- `pixiewps` Pff;ome WPS brute forcer


#### MOBILE APPS for WI-Fi Cracking
- Linux Deploy : Kali Linux on Android
- Wifi WPS WPA Tester
- AndroDumer : WPS Cracker
- Penetrate Pro : WEP / WPA Cracker
- RfA Reaver for Android : WPS Cracker

#### ONLINE CRACKING SITES
- Onlinehashcrack.com : WPA/2., MS Office , ITunes backups ZIP/RAR/7-Zip, PDFs
- Cloud Cracker: 
	- Online cracking tool for WPA/ WPA2, NTLM, SHA-512, MD5. MS-CHAPv2,
	- Offers an API for your app


### 16.6 WEP CRACKING
- WEP uses a weak implementation of the RC4 algorihtm
- Use Initialization Vectors IVs to stretch the pre-shared key
- New IVs are created periodically by the AP and sent in clear text to the client
- IV pseudo-random generation has a bias
- Can run a statistical analysis password crack if you capture enough IVs
- 20,000 IVs for 40 bit key (64-encryption)
- 40,000 IVs for 104=bit key (128=bit encryption)
- No Digital signatures
- No sequencing
- Can capture a client ARP request and replay to accelerate IV Generation
	- Chosen ciphertext attack
	- Replay attack

#### WEP ATTACK TYPES
- You can use the `Aircrack-ng` suite to perform various attack:
- ARP Request Replay Attack
	- Classic ARP replay attack
	- Most effective way to induce the AP to generate new initialization vectors (IVs)
	- The attacker captures an encrypted ARP packet transmitted by another client . Replays it to the AP at high-speed
	- The AP will respond in kind with new IVs
	- When enough IVs have been captured , the key can be cracked
- KoreK chopchop:
	- When successful, can decrypt a WEP data packet without knowing the key
	- The attack does not recover the WEP key itself, but merely reveals the plaintext
	- Then figure out the missing character to make the CRC check valid again
	- Some APs are not vulnerable to this type of attack
- Fragmentation attack
	- There are very few clients connected to the AP
		- The attacker has been waiting but so far has not been able to capture an ARP from a client
	- The attacker captures a packet
	- Since all WEP headers are similar the attacker can take the first 8 bytes of ciphertext and figure out what the plaintext should be 
	- The attacker can XOR the 8 Byte of cipher and plain text to know 8 bytes of keystream
	- The attacker cancreate 19-8 bytes fragments using this little bit of keystream and transmit it to the AP. 
		- You need 16 fragments to create the minimum packet size
		- Half of the bytes are for "data" half for integrity checks
	- The AP will take the received fragments and assemble them into a single 64 byte packet with 64 bytes of keystream
	- The ap echoes the assembled packet with keystream data back to the attacker
	- The attacker has not leveraged 8 bytes of keystream into 64 bytes
	- By repeating this process, the attacker can collect up to 1500 bytes keysteam (pseudo-random generating algorithm - PRGA)
	- The attacker can nowcreate full 1500 bytes broadcast packets and send them to the AP
	- Since they are broadcasts , the AP will replay them but will a new Initialization Vector (IV) 
	- If done enough times, enough IVs can be collected to crack the actual WEP key.
##### WEP SCENARIO 1
- You are conducting a wireless penetration test against an organization
- You have identified that they are using WEP encryption on their wireless access point
- You are impatient and do not want to wait to collect enough packets to find a repeated initialization vector
- You decide to extract part of the key material from one of the packets and use it to send an ARP request to the AP.
- What kind of attack are you conducting?
- *==A fragmentation attack==*

### 16.7 WPA / WPA2 / WPA3 CRACKING
#### WPA / WPA3 Cracking
- WPA introduced TKIP (key rotation)
	- Each packet is encrypted with a unique key
- WPA2 used much stronger encryption (AES /CCMP)
- Both use sequence numbers so replay can't be used
- Both are still susceptible to a dictionary attack
- There are several cracking exploit you can use: 
	- 4 -way handshake dictionary attack
	- KRACK / KROOK

#### WPA / WPA2 HANDSHAKE CRACKING
- In WPA / WPA2 networks, use deauthentication to capture four-way handshake
- Client must perform handshake when connection / reconnecting
- The handshake is protected by the PSK
- Use `besside-ng` to automatically capture and save handshakes:
	- `sudo airmon-ng start wlan0`
	- `iwconfig`
	- `besside-ng wlan`
- Alternatively Use airodumpt-ng to sniff for handshake:
	- `aidodump-ng -c "channel> -bbsid <MAC Address> -w capture wlan0`
- Use `aircrack-ng` to crack the PSK or upload to an online cracking site

#### WPA / WPA2 HANDSHAKE CRACKING EXAMPLE:
```
airmon-ng start ath0
airdump-ng -c 6 --bssid 00:14:6c:7E:40:80 -c 00:0F:B5:AB:CB:9D ath0 
// now wait for some time before next command
aircrack-ng -w /path/to/dictionary out.cap

`explaination`
channel 5
-w out is the file prefix of the file name to be written
ath0 is the interface name
-0 means deauthentication attack
5 is number of groups of deauthentication packets to send out

```


#### KEY REINSTALLATION ATTACK (KRACK)
- The attacker inserts inserts themselves between a client and a legitimate access point
- The rogue acts as  relay between the client and the AP
	- The rogue does not attempt to create a WPA2 session with the client
	- The rogue also does not know the original PSK- that the client to connect to the AP
- The client and the AP perform an initial 4-way handshake, already protected by the PSK
- At step 3 of the handshake the AP gives the client a session key
- The client is supposed to use this session key to encrypt its data
- The rogue, however replays the APs step 3 messages repeatedly
- The client ends up reinstalling the same key, reusing it to encrypt various packets. The key is supposed to be different with each packet
- If the client sends with known content (such as an ARP) the rogue now has the plaintext version of the ciphertext and can easily derive the used keystream.
- As the client continutes to use the same keystream the rogue can decrypt the packets

#### KROOK
- A #KRACK variant 
- The client is deauthenticated by the attacker
- It destroyes its session key and for security overwrites the key as a series of zeroes on any outbound packets still left in its transmits queue
- The client is not supposed to transmit anything left it its queue, but it does anyway with a session key of all zeroes
- The attacker can sniff the packets and decrypt them with an all zeroes session key
- The client will attempt to reauthentication with new handshake
- The attacker repeats the deauth cycle, the collecting and decrypting packets that the client never has chance to properly send.

- 

| KRACK                                                                                               | Kr00k                                                                               |
| --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Krack as expanded acronym suggests is a series of attack exploits                                   | Kr00k on the othe hands is vulnerability -bug                                       |
| The basic idea behind KRACK is that the Nonce is reused to be acquire the keystream                 | The main idea behind Kr00k is that data encrypted with an all zero session key (TK) |
| Triggered during the 4-way handshake                                                                | Triggered after a disassociation                                                    |
| Affects most wi-Fi capable devices as its exploits implementation flaws in the WPA2 protocol itself | Affects the most widespread Wi-Fi chips (by broadcom and Cypress)                   |

#### KRACK / KR00k tools
`krackattack-all-zero-tk-key` #github 
`r00kie-kr00kie,py` #github
> KRACK or its variants work against nearly any unpatched WPA2 device, regardless if authentication is PSK or 802.1x

ROOKIE-KROOKIE EXAMPLE
`python3 rookie-krookie.py -i wlan0 -b D4:38:9C:82:23:7A -c 88:c9:D0:FB:88:D1 -l 11`
-  The victim connects to the client and, by doing so, disconnects the victim from the hotspot
- The attacker sends disassociation requests to the client and, by doing so, disconnects the victim from the hotspot
- Wireless Network Interfacce Controllers (WNIC) Wi-Fi chip of the client clears out a session key (Temporal Key) used for traffic decryption
- However, data packets, which can still remain in the buffer of the WiFi chip after the disassociation, will be encrypted with an all-zero encryption key and sent
- The adversary, will can still remain in the buffer of the WiFi chip after the disassociation, will be encrypted with an all-zero encryption key and sent.
- However, data packets which can still remain in the buffer of the WiFi chip after the disassociation, will be encrypted with an all-zero encryption key and sent.
- The adversary intercepts all the packets sent by the victim after the disassociation and attempts to decrypt them using a known key value (which, as we remember is set to zero)
- PROFIT

WPA2 ENTERPRISE
- WPA2 without a pre-shared key
- Instead , authentication requests are forwarded to a RADIUS server
- 802.1x-complaint WAPs put the client session on hold until the user (or client) successfully authenticates
- There is no pre-shared key

> WLAN Client try to connect Access point --> WLAN Controller --> AAA Server 

#### WPA2 ENTERPRISE ATTACK
- If the client devices (supplicants) authenticate themselves to a RADIUS server with their own password, you can use a MITM attack to capture the user password.
- Hostapad is a linux-based attack tool that sets up:
	- a rogue AP
	- a rogue RADIUS server
- You must present a stronger signal to the clients than the legitimate AP
	- You need them to connect to your rogue, rather than the legitimate AP
- The steps are:
	- Use `airodump-ng` to enumerate clients
	- Use `aireplay-ng` to de-authenticate a client so they reconnect to you
	- You rogue becomes a MITM relay between the client and the AP
	- As the user logs on, you capture their hashed password
	- Use dictionary crackers such as `asleap` or `John the Ripper` to crack the user's password

#### WPA3 ATTACKS
- The best Wi-Fi security standard currently available
- Uses Elliptic Curve Diffie-Hellman key exchange
	- A smaller key provides the same strength encryption as RSA
	- Uses considerably less power
	- Great for small devices
- Uses a `dragonfly` handshake
	- AKA simultaneous Authentication of Equals (SAE) handshake
	- Password Authenticated key Exchange (PAKE)
	- Turns a password into a high-entropy key (has a high level of randomness)
	- Prevents offline dictionary attacks and provides forward secrecy

#### WPA3 VULNERABILITIES
- CERT ID #VU871675 : Downgrade attack against WPA3-Transition mode leading to dictionary attacks
	- For clients that supports WPA3 into connecting to the rogue WPA2-only network
	- The Captured partial WPA3 handshake can be used to crack the password (using brute-force or dictionary attacks)
	- No man-in-the-middle position is required to perform this attack
- CERT ID #VU871675 Security group downgrade attack against WPA3 Dragonfly handshake : Reduce key strength
- CVE-2019-9494 : Timing-based side-channel attack against WPA3 Dragonfly handshake. The amount of times it takes for an AP to respond to client commit frames may leak information about the password
- CVE-2019-9494 : Cache-based side-channel-attack against WPA3 Dragonfly handshake
	- Memory access patterns reveal information about the password being used
	- Leaked patterns can be used to perform a dictionary attack
	- Performed by simulating the memory access patterns associated to a password
- CERT ID #VU871675 Resource consumption attack (DoS) against WPA3's Dragonfly handshake
	- Causes high CPU usage on the AP drains its battery, prevents or delays other devices from connecting to the AP using WPA3
	- May also halt or slow down other functionality of the AP as well
- Dictionary brute force attack
	- It is possible to brute force the password of a WPA3 access point
	- Use a tool such as Wacker or other Python scripts
- `python wacker.py -h`

### 16.8 WPS CRACKING
- A method for setting up a secure Wi-Fi network at home with minimum effort
- Eliminates the need for the user to enter a WPA/WPA2 pre-shared key on the wireless client device.
- Can be implemented in several ways
	- The user presses a button the Wi-Fi Access point
		- The psk is transmitted to the client device long enough for a connection to be made
	- The user enters a PIN (on a sticker pasted to the WAP)
		- Key exchange is protected by the PIN
	- Devices use Near Field Communication (NFC)
		- Key exchange is performed "out of band " using NFC
	- A USB flash drive or cable is used to exchange the key between the device and the WAP.

#### WPS ATTACK
- If a Pin is used 
	- Each PIN half is calculated separately
	- There are only 11,000 possible values
	- Easy to crack within hours
- Lockout policies on the WAP/router can hamper PIN Cracking online
	- Might take a couple weeks, but still feasible
	- Lockout may look for MAC address, so spoofing could be used to bypass
	- Brute forcing may trigger DoS on certain WAPs
- Automated brute-forcing tools can be used to ultimately crack WPS

##### BULLY WPS ATTACK
example : `bully mon0 -b host-mac-address -e mendela2 -c 9`

### 16.9 BLUETOOTH HACKING
- Discoverable Modes;
	- Discoverable:  The devices broadcasts its presence and is able to be seen (detected) to other Bluetooth devices in range
	- Limited Discoverable: The device is discoverable for only short period of time
	- Non-Discoverable: Prevents the devices from being listed when another devices search for bluetooth-enabled devices. Does not actually turn bluetooth off. A Non-Discoverable device can still be attacked if its MAC address is known or determined by brute force.
- Paring Modes
	- Non-Pairable
	- Pariable


#### BLUETOOTH THREATS
- Personal information disclosure
- Remote code execution
- Social engineering / false SMS messages
- Unauthorized calls / using the victim's airtime

BLUEToOTH ATTACK TYPES #BluetoothAttacks ^b0f31b
- Blueborne attack
	- Collectoion of overflow attack that could result in arbitrary code execution
	- An attack virus that spreads through air
	- Gets into a device via bluetooth
	- Takes full control of the device
	- Does not requires pairing
	- The device need not be in discoverable mode
- Bluejacking
	- Sending unsolicited messages to Bluetooth-enabled devices
	- Can include a malicious payload such as a trojan horse
- Bluesnarfing
	- Unauthorized access to emails, messages, contacts, etc on the target 
	- Command `bt stiff # btobex` #kali
- Bluebugging
	- Remote access to phone features such as the microphone or camera
- Bluesmacking
	- Denial of service attack
- Bluesniffing
	- Locate Bluetooth devices
- Blueprinting
	- Enumerate details about bluetooth-enabled devices
- MAC Spoofing Attack
	- Used to cloen or MITM Bluetooth devices
- Man-In-the-Middle Attack
	- Manipulate communications between Bluetooth devices
	- Often uses MAC spoofing
	- Commonly used against Bluetooth Low energy IoT devices and their smartphone app.

#### BLUETOOTH HACKING TOOLS
#Blueborne: Bluebprne exploit framework available on GitHub
#spooftooph Automates spoofing or cloning of Bluetooth device
#BlueScanner #btscanner Bluetoothdevice scanners designed to extract as much information as possible from bluetooth devices without pairing 
#btCrawler Scans for visible Bluetooth devices
#Bluedriving Bluetooth wardriving utility
#phoneSnoop allows you to turn a Blackberry into a room bugging devices
#BHBlueJack Open-source bluejacking software
#Bluesnarfer, #btobex Bluetooth bluesnarfing utility
#BlooverII bluebug / bluejack / bluesnarfer
#Bluediving is tool suite that can spoof, Bluebug, bluesnarf and BlueSmack
#GATTacker #BtleJuice Bluetooth low energy eavesdropping and MITM tools. Conduct attack against BLE peripherals (such as IoT wearables) and a phone

#### BLUETOOTH MOBILE APP TOOLS
#bluesniff Bluetooth scanner that runs on Iphone
#BLEScanner Bluetooth scanner that runs on Android
#SuperBluetoothHack is bluesnarfer that run on Android
#CIHwBT Bluetooth exploit suite (BlueSnarf, BlueJack, DoS) that runs on Windows Mobile

### 16.10 OTHER WIRELESS HACKING
#### Attack Againsts NEW Cellular ; 4G 5G networks
- #TorpedoAttack 
	- Exploits a weakness in the cell tower paging system
	- Allows an attacker to track a phone's location
	- Spoof, inject or block emergency alerts such a severe weather warnings and Amber alerts
- Piercer Attack
	- An attacker can determine an international mobile subscriber Identify (IMSI) number
- IMSI-Cracking Attack: An attacker can crack the encrypted IMSI number in order to clone it
- `StingRay` Cell Tower Simulator
	- Cell phone surveillance and eavesdropping
#### CELL TOWER SIMULATORS
- aka IMSI catcher
- Device masquerades as a legitimate cell phone tower
- Tricks phones within a certain radius (up to 500 meters) into connecting to its rather than a legitimate tower
- Can be used to intercept call information
	- Cell phone's International mobile Subscriber Identity (IMSI) number
	- Metadata about calls (number dialed, duration of call)
	- Content of SMS and voice calls
	- Data usage and websites visited
- Can also spoof text messages and callerID
- Currently only worker on 3G and 4G networks
	- However many 5G carries also provides 4G parallel capability
	- A victim could be forced to downgraded to 4G for particular call
- Popular products include Stingray, #DRTBox

 #### RFID BADGE CLONING
 - Badge cloning is the act of copying authentication data from an RFID badge's microchip to another badge
 - The attacker can obtain authorization credential without actually stealing a physical badge from the organization.
 - The older RFID badge technology uses the unencrypted 125 kHz EM4100 protocol . Device will begin transmitting data to any receivers that are nearby.
- #PRoxmark3 
	- The swiss army knife of badge cloners
	- NFC and RFID badge cloner
	- You can attack High and Low Frequency as well as long-range antennas
- iCopy-X 
	- Hand-held rapid cloner
	- Built on proxmark3
- You can hide everything in a backpack
	- Just get within a foot or two from the victim
	- Crowded elevator, food counter, checkout line, go up and talk to them.
#### NFC BADGE / TAG CLONING
- NFC badges / tags use MIFARE encrypted 13.56 MHz 
- You can buy an NFC RFID reader / writer tool . There are several models available online and software setup of latpop
- An Android phone provides an easier way to clone NFC
	- Android has built in NFC capabilities
	- Download the MiFARE classic Tool app
		- Key brute force cracker
		- Also comes with NFC card manufacturer default keys
		- Many organizations do not bother to change the default key, allowing you to easily you to easily clone the badge
- #MTools #Mkeys is another mobile app NFC key cracker
- Performs dictionary attacks
- https://why-yuyeye.cc/post/mtools-guide

### 16.11 WIRELESS SECURITY TOOLS
- #KISMET
	- Wi-Fi device detector, sniffer, WIDS framework
	- Detectors 802.11a/b/g/n Aps
	- Runs on Linux
- #Solar Winds Network Performance Monitor / Rogue AP Detection
	- All in one network monitor
- #OSWA -Assistant 
	- Free standalone wireless auditing toolkit
- #Mooncherhunter Geolocate unauthorized wireless clients (moochers and hackers)
- Rapid 7 #Nexpose
	- Network vulnerability scanner
	- Can scan wireless networks and devices as easily wired
- #WiFishFinder (sourceforge)
	- Open source testing tools to see if active wireless devices are vulnerable to 'Wi-Fishing' attacks
- 

#### WIRELESS IPS TOOLS
- Extreme network intrusion prevention system
- AirMagnet Enterprise
- Dell SonicWall Clean Wireless
- HP TippingPoint NX platform NGIPs
- MoJo AirTight WIPS
- Network Box IDP
- NEtwork Box IDP
- AirMobile Server
- Wireless Policy MAnager (WPM)
- ZENWorks Endpoint security MAnagement
- FortiWiFi


#### MOBILE WI-FI Security Tools
- Armis BlueBorne Vulnerability Scanner
	- Check if your device, or the devices around you, are at risk
- Acrylic Bluetooth Low Energy Analyzer
	- Can identify Bluetooth devices including new IOT devices around you
- WiFi Protector : Wireless VPN
- #SoftPerfectWiFiGuard Network scanner that runs at set intervals and reports any unrecognized connected devices
- Xirrus Wifi Inspector : Realtime monitor of traffic performance and clients, rogue detector

#### BLUETOOTH SECURITY TOOLS
- BlueAuditor
- Frontline BlueTooth protocol Analyzer
- Ellisys Bluetooth Tracker
- Acrylic LE Analyzer
- BLE Scanner for PC
- BlueMaho

### 16.12 WIRELESS HACKINGCOUNTER MEASURES
### Wi-Fi Router configuration Best Practices
- Strategically place antennas to always point inward into the building /complex
- If Possible, maintain low power levels on WAPs , And more WAPs to make up for coverage gaps
- Ensure remote router login is disabled
- Ensure router access password is set and firewall protection is enabled
- Ensure MAC address filtering is enabled on routers / access points. WAP won't respond to connection request from clients  that are not on the approved list
- Ensure SSID broadcasts are disabled at access points and passphrase is changed frequently


#### SSID SETTINGS BEST PRACTICES
- Change the default SSID
- Hide the SSID when practical
- Keep passphrases free of SSID, network / company name , or anything that is easy to figure out.
- Ensure there is firewall/ packet filter between AP and Internet
- Keep wireless network strength low enough avoid detection outside organization
- Regularly ensure there are no issues with setup/ configuration
- Use extra traffic encryption

#### AUTHENTICATION BEST PRACTICES
- When practical, implement MAC filtering on the Access Point
- Use captive portals for legal protection and to enforce user/ device registration
- Use the highest security standard possible
	- WPA3 for SOHO use
	- 802 .1x for enterprise use
- Ensure access points are in secure locations
- Ensure all wireless drivers are up-to-date
- Ensure network is disabled when it isn't needed.

#### ADDITIONAL WIRELESS SECURITY BEST PRACTICES
- Use different SSIDs and VLANs to isolate users/ devices by security level : Guests , Wireless Clients
- Enroll devices (including BYOD) into Mobile Device Management to:
	- Implement Geofencing
	- Enforce end point protection
	- Enforce separation of business and personal data
	- Disallow jailbroken or rooted devices on the network
- Educate users on the risks of using public / free wi-fi
>Realize the MDM and endpoint security software is not used to protect the mobile device, but instead used to protect the network from mobile devices.


#### BLUETOOTH HACKING COUNTERMEASURES
- Ensures PIN keys use non-regular patterns
- Ensure device is always in hidden mode
- Keep track of all past paired devices and delete suspicious devices
- Ensure BT is kept disabled unless required
- Never accept pairing requests from unknown devices
- Ensure encryption is enabled when connecting to a PC
- Keep device network range at its lowest
- Only pair with other devices in a secure area
- Ensure antivirus is installed
- Ensure default security setting are changed to the best possible standard
- Ensure all BT connections use Link Encryption
- Ensure encryption is empowered for multiple wireless communications

#### OTHER WIRELESS ATTACK COUNTERMEASURES
Celluar:
	Upgrade to 5G
	Use encryption when making Wi-Fi calls
	Prefer encryption messaging platforms over unencrypted SMS
RFID / NFC
	Upgrade older 125 KHz RFID systems to newer 13.56 MHz NFC systems
	Change default keys on NFC systems
	Use RFID blocking sleeves or cards to protect the card from RFID pickpocketing

### 16.13 HACKING WIRELESS NETWORKS REVIEW
- Wi-Fi infrastructure is made of software and hardware
- the SSID is friendly name for a Wi-Fi network
- The BSSID is the MAC address of a wireless access point
- A BSS is a Wi-Fi network with one AP
- An ESS is a Wi-Fie network with multiple APs
- The APs typically use the same SSID
- WEP uses a 24-bit IV, stream cipher RC4 , and CRC-32 checksum
- Because WEP has no digital signature or anti-replay capability, you can use `aireplay-ng` perform a replay attack against the AP. This speeds up collecting IVs for cracking the password
- You can also use a fragmentation attack against WEP to collect keying information from the header of a captured packet
- You can use that to quickly obtain more keying material from the AP until you have the PRGA
- You can use the PRGA with `packetforge-ng` to create a custom packet to quickly obtain IVs for password cracking
- WPA introduced TKIP to change the encryption key for every packet
- It also uses sequence numbers to guard against replay attacks
- The IV is 48-bit and the key is 128-bit
- WPA2 introduced CCMP-AES for encryption
- Both WPA and WPA2 have an imperfect 4-way handshake that can be captured and cracked
- Both WPA and WPA2 offer an enterprise version that uses 802.1x and RADIUS to centralized authentication
- The user or client's authentication is forwarded to the RADIUS server
- If authentication is successful, the client can enter the network
- 802.1x uses the extensible Authentication Protocol (EAP) to allow a wide range of authentication factors including MS-CHAPv2 passwords, certificates and tokens and biometrics
- WPA3 has been recently introduced. It is possible to brute force a WPA3 key
- Bluetooth has a variety of vulnerabilities and exploits that allow you to:
	- Send spam messages to the victim, read the Victim's messages and contact list, and remotely execute code on the device
- Cellular devices are susceptible to #StrinRay and #DRTBox MITM attacks
- RFID and NFC Badges and tokens can be cloned from a short distance
- There are several NFC hacking apps you can use to crack the NFC key.
- There are a number of vulnerability scanners you can use to test Wi-Fi networks
- There are also a number of Wi-fi security tools and IPSec available to protect the wireless network


