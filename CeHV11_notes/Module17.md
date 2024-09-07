###  17.1 MOBILE PLATFORM OVERVIEW
#### WHAT is a MOBILE device
- A mobile device is essentially a small hand-held computer with a touch screen.
- The user interface uses direct manipulation (multi-touch gestures)
- It has an embedded operating systems that can 
	- makes and receives voice calls
	- Send and receives voice calls
	- Connect to a network (including the internet)
	- Run applications
- Most mobile devices have a subscriber identify module (SIM ) card that contains a phone number and other information necessary to connect to a cellular carrier
- Most modern mobile devices can connect to multiple network types simultaneously including cellular, Wi-Fi Bluetooth, NFC
	- In can also connect to a PC via USB

#### MOBILE ECOSYSTEM
Mobile devices have an entire ecosystem of hardware, software services and vendors to support the mobile users.
mobileuser , MobieManufacturers, OperatingSystem, MobileApps, Website, testing developing tools, Mobile Apps, Mobile Websites developement companies , Mobile App stores, Mobile AD companies Carrier, Network, MobileCloud, Devices, Other
- 

#### OWASP Mobile to 10 risks
- Improper platform usage
	- The organization exposes a web service or API call consumed by the app
	- Attacker could feed malicious input to the vulnerable device
- Insecure Data Storage
	- App developer erroneously assumes users/malware will have no access to the device filesystem
- Insecure Communication
	- SSL / TLS may be used during authentication but not elsewhere in the communication
- Insecure Authentication
	- Weak or missing authentication schemes
	- Uptime limits may require apps have offline authentication, which attackers could learn to bypass
- insufficient Cryptography
	- 'Roll your own' encryption, or weak algorithm / key implementation
- Insecure authorization
	- Poor or missing authorization schemes can allow privilege escalation
- Client code quality
	- Attackers could fuzz the app to look for memory leak / overflow opportunities
- Code Tampering
	- Unauthorized versions and patches, can inject malicious instruction or remove security features
- Reverse Engineering
	- Hackers analyze the core binary a look for ways to compromise the app
- Extraneous functionality
	- Attackers download the app and look for hidden switches or test code artifacts that could be exploited
> Most people do not take mobile security as serious as they do laptops or computer security


#### SECURITY ISSUES FROM APPLICATION STORES
- Non-Existient or insufficient app vetting
- Malware / malicious apps distributed through store
- Social engineering of users to access apps outside store
- Malicious apps damage other apps so attackers can access sensitive data
- Unofficial app stores/ repositories
- Sideloading apps via email / Social media / alternate download sites / removeable media.

### 17.2 MOBILE DEVICE ATTACKS
- Source : Website, AppStore, SMS Device , Wi-Fi MiTM Rogue AP, Stingray
- Device : SMS/ MMS , WI-FI , Network , GPS Location
- Destination : Premium SMS Service, Cloud Storage, Corp Storage,  PC/Mac

#### BROWSER BASED MOBILE ATTACKS

- Phishing: 
	- Emails or popups redirect users to fake web pages that mimic trustworthy sites
	- Users enter personal information such as credential bank account and credit card numbers, contact information
- Iframes:
	- Attackers superimpose a single pixel iframe on a website that contains malicious instruction that the phone the phone's browser executes
- Clickjacking : Userjacking
	- Users click something different from what they think they are clicking\
	- Often used in conjunction with Iframes
- MITM 
	- Attacker plants malicious code in the phone to bypass password verification such as one-time passwords via SMS or voice
- Buffer overflow
	- An attacker exploits code weakness in a mobile app to cause erratic behavior including arbitrary or remote code execution or device crash
- Data Caching Attack: The attacker access local storage where apps save credentials and other sensitive information

#### MOBILE DEVICE PHISHING EXAMPLE
- Victim receives a phishing emails
- Downloads and opens the attachments
- Device makes a connection in the background to the waiting hacker

#### PHONE / MESSAGE Attacks
- BAseband attack : Attackers exploits vulnerabilities in a phone's GSM / 3GPP baseband processor which sends and receives radio signals to cell towers
- Smishing : Attackers send fake messages via SMS or other messaging apps
	- Attackers send fake messages via SMS or other messaging apps
	- These message contain deception links to a malicious websites
	- Most common SMishing Attacks
		- "Urgent" messages about your credit card or bank account
		- Notification that you have won something
		- Fake survey links
		- Fake messages from trusted brands
	- Tools : #Evilginx2 #SEToolkit #HiddenEye #KingPhisher #SocialFish #Shellphis
- Vishing :
	- The voice version of Smishing
	- Attackers call the live or call with pre-recorded messages that social engineer the user into revealing sensitive information or pressing a button that re-routes them to an expensive pay-by-the-minute phone number
- 
#### APPLICATION-BASED ATTACKS
- Configuration manipulation: External configuration files and code libraries can be manipulated to cause buffer overflows, weak authentication and access to administrative information and data stores
- Dynamics Runtime Injection: Attackers abuse and manipulate the code as it runs, circumventing security , accessing privileged parts of an app and even stealing data

#### HARD-CODED CREDNTIALS EXAMPLE
You perform a static analysis of a mobile app and see this in the source code:
```
int verifyAdmin(String password){
	if(password.equals ("mR7Hcad#d"))) {
		return 0;
		}
	return 1;
	}
}
```
- The function uses hard-coded credentials in the function
	- An insecure practice that can lead to compromise
- The password for the application is shown in the source code 
- Even if this was obfuscated using encoding or encryption, it is a terrible security practice to include hard-coded credentials in the application. An attacker can reverse-engineer the credentials

#### SYSTEM ATTACKS
- OS DATA Caching Attack
	- The OS Pages user data to local storage
	- An attacker can boot the device to with a malicious OS that extracts this information
- Side-channel Attack:
	- Electronic emanations of phones can be used to break cryptographic keys
- Confused Deputy Attack
	- A type of privilege escalation in which a legitimate, more priveileged app is tricked by another app into misusing its authority on the system
- Device Lockout / Bricking
	- An attacker could change the password on a phone, or a user could forget their password and get locked out
	- Too many failed login attempts could induce a mobile device management (MDM) system to remotely wipe (brick) the device
#### NETWORK ATTACKS
- Rogue access points : Fake access points are used to capture credentials and perform MITM attacks
- Man-in-the-Middle(MITM) An attacker inserts themselves between the mobile device and a website
- SSLStrip / Downgrade Attack : An attacker performing an MITM attack can also force the mobile device to downgrade to a weaker form of authentication or encryption, or none at all.
- Session Hijacking: An attacker can steal a token, or use spoofing / poisoning/ sequence number prediction to hijack a user's session with a website
- Packet Sniffing / Port Scanning: An attacker can scan a mobile device over-the-air or capture clear text transmissions from the phone
- DNS Poisonings : A type of spoofing in which name resolution lookups direct a user to a malicious site rather than the actual site
- 

BLUETOOth ATTACKS
from chapter 16:

#### BLUETOOTH DISCOVERABILITY AND PAIRING
- If a mobile device can be connected to easily it can fall prey to Bluetooth attacks
	- Discover mode: 
	- Limited Discoverable : restricts the action
	- Non Discoverable : ignores all inquiries
- Pairing mode: How the device deals with pairing requests
	- Pairable : accepts all request
	- Non pairable - rejects all connection requests

#### BLUETOOTH ATTACK TOOLS
 Chapter 16: BLUETOOTH HACKING TOOLS

#Bluescanner #BTBrowser #Bloover #BlueDiving #SuperBluetoothHack 

#### NFC Near field Communications
A set of standard for mobile device to establish radio communication with each other by : Being touched together, Brought within a short distance (usually no more than a few centimeters)

#### NFC Common Applications
- Payment via mobile devices such as smartphone and tablets
- Electronic identity
- Electronic ticketing for transportation
- Integration of credit cards in mobile devices
- Data transfer between any types of devices such as digital cameras, mobile phones , media players
- P2P connection between wireless devices for data transfer
- Loyalty and couponing / targeted marketing / location-based services 
- Device pairing
- Healthcare / patient monitoring
- Gaming
- Access control / Security patrols / inventory control (tags and readers)

#### NFC attack methods
- Eavesdropping, 
- Spoofing : Capture and replay RFID data
- RF jamming Denial of service
- Data modification / corruption: Very brief spikes of interference by attacker could alter received data
- MITM : Real time relay attack between sender 
- NFC Protocol stack fuzzing
	- Force a device to parse images, videos contact documents etc, without user interaction
	- Possibly take complete control over the phone to steal data, send texts and make calls
#### NFC ATTACKS
- Launch a buffer overflow/code execution attack on NFC-equipped ATM machines
	- Include ATM jackpotting -causing the ATM to dispense all its cash
	- NFC reader don't validate the size of the packets
- NFC beaming vulnerability CVE - 2019-2114
	- Malware can be installed on a phone via tapping a malicious devices or payment terminal 
	- Bypasses "Install unknown apps" prompt

#### ANDROID OVERVIEW
- Mobile operating system based on linux
- Developed by google
- Large app dev community
- Most apps written in kotlin or android java, packaged as APKs
- Users can install apps from Google play or side-load from other sources without root permission
- Application framework allows for component reuse / replacement
- Android framework allows for component reuse /replacement
- Android is susceptible to compromise. Just like laptops and desktop computers
- Particularly susceptible to malicious attachments. User can side load apps without root permissions

#### ANDROID SECURITY FEATURES
- App signing
	- Allow developers to identify the author of the app
	- You can update your app without creating complicated interfaces and permissions
	- Every app that runs on the android platform must be signed by the developer
- Biometrics:
	- Android 10 and higher includes a biometricprompt API
	- Integrated fingerprint and face recognition
- Keystore :  Hardware-backed secure storage for cryptographic secrets provides
	- Key generation
	- import and export of asymmetric key
	- import of raw symmetric keys
	- asymmetric encryption and decryption with appropriate padding modes
- Verified Boot:
	- Attempts to ensure all executed code comes from a trusted source
	- Ensures that the device is running a safe android system.

#### ANDROID APP SANDBOXING
- Android and linux protection mechanism to identify and isolate app resources . Apps are separated from and other Apps
- Android assigns a unique user ID (UID) to each app
	- The UID is used to set up a kernel-level app sandbox that the app runs in 
	- Each app runs as Dalvik Java virtual machine
- Without app sandbox : any app can access any user data or system resources without any restrictions
- With app sandbox: There will be unrestricted access of some user data and system resources only based on permissions

#### ANDROID VULNERABILITY TYPES

| Vulnerability                                        | Description                                                                                                                                                                  |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Physical theft or damage                             | Small size make android devices especially vulnerable to theft , loss and accidental damage                                                                                  |
| Weak or no passwords                                 | Many users do no enable passwords or use weak passwords on the device.                                                                                                       |
| Lack of data encryption                              | Many apps, including those that use the SQLite database, store data in cleartext                                                                                             |
| Ability to side-load apps                            | Android allows users to install unsigned apps from any source, even on devices that are not rooted                                                                           |
| Rooted device                                        | Many android users root their devices to have more control over their phones.<br>Makes it easier to compromises the phones (having root level privileges)                    |
| SQL Injection                                        | The SQLite database is vulnerable to a SQL injection attack                                                                                                                  |
| Unauthorized access or excessive permissions by apps | Many apps request more permissions than they actually need or donot request permissions at all access resources such as contacts, microphone, camera, location services, etc |
| Data leakage from syncing                            | Security vulnerabilities in cloud-based services cloud expose the android device to attack<br>especially if the user uses the same password for multiple websites            |
| Lack of antivirus / malware protection               | Most users do not install endpoint protection on their devices <br>This leads to virus infections, unsafe surfing, malicious downloads, SMShing , etc                        |
| missing updates and patches                          | android and its apps need periodic patching                                                                                                                                  |
|                                                      |                                                                                                                                                                              |
### 17.4 ROOTING ANDROID

#### WHAT IS ROOTING?
 - The process of removing restriction in android 
- Allows root (administrator) access to commands, system files and folder locations
- The user can
	- Run superuser (SU) commands
	- Modify the system
	- Remove applications installed by manufacturers and carriers
	- Run unsigned code or software that has not been approved by Google
	- Install tweaks and theme to customize the look and feel of the device and enhance functionality
#### ABOUT ROOTING
- By itself is not illegal
- Might void the device warranty 
- It makes it much easier for you to use your phone to do illegal things
- It bypasses firmware based digital signatures
	- Makes it easy to introduce malware into the device
- Grant you root (full system administrator) privilege

#### BENEFITS AND RISKS OF ROOTING ANDROID
- Root access allows you to:
	- uninstalling bloatware and apps that cannot be normally uninstalled
	- Install any app you like, including hacking tools
	- Work deeply with the operating system
- Risks includes
	- Bypassing built-in security mechanisms puts your phone at greater risk of malware
	- You can accidently permanently damage your phone while rooting
	- Chances are excellent that free "one-click" rooting solutions will install malware an spyware on you phone

#### TYPES OF ROOTING

| Type                  | Description                                                                                                                                                                                  |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Systemless            | Modifies the system without changing and system files<br>modification are stored in boot partition<br>can evade Google safetynet<br>Mostly commonly implemented by magisk third party rooter |
| Flashing an SU binary | AKA "hard rooting" done by manufactures                                                                                                                                                      |
| Exploit               | Aka "Soft rooting"<br>Performed by users<br>Takes advantages of a privilege escalation vulnerability on the device<br>may or may not requires a PC                                           |


#### ANDROID ROOTING TOOLS
#KINGO #SRSOneClickRoot #RootGenius #iRoot #SuperSUProRootApp #OneClickRoot #kingRoot #WonderShareTunesGo #VRoot #Towelroot #Magisk

### 17.5 ANDROID EXPLOITS
#### EXPLOITS AGAINS ANDROID
- Metasploit offers 32 modules against android (6 exploits with rank of excellent)
- You can use Metasploit and #msfvenom to create a malicious APK
	- Use social engineering to get the victim to side-load on their device
	- The payload can be Metasploit meterpreter (or whatever else you desire)
- You can program a HAK5 O.MG cable to install malware and a backdoor on an android phone 
	- use the OMG-cable-android-script (GitHub) to pre-program the malicious charger cable use, social engineering to get the victim to plug their phone into their computer using this cable
- `Exploit-db` offer 75 verified downloadable exploits against android
- GitHub list 387 downloadable android exploit repos


#### DIRTY PIPE ATTACK
- Local privilege escalation gives the attacker root-level access
- CVE-2022-084
	- Linux kernel 5.8 or later
	- Android 12, Pixel 6/6 pro, Samsung Galaxy S22, Xiaomi 12 pro, Qualcomm snapdragon 8
- GitHub list 59 Dirty Pipe repositories
- Metasploit modules : exploit / Linux / local / CVE_2022_0847_dirtypipe


#### GHOST FRAMEWORK
- Exploits android debug Bridges (ADB ) to access phones / smart TVs remotely 
- ADB must be enabled on remote device, with port 5555 open
	- You already compromised the device to open the port
	- You used Shodan.io to locate a device IP that has port 5555 open
- Run these commands to install and use Ghost on kali
```
Sudo pip3 install git hittps://github.com/EntrySec/Ghost`
ghost
connect <target IP>
help
```

#### STAGEFRIGHT
- RCE /ID PRIV Esc vulnerability in the android media framework
- Most commonly attacked via malicious MMS (text)
- 77 CVEs related to #stagefright
- Github lists 125 #stagefright repos
	- Including popular metaphor exploits
- Metasploit modules:
	- exploit / android / browser / stagefright_mp4_tx3g_64bit
- Check a device with #stagefright Detector app

#### ANDROID TROJANS
#androRAT #zitmo #FakeToken #FakeDefender #Obad #FakeInst #OpFAke #Dendroid


### 17.6 ANDROID BASED HACKING TOOLS
> PENTESTING SUITES THAT RUNS ON ANDROID

- The android network hacking toolkit
	- Developed for the penetration tester and ethical hackers to test any network and vulnerabilities by using their mobile phones
	- This toolkit contains different apps that will help any hacker to find vulnerabilities and possibly exploit them 
- Kali Linux Hunter
	- Open-source penetration testing platform for android devices
- #dSploit
	- Port and vulnerability scanner, MITM, WiFi, Wi-Fi Scanning
- #zAnti spoofing , scanning password cracking MITM , HTTP hijacker
- #cSploit : Network m
- 
- 
- apper, OS fingerprinting, port scanning, password sniffing, DNS spoofing, session hijacking
- #Hackode \
	- Perform different tasks like reconnaissance, scanning, performing exploits, etc
	- This app contains different tools like google hacking, google Dorks, whois scanning etc
- Droid Pentest
	- Features many hacking tools

#### SCANNERS THAT RUNs on ANDROID
- NMAP for android, email results
- Network scanner: identify device on the network
- Fing: Scan for devices on your Wi-Fi network

#### SNIFFERS THAT RUN ON ANDROI
#whatsapp sniffer: Catpure whatsapp messages from surrounding phones
#PAcketSniffer : capture and display wifi and bluetooth packets and save them for future analysis
#tPAcketCapture Packet capture without root, Uses android OS VPN
#ANdoridPCAP : Sniffer that doesnot require root
#sharkForRoot Works on rooted devices , Based on #TCPdump

#### SPOFFING APPS THAT RUNS ON ANDROID
- #DroidSheep ARP spoofing app
- Capture facebook, Twitter, linkedin and other accoutns
- #SpoofApp 
	- Spoof (place) calls with any called ID number
	- Manipulate what number shows up on the person's phone when you call
	- Include several other features like a voice changer and call recorder
- #NetworkSpoofer Change how website appears to other from your phone . Flip text and picture, delete/replace words, change pictures, redirect to other pages

#### MITM / HIJACKING APPS that RuNs on ANDROID
#EvilOperator : Phone call MITM
#PurpSuite For Man-in-the-browser attacks, Security test web apps
#FaceNiff: Session Hijacker for Android (Against Facebook and Twitter)

#### DOS APPS that Run on ANDROID
#WifiKill kick others off a WiFi network
#AnDosid-Dos Tool for Android : - Performs an HTTP Post Flood DoS attack from an Android phone
#LOIC for Android : Low Orbit Ion Cannon, Launch a TCP , UDP or HTTP flood

#### SSH SERVER APPS THAT RUN on ANROID
- SSHDroid : 
	- An SSH server implementation for android
	- Lets you connect to your device from a PC and execute command like terminal and "ADB Shell"

#### ADDITIONAL HACKING TOOLS THAT RUN ON ANDROID
#USBCleaver Steal browser passwords and network information from any connected windows computer
#Orbot :  A tor client for Android#


### 17.7 Reverse Engineering and Android APP

#### Reverse Engineering and APK
- Examine an APP's functionality without having access to the source code. The person examining the app tries to re-create the app or its functionality based on observation
- An Attacker can attempt to decompile the app to recover as much code as possible
- An Android APK is really an archieve (ZIP) file that can be uncompressed
	- Various configuration files and codes libraries can be extracted
	- Binaries can be searched for text strings such as hard-coded credentials, names and IP addresses 
- Reverse engineering can be performed on:
	- A legitimate app for nefarious purposes
	- Malware to understand how it infects targets and propagates
> Do not confuse reverse-engineering with static code analysis (in which you have the actual source code available for study)

#### ANLAYZING AND ANDROID APK
- Application developers typically don't follow secure development best practices 
- They hard-code IP addresses, passwords, API keys and other credentials in their code.
- They fail to hash or encrypt data including credentials
- They don't obfuscate their final code. Make it more difficult to reverse-engineer
- You can use tools in Linux an Windows to decompile and APK to:
	- Statically inspect the application, its structure, code and resources (images, text)
	- Search for text strings containing credentials and addresses.

#### TOOLS to Decompile an APK
#APKExtractor Extracts all APKs from an Android Device GooglePlay
#APKVulnerabilities Analyzer : Decompile Android APK and analyze all security vulnerabilties
#SISIK Online APK Analyzer [link](https://www.sisik.eu/apk-tool)
#BugjaegerMobileADB GooglePlay
#APKTool ibotpeaches.github.io/APKTool/install
#IntelliJIdea with Smali Support Plugin
#Android AssetPAckagingTool IbotPeaches.Github.io/APKTool/install
#APKInspector : Reverse Engieer android apps

#### ANDROID APP DYNAMIC ANALYSIS
- You can obtain information from a running app including
	- Hashes for the anlayzed package
	- Incoming / outgoing network data
	- File read and write operations
	- Started services and loaded classes through DexClassLoader
	- Information leaks via the network, file and SMS
	- Circumvented permissions
	- Cryptographic operation performed using Android API
	- Listing broadcast receivers 
		- app components that want to know about events and state changes
	- Sent SMS and phone calls
- Tools:
	- DroidBox ([honeynet.org](https://www.honeynet.org))

#### 17.8 Securing ANDROID
- Do :
	- Enable screen locks
	- Use biometric for authentication when possible
	- Only Download apps from google play
	- Install endpoints protection ; keep the antivirus up-to-date
	- Keep the OS updated
- Don't 
	- Use easy PINS such "1111" or "1234"
	- Root an Android Device
	- Download APK files directly / side-load apps from unknown sources
	- Use hardware (including charging cables) of unknown origin

#### ANDROID SECURITY TOOLS
- DroidSheep Guard
- TrustGo Mobile Security
- Sophos Mobile Security
- 360 Security
- AVL
- Avira Antivirus Security
- X-Ray Vulnerability scanner

#### ANDROID DEVICE TRACKING TOOLS
- Google Find your phone
- Prey Anti-theft
- My AntiTheft
- Wheres my Droid
- iHound
- GadgetTrak MobileSecurity
- Total Equipment protection App
- AndroidLost.com

#### GOOGLE SECURITY FOR ANDROID
- GOOGLE PLAY PROTECT
	- Analyzes potentially harmful apps before you download them
	- Regularly scans your apps for malware, prompting you to uninstall any bad apps
	- Use machine learning to stay on top of the latest threats
- Google Safe Browsing
	- Monitors for malicious websites and dangerous files
- Passwords protection
	- Checks your password against a list of known compromised passwords
- Built-in anti spam protection
	- Tells you if an incoming call is suspicious
	- Attempts to keep spam out of your messages inbox
- google [link](https://www.android.com/safety)


### 17.9 IOS Overview
Apple IOS
- The apple mobile operating system
- It is made of multiple framework (layers of coded features) that provide:
	- Application support
	- User interface
	- Services
	- Core operating system

#### IOS SYSTEM SECURITY
- iOS Secure boot chain
- System software Authorization
- Secure Enclave Processor
	- A separate processor
	 - handles biometric information
- TouchID
- FaceID
> BOOT ROM (Hardware root of Trust ) ==Laid down during chip fabrication==
> Low Level Bootloader (LLB) :==Firmware checks verify kernel signature==
> iBoot : ==Kernel and OS are loaded==
> iOS Kernel 
> iOS Apps


#### TOUCH ID
- Reads fingerprint data from any angle
- Learns more about a user's fingerprint over time
- Continues to expand the fingerprint map as with continued use
- Used to : Unlock the device, Make payments, Access Data
#### FACEID
- A sensor with three modules
	- A dot projector that projects and grid of small infrared dots onto a user's face
	- A flood illuminator module that reads the resulting pattern and generates a 3D facial map
	- An infrared camera which takes an infrared picture of the user
- The map is compared with the registered face using a secure subsystem
- The user is authenticated if the two faces match sufficiently
- The system can recognize faces with glasses, clothing, makeup and facial hair, and adapts to changes in appearance over time 
	- Unlock the device
	- Make payments
	- Access data

#### IOS Keys
- Each file is individually encrypted
- Class keys are stored in the system keybag
	- Secure location for storing cryptographic secrets
	- Encrypted with user's passcode and device hardware key
- Class key and file system key encrypt individual file keys
- File keys encrypt individual file

> Hardware key locks {File System key }
> Hardware key and Passcode key locks {class key }
> File System keys and Class keys locks File metadata & file key
> This file key locks file contents

#### IOS SANDBOXING
- Apple apps are (mostly) develope using Swift or Objective-C Programming language
- Apple has strict rules for vetting and accepting apps to the apple store
- Apps must be digitally signed with a certificate from apple
- Apps can only be distributed through the apple store. Exception : Apple Developer enterprise program allows a in-house apps to be distributed in house.

#### iOS VULNERABILITIES
Critical iOS vulnerabilties since jan 2021

| CVE                                                                                                                                                            | CVSS | Type                                    | Description                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| CVE-2021-30991<br>CVE-2021-30985<br>CVE-2021-30983<br>CVE-2021-30980<br>CVE-2021-30971<br>CVE-2021-30954<br>CVE-2021-30949<br>CVE-2021-30937<br>CVE-2021-30934 | 9.3  | Exec <br>Code<br>Overflow<br>Corruption | Out-of-bounds read and write arbitrary cod execution<br>Buffer overflow<br>Use after free<br>iOS devices prior to 15.2 |
| CVE-2021-30916<br>CVE-2021-30886                                                                                                                               | 9.3  | Memory<br>Corruption Exec Code          | Memory Corruption, iOS devices prior to 15.1                                                                           |
| CVE-2021-30883                                                                                                                                                 | 9.3  | Exec code memory<br>corruption          | Momory Corruption<br>iOS                                                                                               |
| CVE-2021-30869<br>CVE-2021-30859                                                                                                                               | 9.3  | Exec Code                               | Type confusion issue<br>iOS devices prior to 12.5.5, 14.8                                                              |

> CVE Details.com reports 88 additional CVEs against Apple iOS with a CVSS of 9.0 or higher since January 2021


#### FAMOUS IOS Vulnerabilities

| Vulnerability                                        | Description                                                                                                                                                                                                                                                                                                                 |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Mactans                                              | - Plugging your iPhone /iPad into this malicious USB charger will inject persistent malware into your device<br>- Does not require jailbreaking or user action<br>- Affects all iOS devices                                                                                                                                 |
| CVE-2018-4150 Kernel Memory<br>Corruption            | - Allows attackers to execute arbitrary code or cause a DoS <br>- Affects iOS verson prior to 11.3                                                                                                                                                                                                                          |
| CVE-208-4109 Graphic Driver Vulnerability            | - Allows attackers to execute arbitrary code or cause a DoS <br>- Affects iOS versions prior to 11.2.5                                                                                                                                                                                                                      |
| CVE-2017-13879 IOMobileFrameBuffer <br>Vulnerability | - A weakness in the kernel extension used to manage the screen frame buffer<br>- Allows attacker to execute arbitrary code <br>- Affects iOS prior to 11.2                                                                                                                                                                  |
| Jailbroken iPhone                                    | - Jailbreacking overwrites the firmware, bypassing security controls which gives user root Preivilege and can install unauthorized applications including malware<br>- often opens an SSH server backdoor, default username and password easily found on the internet<br>- Most one-click jailbreaks are themselves suspect |
| iCloud API Vulnerability                             | - Celebgate a series of iCloud attacks, lead to the theft of about 500 private celebrity photos<br>- It exposed a weakness in the iCloud API that allowed unlimited password brute forcing                                                                                                                                  |
| MaControl Backdoor                                   | - An APT backdoor that has had multiple variations and delivery tools <br>- It connect to a command and Control (CnC) in China to receive instructions                                                                                                                                                                      |

### 17.10 JAILBREAKING IOS
#### JAIL BREAKING AN IPHONE
- Installation of modified set of kernel patches to run third party apps not from OS vendor
- Overwrites the firmware to remove digital signature protections
- Allows root access to OS and use of third-party apps, extension, themes . Install the cydia package manager to find/install apps
- Gets rid of sandbox restrictions, allowing malicious apps access to device
- Jailbreaking comes with the following security risks:
	- Voided phone warranty
	- Malware infection
	- Diminished performance
	- Bricking the device

#### FORMs of JAIL BREAKING
- Userland Exploit
	- Userland apps runs after the kernel has started
	- Entirely software based, can be patched by Apple
	- #JailbreakMe, #Star, #Saffron, #Spirit, Absinthe, evasi0n, #Pangu
- #iBootExploit
	- iBoot is a second-stage bootloader for recovery mode
	- Runs over physical USB or serial interface
	- Source code leaked onto GitHub
- #BootromExploit
	- Lowest level - can only be fixed by releasing new hardware

#### TECHNIQUES FOR JAILBREAKING
- Untethered Jailbreaking
	- Normal jailbreak
	- Device remains in a jailbroken state indefinitely
	- After jailbreaking, you reboot the device
- Semi-untethered Jailbreaking
	- After rebooting, the device appears to not be jailbroken
	- You must open the jailbreaking app, lock the phone and wait for the refresh
- Tethered Jailbreaking
	- Every time you reboot the devices, you have to jailbreak it with a computer
	- Otherwise the device won't even boot.

#### JAilBreaking Tools
#checkraIn #Pangu #RedSn0W #Absinthe #evsi0n7 #Sn0wbreeze #PwnageTool #LimeRaln #Blackraln

#### #CYDIA
- Cydia is an alternative App Store for IPhone , iPad and iPod Touch
- The most popular place to browse and obtain apps for your jailbroken iPhone
- It offers many apps that aren't available on App Store and are often rejected by Apple for Violating terms of use.
- Whenever you jailbreak your phone a process that's like rooting your Android device- the option is to install Cydia is often shown
- It can also be separately installed via Installer.App/AppTap
- Using Cydia, You can install many apps and tools
- You can also download apps from other places such as GitHub

#### 17.11 IOS Exploits
#### HAK5 O.MG Lightning CABLE
- Not a iOS exploit
- Looks and behaves like regular Apple lightning cable
- Acts as a keyboard when plugged into a pc
	- Runs a pre-created script that you programmed into its firmware
	- Types commands into the PC
- Also a short-range wireless access point for you to connect to 
- Your iPhone become an unwitting participant in hacking in PC
- Does not actually require an iPhone to be plugged into its other end
- Full shell of the target host via covert Wi-Fi Communications
- C2 remote management of O.MG devices
- #AirGap Host Comms :- Bidirection comms with target via covert channel
- #networkedC2 Control multiple O.MG from anywhere

#### IOS Exploits
`Exploit-db `offers 21 verified downloadable exploits against Apple iOS 
Metasploit offers 16 modules against Apple iOS
GitHub has 28 repositories with iPhone exploits
You can use #msfVenom to create a meterpreter payload for victims to side-load onto a jailbroken iPhone #you will have to use social engineering to get the victim to install the app.

#### IPWN
Framework for exploiting iOS devices
Target must be jailbroken
Features include:
	SSH brute forcing
	Remote command execution
	Payload delivery
	Data exfiltration
https://github.com/brows3r/iPwn.git

#### FORCEDENTRY
- CVE-2021-30860
- Developed by NSO Group to deploy their Pegasus spyware. Used by Goverments to attack political dissidents and human rights groups
- Uses PDF files disguised as GIF files to inject JBIG2-encoded data
- Enables the "Zero-click" exploit that is prevalent in iOS 13 and below
- Provokes an integer overflow in Apple's CoreGraphics system
- Circumvents iOS 14 "BlastDoor" sandbox for message content

#### ZEROClick
CVE-2020-3843
CVSS 8.8
iOS 13 radio proximity kernel memory corruption
Remote control a device over Wi-Fi using a Zero-click attack. No input required from the target
https://packetstormsecurity.com/files/download/162119/GS20210407204617.tgz

#### CHECKM8 IPWNDFU
- iPhone permanent unpatchable bootrom vulnerability exploit
- iPhone 4S (A45 Chip) to iPhone 8 , iPhone X (All chip)
- Features include
	- Dump SecureRom
	- Decrypt keybags for iOS firmware
	- Demote device for JTAG connections
		- Enable JTAG / SWD debugging on device that are fused
		- Turn the device into an "Apple internal use only" pre secured device
		- You can bypass its security features and attack a debugger to watch how the OS works. Ordinaryly you can't because it's always encrypted
		- You'll need a dedicated cable and software
		- http://blog.lambdaconectp.com/post/2019-10/iphone-bootrom-debug/
	- GitHub : axi0mX/ipwndfu
- #checkm8info is paid online iPhone unlock service 
#### 17.12 IOS-BASED HACKING Tools

#### #NetKillUI
Knock other device off your Wi-Fi network
Features similar to WiFiKill for Android
https://extigy.github.io/repo/

#### #Fing 
- Alternative to NMAP
- identify devices on your network Pinger, Port scanner, traceroute, DNS lookups
- Available on the APP Store
#### WIFI TOOL AND ANALYZER
- Multi network reconnaissance tool
- Features include:
	- Ping
	- LAN Scanning
	- DNS lookups 
	- Port scanning
	- WhoIs
	- Traceroute
- Available on the APP store

#### SPYWARE APPS
#iKeyMonitor #NeatSpy #Spyic #Spyier #MinSpy #Spyine #HoverWatch #Spyera #TheTruthSpy #HighsterMobile

#### #MYRIAM iOS Security APP
- A vulnerable iOS App with Security Challenges
- Contains Vulnerabilities for pen-testers to discover and exploit
- https://github.com/GeoSn0w/myriam

#### #OWASP #IGOAT
Multi-vulnerability learning tool
For developers and pentesters
identify, exploit, and fix app vulnerabilities
https://igoatapp.com

#### 17.13 REVERSE ENGINEERING AN IOS APP
#### DECOMILING AN IOS APP
As with android, you can decompile an iOS app to understand how it works
You can examine its various components and search for strings in the code
An iOS app has the extension .ipa
You can extract and decompile an IPA from a jailbroken phone
You can also obtain unauthorized IPAs from alternate download sites. #FileDude #FileApe and #AppTracker 

#### APPLE IPA FILE
- An .ipa files is an iOS application archieve file which stores all the files that comprise an iOS app:
	- Meta-INF folder
	- Payload folder
	- Various `*.plist` files
	- app container with application and its related data as graphics, settings, media files, etc.
	- Each `ipa` extension can be uncompressed by changing the extension to .zip and unzipping
#### DECOMPILING AN ipa
- Tools:
	- #Clutch (Cydia)
		- A script for cracking (removing DRM from) iPhone apps
		- In addition to cracking apps, #Crackulous offers automatic uploading of cracked `.ipa` files to #fileDude, #FileApe and #AppTracker 
	- #Crackulous : GUI front end for Clutch
	- #DumpDecrypted GitHub

#### REVERSE ENGINEERING TOOLS FOR iOS
- iRET - iOS Reverse Engineering Toolkit
	- Binary analysis using otool, reading database content using sqlite
	- Reading log and #plist files
	- Keychain analysis using `keychain_dumper`
- #HopperApp 
	- Reverse engineering tools for iOS apps
	- Great for forking and reassembling code
	- https://www.hopperapp.com

#### IOS APP ANALYSIS TOOLS
- #ispy 
	- Dynamic analysis of iOS apps
	- Class dumps , SSL certificate pinning bypass, etc.
	- Https://github.com/BishopFox/ispy
- Cycript
	- Explore and modify runnings iOS apps
	- Interactive console using Objective c++ and javascript syntax
	- Can be used to inject code and add breakpoints in jailbroken devices 
	- https://www.cycript.or

### 17.14 SECURING IOS

#### IOS SECURITY BEST PRACTICES
- Keep your device and apps updated
- Lock iPhone with passcode lock feature
- Do not use easy-to-guess PINs or swipe patterns
- Prefer to use biometrics such a #TouchID and #FaceID when logging into your device or running apps that handle sensitive data such as financial or health information
- Be cautions about connecting to free /public wi-fi
- Use VPNs when possible
- Do not use hardware (including USB cables) of unknown origin
- Prefer to carry your own power pack or AC charger, rather than using public USB charging stations
- Only downloads apps from the APP store
- Never open attachments / links from unknown sources
- Use find my phone to wipe a stolen / lost device
- Guard against unauthorized access to iTunes Apple ID and Google Accounts

#### IOS DEVICE TRACKING TOOLS
- Find my iPhone (iCloud)
- iHound
- GadgetTrack iOS security
- iLocalis

#### IPHONE ENDPOINT SECURITY APPS
- Norton security
- Total AV
- McAfee Mobile Security
- Avira
- Trend Micro
- Sophos Intercept X

### 17.15 MOBILE DEVICE MANAGEMENT
#### MOBILE DEVICE MANAGEMENT (MDM)
- Aids in the management of company and employee-owned devices
- Features typically include
	- Over-the-air app and patch installation / update / unintallation
	- Device tracking / geolocation
	- Remote locking/ Remote wiping
	- Jailbreaking / root and malicious app detection / restriction
	- Containerization to separate company data from personal data
	- Can wipe company data from a BYOD without affecting personal data
	- Enforce full storage encryption
	- GeoFencing
		- Allow or disallow phone features (mic , camera) in sensitive areas
	- Support for multiple device types including Android , iOS IoT and Laptops/ tablets
#### MDM EXAMPLES
#kandji #MangeEngineMobileDeviceManagerPlus #Scalefusion #VMWareWorkspaceONE #BlackBerryUnifiedEndPointManagement #CitrixEndpointManagement #SOTIMobiControl #IBMMaaS360 #CiscoMeraki #MiradoreMobileDeviceManagement #JamfNow #BeachHeadSecure

#### GOOGLE WORKSPACE ANDROID DEVICE POLICY
- A  lightweight MDM for Android on google Workspace
	- Google Workspace (formerly G-Suite) includes business tools such as: Gmail, Calender, meet ,etc
- Your google workspace admin can create Android Device policies for
	- Zero touch enrollment
		- Deploy company owned devices in bulk without manually setting up each device
	- Advanced password management
		- Set advanced password requirements. For example : disallow repeating or sequential characters
	- Advanced VPN management
		- Specify an app to be an Always on VPN
	- Lock screen feature management
		- Disable notifications, trust agents, fingerprint unlocks, and keyguard features on fully managed devices
		- Automatically adding new security features
#### #BYOD
BRING YOUR OWN DEVICE
- A policy allowing employees to use their personal devices in the workplace 
	- permits employees to use the device that best fits their work needs and personal preferences
- BYOD benefits
	- Better productivity
	- Increased flexibility
	- Improved employee satisfaction
	- Reduced costs

#### BYOD RISKS
- IT dept will need to support many types of devices
- Could introduce vulnerable devices to a corporate network
- Increase the risk of data leakage
- Problems with endpoints security
- Need to deal with stolen / lost devices
- Combining corporate and personal data
- Employees need to understand that devices can be confiscated as evidence in criminal investigations
	- Might take some time to get the device back

#### SCENARIO #1
- Your company is adopting a new BYOD policy for tablets and smartphones
- What would allow the company to secure the sensitive information on personally owned devices and the ability to remote wipe corporate information without the affecting the user's personal data?
- Containerization via the mobile device management (MDM ) system
- Containerization is the logical isolation of enterprise data from personal data while co-existing in the same device
- The major benefit of containerization is that administrators can only control work profiles that are kept separate from the user's personal accounts app and data
- This technology basically creates as secure vault for you corporate information
- Highly targeted remote wiping is supported with most container-based solutions


#### SCEANARIO #2
A company wants to ensure that its mobile devices are configured to protect any data stored on them if they are lost or stolen
What should you enable and enforce through their MDM?
==Full Storage encryption==
Since the company in concerned with protecting data on the devices , you should enforce full storag encryption with protecting data on the devices, you should enforce full storage encryption on the devices
Even if the device is lost or stolen, the devices data would be inaccessible to the person who stole or found the device
Additionally the company may wish to enable the capability to conduct remote wipes of the device if they are lost or stolen to protect the data further

### 17.16 HACKING MOBILE PLATFORMS COUNTERMEASURES
#### MOBILE DEVICE HACKING COUNTERMEASURES
- Pentest your mobile device
- Keep the OS and apps updated
- When backing up to the cloud, use data and transport encryption
- Lock your device with an unusual passcode/ swipe pattern
- Do not Jailbreak or root your device
- Download app from reliable sources only ;do not side-load apps
- Turn off Bluetooth, Wi-Fi and NFC when not in use
- Connect to trusted wireless network only use a VPN when practical
- Do not use hardware or charging cables of unknown origin
- Prefer to carry your own power pack , or AC adapter rather that plug your device directly into a public USB charging station
- Never click or links or call a phone number provider in an unsolicited message
- Use what you have learned about social engineering wireless victim to MITM , phishing , downgrade attacks , XSS, CSRF etc.
- Implement Mobile Device Management for your organization
- Keep mobile endpoints secure to reduce the attack surface risk they introduce to your network
### 17.17 HACKING MOBILE PLATFORMS REVIEW
- Mostly people do not take mobile device security as seriously as laptop or other computer security
- Mobile devices are subject to the same types of attacks that other computers are 
- A malicious charging cable can be used to install malware on a mobile device, even if it is not jailbroken / rooted
- User jailbreak or root a device to obtain superuser privilege and install apps that are normally disallowed
- You must be careful when jailbreaking or rooting a device because:
	- It by passes normal firmware digital signature security
	- It's likely to open ports that an attacker can connect to 
	- The jailbreak app itself is likely to be compromised
- Android user can side-load apps from unauthorized sources without root privilege 
- iPhone users can also side-load apps on a jailbroken device
- #Cydia is an alternate app store for jailbroken iOS devices
- Numerous mobile tools and exploits can be found in metasploit, on Explioit-DB.com and GitHub
- A number of hacking tools that run on Android or iOS can also be found
- You can decompile an app to learn how it works an search for hard-coded credentials and IP addresses
- Mobile Device Management is a system that allows an organization to control the security of an enrolled mobile device
- Bring-Your-Own-Device (BYOD) allows company users to use their own personal device for work
- BYOD is conventional for users, but introduces administrative challenges and security risks to the network.

