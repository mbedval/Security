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

