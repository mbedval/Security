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


#### 6.23 SYSTEM HACKING REVIEW p923
