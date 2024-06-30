### ABOUT VULNERABILITIES

- A weakness that might be exploitable
- Can occur anywhere in the network
	- People
	- Process 
	- Technology
- You can have vulnerabilities that you are not aware of 
- You can have know vulnerability that no one has yet created an exploit for

### Vulnerability Classification



| Type | Type                          | Description                                                                                              |
| ---- | ----------------------------- | -------------------------------------------------------------------------------------------------------- |
| 1    | Misconfigration               | - Not Applying secure settings or configuration per best practises<br>- No Firewall, not anti-virus, etc |
| 2    | Leaving default in place      | - Configurations<br>- Passwords<br>- Services                                                            |
| 3    | Buffer Overflows              | -Not patching against known code weakness                                                                |
| 4    | Unpatched systems             | -Not applying security updates from the vendor                                                           |
| 5    | Desing Flaws                  | - Software that had a hurried development process with insufficient build-in security                    |
| 6    | OS Flaws                      | - Vulnerabilities discovered in the operating system                                                     |
| 7    | Application Flaws :           | - Vulnerabilities disovered                                                                              |
| 8    | Open Services                 | Services that freely permit client connections with no authentication or security controls               |
| 9    | User-based vulnerabilties     | User susceptibility to social engineering, lack of training or awareness                                 |
| 10   | Process-based Vulnerabilities | Security gaps in a business process that might allow exploitation by an attacker                         |

#### VULNERABILITY SCANNING
- You can scan for vulnerabilities and/or compliance
- Should include both physical and virtual systems (VMs, containers)
- Tools are typically automated and include host discovery and port scanning as part of the scan
- Some tools only “rattle the door knob” to see if the vulnerability exists
	- They do not attempt to actually exploit the vulnerability
- Some tools also attempt to exploit the vulnerability and provide proof
	- Such as a stolen file, obtaining a shell (command prompt), etc.
- Most tools refer to discovered vulnerabilities by CVE number
	- They provide links to additional information and recommendations
- Most tools have reporting capabilities
- Some tools use standardized output that you can import into another tool for additional
- validation

#### VULNERABILITY SCANNING APPROACHES

| Approach          | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Passive Scanning  | - Observation<br>- Passive Sniffiing                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Active Scanning   | -Send probes and specially crafted request to targets<br>--- Host discovery - see what hosts are alive<br>--- port scan and service enumerataion -- see what open ports, services and versions exists on the hosts<br>--- Rattle the doorknob<br>--- see if the OS or services responds in a way that suggests it is susceptible to a specific attack<br>--- Need not include actually launching the attack and compromising the device . That is usually done in a penetration test |
| Credntailed scans | - You provide the scanner with authentication credentials for the various systems it will scans. The scanner logs into the systems to retrieve their configuration information and log data<br>- Uncredentialled scans are generally unable to detect many vulnerabilities on a device. The rely on external resources for configuration settings that can be altered or incorrect.                                                                                                  |

#### VULERABILITY SCANNING TOOLS TYPES


| HOST BASED                                                                                       | CLOUD-Based                                                                                                     |
| ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| - OS<br>- Services<br>- Apps<br>- Versions<br>- Patch Levels<br>- Defaults and Misconfigurations | - Comprehensive solutions<br>- Emulated attacks<br>- Good for DevSecOps<br>- Often use AI for advanced analysis |

| Network-based                                                 | Depth Assessment                                           |
| ------------------------------------------------------------- | ---------------------------------------------------------- |
| - Protocols<br>- Ports<br>- ACLs / Firewall rules / IDS / IPS | - Fuzzers<br>- Look for previously unknown vulnerabilities |


#### CHARACTERISTICS OF A GOOD VULNERABILTY SCANNER

- Follows and inference-based approach
	- Assess vulnerabilities depending on the inventory of protocol in the environment
- Inventories protocols
- Detects open ports
- Identifies services behind the ports
- Checks for vulnerabilties
- Validates vulnerabilities
- Can be autoamted
- Signature database regularly updated
- Supports different network/host types
- Suggests proper remedies and workarounds
- Imitates outside attackers
- Creates actionable, customization reports
- Includes trends and categories by severity

#### LIMITS OF VULNERABILITY SCANNERS

- Just a start. only one part of larger penetration test
- Tools only look for known signatures
- Automated tools can produce a lot of false positives
- Automated tools focus on technology. You will need a skilled pentester to also evaluate vulnerabilities in people and processes
- Requires a pen test to determine if the system can truly be compromised
- Can destabilize fragile systems/ interfere with normal operations
- Likely to be incomplete if uncrednetialed
 
#### POPULAR VULNERABILITY SCANNERS

|                            |                    |                      |
| -------------------------- | ------------------ | -------------------- |
| OpenVAs                    | ImmuniWeb          | Kiuwan code security |
| TripWire IP360             | SolarWinds         | Acunetix             |
| Nessus                     | Intruder           | Invicti              |
| Nexpose                    | Core Impact        | Hakware archangel    |
| Comodo Hackerproof         | SecPod sanernow    | Runecast Analyzer    |
| Vulnerability Manager Plus | ManageEngine       | Astra Pentest        |
| Nikto                      | Paessler           | Qualsys              |
| Retina                     | CrowdStrike Falcon | Aqua                 |
|                            |                    |                      |

> Python can be used to
> 	Perform customized vulnerability sccanning
> 	Automate Tasks
> 	Parse results


```
from socket import *
import time
startTime = time.time()
if __name__ == '__main__':
	target = input('Enter the host to be scanned: ')
	t_IP = gethostbyname(target)
	print ('Starting scan on host: ', t_IP)
	for i in range(50, 500):
		s = socket(AF_INET, SOCK_STREAM)
		conn = s.connect_ex((t_IP, i))
		if(conn == 0) :
		print ('Port %d: OPEN' % (i,))
		s.close()
print('Time taken:', time.time() - startTime)
```


#### SECURITY CONTENT AUTOMATION PROTOCOL (SCAP)
- A multi-purpose framework of specification supporting
	- Automated configuration
	- Vulnerability and patch checking
	- Technical control compliance
	- Security measurement
- Used by the NVD
- SCAP is an industry standard
- SCAP scanners are typically used to test a system for compliance

#### SCAP Framework

> Security Standards Efforts : Security Content Automations Protocol

|                                                         |                                  |
| ------------------------------------------------------- | -------------------------------- |
| What IT systems do i have in my enterprise              | CPE (Platform)                   |
| What Vulnerabilties do i need to worry about?           | CVE (Vulnerabilties)             |
| What vulnerabilties doi need to worry about "RIGHT NOW" | CVSS (Scoring system)            |
| How can I configure my system more securly              | CCE (Configurations)             |
| How do i define a policy of secure configurations?      | XCCDF (Configuration Checklists) |
| How can i be sure my systems conform to policy          | OVAL (Assessment Language)       |

#### SCAP SCENARIO
- You are creating baseline systems images
- The image will be used to remediate vulnerabilities found in different operating systems
- Before any of the images can be deployed, they must be scanned for malware and vulnerabilties
- You must ensure the configuration meet industry-standard benchmarks and that the baselining creation process can be repeated frequently
- User an operating systems SCAP plugin to check the OS against known good baselines

#### VULERABILITY SCANNER OUTPUT
- Usually includes
	- Dashboard with summaries
	- Details for each device
- Output for both physical and virtual hosts
- Device OS Version
- Open TCP and UPD ports
- Installed application and services
- Discovered vulnerabilities, insecure default settings and misconfigurations
- Accounts with weak or default passwords
- Files and folders with weak permissions
- Technology-or device-specific issues
- Missing patches and hotfixes
- End-of-Life / End-of-Service software information
- Higher-end scanning tools will separate the report into
	- Executive summary
	- Technical details
- May include CVE and CVSS references
- Should incude recommendations to correct/ mitigates discovered issues.


#### SCAN RESULT CATEGORIES

- TRUE POSTIVE: The scanner detects a vulnerability, which is real
- TRUE NEGATIVE : Vulnerability do not exist and is not detected
- FALSE POSITIVE: There is no Vulnerability but Scanner detects a vulnerability
- FALSE NEGATIVE: Though there is Vulnerability, Scanner did not detects it.

#### COMMON REPORT ELEMENTS
- Executive summary
- Major Finding\
- Scan Information (Tools used, scope)
- Target Information
- Results
- Target Details
	- Node
	- OS
	- Services  / Ports
	- Date
	- Modules used
	- Outcomes
- Vulnerability Classification : Typically includes CVE references
- Threat assessment
- Recommendations
- Summary

### VULNERABILITY ASSESSMENT

#### WHAT IS A VULNERABILITY ASSESSMENTS
- A comprehensive assessment of a system's ability to withstand attack
	- Includes the use of automated vulnerability scanning tools
	- Part of the overall security audit
- Should also assess non-technical vulnerabilties (people, processes)
- Should produce an actionable report

#### What is Common Vulnerability Scoring System (CVSS)
- Open framework for communicating characteristics and impacts of IT vulnerabilities 
- Uses three groups of metrics for measuring vulnerabilities
	- Base metrics - inherent qualities of a vulnerabilities
	- Temporal metrics - features that keep changing during vulnerability lifetime
	- Environmental metrics - vulnerabilities based on a particular environment or implementation
- 1 (lowest) to 10 (Most Severe) Scoring
- Recorded in National Vulnerability Database

![[Pasted image 20240623185138.png]]


#### CVSS ATTACL VECTOR METRICS
The Attacker vector metric is scored in one of four levels (N A L P)
- Network (N)
	- Vulnerabilities with this rating are remotely exploitable, from one or more hops away, up to, and including, remote exploitation over the Internet
- Adjacent (A):
	- A Vulnerability with this rating requires network adjacency for exploitation
	- The attack must be launched from the same physical or logical network
	- The attacker must have access to the local network that the system is connected to.
- Local (L)
	- Vulnerabilities with this rating are not exploitable over a network
	- The attacker must access the system locally, remotely (via protocol like SSH or RDP)
	- Or requires use of social engineering or other techniques to trick an unsuspecting user to help initiate the exploit
- Physical (P)
	- In this type of attack, the adversary must physically interact with the target system.

#### CVSS ATTACK COMPLEXITY METRICS 
- The Attack complexity metrix indicates conditions beyond the attacker's control
	- These conditions must exist in order to exploit the vulnerability
	- Most commonly, this refers to either required user interaction, or specific configuration of the target system
- The attack complexity metric is scored as either Low or High
	- Low (L)
		- There are not specific pre-conditions required for exploitation
	- High (H)
		- There are conditions beyond the attackers control for successful attack
		- For this type of attack, the attacker must complete some number of preparatory steps in order to get access
		- This might include gather reconnaissance data, overcoming mitigations, or becoming a man-in-the-middle
#### CVSS PRIVILEGES REQUIRED METRIC
- This metric is exactly as it sound, describing the level of privileges or access and attacker must have before successful exploit
- Privileges requires falls under three ratings
	- None (N) : There is no privilege or special access required to conduct the attack
	- Low (L) : The attackers requires basic, "user" level privileges to leverage the exploit
	- High (H) Administrative or Similar access privileges are required for successful attack
- Reference: https://www.balbix.com/insights/base-cvss-scores

#### NATIONAL VULNERABILITY DATABASE (NVD)
- source:   https://nvd.nist.gov/
-  US government repository of standards-based vulnerability management data
- Uses Security Content Automation Protocol (SCAP)
	- Suite of specifications for automatically exchanging security content between systems
- Enables automation of vulnerability management
- Aggregates data to produce:
	- CVSS
	- Common Weakness Enumeration (CWE)
	- Common Platform Enumeration (CPE)
- Does not perform the actual tests

#### COMMON VULNERABILITIE AND EXPOSURES (CVE)
- SOURCE: https://cve.mitre.org
- ID system to precisely identifiy a vulnerability
- Used by both malicious and ethical hackers


#### RESEARCHING VULNERABILITIES
- Gather information about security trends, threats and attacks
- Discover system design faults and find weaknesses before an attack
- Learn how to recover from a network attack
- Classify vulnerabilities by:
	- Prioritiy
	- Severity
	- Scope
- Stay updated about new product, technologies and exploits 
- Check underground hacking web-sites (deep and dark web sites) for newly discovered vulnerabilities and exploits
- Check for news releases on security innovations and product improvements


#### RESOURCE FOR VULNERABILITY RESEARCH
 - SANS (https://sans.org)
- CISA (https://cisa.gov)
- CVE Details (https://www.cvedetails.com)
- OWASP (https://www.owasp.org)
- Microsoft Vulnerability Research (MSVR) (https://www.microsoft.com)
- Dark Reading (https://www.darkreading.com)
- SecurityTracker (https://securitytracker.com)
- Trend Micro (https://www.trendmicro.com)
- Security Magazine (https://www.securitymagazine.com)
- PenTest Magazine (https://pentestmag.com)
- SC Magazine (https://www.scmagazine.com)
- Exploit Database (https://www.exploit-db.com)
- Rapid7 (https://www.rapid7.com)
- Security Focus (https://www.securityfocus.com)
- Help Net Security (https://www.helpnetsecurity.com)
- HackerStorm (http://www.hackerstorm.co.uk)
- Computerworld (https://www.computerworld.com)
- WindowsSecurity (http://www.windowsecurity.com)
- D'Crypt (https://www.d-crypt.com)
- Sophos (https://www.sophos.com)

### 5.3 VULNERABILITY ANALYSIS REVIEW
- You can perform vulnerability scans to identify weaknesses or lack of compliance 
- Scanning can be passive or active
- Vulnerability scanning tools can focus on hosts, network devices, cloud services or applications
- Credentialed scans typically provide more information than uncredentialled scans
- SCAP Scans are used to test a system for compliance
- Scan results can return four different types of results
	- True Positive : There is really a vulnerability
	- True Negative : There is really no vulnerability
	- False Positive : The scanner reports vulnerabilities that do not actually exist
	- False Negative - the scanner fails to report vulnerabilities that actually exist
- Vulnerability assessment should include both technical and non-technical targets (people, processes)
- A vulnerability assessment should produce an actionable report
- Common Vulnerability Scoring System (CVSS) ranks vulnerability severity on a scale of 1-10
- CVSS identifies four attack vectors, network, adjacent, local, physical
- The NATIONAL Vulnerability Database is a central repository of vulnerability information
- Common Vulnerability and exposures (CVE) is an identification system used to precisely identify a specific vulnerability
- CVEs are used by both malicious and ethical hackers
- Vulnerability research should be an ongoing process
- There are many sites and services dedicated to providing the latest vulnerability information
- 