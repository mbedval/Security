## HACKING WEB SERVERS
### 13.1 WEB SERVER OPERATIONS

#### 13.1.1 Web Server Security
- Focuses on the server rather than the web apps
- Involves all of the typical system hacking techniques and countermeasures
- Popular Web Servers Apache, Microsoft IIS and NGINX
	- Apache: 
		- The most widely used web server in the world
		- Open source 
		- Runs on unix/linux and windows
		- Strong support community
	- Microsoft Internet Information Server (IIS)
		- ASP.Net integration
		- All components are separate moduels that can be updated
		- Runs in the context of LOCAL_SYSTEM
		- ISS 5.0 had many vulnerability
	- NGINX
		- Uses a very different architecture for high performance
		- Web Server, Reverse proxy, load balancer, mail proxy and HTTP cache
		- Fellows worker can asynchronously handle 1000 requests at a time
		- Rendered pages are cached.
- 
N-Tier WebSite
	- Distributes processes across multiple servers
	- "N" tiers mean you can have as many processing tiers as makes sense for yours use case.
	- "N-Tier is normally implemented as three separate fault-tolerant servers:
		- Presentation
		- Business logic
		- Data(Database server back end)

#### 13.1.2 Web Server Architecture
 ##### N-Tier Architecture & component
- Client (Web/Desktop/Mobile)  ==> 
- WAF ==> 
- Web Tier  (Presentation Layer) working on Apache/IIS/NGINX ==> 
- MESSAGE QUEUE/API >> 
- Middle Tier 1/Tier2  (Business Layer) working on Servers like (Apache Tomcat, Java Server Pages, C# APP ==> 
- Cache (could be there)
- Data Tier (Data Layer) working on MySQL, Oracle SQL, MSSQL, DB2 , etc

##### N-Tier Server Topology
- Load Balancer Web Server
- Load Balanced Clustered Application Server
- Clustered Database Server 
##### 13.1.3 Web Server Vulnerabilities

- Webserver, OS and network misconfigurations
- Bugs in the OS, Web Apps, logic software and database engine
- Insufficient host hardening
- Improper authentication
- Improper permissions for files/directories
- Unchanged default accounts, settings and sample files
- Vulnerable Web security 

###### CONSEQUENCES OF WEB SERVER ATTACKS
- Tampering /Theft of data
- Defacement of websites
- Compromised user accounts
- Root Access to other apps/servers
- Secondary attacks from the website




### 13.2 HACKING WEB SERVERS

#### WEB SERVER ATTACK METHODOLOGY 
-  Attacking a web server involves the same basic steps as any other system hacking
	- #Footprinting #Scanning #Enumeration #Exploitation
- Consider mirroring the websites to make an offline copy that you can probe at your convenience
	- Realize that a local copy of the website might not include access to business logic or database functionality 
	- #MirroingTools Copies entire site to your own machine so you can take your time examining it.: #Wget #BlackWidow #HTTrack #WEbCopierPro #WebRipper #SurfOffline 
#### Vulnerability Discovery
- Banner grab
- Port and vulnerability scan
- Test HTTP methods
	- Checks for GET, Head, POST , Options, Delete Put, Connect, Trace
	- Risky method are DELETE, PUT, CONNECT, TRACE and should be disabled
	- `nmap --script http-methods <target>`
- List email addresses  `nmap --script http-google-email`
- Enumerate common web apps `nmap --script http-enum -p80`
- #VulnerabilityDiscoveryTool #nmap #acunetixWebVulernabilityScanner #HPWebInspect #Nessus #Nikto #metasploit 
```
nmap --script http-trace -p80 localhost 
// Detect vulnerable Trace method

nmap --script http-google-email <host> 
// List email addresses

namp --script hostmap-* <host> // Discover virtual hosts on the IP address you aretrying to footprint; * is replace by online db such as IP2Hosts

nmap --script http-enum - p80 <host> 
//Enumerate common web apps

nmap --script http-robots.txt -p 80 <host>
// Grab the robots.txt file

```

#### SUB-Directory BRUTE forcing

- Attacking to identify website sub-directories and files
- These objects can exist without obvious navigation to them
- They often contain sensitive information
- Tools L #DirBuster, #GoogleDorks #SiteCheckerPRo #URLFuzzer





### 13.3 COMMON WEB SERVER ATTACKS

- Passworking cracking: 
	- Websites passwords are often exempt from normal lockout policies 
	- Password cracking techniques include 
		- BruteForce attack
		- Dictionary Attack
		- Password Guessing
	- Password cracking tools include : #THC-hydra #Brutus #Medusa 
	- Vulnerabilities that facilitate password cracking:
		- No intruder lockout after a certain number of failed attempt
		- Intruder lockout time that's too short
		- Allowing simultaneous logins from the same or multiple hosts
		- Transmitting login traffic via HTTP instead of HTTPS
	
- DNS server Hijacking
	- Does not compromise the web server itself
	- Instead changes the web server's DNS A record
		- DNS then misdirects users to a malicious site.
	- Attacker modifies the web server's A record by :
		- Pretending to be a primary DNS server providing a zone transfer to a secondary server
		- Pretending to be the web server performing a dynamic DNS update of its own record 
		- Corrupting the saved lookups on a caching-only DNS server.
	- 
- Misconfiguration Attacks
	- A number of exploits take advantages of web server misconfiguration including:
		- Unnecessary features
		- Default accounts
		- Weak passwords
		- Error messages that reveal sensitive information
		- Lack of updates and patching
		- Incorrect permissions
	- Ancillary services such as SMTP and FTP can also put a web server at risk.
		- These are often extended features of the website.
		- They need their own hardening and proper configuration
	- A misconfigured operating system or insecure physical environment can also make the web server vulnerable 
	- Coding errors in web apps provide another vector for attack.
	
- Web cache poisoning
	- Replaces website cached content with malicious content
 
- Web Page Defacement
	- Replacing authorized content with something else
	- Vulnerable web apps and improper file system permissions are the most common cause.
	
- DoS / DDoS
	- Any attack that makes the web server unavailable
	- Can include
		- Network bandwidth consumption
		- Resource consumption
		- Amplification attacks
	- DNS Emplication DDos
		- Sends UDP Packets with spoofed source IP
		- Send response to source IP
		- Victim receives responses.

- TLS Downgrade / MITM
	- Use a Man-In-the-Middle attack to force the client to downgrade its connection security to the web server.
		- TLS  -> SSL
		- HTTPS -> HTTP
	
- Directory Traversal
	- Escaping web content directory to access other operating system directories
	- 
- Shellshock
	- Shellshock is a bug in the Linux BASH command-line interface shell
	- Causes BASH to unintentionally execute commands when commands are concatenated on the end of the function definitions
	- A vulnerable version of BASH can be exploited to execute commands with higher privileges
	- This allows attacker to potentially take over the system
	- Shellshock is a simple and inexpensive attack that bad actors can deploy against an unknowing target
	- It affect many internet-facing services including those on Linux, UNIX and OS X . It did to directly affect windows.
``` 
env x = `() { : ; }; echo exploit ` bash -c `cat/etc/passwd`
```
![[Pasted image 20240824132452.png]]


- Heartbleed
	- Exploits a flaw in the OpenSSL implementation of TLS
	- SSL includes a heartbeat option
		- Allows a computer at one end of an SSL connection to send a online and get a response back
	- It is possible to send a malicious heartbeat messages
		- Tricks the computer at the other end into divulging content from its memory
		- Leaked information can include private keys, secret keys password, credit card numbers, etc.

- #POODLE 
	- Padding oracle on Downgraded legacy encryption
	- POODLE attacks make use of web browser and server fallback to SSLv3
		- Happens if negotiating a TLS session fails
		- An attacker can "force" TLS negotiation to fail
	- POODLE steps:
		- Attacks inserts themselves as MITM between client and server.
		- Forces a downgrades of TLS to SSLv3
		- Then if the cipher suites users RC4 or Block cipher in CBC mode:
			- Attacker can retrieve partial bytes of encrypted text and later or can get full plain text
	
- DROWN ATTACK
	- Decrypting RSA with obsolete and weakened encryption
	- Exists due to the inclusion of 40-bit encryption in SSLv2
	- Vulnerability requirements:
		- The server must allow both SSLv2 and TLS connections
		- The server's private key must be used on any other server that facilitates SSLv2 connections
- Attack Steps:
	- The attacker must capture both the initial RSA handshake and the encrypted TLS traffic
	- The attacker repeatedly modifies the handshake, sending thousands of these messages to an SSLv2-capable server
	- Each response from the server to the attacker yields partial key material
		- It takes about 1000 handshakes to capture a recoverable key
	- Once the session key is recovered, the captured TLS traffic can be then be decrypted




### 13.4 WEBSERVER ATTACK TOOLS
- Brutus, THC Hydra, Medusa #windows
	- Brute force network-based password crackers
- Metasploit #linux
	- Open Source Hacker framework with many exploits and payloads
	- You can search for "apache", "IIS", "nginx" "poodle", "shellshock", etc.
	- Installed by default in kali linux
		- Can also be downloaded and installed in other Linux distributions.
		- Metasploit Pro (commercial version) can be installed on windows
- SearchSploit #linux
	- A command line search and download tool for Exploit-DB
	- Installed by default
- WFETCH :  Microsoft tool to customize and send HTTP requests #windows
- Low Orbit Ion Cannon (LOIC): Floods a target server with TCP, UDP or HTTP packets #windows
- High Orbit Ion Cannon (HOIC) : Floods target systems with junk HTTP GET and POST requests #windows
- Hulk #windows #cygdrive
	- Attack web server by generating unique and obfuscated volumes of traffic.
	- Bypasses caching engines, directly hitting the server's resources pool

### 13.5 HACKING WEB SERVERS COUNTER MEASURES

#### 13.5.1 General Webserver Defense
- Set file system permissions on all directories and content
- Requires HSTS on the webserver
- Keep all related services and components patched and up-to-date
- Harden the Operating system and network infrastructure
- Remove unnecessary services and features and change defaults (Move other network services to other hosts)
- Ensure restricted access to configuration files including registry settings
- Relocate all websites / virtual directories to non-system partitiions. Restrict access using web-server and file system permissions.
- Ensure all incoming traffic requests are screened / filtered with a firewall and WAF
- Implement NIDS in the DMS and private webservices-related VLANS
- Implement HIDS and host firewalls on all systems
- Disable serving directory listings.
- Get rid of unnecessary .jar and non-web files.
- USe byte code to eliminate configuratio information that is sensitive.
- Remove unnecessary script mappings for files extensions that are optional
- Physically separate the web front end, applications layer, and database layer onto separate servers.
	- Only put the web front end in the DMZ
	- Implement a transport mode IPSEC VPN between.
		- The web front end and the application server
		- The application server and the database server.
- Implement fault tolerance and redundancy
	- Load balance the web server
	- Cluster the application server
	- Cluster the database server
- Run your own vulnerability scans and remediate any findings.
- Enable minimum auditing level on webserver and protect log files using file system permissions.
- Forward logs to syslog servers.
- Use SIEM to track and analyze trends
- Ensure the server certificate is current and issued by a reputable certification authority
- Ensure that the web service , application service and database service use different accounts.
- Configure a separate anonymous user account for each app when hosting more than one web app.
\
#### WEBSERVER VULNERABILITY SCANNERS
- #Nikto
	- Open source web server and web application scanner
	- Performs comprehensive tests for multiple security threats including
		- Dangerous files/ programs
		- Outdated web server software
		- Version-specific problems
	- Online website vulnerability scanners.
		- SUCURI
		- QUALSYS
		- QUTTERA
		- INTRUDER

#### 13.5.2 Protect Apache
- Update LAMP components to the latest version
```
sudo apt-get update
sudo apt-get upgrade
```
- Discover and disable unnecessary modules running on the server
```
sudo ls /etc/apache2/nods-enabled
sudo a2dismod module_name
```
- Check the log for suspicious request and hacking attempts
- Ensure that Apache and SQL use different, non-root user accounts
- Configure `/etc/apache2/apache2.conf`
	- Disable `ServerSignature` and `ServerTokens` directives
	- Disable server Directory listings
	- Protect system settings by disabling the `.htaccess` directive
	- Defend against a `slowloris` DoS attack by reducing the connection timeout value
	- Limit HTTP/HTTPS request per directory


#### 13.5.3 Protect IIS
- Use `UrlScan` to screen/filter incoming requests based on rules by admin
- `Machine.config`
	- Make sure to map protected resources to HttpForbiddenHandler
	- Remove unused HttpModules
	- Disable tracking `(<trace enable ="false"/>)`
	- Turn off debug compiles
- Check the log for suspicious requests and hacking attempts:
	- `%SystemDrive%\inetpub\logs\LogFiles`
- Remove unnecessary ISAPI extension and filters
> ISAPI filters provide Web servers such as IIS the ability to preprocess or postprocess information sent between client and server. They are used for such tasks as custom authentication, encryption, and compression schemes or for updating logging statistics on the web server



 

#### 13.5.4 Protect NGINX
- Keep NGINX and PHP updated to avoid these well-known NGINX vulnerabilities
	- SPDY heap buffer overflow
		- Allows the attacker to execute arbitrary code through a crafted request
		- SPDY = Google protocol to accelerate web content delivery
	- Root Privilege Escalation Vulnerability
	- Remote Integer Overflow Vulnerability
		- A Boundary Condition Error Type that grants access to sensitive information
	- NGINX Controller vulnerability
		- Allows creation of unprivileged user accounts
	- PHP7 remote code execution vulnerability
		- Can lead to information disclosure or unauthorized modification.
		- 
#### WEB SERVER ATTACK SCENARIO
- You discovered several unknown files in the root directory of your Linux FTP server.
	- A `tarball` t wo shell script files and binary files name "nc"
- The FTP servers access logs show that the anonymous user account:
	- logged in to the server
	- uploaded the files
	- extracted the contents of the tarball
	- ran the script using a function provided by the FTP server's software
- The "PS" command shows that the "nc" file is running as process
- The netstat command shows the "nc" process is listening on a network port.
- What kind of vulnerability must be present to make this remote attack possible?
- File system did not have proper permissions
- The anonymous user must have write permissions to the FTP directory
- Perform a review of all permissions to the FTP directory

### 13.6 HACKING WEB SERVICES REVIEW
- Use a multi-layered approach when attacking or defending a web-server
- Webservers are vulnerable to attacks againsts
	- The operating system
	- The web service
	- Web Apps
	- Other Vulnerable network services running on the same server
	- Supporting network services like DNS
	- Client appliactions
- Common attack includes:
	- Dos/DDoS
	- Password Cracking
	- HTTP Response splitting
	- Session hijacking
	- Brute forcing
	- Defacement
	- Directory Traversal
	- Misconfiguration attacks
	- Web cache poisioning
	- TLS Downgrade MITM
	- Shellshock
	- #Heartbleed
	- POODLE
	- DROWN




