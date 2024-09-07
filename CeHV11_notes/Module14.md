### 14.1 WEB APPLICATION CONCEPTS
##### HOW Web App Architecture work
- Web apps use web pages to provide an interface between web servers and end users.
- The web app can dynamically build, modify or populate the web page
- The app are independent of the operating system
- Users can access them from any device.
- They use flexible technologies such as:
	- JSP, Servlets, Active Servers pages, SQL Server, .Net and Scripting language.
- Although they can enforce some security policies, they are vulnerablt to various attacks such as SQL injection, cross-site scripting and session jijacking.

##### Popular Web APP Technologies
Browser Client App: Javascript, jQuery, HTML, CSS, DOM, AJAX
Data Structure : XML , JSON
API : REST , SOAP
WEB APP : PHP, Javascript, ASP.Net , Java, Python, C# , Perl, RUBY, GO
Database: SQL, NoSQL


### 14.2 ATTACKING WEB APPS

##### WEB APP VULERNARBILITY STACK
1. Web APP
2. Third Party Components
3. Database
4. Web-Server
5. Operating System
6. Network
7. Physical Environment

##### UNVALIDATED and UNSANITIZED INPUTS
- This is the single biggest web app coding mistake
	- It is responsible for the more vulnerabilities than any other type of error.
- Most web app attacks can be mitigated through input validation
- Disallow any characters that would not be part of normal input
- Make sure the app filters out or escapes metacharacters so they lose their special meaning
- Note: The exact characters will depend on the programming
- Examples : `& } (  ) < > * ? Space [ ] `  `` `

#### OWASP TOP 10 WEB App Vulnerabilities (2021)
A01 -Broken Access Control
A02 -Cryptographic Failures
A03 -Injection
A04 -Insecure Design
A05 -Security Misconfiguration
A06 -Vulnerable and outdated components
A07 -Identification and Authentication Failures
A08 -Software and Data Integrity Failures
A09 -Security Logging and Monitoring Failures
A10 -Server-Side Request Forgery


#### WEB APP HACKING PRACTISE PLATFORMS
https://www.certifiedhacker.com #VulnerableonlineSite
http://Testphp.vulnweb.com : #VulnerableonlineSite
www.tryhackme.com : Step by Step guided hacking practice on an online website
www.Vulnhub.com : Download deliberately vulnerable virtual machines
#WebGoat : Deliberately insecure web app provided by OWASP #VulnerableonlineSite
#BeeBox : Download #VirtualMachines with any deliberate web app vulnerabilities 
#Metasploitable2 : Download #VirtualMachines that is deliberately vulnerable, includes (`DVWA` & `Mutillidae`)


### 14.3 A01 -BROKEN ACCESS CONTROL 

- Access control (Aka Authorization ) is a security measure that
	- Makes resources available to users that should have access
	- Denies access to users who should not have access
- Broken access control occurs when an issue witih the access control enforcement allows a user to perform an action outside of the user's limits
- Example: 
	- An attackers exploits a flaw in an application
	- Intent is to gain elevated access to a protected response to which they are not entitled.
	- The resulting privilege escalation lets the attacker perform unauthorized actions.

##### COMMON ACCESS CONTROL VULNERABILITIES
- Violation of the principle of least privilege or deny by default
	- Where access should only be granted for particular capabilities, roles, or users, but is available to anyone.
	- Bypassing access control checks by modifying the URL (Parameter tampering or force browsing) internal application state, or the HTML page, or by using an attack tool modifying API requests
	- Permitting viewing or editing someone else's account by providing its unique identifier (insecure direct object references)
	- Access API with missing access controls for POST, PUT and DELETE
- Elevation of Privilege
	- Acting as a user without being logged in or acting as an admin when logged in as a user.
	- Metadata manipulation, such as replaying or tampering with a JSON web token (JWT) access control token
	- A cookie or hidden field manipulated to elevated privileges
	- A CORS* misconfiguration allows API access from unauthorized / untrusted origins
	- Force browsing to authenticated pages as an unauthenticated user or to privileged pages as a standard users.
	>Cross Origin resource sharing (CORS) is a mechanism that allows a way for web pages to access an API or assets running on a server from a different restricted DNS domain.	>
- Attack Example 1: The attacker uses forced browsing techniques to exploit an unprotected static directory on the target system.
		- The attacker uses an automated scanning tool to search for unlinked resources on the target system and finds the following unprotected resources : /admin
		- The attacker initiates a forced browsing attack on the target system to verify whether administrative rights are required to access the admin page
		- The attacker accesses the admin page as an unauthorized user and performs unauthorized actions.
- Attack Example 2: 
	- The application uses unverified data in a SQL call that is accessing account information : `pstm.setstring(1, request.getparameter("acct")); resultset results = pstmt.executequery();`
	- An attacker modifies the browser's 'acct' parameter to send whatever account number they want
	- If no correctly verified, the attacker can access any user's account: 
	- `https://example.com/app/accountinfo?acc-someotheracc`
- Attacker Example 3:
	- An attacker manually enters restricted pages in the browser
	- If the unauthorized attacker can access either page, its a flaw
	- `https://example.com/app/getappinfo`
	- `https://example.com/app/admin_getappinfo`
- Attacker Example 4:
	- Parameter tampering
	- While visiting an online bank, you see this string in the URL:
		- `http://www.mybank.com/account?id=3423423425&Damount=12345&Camount=21`
	- You manually change the values for Damount and Camount and submit the request
	- The data on the web page reflects the changes.


##### BROKEN ACCESS CONTROL COUNTERMEAURES

- Except for public resources, deny by default
- Implement access control mechanism once
	- Re-use them throughout the application
	- Minimize cross-origin resource sharing (CORS) usage
- Access controls should enforce record ownership, rather than accepting the user can create, read, update or delete any record
- Enforce unique application business limit requirements
- Disable web server directory listing
	- Ensure file metadata (eg .git ) backup file are not present within web roots.
- Log access control failures, alert admins when appropriate (eg repeated failures)
- Rate Limit API and controller access
	- Minimize the harm from automated attack tools
- Stateful session identifies should be invalided on the server after logout.
- Stateless JWT tokens should be short-lived. Minimize the attacker's window of opportunity
- For Longer lived JWT,s follow the OAuth standards to revoke access
	- https://oauth.net/2/
- Ensure that developers and QA staff include functional access control in unit and integration tests


### 14.4 A02 CRYPTOGRAPHIC FAILURES
- Cryptographic failure is the root cause for sensitive data exposure
- Attackers often target sensitive data, such as passwords, credit card numbers and personal information, when you do not properly protect them
- Determine the protection needs of data in transit and at rest
- Examples of data that requires extra protection includes
	- Passwords credit card number, health records, personal information, and business secrets.

##### ATTACKS
- Attack1: 
	- An application encrypts credit card numbers in a database using automatic database encryption
	- However this data is automatically decrypted when retrieved.
	- This allows a SQL injection flaw to retrieve credit card numbers in clear text.
- Attack2:
- Attack3:
	-  A site doesn't use or enforce TLS for all pages or supports weak encryption
	- An attacker monitors network traffic (eg at an unsecure wirelss network)
		- Downgrades connections from HTTPS to HTTP
		- Intercepts requests
		- Steal the user's session cookie
	- The attacker then replays this cookie
		- hijacks the user's (authenticated) session
		- Access or modifies the user's private data
	- Alternatively the attacker could alter all tranported data
- Attack4:
	- The password database uses unsalted or simple hashes to store everyone's passwords
	- a file upload flaw allows an attacker to retrieve the password database
	- All the unsalted hashes can be exposed with a rainbow table of pre-calculated hashes
	- Hashes generated by simple or fast functions may be cracked by GPU's even if they were salted
##### BEST PRACTICES FOR USING CRYPTOGRAPHY TO PROTECT SENSITIVE DATA
- Classify data processed, stored or transmitted by an application
	- Identify which data is sensitive according to privacy laws, regulatory requirements or business needs.
	- Don't store sensitive data unnecessarily
		- Discard it as soon as possible or use PCI DSS compliant tokenization or even truncation
		- Data that is not retained cannot be stolen
	- Make sure to encrypt all sensitive data at rest.
	- Ensure up-to-date and strong standard algorithms, protocols, and keys are in place. Use proper key management
-  Encrypt all data in transist with secure protocols such as TLS with forward secrecy (FS) ciphers, cipher prioritization by the server and secure parameters. Enforce encryption using directives like HTTP strict Transport Security (HSTS)
- Disable caching for response that contain sensitive data
- Apply required security controls as per the data classification.
- Do not use legacy protocols such as FTP and SMTP for transporting sensitive data.
- Store passwords using strong adaptive and salted hashing functions with a work factor (delay factor) (i.e. Argon2, scrypt, bcrypt or PBKDF2)
- Initialization vectors must be chosen appropriate for the mode of operation
	- For many modes, this means using a CSPRNG (cruptographically secure pseudo randon number generator)
	- For modes that requires a nonce, then the initialization vector (IV) does no need a CSPRNG
	- In all cases, the IV should never be used twice for a fixed key
- Always use authenticated encryption instead of just encryption
	
### 14.6 A04 INSECURE DESIGN

##### INSURE DESIGN
 - Insecure design is a broad category representing different weakness, expressed as missing or ineffective control design
 - One of the factor that contribute to insecure design is the lack of business risk profiling inherent in the software or system being developed
	 - The developers fail to determine what level of security design is required
 - There is a difference between insecure design and insecure implementation
	 - A secure design can still have implementation defects
	 - An unsecure design cannot be fixed by a perfect implementation as by defintion.

##### INSECURE DESIGN EXAMPLE
- The web app developer implemented a poorly designed API that does not properly filter input
- Attack steps 
	- Scan for vulnerable APIs
	- Identify an API that does not:
		- properly filter input
		- use  the organization's API security gateway
	- Inject a malicious script into the vulnerable API
	- The victim's browser accesses the API through the application
	- The browser loads content with the malicious script.

##### DESIGINING SECURELY

- Secure design is neither an add-on nor a tool that you can add to software
- Secure design is a culture and methodology
- It constantly evaluates threats and ensures that code is robustly designed and tested to prevent known attack methods
- Threat modeling should be integrated into refinement sessions. (or similar activities)
- Look for changes in data flows and access control or other security controls
- In the user story development determine the correct flow  and failure states
	- Ensure they are well understood and agreed upon by responsible and impacted parties
- Analyze assumptions and conditions for expected and failure flows
	- Ensure they are still accurate and desirable
- Determine how to validate the assumptions and enforce conditions needed for proper behaviors
	- Ensure the results are documented in the user story
- Learn from mistakes and offer positive incentives to promotes improvements
- 


### 14.7 A05 SECURITY MISCONFIGURATION

#### COMMON CONFIGURATION MISTAKES
- An app is missing appropriate security hardening across any part of its stack
- Cloud services have improperly configurated permissions
- The app has unnecessary features enabled or installed
	- Unnecessary ports, services, pages, account or privileges
- Default accounts and their passwords are still enabled and unchanged
- Error handling reveals stack traces or other overly informative error messages to users.
- For upgraded systems, the latest security are disabled or not configured securely
- Security settings in application servers application framework (eg. struts, spring, asp.net) libraries, databases , etc are not set to secure values.
- The server does not send security headers or directives
	- or they are not set to secure values
- The software is out of data or vulnerable

#### MISCONFIGURATION EXAMPLE
Attacker uses default credentials , gains access to internal network, scans for devices with default credential , takes over devices with default credentials and uses internal (exploits) resources

##### CONFIGURATION BEST PRACTICES
- Implement a repeatable hardening process
	- Makes it fast and easy to deploy another environment that is appropriately locked down
	- Development, QA and production environment should all be configured identically with different credential used in each environment
	- This process should be automated to minimize the effort required to setup a new secure environment
- Implement a minimum platform without any unnecessary feature, components documents and samples: remove or do not install unused features and frameworks
- Create a task to review configuration and update effectiveness as part of your patch management process
	- Review cloud storage permission (eg S3 bucket permissions)
- Implement a segmented application architecture
	- Provides effective and secure separation between component or tenants
	- Use segmentation containerization or cloud security groups (ACLs)
- Send security directives such as security headers to clients
- Create an automated process to verify the effectiveness of configuration and settings in all environments

 ### 14.8 VULNERABLE AND OUTDATED COMPONENTS
 - You do not know the versions of all components you use (both client and at server side)
	 - Includes components you directly use as well as nested dependencies
 - The software is vulnerable unsupported or out of date
	 - Include the OS, web/application server and database management system (DBMS), applications APIs and all components, runtimes environment and libraries
 - You do not scan for vulnerabilities regularly and subscribe to security bulletins related to the components you use
 - You do not fix or upgrade the underlying platform, framework and dependencies in risk-based timely fashion
	 - Occurs in environments when patching is a monthly or quarterly task under change control
	 - Leave organizations open to days or months of unnecessary exposures to fixed vulnerabilities 
 - Software developers do not test the compatibility of update, upgraded or patches libraries
 - You do not secure the components configurations.
 - Attacker exploits flaws in outdated systems and install malicious code on them

#### HOW TO AVOID BECOMING OUTDATED
- Institute a patch management process
- Implement an ongoing plan for monitoring triaging and applying updates or configuration changes for the lifetime of the applications or portfolio
- Remove unused dependencies unnecessary features components files and documentation
- Continuously inventory the version of both client-side and server side component (eg: framework libraries) and their dependencies. Use tools like versions, OWASP dependency checker, retire.js, etc.
- Continuously monitor source like common vulnerability and exposures (CVE) and national vulnerability Database (NVD) for vulnerabilities in the components
- Use software composition analysis tool to automate the process
- Subscribe to email alerts for security vulnerabilities related to component you use
- Only obtain components from official sources over secure links
- Prefer signed packages to reduce the chance of including a modified, malicious component
- Monitor for libraries and components that are unmaintained or do not create security patches for older versions
- If patching is not possible, consider deploying a virtual patch to monitor, detect or protect against the discovered issue.

### 14.9 A07 IDENTIFICATION AND AUTHENTICATION FAILURES
- Broken Authentication
	- Broken authentication is general term
	- It refers to a weakness that allow an attacker to either capture or bypass the authentication methods that are used by a web application.
	- The goal of an attack is to:
		- Take over one or more accounts
		- Grant user's privileges to the attacker

#### CLASSIC SIGNS OF BROKEN AUTHENTICATION
Authentication is considered broken if it :
- Permits automated attacks such as credential stuffing where the attacker has a list of valid usernames and passwords
- Permits brute force or other automated attacks
- Permits default, weak or well-known passwords such as "Password1" or "admin/admin"
- Uses weak or ineffective credential recovery and forge-password process
	- Example "Knowledge-based answer" which cannot be made safe
- Use plain text or weakly hased/ encrypted passwords.
- Has missing or ineffective multi-factor authentication
- Exposes session IDs in the URL (eg: URL rewriting)
- Does not rotate session IDs after successful login
- Does not properly invalidate session IDs
	- User session or authentication tokens (particularly single sign-on (SSO) tokens) aren't properly invalidated during logout or a period of inactively.

#### BROKEN AUTHENTICATION EXAMPLES
- Credential stuffing
	- The attacker obtains a list of stolen credentials
		- from a breach or purchased on the dark web
	- Attacker tries using same sets of credentials across many unrelated websites
	- Successful when users reuse the same credential across a majority of their accounts
- Application Session timeouts aren't set properly
	- A user Uses public computer to access an application
	- Instead of selecting "logout" the user simply closes the browser tab and walks away
	- An attacker uses the same browser and hour later and the user is still authenticated
- Passwords are not properly hashed and salted
	- An insider or external attacker gains access to the system's password database
	- User passwords are not properly hashed and salted exposing every user's password

##### Credential Stuffing
- An attacker obtains a list of known passwords
	- uses a botnet to harvest credentials
	- purchases the list of the dark web
- The web web app does not implement automated threat or credential stuffing protection
- Unlike password cracking, credential stuffing attacks do not attempt to use brute force or guess any passwords
- The attacker simply automates the logins for a large number (thousands to millions) or previously discovered credential pairs
- Tools includes
	- Selenium, `cURL`, `PhantomJS`, Sentry, MBA, SNIPR, STORM, `BLACKbullet` and `OpenBullet`
- Example:
	- Attacker uses credential stuffing with stolen password database (on various websites)
- AUTHENTICATION TIMEOUT EXAMPLE
	- A user uses public computer to do some online banking
	- Instead of selecting logout the user simply closes the browser tab and walks away
	- An attacker uses the same browser an hour later and the user is still authenticated.
#### SESSION FIXATION ATTACK
A type of session hijacking
 - The  attacker obtains a legitimate sessions ID from a site
 - The attacker then social engineer a victim into clicking a link with this session ID
 - The user logs on while using the attacker-provided session ID
 - The site assumes that whoever presents the same sessions ID is legitimately logged in
 - The attacker returns to the site and is accepted without having to log in
 - The attacker can now perform tasks as if they are the victim

#### CAPTCHA
captcha is type of challenge-response prompt that attempt to verify whether or not a user is human
Can be text-based, picture-based or sound-based
Google `reCaptcha` analyzes your mouse pattern and decides which test to show


#### CAPTCHA BYPASS STRATEGIES
- Check your page's source code for CAPTCHA solutions (in case it's text)
- Use an old CAPTCHA value in case they get the same challenge twice
- Use OCR to read the characters on screen
- Check how many images are being used and detecting them with MD5
- Send the CAPTCHA parameter empty to see if that works
- Use an online capture solving service

##### CAPTCHA PHISHING ATTACK EXAMPLE
- The victim first receives a legitimate-looking email that claims to contain a faxed document as a pdf attachment
- Trying to open PDF leads users to fake site with a CAPTCHA form
- Once user solve the captcha they are directed to a Microsoft OneDrive login page, where they are asked to enter their email address and password to access the PDF
- The phishing email contains a seemingly harmless re-captcha that the mail client won't be able to solve
- Hence the attachment will not be scanned for malicious contents
##### BROKEN AUTHENTICATION COUNTERMEASURES
- Where possible implement multi-factor authentication to prevent automated credential stuffing, brute force and stolen credential reuse attacks
- Do not ship or deploy with any default credentials, particularly for admin users
- Implement weak password checks such as a testing new or changed passwords against the top 10.000 worst passwords lists
- Use NIST 800-63b guidelines for password length, complexity and rotation policies
- Ensure registration credential recovery and API pathways are hardened against account enumeration attacks by using the same messages for all outcomes
- Limit or increasingly delay failed login attempts, but be careful not to be create a denial of service scenario
- Log all failure and alert administrators when credential stuffing, brute force or other attacks are detected.
- Use a server-side, secure, built-in session manager that generates a new random session ID with high entropy after login.
	- Session identifier should not be in the URL, be securely stored, an invalidated after logout, idle and absolute timeouts.
- 
##### SCENARIO
- Wiley widgets has a business crucial website that sells widgets to customers worldwide
- All developed components are reviewed by the security team on a monthly basis
- In order to drive more business the developer team add 3rd party marketing tools to it
- The tools are written in JavaScript and can track the customer's activity on the site
- These tools are located on the servers of the marketing company
- What risk does this introduce?
- External script contents could be maliciously modified without the security team's knowledge.


### 14.10 A08  SOFTWARE AND DATA INTEGRITY FAILURES

#### UNDERSTATING SOFTWARE AND DATA INTEGRITY FAILURES
- Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations
- An example of this is where an application relies upon plugins, libraries or modules from untrusted sources, repositories and content delivery networks (CDNs)
- An insecure CI/CD pipeline can introduce the potential for unauthorized access malicious code or system compromise
- Lastly many applications now include auto-update functionality where updates are downloaded without sufficient integrity verification and applied to the previously trusted application
- Attackers could potentially upload their own updates to be distributed and run on all installations
- Another example is where objects or data are encoded or serialized into a structure that an 9attacker can see and modify is vulnerable to insecure deserialization.
- Attacker get access on network , install malicious code into CI/CD pipeline and through that (deployed application built by the infected code) gives access to network through malicious code.
- Attacker Example 2: Consumer devices that download unsigned updates, 
	- Many home routers, set-up boxes, device firmware and other do not verify updates via signed firmware.
	- Unsigned firmware is a growing target for attackers and is expected to only get worse
	- This is a major concern as many times there is no mechanism to remediate other than to fix in a future version and wait for previous versions to age out.
- Attacker Example 3: Solarwinds malicious update
	- Nations-state have been known to attack update mechanism with a recent notable attack being the SolarWinds Orion attack.
	- The company that develops the software had secure build and udpate integrity processes
	- Still, these were able to be subverted and for several months, the firm distributed a highly targeted malicious update to more than 18000 organization of which around 100 or so were affected.
	- This is one of the most far-reaching and most significant breaches of this nature in history.

#### MAINTAINING SOFTWARE AND DATA INTEGRITY
- Use digital signatures or similar mechanism to verify the software or data is from the expected source and has not been altered
- Ensure libraries and dependencies such as npm or Maven, are consuming trusted respositories
	- If you have a higher risk profile, consider hosting an itnernal known-good repository that's vetted.
- Ensure that a software supply chain security tool, such as #OWASPDependencycheck or #OSWASPCycloneDX is used to verify that components do not contain known vulnerabilities
- Ensure that there is a review process for code and configuration changes to minimize the chance that malicious code or configuration could be introduced into your software pipeline.
- Ensure that your CI/CD pipeline has proper segregation, configuration, and access control to ensure the integrity of the code flowing through the build and deploy processes
- Ensures that unsigned or unencrypted serialized data is not sent to untrusted clients without some form of integrity check or digital signature to detect tampering or replay of the serialized data.


###  14.11 A09 SECURITY LOGGING AND MONITORING FAILURES
- Security Monitoring is used to help detect, escalate and respond to active breaches
- Without logging and monitoring breaches cannot be detected
- Insufficient logging, detection, monitoring and active response can occur anywhere.
- FAILED LOGGING EXAMPLE:
	- Attacker gains access to internal network, scans for vulnerable systems and obtains sensitive data. Unable to detect attack and breach continues undetected.
#### INDICATORS OF FAILED MONITORING
- Auditable events, such as logins, failed login and high-value transactions are not logged.
- Warnings and errors generate no, inadequate or unclear log messages.
- Logs of applications and API are not monitored for suspicious activity
- Logs are only stored locally
- Appropriate alerting thresholds and response escalation processes are not in place or effective.
- Penetration testing and scans by dynamic application security testing (DAST) tools such as *`OWASP ZAP`* do not trigger alerts.
- The application cannot detect, escalate, or for active attacks in real-time or near real-time
- Attack Example 1:
	- A children's health plan provider website operator couldn't detect a breach due to a lack of monitoring and logging
	- An external party informed the health plan provider that an attacker had accessed and modified thousands of sensitive health records of more than 3.5 million children
	- A post-incident review found that the website developers had not addressed significant vulnerabilities.
	- As there was no logging or monitoring of the system, the data breach could have been in progress for more than seven years.
- Attack Example 2:
	- A major European airline suffered a GDPR reportable breach.
	- The breach was reportedly caused by payment application security vulnerabilities exploited by attackers
	- The attackers harvested more than 400,000 customer payment records.
	- The airline was fined 20 million pounds as a result by the privacy regulator.
#### IMPROPER ERROR HANDLING
- Improper error handling can introduce various securely problems
- Detailed internal error messages might be displayed to an attacker
	- Provided knowledge of the source code.
	- Allows attackers to take advantages of things like default accounts/logic flaws
- Attackers use information in error message to identify vulnerabilities.
- Leaked information can include:
	- System call failure
	- Network timeout
	- Null pointer exceptions
	- Databased unavailable 
	- App environment
	- Web app logical flow
	- Stack traces
	- Database dumps
	- Error Codes.
#### LOG INJECTION
- An attacker forges log entries or injects malicious content into the logs
- Log injection vulnerabilities occur when:
	- Data enters an application from an untrusted source
	- The data is written to an application or system log file
- Successful log injection attacks can cause:
	- Injection of new/bogus log events (log forging via log injection)
	- Injection of XSS attacks , hoping that the malicious log event is viewed in a vulnerable web application.
	- Injection of commands that parsers (like PHP parsers) could execute
	- Skewing of log file statistics
	- Log file corruption to cover an attacker's tracks. or implicate someone else in malicious activity.

#### LOG4J VULERNABILITY
- Open source software provided by the Apache software foundation
- Records events (errors and routine system operations)
- Communicate diagnostic messages to sytem administrators and users 
- Very wide-spread
	- Popular games,  cloud services, software development tools, security tools
	- Frequently bundled as part of other software
- The Log4Shell exploit injected malicious text to trigger a log message
	- Log4J processed the text as instructions
	- Created a reverse shell back to the attacker
- Spawn a frenzy of attacks:
	- Ransomware gangs
	- Bitcoin miners
	- Malicious state actors hacking geopolitical rivals.
#### MAINTAINING EFFECTIVE SECURITY MONITORING AND LOGGING
- Patch all systems
- Test systems when high-profile vulnerabilities become known.
- Ensure all login, access control, and server-side input validation failures can be logged with sufficient user context
	- To identify suspicious or malicious accounts
	- Held for enough time to allow delayed forensics analysis
- Ensure that logs are generated in a format that log management solutions can easily consume.
- Ensure log data is encoded correctly to prevent injections or attacks on the logging or monitoring systems
- Ensure high-value transaction have an audit trail with integrity controls to prevent tampering or deletion, such as append-only database tables or similar
- #DevSecOps teams should established effective monitoring and alerting, so that suspicious activities are detected and responded to quickly
- Establish or adopt an incident response and recovery plan. Consider using National Institute of standards and Technology (NIST) 800-61r2


### 14.12 A10 SERVER SIDE REQUEST FORGERY
- Exploits web apps that fetch remote content without validating the user-supplied URL.
	- Exposes information even though the attacker is unauthorized.
	- Can bypass ordinary access controls such as firewall, VPN and ACLs
	- Can take advantages of the trust relationship between the web app and back-end servers.
- Incidence and severity of SSRF in increasing.

#### COMMON SSRF ATTACK ACTIVITIES
- PORT Scan interval servers: 
	- If the network architecture is unsegmented, attackers can map out internal networks.
	- Use connection results or elapse time to determine if ports are open or closed.
- Sensitive data exposure:
	- Attackers can access local files such as /etc/passwd or internal services to gain sensitive information.
	- Examples:
		- file://ect/password
		- http://localhost:28017
- Access metadata storage of cloud services
	- Most cloud providers have metadata storage such as http://169.254.169.254
	- An attacker can read the metadata to gain sensitive information.
- Compromise internal services:
	- The attacker can abuse internal services to conduct further attacks such as Remote Code Execution (RCE) or Denial of Services (DoS)

#### SSRF ATTACK 
- ATTACK 1 :  Attacker request http with SSRF payload, Server process SSRF request triggers malicious request to internal resources , Server returns sensitive user data.
- ATTACK 2: Replace the API Call, Instead of fetching the current forecast, fetch something unauthorized.
- AMAZONE EC2 ATTACK EXAMPLE: 
	- One of the most prevalent examples of an SSRF attack
	- Gain access to Amazon EC2 instance credentials
	- If an IAM role can access an EC2 instance, an attacker can obtain provisional credential by sending a request to:
	- `http://169.254.169.254/lates/meta-data/iam/security-credentials/{role-name}`

#### NETWORK-LAYER COUNTERMEASURES
- Segment remote resource access functionalities in separate networks to reduce the impact of SSRF
- Enforce "deny by default" firewall policies or network access control rules to block all but essential intranet traffic
- Establish an ownership and a lifecycle for firewall rules based on applications.
- Log all accepted and blocked network flows on firewalls.

#### APPLICATION-LAYER COUNTERMEASURES
- Sanitize and validate all client-supplied input data
- Enforce the URL schema, port and destination with a positive allow list.
- Do not send raw responses to clients.
- Disable HTTP redirections
- Disable potentially harmful URL schemas including `dict://` , `file:///` and `gopher://`
- Be aware of the URL consistency to avoid attacks such as DNS rebinding and "time of check", "time of use" (TOCTOU) race conditions.
- Whitelists the IP addresses or DNS names that your applications requires access to 
	- Avoid using blacklists/deny lists or regular expressions.
	- Attackers have payload lists, tools and skills to bypass deny/blacklists.



### 14.14 CSRF
#### CROSS-SITE REQUEST FORGERY (CSRF)
AKA. XSRF
- Exploits the server's trust in an authenticated user
- Takes advantages of saved authenticated to access sensitive data
- Induces a victim to perform actions they do not intend to perform.
	- Forces the user's browser to send an authenticated request to server
	- Forces an end user to execute unwanted actions on a web application in which they are currently authenticated.
- Crafted URL and send to victim
	- Victim clicks link and automatically signs in to the site due to a saved cookie.
	- Requested action executes automatically.
- Attacker wants the user's browser to perform an unauthorized action in the background, Example: share the link through email or social media. Because user already has a cookie to the legitimate site, When potential victim opens the link thinking they are going to a legitimate website, is redirected to malicious site , the malicious payload is executed.
- CONDITIONS FOR ATTACK TO BE SUCCESSFUL
	- There was a sole reliance on session cookie
	- The user had already logged into the legitimate site
		- Their session cookie was stored in their browser
		- The cookie was not not set with the `SameSite` attribute
		- The attacker was able to steal it.
- A state-changing, sensitive 'Action' existed in the vulnerable app
- The application doesn't perform adequate checks to identify a user. It relies solely on the request containing a session cookie.
- There were no unique parameter in the request that the attacker couldn't determine.


#### CSRF COUNTERMEASURES
Use the OWASP Cross-Site Request Forgery Prevention Cheat sheet for guidance:
- Send random challenges tokens
- Validate tokens
- Check if your framework has built-in CSRF protection and use it
- Consider using the `SameSite` cookie Attribute for session cookie.
- Consider implementing user interaction-based protection for highly sensitive operations.
- Consider the use of custom request headers
- Consider verifying the origin with standard headers.
- For stateful use the synchronizer token pattern
- For stateless software use double submit cookie.
- Scenario 1: Which of the following attacks exploits web page vulnerabilities that allow the cybercriminal to control and send malicious requests from an unsuspecting user's browser without the victim's knowledge? and CSRF
- Scenario 2: 
	- While Moo is accessing his bank account using a web browser, he receives an email containing a link that say "awesome cats"
	- He clicks on the link and shows a video of dancing cats.
	- The next day, he receives an email notification from his bank, asking to verify the transactions made outside of the country
	- What web browser-based vulnerability was exploited? 
	- #CSRF is type of malicious exploit that allows an attackers to trick users to perform actions that they do not intend to.

### 14.15 PARAMETER TEMPERING
- A simple attack targeting the application business logic
- This attack takes advantages of the fact that many programmers rely on hidden or fixed fields (such as a hidden tag in a form or a parameter in URL) as the only securely measure for certain operations.
- A classic example of parameter tampering is changing parameters in form fields
- When a user makes selections on an HTML page, they are usually stored as form field values and sent to the web application as an HTTP request.
- Cookie Manipulation
	- `ASP.NET_SessionID=SADFW452fg4f425shjd4;lang=en-us;ADMIN=no;y=1`
	- `ASP.NET_SessionID=SADFW452fg4f425shjd4;lang=en-us;ADMIN=yes;y=1`
- URL Manipulation
	- `http://www.example.com/tranfer.asp?accountnumber=10002344563211&debitamount=1`
	- `http://www.example.com/tranfer.asp?accountnumber=2345344563211&debitamount=1000`
- HTTP Headers:
	- Original : `HTTP/1.1 200 OK ... Set-Cookie: user=Jane Smith ...`
	- Hacked : `HTTP/1.1 200 OK .. Set-Cookie: user=Moo Hacker HTTP/1.1 200 OK ...`

#### HIDDEN FIELD MANIPULATION ATTACK
- Selection on an HTML page are stored as field values
	- They are sent to the app to generate as HTTP request
- Field values can be stored as hidden fields (not rendered to screen)
- Hidden values are still submitted as parameters when forms are submitted
- Attackers can change hidden field values 
- Example 
	- `<input type="hidden" id=1211 name="cost" value="700">` changed to 
	- changed to `<input type="hidden" id=-"1211" name="cost" value="70.0">`

#### PREVENT PARAMETER TAMPERING
- Filter and whitelist inputs
- implements a Web Application Firewall (WAF)
- Encrypt session cookies
- If the cookie originated from the client-side such as a referrer, it should not be used to make any security decisions
- Avoid including parameters in the query string


### 14.16 CLICKJACKING

#### CLICKJACKING
- Clickjacking aims to capture a user action through a UI trick
- A user is fooled into clicking a web page link that is different from where they had intended to land
- The link redirects the victim to a pharming page or other malicious page
	- The visitor things they are clicking a button to close window
	- Instead the action of clicking the "x" button prompts the computer to download a Trojan horse, transfer money from a bank account or turn on the computer's built in microphone some well-known site
	- The attacker tricks users into visiting the site through social engineering

#### CLICKJACKING COUNTERMEASURES
- Prevent the browser from loading the page in frame using:
	- x-frame-options
	- Content security Policy (frame-ancestors) HTTP headers
- Prevent session cookies from being included when the page is loaded in a frame
	- Use the `samesite` cookie attribute
- Implement JavaScript "Frame-buster" code in the page. Prevent it from being loaded in a frame.


### 14.17 SQL INJECTION
#### SQL INJECTION (SQLI)
- A type of command injection
- The attacker modifies SQL statements before they are processed by the database management DBMS
- The database is manipulated by injecting malicious SQL queries into web app input fields
- SQL by itself has no way of validating input
- The web app must be designed to filter out the injection
- Attacks can be executed via (address bar, App fields , Search / queries)


##### SQL and web APPS
- The developer pre-creates a SQL query as part of a web page
- The query just needs some user input to be complete
- The user inputs the missing information into a form
- The web app takes the input from the form and uses it to complete the query
- The query is then sent to the database for processing

#### INJECTING A MALICIOUS SQL COMMAND
- Instead of the expected input, the attacker enters a partial SQL statement
	- `select fname, lname, ccard from customers where cust_id = var_from_web_input`
	- attacker enters` var_from_web_input = haha or 1=1`
- The database sees that the query contains an OR statement
- because 1 is equal to 1 , this statement is evaluated against each row in table and because it 1 is equal to 1, the database returns every row, including customers names and credit card numbers

##### What can attacker do with SQLi?
- Steal / modify / delete data
- Delete whole tables
- (Sometimes) run operating system commands
##### SQLi Tools
#sqlmap #sqlninja #havij #SQLBrute #Pangolin #SQLExec #Absinthe #BobCAt 

#### SQL INJECTION COUNTERMEASURES
- The preferred options is to use safe API
	- Avoid using the interpreter entirely
	- Use parameterized queries
	- Migrate to Object Relational mapping tools (ORMs)
- Note: 
	- Even when parameterized, stored procedures can still introduces SQL injection if PL/SQL or T-SQL
		- Concatenates queries and data
		- Executes hostile data with execute immediate or Exec()
- Use positive server-side input validation
	- Note: this is not a complete defence
	- Many applications require special characters such as text areas or APIs for mobile applications
- For any residual dynamic queries, escape special characters using the specific escape syntax for that interpreter
	- Note: SQL structures such as table names, columns, and so on cannot be escaped
	- Thus user-supplied structures names are dangerous
	- This is a common issue in report-writing software
- Use LIMIT and other SQL controls within queries to prevent mass disclosure of records in case of SQL injection

### 14.18 INSECURE DESERIALIZATION ATTACKS

#### SERIALIZATION
- Serialization is the process of taking an object out of memory and converting it into a steam of bytes
- The bytes can now be transmitted across the network as well as stored on disk.
- When an app performs the serialization of an object, we say that object is serialized
- Serialization can be performed in most any programming language
- Class, propertie (object) ==> stream of Bytes ==> Memory , Database, files (storage)
- Serialized JSON object example: 
	- `{ "employee":{ "name":"mukesh" , "salary":90000, "profile": "PSVE" } } ` 
	- ;`a:1:{s:8: "employee"; a:3:{s:4: "name" ; s:3:"Mukesh"; s:6:"salary" ; :90000 ; s:7:"profile";p:"PSVE"; } }`


#### DESERIALIZATION
- Consists of converting serialized data into an in-memory representation which the app can then manipulate
	- Concept:
		- A Game want to retrieve the state of the serialized character object. It needs to DE serialize it first
		- An attacker stores a serialized file representing a malicious payload
		- If the developer doesn't perform a verification before deserialization, the insecure deserialization will trigger the attacker's code
		- A malicious version of the object will be created and used by the game
	- Example:
		- In this example: PHP object serialization is used for PHP forum to save a "super" cookie loaded with data
		- It contains the user id, role , password hash, and other states
		- An attacker modifies the serialized object to obtain admin privileges and tamper with the data
		- `a:4: { i:0; i:132; i:1; s:7:"MOO"; i:2;s:4:"user"; i:3:s:32:"32jgj345kl43j3l5l6343fgadaf"; }`
		- The attacker changes the serialized object to give themselves admin privileges
		- - `a:4: { i:0; i:132; i:1; s:7:"Mukesh"; i:2;s:4:"admin"; i:3:s:32:"32jgj345kl43j3l5l6343fgadaf"; }`


#### INSECURE DESERIALIZATION COUNTERMEASURES
- Use the OWASP insecure deserialization cheat sheet for guidance
- Do not accept serialized objects from untrusted sources.
- Encrypt the serialization process. Prevent hostile objet creation and data tampering
- Run the deserialization code with limited access permissions
- Strengthen your code's `Java.Io.ObjectInputStream`
- Monitor the serialization process, catch any malicious code and breach attempts
- Validate user input
- Use a web application firewall. Detect malicious or unauthorized insecure deserialization.
- Use non-standard data formats. something the attacker won't recognize
- Only DE serialize digitally signed data 

### 14.19 INSECURE DIRECT OBJECT REFERENCE #IDOR

- A common access control vulnerability
- Occurs when a reference to an internal  implementation object is exposed without any controls
- The referenced object is typically displayed in a URL
- The vulnerability is often easy to discover and allows attackers to access unauthorized data.
	- Examples
		- `http://examples.com/somepage?invoice=1001`
		- `http://example.com/changepassword>user=mux`

#### IDOR ATTACK TECHNIQUES
- Try incrementing ID or account numbers
- Try replacing a file name with a path such as /etc/passwd
- Try abusing REST HTTP methods
	- for example you seee GET /api/profile
	- Try the following
```
	Get /api/profile/1
	PUT /api/profile/1
	Host: vulnerable
	Content-Type: application/json
	{"email" ; |mb@gmail.com}
```


#### IDOR COUNTERMEASURES
- As a developer or tester, make sure to write integration tests which cover IDOR use cases
- Register two accounts for each role the application supports
	- Try to replace one with the other
	- This tests lateral access control measures and privilege escalation
- Discover as many features as you can, preferably with the role with the highest privilege
	- If the application provides paid membership, try to get test accounts or purchase it.
- Collect all the endpoint found and try to find a naming pattern.
	- Then guess new endpoint names based on the pattern you discovered.
- For DevOps engineers, make sure you set up a continuous integration / continuous delivery (CI/CD) pipeline which includes all automated tests.
- Use GUIDs that are hard to guess.

#### SCENARIO
- Moo Cow system recently bought out its competitor. `Whamiedyne `Inc which web out of business due to series of data breaches.
- As a cybersecurity analyst for Moo Cows, you are assessing `whamiedyne's`  existing application and infrastructure.
- During you analysis, you discover the following URL is used to access an application.
- `https://www.whamiedyne.com/app/accountinfo?acc=12345`
- what is that an example of ?
- This is an example of an insecure direct object reference. Direct object references are typically insecure when they do not verify whether a user is authorized to access a specific object.


### 14.20 DIRECTORY TRAVERSAL

#### DIRECTORY TRAVERSAL aka dot-dot-slash
- Allows an attacker to navigate outside the web publishing directory
- An attacker can:
	- Request a file that should not be accessible from the web server
	- Gain access to restricted directories and files
	- Execute commands outside of the root directory of the server
	- Manipulate variables related to ../files
`http://www.example.com/../../../etc/passwd`
`http://example.com/events.php?file=../../../etc/passwd`
`http://TARGET/Scripts/..%255%255c../winnt/system32/cmd.exe>/c+dir+c:\`

#### DIRECTORY TRAVERSAL COUNTERMEASURES
- Avoid passing user-supplied input to filesystem APIs
- Make the application validate the user before processing it.
	- Either compare the input against a whitelist of permitted values.
	- or verify that the input contains only permitted content - for example, alphanumeric characters.
- After validating the user-supplied input, make the application verify that the canonicalized (absolute) path starts with the expected base directory
	- Java snippet example to validate the canonical path of a file:
```
File file = new File (BASE_DIRECTORY, userInput);
if(file.getCanonicalPath().startwith (BASE_DIRECTORY))
{
	process file
}
```


### 14.24 SESSION MANAGEMENT ATTACKS

#### SESSION MANAGEMENT
- Each web session is given a session ID
- Because HTTP is stateless, the session ID is attached to every request sent from the client to the server.
#### SESSION MANAGEMENT MECHANISM
- Unique identifier embedded in URL `http:/www.bank.com/accoun.php?sessionid=BM3434233`
- Unique identifier in hidden from filed, submitted with HTTP POST command.
	- `<FORM METHOD="POST" ACTION="/account.php">`
	- `<INPUT TYPE="hidden NAME="sessionid" VALUE="BM2424233">`
- Unique identifier in cookies
	- `Set-Cookie: BA60012219' path="/" ; domain="www.bank.com"; expires = 2023-06-01 00:00:00GMT; version`

#### COMMON SESSION MANAGEMENT ATTACKS

| Attack                               | Description                                                                                                                                                                                                                        |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Session Hijacking ( aka sidejacking) | - Involve employing technique to tamper with or take over TCP and web application user sessions<br>- If the attacker successfully impersonates the user/client, they gain access to any sensitive information found in the session |
| Cracking Apache IDs                  | - Some web application use the built-in cookie session id generation algorithm m that ship with the Apache Web server.<br>- An ID generated via the algorithm in mod_usertrack.c can be guessed using automated scripts.           |
| sniffing session ids                 | - Sessions that use encrypted HTTP can be sniffed and their session ID extracted                                                                                                                                                   |
| Session fixation                     | - Instead of stealing / hijacking the victim's session the attacker fixes the user's session ID before the user even logs into the target server<br>- Eliminates the need to obtain the user's session ID afterwards<br>           |
| Credentials/ session prediction      | - If an app simply increments the IDS for each new session future IDs can be quickly predicted.                                                                                                                                    |

#### COOKIE / SESSION POISIONING
- Cookie maintain session state
- Poisoning :
	- Alters the cookie content
	- Permits in injection of malicious content, alter user's experience, gather sensitive information
	- Rewrites session data
- Countermeasures:
	- Set the `Secure` attributes on the cookie to protect its confidentiality
	- Hash the cookie to protect its integrity

#### OTHER SESSION VULNERABILITIES
- Insufficient session expiration
	- A web application takes a long time to time out
	- If the user simply closes the browser, the session is still active
	- If the user leaves ( such as at a public café) an attacker could take their place, open the site again , and automatically enter without authenticating.
- Weak session cryptographic algorithms
	- The common (and outdated) MD5 hashing algorithms can be attacked by a number of password brute forcer.
- Insufficient session IDS length : the shorter the IDs the easier it is to crack (even if encrypted)
- Proxies and caching : If the web app is accessed from behind a corporate proxy, whenever the session ID is passed the proxy will cache it.
- Insecure server-site session ID storage
	- Some frameworks use shared areas of the web server's disk to store session data
	- In particular, PHP uses `/tmp` on UNIX, and `C:\windows\temp` on Windows by default 
	- These areas provide no protection

#### SESSION ATTACK COUNTERMEASURES
- Make session IDs unpredictable
- Encrypt session token
- Change the session token after authentication
- Use a message Authentication Code (MAC) to validate sensitive data
	- A MAC function adds a secret key to a hashing function
	- An attacker cannot generate a valid MAC without the key
	- The server and browser will include the MAC for any data sent
	- The server can verify the MAC using its secret key


### 14.22 RESPONSE SPLITTING
#### HTTP RESPONSE SPLITTING
- A protocol manipulation attack similar to parameter Tampering
- Uses CRLF (Carrier Return, Line feed) injection
- An attacker adds header response data to an input field so the server splits the response
- The web app must perfmit carriage return and line feed characters in its input.
- Since HTML is stateless, neither the server nor the client notices the odd behavior
- With HTTP Response splitting, it is possible to mount various kinds of attacks:
	- Cross-site Scripting (XSS) attacks
	- Cross User Defacement
	- Web Cache Poisoning
	- Page Hijacking
	- Browser Cache Poisoning
	- Browser Hijacking

#### RESPONSE SPLITTING COUNTERMEASURES
- To mount a successful exploit, the application must allow input that contains
	- CR (carriage return, also given by `%0d` or `\r `)
	- and LF (Line feed, also given by `%0a` or `\n` )characters into the header
- AND the underlying platform must be vulnerable to the injection of such characters
- Retire all old application servers.
- This vulnerability has been fixed in most modern application servers. Regardless of what language the code has been written in.



### 14.24 OVERFLOW ATTACKS
#### Application memory structure
- #Stack Temporarily stores variables created by a function when the task is complete, the memory is erased.
- #heap Temporarily stores data created while the program is running.

#### OVERFLOW TYPES

| OVERFLOW TYPE    | Description                                                                                                                                                                          |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Integer Overflow | A condition that occurs when the result of an integer operation does not fit within its allocated memory space.                                                                      |
| Buffer Overflow  | - An unexpected evern where a program, while writing data to a buffer, overruns the buffer's boundary<br>- Overwrites adjacent memory locations<br>- Can be a heap or stack overflow |
| Heap Overflow    | - Less common and harder to execute<br>- Involves flooding the memory space allocated for a program beyond memory used to current runtime operations.                                |
| Stack Overflow   | - More common type of buffer overflow<br>- Exceeds the stack memory that only exists during the execution time of a function.                                                        |
|                  |                                                                                                                                                                                      |

#### INTEGER OVERFLOW
- A common cause of software errors
- Occurs when the results of an integer operation does not fit within the allocated memory space.
- Usually causes the result to be unexpected rather than an application error. The app could continue with wrong values.
- In a "signed" integer half of the range is positive, the other half is negative.
	- You can't exceeds either value
	- An attacker could take advantages of this to get a refund, rather than having to pay
	- `Inter.MAX_VALUE + 1` will show the integer overflow
- In an "unsigned" integer the numbers are only positive 

#### BUFFER OVERFLOW
- App writes more data than a block of memory is designed to hold.
	- Inputs more data than the buffer is allowed.
- Allows attackers to change address space of target process.
- Attackers direct program execution to memory locations containing malicious code.


#### FUZZ TESTING
- Fuzz testing is a quality and assurance checking technique that is used to identify coding errors and security loopholes in a targeted web applications.
- Huge amounts of random data called "Fuzz" will be generated by the fuzz testing tools (Fuzzer)
	- The hope is to crash the program, or get it to behave strangely
- Fuzzing is also used against the target web application to discover vulnerabilities that can be exploited by various attacks
- Can be used in all sorts of injection attacks
- Typically used to discover buffer overflow vulnerabilies

#### OVERFLOW COUNTERMEASURES
- Perform static code analysis on the source code.
- Use fuzzing to test running code dynamically
- Place a "canary" (typically a small random integer) in your code
	- Put it before the return carriage of the termination point of the buffer
	- It will have to be overwritten first before the overflow can occur
	- The system can monitor for this.

### 14.25 XXE ATTACKS
#### XML EXTERNAL ENTITIES ATTACK
- AKA XXE OR XEE
- An Attack against an application that uses XML for data exchange
- If a web application uses XML data an attacker can interfere with the request and manipulate it 
- The attacker could inject malicious code in the XML. Similar to SQL injection or command injection
- 
```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >

//example1: The malicious code typically references an "external entity" such as an operating system file

<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>  

//example2: probes the private network of the server by changing the entity line to an IP address
<!ENTITY xxe SYSTEM "https://192.168.1.100:8080" >]>

//example3: the attackers include a potentially endless file to create a denial of service attack & /dev/random is an interface to the kernel' random generator
<!ENTITY xxe SYSTEM "file:///dev/random" >]> 
<foo>&xxe;</foo>
]

```

#### HOW TO PREVENT XXE ATTACKS
Use simple data formats such as JSON whenever possible
Avoid sensitive data serialization
Upgrade or patch all XML libraries and processors used by the underlying operating system or the application.
Prefer to use dependency checker and upgrade to SOAP 1.2 or higher
Disable DTD processing of XML external entity in all applications iin all XML parsers. Document type Definition defines the tree structure of HTML and XML (and other ) documents
Implement whitelisting or positive server-side input validation, sanitization or filtering
Perform manual code review.
Scan code using Static application security Testing ( #SAST) tools.


### 14.23 WEB APP DOS
#### Denial of service (DOS)
- Attackers overload server resource by sending hundreds of requests
- JavaScript-based DDoS attacks are a growing problem on the Internet
- App-level attacks are hard to detect
- App vulnerabilities susceptible to DoS include:
	- Poor validation of data
	- Flaws in implementation
	- Reasonable use of expectations
	- Bottlenecks in the application environment


- Billion Laughs XXE Dos : DOS attack that takes up an exponential amount of space or time . each string expands to ten of previous string, or ultimately this small block contains $10^9$ (a billion) lols
- JavaScript DoS attack: This script sends floods of request to victim websites 
- Example:
```
function imgflood(){
	var TARGET = "victimsite.com"
	var URI ='index.php>'
	var pic = new image()
	var rand = Math.floor(Math.random() * 1000)
	pic.src = "http://'+target+URI_RAND+'=val"
}
setInterval(imgflood, 10)

Explaination: Script creates an image tag on the page 100 times per second. The iamge points with random number queries (From 0 to 999). Every visitor to this site that contains this script become a unwitting participant in the DDoS attack againt this site. This message sent by the browser are valid HTTP requests. This will clog up the pipes with lot of network traffic, the web server and backend to become overloaded with work
```

#### DOS COUNTERMEASURES
- Carefully review and test your code to look for vulnerabilities that can lead to DoS / DDoS attacks
- Load Balance critical services so they can absorb an attack
- Consider using an online service to filter / buffer your website traffic against DDoS attacks.

### 14.26 SOAP ATTACKS
SIMPLE OBJECT ACCESS PROTOCOL (SOAP)
- A light weight data interchange protocol
	- Exchange data between web services
	- Provides a structured model for messaging
	- Mainly used for web services and APIs
- Based on XML
- Built on top of HTTP
- Designed to be OS and platform independent

#### SOAP VULNERABILITIES
Because SOAP uses XML and HTTP, it is vulnerable to many web app attakcs
	Code Injection
	Leaked / breached access
	Distributed Denial of Services
	Cross-site scripting
	Session Hijacking


#### MALICIOUS SOAP REQUEST EXAMPLE:
An attacker changes the delivery address of an item bought at an online store
The request is still considered valid because the part that was "signed" by security is still there.

#### HOW to Secure SOAP
- Ensure that SOAP message are shown to authorized users only 
- Add a security credential to the SOAP header
	- Includes username and password as variables
	- When SOAP messages are generated these credentials are also generated, and the username and password will be required when a user calls the web service
- Valid input
- Limit SOAP message length and volume to mitigate DOS attacks
- Monitor application requests
- Regularly test the app
- Implement redundant security

#### 14.27 AJAX ATTACKS
#### ASYNCHRONOUS JAVASCRIPT TECHNOLOGY AND XML (AJAX)
- AJAX is a collection of technologies (XML , HTML, DOM , CSS, JavaScript)
	- They are used together on the client side to increase interactivity speed and usability
- Web apps are designed to provide a rich user experience and imitate "traditional" desktop applications.
	- Examples : Google Docs, Google Sheets, Google Maps, Yahoo Mail
#### AJAX VULNERABILITIES
- Increased attack surface with many more inputs to secure. Internal functions of the application can become exposed
- Client has access to third-party resources with no built-in security
- Failure to protect authentication information and sessions.
	- An attacker might be able to use hidden URLs to hijack servers requests to back-end applications.
- Blurred line between client-site and server-side code, possible resulting in security mistakes.
- AJAX is particularly vulnerable to
	- SQL injection
	- XSS 
	- CSRF
	- DoS

#### AJAX and XSS
- Browser and AJAX requests look identical - a server can't tell the difference
- A javaScript program can use AJAX to request a resource in the background without the user's knowledge 
	- The browser will automatically add the necessary authentication or state-keeping information such as cookie to the request
	- JavaScript code can then access the response to this hidden request and then send more requests
	- This expansion of JavaScript functionality increases the possible damage of XSS
- A XSS attack could send request for specific pages other than page the user is currently looking at. This allow the attacker to actively look for certain content, potentially accessing the data.

#### Defending AJAX-Enable Web Apps
- Sanitize input and whitelist allowed characters
- Properly encode all output to strip metacharacters of any special meaning
- Consider using an automated tool to scan JavaScript files and identify vulnerable AJAX call in running code.
- Tools include
	- FireBug
	- Acunetix Web Vulnerability Scanner
	- OWASP ZAP AJAX Spider

### 14.30 WEB APP HACKING TOOLS
1. #GRABBER : Simple , portable vulnerability scanner, suitable for small websites, [link](http://rgaucher.info/beta/grabber)
2. #Vega : Open source web scanner and testing platform. Can be used for automated, manual or hybrid security testing, [link](https://subgraph.com/vega)
3. `Zed Attack Proxy` (#ZAP) : Automated web app scanner and intercepting proxy for manual tests on specific pages. [link](https://github.com/zaproxy/zaproxy)
4. #Wapiti: Scan web pages and inject data [link](https://www.sourceforge.net)
5. #W3af: Web app attack and audit framework [Link](http://w3af.org) 
6. #WebScarab : Java-based security framework/intercepting proxy. Analyze web app using http or HTTPS [link ](https://www.owasp.org/index.php/category:OWASP_WebScarab_project)
7. #SQLMAP: Automated finding the exploiting SQL injecting vulnerabilities in a websites database [Link](https://github.com/sqlmapproject/sqlmap) 
8. #RatProxy : Web app security audit tool, Can distinguish between CSS stylesheets and JavaScript codes. Also support the SSL man-in-the-middle attack. You can also see data passing through SSL. [Link](http://code.google.com/p/ratproxy)
9. #Grendel-scan: Automatic tool for finding security vulnerabilities in web applications. Many features are also available for manual penetration testing. This tool is available for windows, linux and Macintosh and was developed in Java. [Link]( http://www.sourceforge.net/projects/grendel)
10. #Skipfish: Web site crawler/page checker . available in #kali distribution
11. #BurpSuite: 
	- A graphical tool used for testing web application security
	- Helps you identify vulnerabilities and verify attack vectors that are affecting web applications
	- While browsing the target applications a penetration tester can configure its internet browser to route traffic through the Burp Suite proxy server
	- Burp suite then acts as a `Man in the Middle` 
	- It captures and analyzes each request to an from the target application so that htey can be analyzed
	- Burp suite testers can pause, manipulate and replay individual HTTP requests in order to analyze potential parameter or injection points.
12. #Arachni: Detect various vulnerabilities like SQL injection, XSS, local file inclusion, remote file include, invalidated redirect and many others.
13. #metasploit  WMAP Web Scanner: The most-used penetration testing framework. Comes pre-installed in kali Linux
14. #watcher :
	- Add-on to fiddler (web debugging proxy tool)
	- Passive web security scanner. It does not attack with loads of requests or crawl the target website
	-  [link](http://websecuritytool.codeplex.com)
- #Nikto: performs over 6000 tests against a website
- #WPScan : Scans you wordpress website and checks the vulnerabilities within the core version plugins, themes, etc.
- #Netsparker web vulnerability scanner: uses proof -based scanning to automatically verify false positive and save time.

