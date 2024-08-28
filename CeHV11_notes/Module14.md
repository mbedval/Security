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
