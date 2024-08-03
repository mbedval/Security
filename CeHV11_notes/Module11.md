### 11.1 SESSION HIJACKING

#### WHAT IS SESSION HIJACKING ?
- The act of “taking over” someone else’s session after they have established it
- Usually aimed at web browsers
- Can sometimes be done at the network level
- The server does not realize that someone else is masquerading as the client
- The victim (user) also may not realize their session has been hijacked
- The attacker and victim might be running parallel sessions
- The server would see this as two sessions by the same client

#### WHAT IS WEB SESSION HIJACKING
- A session hijack attack compromises the client's session token
	- Steal or predict a valid session token
	- Gain unauthorized access to the web server
- HTTP communication uses many different TCP connections the web server needs a methods to recognize every users connections
- The most useful methods depends on a token that the web server sends to the client browser after a successful client authentication
- A Session token is normally composed of a string of variable width and it could be used in different ways
- For Example:
	- In url , the token is a cookie included in the header or body of an HTTP request 
	- It could also be a JSON web Token (JWT)
- URL Token Example
	- `http://www.example.com/PHPSESSID=298zf09hf012fh2`
	- `http://www.example.com/userid=sup3r4n0m-us3r-1d3nt1f13r`
- JSON Web Token Example
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
eyJzdWIiOiJ1c2Vycy9Uek1Vb2NNRjRwIiwibmFtZSI6IlJvYmVydCBUb2tlbiBNYW4iLCJz
Y29wZSI6InNlbGYgZ3JvdXBzL2FkbWlucyIsImV4cCI6IjEzMDA4MTkzODAifQ
1pVOLQduFWW3muii1LExVBt2TK1-MdRI4QjhKryaDwc
```

#### WEB SESSION HIJACKING Example #1 SESSION SNIFFING
- Victim has running session 
- Attack sniff the session using tools like Wireshark, Kismet
- After acquiring start using it 

#### WEB SESSION  HIJACKING EXAMPLE #2
- Attack injects script 
- Victim authenticates on servers 
- Server returns page code with injected script
- Victims' browser executes script and sends sessions cookies to attacker
- Attack now use this valid user session to access the server

#### #3 SESSION PREDICTION
- Attacker analyzes the websites session ID generation process
- Attacker than predict valid session ID values and get access

#### WHY SESSION HIJACKING IS SUCCESSFUL
- Lack of account lockout for invalid session IDs
- Session expiration time is indefinite
- Session IDs are small or the ID generation algorithm is weak
- Vulnerability of most TCP/IP computers
- Session IDs handled insecurely
- Majority of countermeasures require encryption to work

#### Difference Hijacking Vs Spoofing
- Hijacking
	- Process of taking over active session
	- Needs legitimate user to make/ authenticate connection
- Spoofing
	- Process of initiating new session using stolen credentials
	- Attacker pretends to be a user / machine to gain access


### 11.2 COMPROMISING A SESSION TOKEN

#### What is COOKIE-Based Authentication
- The Traditional Stateful web authentication mechanism
- Provides "proof" to the website that the user has already been authenticated 
	- The website can trust a browser that presents the cookie
- Lifetime of cookie:
	- User enters their login credentials
	- Servers verifies the credentials are correct and creates a session which is then stored in a database
	- A cookie (text file ) with session ID is placed in the user's browser
	- On subsequent request the session ID is verified against the database and if valid the request processed
	- Once a user logs out of the app, the session is destroyed both, client-side and server-side

#### What is Token-Based Authentication
- A token is (usually) a JSON web Token (JWT)
	- Digitally signed JSON object (Key/value pair)
	- can be base-64 encoded
- Token-based authentication is stateless
	- The server does not keep a record of which users are logged in
	- Does not keep track of which JWTs have be issued
	- Every request to the server is accompanied by the token which is server uses to verify the authenticity of the request
- Token-Based authentication has gained prevalence over the last few years due to rise of 
	- Single Page applications
	- Web APIs
	- Internet of Things (IoTs)
- JWT Example
	- Header + Payload + Signature : All 3 content is then serialized (put in  one line) and typically Base64 Encoded
- Token Lifetime
	- For valid credential server returns signed token
	- This Token is stored client-side (commonly in local storage), but can be stored in session storage or cookie as well
	- So from now subsequent requests to the server include this token as an additional authorization header
	- Server decodes JWT and validate it , if token is valid then process the request
	- When user log-out the token is destroyed from client-side. No interaction with the server is necessary
- HOW IS a session Token Used?
	- In the URL
	- In the header of the http requisition as a cookie
	- In other parts of the header of the http request
	- In the body of the http requisition.
- How to Obtain Token
	- Stealing
		- Attacker steals session IDs using various techniques
			- Sniffing
			- XSS
			- Malicious Site
		- Guessing
			- Attacker looks at variable parts of session IDs to try to guess what they are
		- Brute Force
			- Attacker keeps trying session IDs until the right one is found

#### SESSION HIJACKING METHODS
- Command Injection
	- Attacker Injects malicious code into the target server
- Session ID Prediction
	- Attacker takes over the session
- Session Desyncrhonization
	- Attacker breaks the connection with target machine
- Monitoring
	- Attacker watches the TCP segment flow and predicts the TCP sequence number
- Sniffing
	- Attacker intercept a token
- Attacker gains access to a machine that still has an active session
	- User has stepped away
	- Access is via RAT
	- Session has no logout or expiration time
- 

### 11.3 XSS (Cross Site Scripting)
- A popular and effective attack type
- Takes advantages of client trust in a server
- Malicious code (typically javascript is inserted into a web page)
- While the victim views the page, their browser executes the malicious code in the background
- Made possible when the web-app does not validate user input
- Requires some level of social engineering
- Can compromise a session by stealing its cookie
- An attacker exploits a vulnerability on the websites software
- They inject their own script which is executed by the victim browser
- The script can steal the session cookie/ token, entice the user with phishing or perform unwanted actions in the user's name
- XSS Types
	- Stored XSS
		- Persistent XSS: Malicious code is stored permanently in a website database
		- Victim later unknowing run the cod
		- An attacker injects a malicious script onto the site that others will read (on social platform) , Visitors read the posting, their browser is also running the malicious script in the background, `document.cookie` property in script is common way to capture a cookie
		- example : ``<p>Yeah it’s great<script>some bad command here</script></p>``
	- Reflected XSS
		- it is non-persistent XSS, In this attack, web app receives data in an HTTP request. Malicious code is run in the victims browser in the context of their current session within the website
			- If you want to steal the user's cookie, you need them to first obtain a cookie
			- While they still have session going, need the same browser (in the same session) to execute the malicious code.
			- If you simply send them a malicious link, it will open another instance of the browser which will be in a different session.
			- The injected script is reflected off the webserver as part of 
				- An error message
				- A search result
				- Any other server response
			- The attacker must search the web app for any place where user input directly trigger a response. A search field is a very common choice
			- Once a vulnerable insertion point is found the attacker can craft a link containing it (and the malicious script) and send it to the victim.
			- Reflected XSS Example:
				- for form creates url containing search item `https://www.example.com/search?term=chocolate`
				- The attacker temper it with `https://www.example.com/search?term=<script>some+malicious+code</script>`
				- This will run the script code in background in victim's browser, may be it includes stealing the user's session token				- 
	- DOM XSS
		- AKA DOM Based Cross Site Scripting
		- Abuses the Document Object Model
			- A standard way to represent HTML objects in a hierarchical manner
		- In a DOM XSS attack, the malicious JavaScript code is inserted directly into the victims' browser. unlike the other XSS attacks which upload (or reflect) malicious code off the server.
		- There are several HTML objects that are particularly suited for DOM XSS.
			- Window.Location
			- Document.URL
			- Document.Location
			- Document.referrer
		- About DOM
			- Dom is programming interface for HTML and XML Document
			- Dom treats an HTML/XML document as a tree structure
			- Each node in the tree is an object representing part of the document. The document itself is also considered an object
			- Objects have Methods that can be used programmatically to change the content of the document
			- 

#### 11.3.4 XSS Countermeasures
- Includes Input Validation/sanitization in the web app
- Use a tool such as #BurpSuite to scan your website or web application regularly
- Restrict user input to a specific allow list by providing a drop-down menu that a user must choose from
- Avoid / restrict HRML in inputs.
	- Require all input be text only
	- Sanitize all input to remove any possible code
- Sanitize all inputted values\
	- Escape all unsafe characters so that they don't result in HTML
- Use HTTPOnly Flags on Cookies. This will prevent JavaScript from reading the content of the cookie
- Use a Web Application Firewall to help pre-screen all input

### 11.4 CSRF
#### 11.4.1 Cross Site Request Forgery 
- Exploits a server's trust in the client
- Takes advantage of a saved authentication to access sensitive data
- The attacker tricks an authenticated victim into unwittingly executing an undesirable action
	- The victim authenticates/is already authenticated to the web site
	- The attacker sends a malicious link to the victim
	- The link instructs the victim browser to perform an unwanted action in the background
- A CSRF attack can force the unwitting victim to:
	- Transfer funds
	- Make unauthorized purchases
	- Change their email address or contact details
- If the victim has an administrative account the attacker can expand the attack to other areas in the web site
	- CSRF Scenario:
		- Visit Banks, and visit attacker site which already have hidden form with same fields as band transfer funds with pre-filled to transfer money
		- Attackers page includes JavaScript that submits form to your bank
		- When form is submitted with browser includes cookie for the bank site including session token
		- This form can be I Frame, Invisible and victim donot know attack occurred.
	- If banks website only uses POST requests it is not possible to frame malicious request using `<A>`  href tag example `<a href="https://mybank.com/transfer.do?account=TheAttacker&amount=$5000">Click for more information</a>`
	- 
	- However the attack can be delivered in a `<form>` tag. This form will be auto-submitted without knowledge of victim. Even attacker can use `document.getElementByID('csrf').submit()` to achieve auto submit. 
```
		<body onload="document.forms[0].submit()>
		<form id=”csrf” action="https://mybank.com/transfer.do" method="POST">
		<input type="hidden" name="account" value=“TheAttacker"/>
		<input type="hidden" name="amount" value="$5000"/>
		</form>
		</body>
```

#### 11.4.2 CSRF Considerations
- The power of CSRF is that it's difficult to detect
	- The attack is carried out be the user's browser as if user requested it
	- The user could enter same URL manually and get same result
	- It's nearly impossible for the browser to distinguish CSRF from normal activity
- CSRF can be difficult for an attacker to execute
	- Requires finding a form that can permit malicious instruction
	- Requires knowing the right values that aren't obscured.
	- Sites that check the referrer header will disallow requests from different origins

#### 11.4.3 CSRF Counter Measurers
- Implement CSRF Tokens
	- A unique, unpredictable secret  value generated by the web app
	- The client must present the token for every request
- Do not use GET requests for state-changing operations
- Use the OWASP CSRF cheat sheet for guidance when developing the web app

### 11.5 The Other Web Hijacking Attacks
#### Session Replay Attack
- Attacker listens in on converasation between user and server
- Attacker obtains user's authentication token
- Attacker replays request to server using obtained token and gains unauthorized server access
#### SESSION FIXATION ATTACK
- AKA session Donation Attack
- Permits an attacker to hijack a valid user session
- Exploits a limitation in the way a vulnerable web app manages the session ID
- An attacker obtains legitimate web app session ID
	- Tricks the victim's browser into using it
- Session Fixation execution techniques include
	- Session token in URL argument
	- Session token in hidden form field
	- Session ID hidden in cookie
- Attack Scene:
	- Attack visits to web application login page and receive session id, but as do not have access do not attempt to login
	- By some way (social engineering, Man-in-the-middle, etc) attacker make victim to use this attacker session id on the website to login
	- Now this session id is considered as Legitimate by server/application
	- Now attacker use this session ID to impersonate the victim
#### MAN-IN-MIDDLE ATTACK (MITM)
- AKA Monkey in the middle
- A general term for an attacker inserting themselves into an existing session to intercept messages
- Uses Various techniques to split TCP connection into two sessions
	- Victim-to-attacker
	- Attacker-to-server
- Once inserted the attacker can read/modify/insert fraudulent data into the communication
- You can capture as session cookie by reading the HTTP header
- You can also change the amount of a money transaction inside the application
- How to accomplish MITM
	- ARP Spoofing
	- DNS poisoning
		- Modify records on the authoritative DNS server
		- Modify the cache of the local DNS server
		- Inject fake cached lookups into the victim's machine
		- Modify the victim machine HOSTs file with fake name of IP Mappings
	- Rogue wireless access point
	- Malicious links

#### MAN-IN-THE-BROWSER (MITB) attack
- Similar to MITM
- attacker uses a Trojan to intercept calls between the browser and its libraries / security mechanism
- Primary objective is to manipulate internet banking transactions
- Customer makes the payment, but malware changes the destination and amount

#### Additional Attack Types
- CRIME (Compression Ratio info Leak made Easy)
	- A client side attack that exploits vulnerabilities present in that data compression feature of protocols such as SSL/TLS, SPDY*, and HTTPS 
- Breach: 
	- An exploit against HTTPS when using HTTP compression (SSL, TLS Compression)
	- Based on the CRIME security exploit
- Forbidden Attack
	- A type of MITM, but exploit the reuse of a cryptographic nonce during the TLS handshake

> Note: SPDY is google protocol that manipulate HTTP traffic. It attempts to reduce page load latency thus speeding up web traffic.


### 11.6- Network Level Session Hijacking

#### 11.6..1 TCP Session Hijacking
- Take a users or client place after it has established a TCP connection with a server
- Enables a connection without providing credentials
- Conditions
	- Cleartext protocol used
	- Attacker needs to observe and correctly predict TCP sequencing numbers
	- Packets can't be digitally signed
- Processes
	- Watch the client/server TCP sequence numbers
	- Send spoofed TCP FIN packets to the clients
	- Spoof your IP or MAC to the server
	- When the client disconnects, continue communicating with the server via the spoofed address
#### RST Hijacking
- A common way to de authenticate a client
- Attacker sends spoofed TCP segments to the client with the RST flag raised
- Victim (typically client) thinks the other side (typically server) has closed the connection
- Attacker takes the client's place.

#### ICMP REDIRECT / ARP SPOOFING
- Two Common technique to redirect traffic to the attacker
- Both require that the client and the attacker be on the same network segment
- ICMP Redirect
	- Attacker sends spoofed ICMP redirect messages top the client
	- Tells the client that it should no longer use its current default gateway
	- Instead the attacker is the clients new default gateway
- ARP spoofing
	- Attacker sends fake ARP replies remapping the server /router IP address to the attacker's MAC address
	- The client will put the attacker's MAC in the destination field of the ethernet or Wi-Fi frame
#### UDP HIJACKING
- UDP Hijacking can happen in one of two ways
	- Attacker sends a forged server reply to the victim before the legitimate server can reply 
	- Attacker intercepts server's reply using man-in-the-middle attack

#### SOURCE-ROUTED IP PACKETS
- A type of MITM
- The attacker does not create two sessions
- Instead the attacker poisons the DNS lookup so the client sends traffic destined for the server to the attacker
- The attacker also manipulates the sources routing option in the IP headers of the client's traffic
- Specifies that the traffic return path from the server passes back through the attacker

#### BLIND HIJACKING
- Performed if source routing is not possible
- Attacker can only send data/ commands - cannot see server's response
	- OK if they can see the results of a command
- 

### 11.7 Session Hijacking Tools
- #Ettercap, #bettercap
	- ARP poisoning and MITM tools
- #T-Sight, #Juggernaut, #Hunt, #Shijack
	- TCP interactive session hijackers
- #sslstrip
	- force SSL downgrade to HTTP
	- Used in HTTPS MITM attacks
- #Hamster
	- cookie sidejacking tool - replaces your cookie with someone else’s
- #Ferret
	- the cookie sniffer used by Hamster
- #BurpSuite, #OWASPZAP, #Paros
	- localhost proxies for intercepting and manipulating web app traffic
- #Firesheep
	- Mozilla Firefox extension
	- Packet sniffer that hijacks browser sessions on unencrypted public Wi-Fi
	- Steals cookies from the user’s favorite sites such as Facebook, Twitter, etc.
- #CookieCadger
	- A Java app that automatically sidejacks and replays insecure HTTP GET requests



#### Hijacking Apps for Mobile Devices

- #DroidSheep
	- Android app that listens for HTTP packets on wireless networks
	- Sidejacks the session and extracts the session ID
- #DroidSniff
	- Sniffer, MITM, automatic password capture of popular social media sites
- #dSploit
	- Pentesting suite that runs on Android
	- Wi-Fi scanning, network mapping, port scanning session hijacking, MITM
- #zANTI
	- ARP poisoning MITM
	- Sniff cookies


#### 11.8 SESSION HIJACKING COUNTER MEASURES

- Protect Session IDs:
	- Use unpredictable (randomized) Session IDs
	- Never use URLs with Sessions IDs
	- Don't Re-use Session IDs
- Use HTTP-Only on Cookies to help prevent XSS (Cross-Site Scripting)
- Regenerate the session key after authentication
- Limit incoming connections
- Minimize remote access
- Set absolute and inactive time limits on sessions
- Use Multi-Factor Authentication
- Use HTTPS or an IPSEC-based VPN to encrypt your connection
- Use OWASP cheat sheets for web app developer best practices.


### 11.9 REVIEW

- In session INTRO hijacking, TO the attacker attempts to take over the client’s session AFTER the user has authenticated
 - Cookies and Java Web Tokens (JWTs) are the most common type of session token
- Session Sniffing Prediction (sidejacking) is passively the next sniff and capture's token 
	- Session prediction is where you can guess what the next token value would be 
- Cross-Site Scripting (XSS) is where the client trusts the server
	- The attacker injects malicious code which the client's browser executes in the background
- Stored (persistent) XSS stores the malicious code on a page that others will see
- Reflected XSS uses a web app's search or error functionality to send the malicious command, along with a session token, back to the user
- DOM XSS injects the malicious script into the victim' browser directly superimposing it on top of a downloaded page
- Cross-Site Request Forgery (CSRF) is where the server trust the client (authenticated user). As the used does something, else the CSRF tricks the browser into sending unauthorized commands to the website, which the website will accept and execute
- Session replay is where the attacker passively sniffs the client's token and then uses it
- Session Fixation is where the attacker obtains a legitimate session token and then tricks the client into using it while authenticating 
- CRIME and BREACH takes advantages of protocol Vulnerabilities
- MITM can be accomplished through ARP spoofing, ICMP redirect, DNS poisoning and Malicious links
- Source-routed hijacking uses the source routing field in an IP header to instruct routers to send traffic through a different path (the attacker)
	- Blind hijacking is used when sources routing is not possible
	- The attacker can relay requests to the server, but cannot see the responses
- TCP session hijacking requires the attacker to predict the next TCP sequence number, de-authenticate the client, and take the clients' place
- UDP hijacking intercepts a server\s UDP response to a client, sending a fake response in its stead.












