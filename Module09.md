### 9.1 SOCIAL ENGINEERING CONCEPTS

> Amateurs hacks systems , Professional hack people

#### WHAT is Social Engineering
- The psychological manipulation of people into divulging confidential information or performing actions that they shouldn't do
- A low-tech way of gaining unauthorized information or access to systems

#### IMPACT OF SOCIAL ENGINEERING ON AN ORGANIZATON
- Social engineers rely on the fact the people are not aware of the value of their information and don't protect it properly
- Impact of social engineering attack on an organization includes
	- Financial loss
	- Loss of privacy
	- Potential terrorism
	- Damaged goodwill
	- Temporary / permanent closure
	- Potential lawsuits /arbitration

#### HUMAN MOTIVATION FOR FALLING VICTIM
Fear, Greed, Curiosity, Helpfulness, urgency, obedience to authority


#### ORGANIZATION VULNERABILITY TO ATTACKS
- Reason organizations can be vulnerable to social engineering attacks
- Insufficient training in security
- Multiple organizational units/ departments
- Access to information isn't regulated
- Insufficient / lack of security policies
- Procedures and protocols that are unclear or not adequately enforced.

#### WHY SOCIAL ENGIEERING IS EFFECTIVE
- Security policies only as strong as weakest link, -generally humans
- social engineering attacks are difficult to detect
- 100% security isn't possible
- Technology cannot adequately compensate for poor judgement

#### PHASES OF SOCIAL ENGINEERING
- Researching Target Organization - Via WebSites, employees , company tour, etc.
- Victim Selection  - Determine the most vulnerable employees
- Developing Relationship - Form a relationship with target employees
- Exploiting Relationship - Gather sensitive information and current tech from employees

### 9.2 SOCIAL ENGINEERING TECHNIQUES
#### Common Social Engineering Attacks

| Attack Type      | Description                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Impersonation    | Calling the victim inside the company or at home and pretending to be someone the user trusts, such as an authority figure or IT support                                                                                                                                                                                                                                                                                              |
| Pretexting       | Giving the victim a (Fake) reason for requesting something of them                                                                                                                                                                                                                                                                                                                                                                    |
| Quid-pro-quo     | Relies on an exchange of information or service to convince the victim to act                                                                                                                                                                                                                                                                                                                                                         |
| Tailgating       | An unauthorized person follows an authorized person into the secure or restricted area without the knowledge or consent of the authorized person                                                                                                                                                                                                                                                                                      |
| Piggybacking     | An unauthorized person follows an authorized person into the secure or restricted area with the consent of the authorized person                                                                                                                                                                                                                                                                                                      |
| Phishing         | - Sending a fake email to a user to entice them into opening a malicious attachment or clicking a malicious link<br>- Typically sent to as many people as possible<br>- Variants include : vishing, smishing, spear phishing, whaling, deep fakes.                                                                                                                                                                                    |
| Spear Phishing   | A phishing attack that is targeted towards a specific group                                                                                                                                                                                                                                                                                                                                                                           |
| Whaling          | A phishing attack that specifically targets a high value person such as a CEO or celebrity                                                                                                                                                                                                                                                                                                                                            |
| Vishing          | - Urgent voice mails or pre-recorded messages that pressures victims into acting quickly to protect themselves from malware, arrest or other risk.<br>- A common trick is for a user to dial a number or press a number on their key pad.<br>-- When the user does so , they are redirected to an expensive pay-by-the-minute phone number that keeps them on hold to incur charges<br>-- The charges will appear on their phone bill |
| Smishing         | Phishing using SMS or social media messaging                                                                                                                                                                                                                                                                                                                                                                                          |
| Water-holing     | - Enticing users with a common interest to visit a malicious website<br>- Targeted to a specific group<br>- Often used as a mechanism to gain entry into a specific network                                                                                                                                                                                                                                                           |
| Pharming         | - Re-directing a user to a bogus website that mimics the appearance of a legitimate one<br>- Performed through various name resolution attacks such as modifying a HOSTS file, corrupting DNS server or resolver cache, DNS man-in-the-middle, etc<br>- Done to obtain personal information such as password, account numbers and the like.                                                                                           |
| Clickjacking     | Overlay an invisible (malicious) HTML element on top of a web page<br>Often a one Pixel iFrame<br>User thinks they are clicking the visible page, but they are also clicking the invisible overlay                                                                                                                                                                                                                                    |
| Baiting          | Online and/ or physical attack that promises the victim a reward                                                                                                                                                                                                                                                                                                                                                                      |
| Fake Malware     | Victims are tricked into believing that malware is installed on their computer and they if they pay, the malware will be removed                                                                                                                                                                                                                                                                                                      |
| Ransomware       | A form of malicious software that encrypts data and then demands a paid ransom for the decryption key                                                                                                                                                                                                                                                                                                                                 |
| Shoulder surfing | an unauthorized person spies over your shoulder as you type, can be done directly or across the room with a mobile device and special camera software.                                                                                                                                                                                                                                                                                |
| Dumpster Diving  | Going through someone's trash to find discarded, but valuable / sensitive information                                                                                                                                                                                                                                                                                                                                                 |
> In Tailgating, the attacker slips in behind the authorized user without their knowledge. In piggybacking, the attacker uses social engineering to get the authorized user to hold the door open for them

#### URL HIJACKING
- An attacker exploits types mistake that users may make when typing in a websites URL
- Also called typos squatting -DNS sends the typo site to bogus site
- Typo Squatted websites are often used in phishing
- Can be : Wrong top level domain, Similar or misspelled name

#### RFID SKIMMING
- RFID identity Theft
- Reads, copies, and writes an RFID card
- Larger / custom antenna allows attackers to be a foot or so away from the target
	- You can hide it in a backpack
	- Get next to the victim in an elevator, checkout line, etc.
- Variants exist for RFID , NFC, encrypted cards
#### USB STICK BAITING
- A type of social engineering
- Compromised sticks are scattered where users will find them
	- When plugged in they autorun the payload
	- Infected "game" or fake media file
	- Payload is often re-encoded to evade anti-virus.
- Hopefully the user will plug the stick into their machine inside the network
- Payload connects to waiting attacker
- Requires attacker set up exploit to receive incoming request.

#### USB CABLE BAITING
- A variant on the malicious USB stick
- A USB phone cable has programmable malicious firmware 
- The victim uses it to plug their phone into a computer


#### Non-PHISHING ATTACKS
- SPAMs
	- User's inbox is flooded with unsolicited mail
	- Advertisements, promotions, get rich quick schemes, etc
	- Often used with phishing
- SPIM
	- SPAM over instant messaging
	- Attacker can send a message over Facebook messenger, WhatsApp's, etc.
	- Encourages an individual to follow a link by offering a product
	- A little more difficult for success because instant messages are synchronous nature
- Hoaxes
	- Intended to elicit fear, make you angry or seem important
	- Designed to make you forward, reply or take some action without first validating the source of information
	- Note: You can visit Snopes. to investigate potential  hoaxes.
- Chain letters: a hoax email tha encourages you to forward the hoax to others


### 9.3 SOCIAL ENGINEERING TOOLS

#### COMMON SOCIAL ENGINEERING TOOLS

- SET (Social Engieering Toolkit)
	- Pentest tool design to perform advanced attacks against human by exploiting their behavior
- WiFiphispher / WiFi Pineapple
	- Rogue Wireless access point
	- MITM automated phishing attacks against WiFi Network
- SPF SpeedPhish Framework
	- Quick reconnaissance and deployment of simple social engineering exercises
- Metasploit Pro
	- Has a good built in phishing campaign tool
	- Use to test effectiveness of staff training
- Metasploit Framework / msfvenom
	- Tool to create malicious USB sticks for USB Baiting
- PhishTank
	- For phishing detection
- O.MG Cable
	- Malicious USB cable with programmable firmware

#### EMAIL RELAYS
- Emails relays are email servers that are (mis)configured to forward any email traffic, regardless or source or destination
	- Spammers and phishers use these to help deliver bulk amounts of emails to intended targets
	- Security analysts attempting to trace the email back to the sender might not be able to trace farther back than the relay
- Spammer and phisher exploit misconfigured email servers for their campaign
	- A properly configured email server should only forward mail that originates from known and trusted users
	- There are tools that constantly and automatically search the internet for open email relays.
	- They search for servers listening on TCP port 25 (SMTP)
- Spammers and phishers often stand up their own email relay
	- They leave it up just long enough to carry out the spam or phishing campaign
	- Then they take the server down quickly to evade indentification.

#### SPEAR PHISHING / WHALING EXAMPLE
- Attacker sends a fake email to victim
- User enters credentials into fake login page 
- User is redirected to the legitimate site


	
	








