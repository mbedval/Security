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
- Fake login page sends those credentials to attacker
- User is redirected to the legitimate site
	
#### Mobile-Based Social Media Attacks
- Attacks
	- Publishing malicious apps
	- Repackaging legititmate apps
	- Fake security applications
	- Smishing using SMS, Facebook messenger, WhatApp, etc
- ZitMo (Zeus-in-the-Mobile)
	- Banking malware that was ported to android

### 9.4 Social Media, Identity Theft Insider Threats

#### SOCIAL MEDIA
Social media is a very platform for social engineering
The attacker can use it to obtain information, develop relationships, and gain trust
	The more the attacker knows about you, the more they can tailor an attack to work against you
Common uses of social media sites for social engineering includes:
	Account takeovers and cloning
	Targeted scams and attacks
		Fake fundraisers
		Fake get-rich quick schemes
		Data gathering /data theft
	Employees often leak sensitive information on social media sites
	Bugs in social networking apps can also introduce new vulnerabilities to the network

#### SOCIAL MEDIA INFORMATION DISCLOSURE SECENARIO
- Too much post with personal information on social media, allows attackers to perform a Cognitive password attack
- Cognitive password is a form of knowledge-based authentication:  It requires a user to answer a question, presumably something they intrinsically know to verify their identity. Either password is recreated , guessed or bypassed
- For Example, a high profile politician's email account was hacked because a high schooler used the "Reset my password" feature on their email service,

#### IDENTITY THEFT
- A crime in which one person steals another person's name and personal information to commit fraud. It can includes personally identifiable information (PTI) such as name, social security number, driver's license number, credit card number
- An attacker can use identity theft to:
- Fraudulently open bank accounts or obtains loans
- Impersonate an employee and gain access to an organizations sensitive information and physical access to the building\
- Commit Crime in another person's name


#### IDENTITY THEFT COUNTERMEASURES
- Don't click on that link in your email to avoid malware, computer viruses, or hackers gathering your data.
- Use trusted sites when shopping online
- Be careful about what personal information you share online (eg. Social network)
- Subscribe to a reputable identity theft protection service, because attacker can :
	- Monitor your personal information, credit files and the web
	- Alert you to any suspicious or fraudulent activity
	- Contact credit bureaus banks and creditors on your behalf
	- Assist you in restoring your identity if it becomes necessary

#### Insider Threats
- An insider is any person who :
	- Has or had authorized access to or knowledge of an organization's resources including personnel facilities information equipment networks and systems
	- Can include employees, former employees contractors  business partners
- An insider threat is the potential for an insider to use their authorized access or understanding of an organization to harm that organization.
	- This harm can include malicious complacent or unintentional acts that negatively affect the integrity, confidentiality and availability of the organization, its data, personnel or facilities
- An insider will use their authorized access, wittingly or unwittingly, to do harm to: 
	- The organization missing resources personnel facilities information, equipment, networks or systems
#### INSIDER THREAT INDICATORS
- Poor performance Appraisals
	- An employee might take a poor performance review very sourly
- Voicing Disagreement with policies
	- Someone who is highly vocal about how much they dislike company policies could be a potential insider threat
- Disagreements with Coworkers
- Change in personality or mood
- Financial Distress
- Alcohol, drug, gambling or other addictions
	- Might put the employee in financial distress
	- Might make the employee vulnerable to social engineering
- Unexplained financial Gain
- Odd Working Hours
- Unusual interest in a co-workers personal life or information
- Unusual interest in a program, project, resource, topic that is outside the scope of the personal's normal job duties
- Unusual Overseas Travel

#### INSIDER THREAT ACTIONS
- Insiders threats can manifest in various Ways:
	- Violence, Espionage, Sabotage, theft, Malicious, Cyber Acitivities, Collusion with outside actors
- Some insider threat actions can be unwitting or under duress


### 9.5 Social engineering Countermeasures

- Train employees to 
	- follows authentication and authorization strict protocols
	- Neven give out passwords / sensitive information via phone
	- Consult their manager if they are not sure what to do 
- Periodically test training effectiveness and refresh/ update training
- Post reminder and encouragements in the physical workspace
- Ensure that browsers have proper privacy and security settings
- Configure spam filter on the email server and emails clients
- Ensure all guests are escorted while onsite
- Ensure the mailroom, server room, phone closet and other sensitive areas are locked and monitored at all times
- Keep an updated inventory of all communication equipment
- Use multi-factor authentication
- Use multiple layers of anti-virus / anti-phishing defenses at all gateways
- Ensure all documents containing private information are shredded / secured

#### IMPERSONATION COUNTERMEASURES
- If you are not part of IT support staff or physical security staff:
- All follow protocol when granting access, activating accounts changing passwords on behalf of a user, etc. 
- Remain especially resistant to urgency / authority appeals when asked to do something improper
- If necessary, engage your supervisor or a colleague to help you resist pressure tactics
- Report attempts to your supervisor

#### PHISHING COUNTERMEASURES
- Familiarize yourself with these indicators
	- Unknown, unexpected or suspicious originators
	- Missing or incorrect recipient name in the body of the message
	- Bad spelling or grammar in the message
- Examine message headers to verify
	- Phone numbers
	- Actual sender
- Never click a link

> Forward the email to IT team for further investigation , or Permanently delete the email to avoid possible damage


#### SOCIAL MEDIA SOCIAL ENGINEERING COUNTERMEASURES
- Threat unexpected messages and posts (especially containing links or attachments ) with caution
- Enable 2-factor authentication
- Always double-checks the source of giveaways and fundraisers
- Don't automatically trust social media ads, pages, or groups
- Be mindful of what you post on social media
- Optimize your privacy settings
- Check your friend lists
- Don't unwittingly give away security data on "fun" shared posts

#### IDENTITY THEFT COUNTERMEASURES
Don't access financial information on shop online using public Wi-Fi (or unsecured network)
Don't give out your social security number or any financial information to people calling, emailing or texting you
Get You credit report regularly to ensure all the data is accurately and that nobody has opened up accounts under your name
Shred any mail or documents that have personal information (e.g. financial information health docs) instead of just tossing in trash
Don't carry your social security card in your wallet ( and have a list of every card in your wallet in case it gets stolen)

#### INSIDER THREAT MITIGATION
- The organization should have a holistic insider threat mitigation program
- Insider threat mitigation programs are designed to help organization intervene 
	- Before an individual with privileged access or an understanding of the organization makes a mistake or commits a harmful or hostile act
- The program development should span the entire organization
	- Should serve as a system to help individuals, rather than be an aggreessive enforcement or sting program
- Know your people
	- An organization must know and engage its people 
	- This awareness enables an organization to achieve an effective level of personnel assurance
- Identify the Organization's assets and prioritize Risks
	- Determine where the organization assets reside and who can access them.
	- This knowledge allows a broader classification of each asset's vulnerability and enable the development of risk-based mitigation strategies.
- Establish the Proven Operational Approach of
	- Detect & Identify
	- Assess 
	- Manage : By gathering and investigating incident and threat information, assess and categorize those risks, then implement management strategies to mitigate the threats

> www.cisa.gov/insider-threat-mitigation


#### 9.6 SOCIAL ENGINEERING REVIEW


 - Social engineering is the use of psychological manipulation through: 
	 - Fear, greed, Curosity, Helpfulness, Urgency, Obedience to authority
	-  
- You  convince people to disclose information or performance an action that they ordinarily would not do
- Attackers use it to acquire sensitive information / inappropriate access privileges
- Computer-based social engineering involves using computer software to get information
- Human-based social engineering involves using computer software to get information
- Human-based social engineering involves getting information through human interaction
-  Successful human-based social engineering requires the hacker to:
	- Have good communication skills
	- Have good interpersonal skills
	- Be creative
	- Be friendly and easy to talk to.

#### SOCIAL ENGINEERING TECHNIQUES
- Impersonation: Pretending to be someone the user trusts, such as an authority figure or IT support
- Pretexting : Giving the victim a (Fake) reason for requesting something of them
- Quid-Pro-Quo : Relies on an exchange of information or service to convince the victim to act
- Phishing , Spear Phishing , Whaling, Vishing and smishing : Sending fake message to trick the vitim
- Water holing: Enticing users with a common interest to visit a malicious websites
- Pharming - Re-Directing a user to a bogus website that mimics the appearance of a legitimate one
- Clickjacking - Overlaying an invisible (malicious ) HTML element on the top of web-page
- Baiting : Online and/or physical attack that promises the victim a reward (often uses innocent looking hardware to entice the victim)
- Fake malware and ransomware 
- Shoulder surfing and dumpster diving
- Piggybacking (victims knows you are behind them they help you get in)
- Tailgating : victim does not know you are behind them
- RFID skimming
- URL hijacking and Evil Twins
- Identity Theft is when one person steals another person's name and personal information to commit fraud
- As insider threat is when someone could use legitimate privileged access or knowledge to harm the organization
- Insiders don't normally start as a threat. Some insider threats are unintentional
- The best defense relies on the implementation of:
	- Good Policies and procedures
	- Technical controls when available
	- Effective training
- 
