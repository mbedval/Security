### 2.1 Footprinting
- Footprinting
- Types of Information
- Information Sources
- Passive Footprinting/OSINT
- Active Footprinting

#### What is footprinting
- Footprinting is the first step in reconnaissance
	- The attacker looks for tracks and traces the target leaves about itself on the internet
	- Collect as much information as possible.
- Value of Footprinting:
	- Gain knowledge of the target's overall security posture
	- Create a "bird's eye" view on the target
		- Physical/facility vulnerabilities
		- High-Level network map
		- Potential target areas to attack
		- Potential human targets to engage
	- Information that may not seem immediately useful may gain relevance later

#### TYPES OF INFORMATION TO GATHER
Search for anything that might help you gain access to the target's network
- General company information
	- Company mission, products, services, activities, location, contact information
- Employee information
	- Email addresses, contact information, job roles
- Internet presence
	- Domain names, websites content, online services offered, IP addresses, network reachability
	- Leaked documents and login information
- Overall security posture
- Technology used
- Industry and market information
	- Company profile, assets, financial information, competitors

#### FOOTPRINTING INFORMATION SOURCES
- Company Website(s)
- Whois
- Search engines
- People Searches
- Job boards
- Social networking / social media
- News articles and press releases
- Specialized OSINT tools

#### PASSIVE FOOTPRITING / OSINT
- Open Source Intelligence
- Use the Internet/ publicly available sources gather information on a target
- Do not directly engage target.


#### ACTIVE FOOTPRINTING
- Engage the target in seemingly innocuous ways
	- use 'normal' expected actions
	- Avoid arousing suspicion
- Interact with the target's public-facing servers
	- Query the organization's DNS server
	- Traceroute to the target network
	- Spider / mirror the target's website
	- Extract published document metadata
- Limited social engineering
	- Gather business cards
	- Chat with company representatives at trade shows and public events
 
#### FOOTPRINTING PROCESS
- If your target has a website, visit it for initial information
- Use search engines to obtain additional information about the target including news and press releases.
	- Google, Yahoo, Bing, Ask, Baidu, DuckDuckGo, AOL Search
- Use search engine cached pages or Archive.org to see information no longer available
- Use OSINT tools to automate information gathering and find hidden information

#### FOOTPRINTING THROUGH SOCIAL ENGINEERING
- Collect names, job titles, personal information, contact information, email addresses, etc.
- Remember at this stage you want to be subtle and go unnoticed
- Technical includes
	- Casual face-to-face contact
		- Trade show or public event
	- Eavesdropping
	- Shoulder surfing
	- Dumpster diving
	- Impersonation on social networking sites

#### ALERTS and UPDATE MONITORING

-  Monitor websites content for changes
- Set Alerts to notify you of updates
- Alerts are usually sent via email or SMS
- To Receive alerts, register on the websites ( Google, Yahoo, Twitter, Giga)
- Some OSINT tools also offer monitoring and alerts

#### USING FOOTPRINTING RESULTS
- Analyze gathered information to determine your next moves
- Get sense of the target's overall security posture
- Look for information that can be used in your next steps
- Device that can get you into the network
	- IP addresses to scan
	- Servers and services to vulnerability scan
	- Internet-attached IoT devices to compromise
- People to social engineer
	- Email addresses to phish
	- Phone number's call for impersonation
	- Names and job roles to target
- Locations for physical reconnaissance
	- Parking areas to scatter malicious USB sticks
	- Easily accessible areas to plant sniffing/snooping devices
	- Detect Wi-Fi signals



### 2.2 OSINT Tools

#### OSTIN FRAMEWORK
- A Search engine that is also a cybersecurity framework
- Assembles information from publicly available sources
- Includes
	- username, email address, contact information, language transition
	- public records domain name IP address, malicious file analysis
	- threat intelligence and more
- https://osintframework.com

#### SPYSE
- Cyberspace search engine
- Combines several data gathering tools into a full-service online platform
- Users can get data directly from Spyse's web interface or their API
- Has free and paid features

#### MALTEGO
- An Open Source intelligence and forensics application
- Use to mine, gather and visualize data and relationships in an easy-to-understand format
- Find relationships and links between people, groups, companies and organizations, websites, internet infrastructure, phrases, documents, files, etc.
- Used by law enforcement to analyze social media accounts
	- Track profiles, understand social networks of influence, interests and groups
> During Covid-19 crisis Maltego was used to aid virus containment efforts. Scientific study of the Virus spread and Trace tourist/visitor movement from coronavirus hotspots to other locations.

#### SHODAN
- https://Shodan.io
- It is Search engine used to help users identify potential security issues with their devices
- Can find anything that connects directly to the internet
	- Router and Servers
	- Baby monitors
	- Security cameras
	- Maritime satellites
	- Water treatment facilities
	- Traffic light systems
	- Prison pay phones
	- Nuclear power plants

#### CENSYS.IO
- Similar to Shodan
- Continually discover Internet-facing assets including IoT devices
- Offer cloud-based dashboard

#### THEHARVESTER
- OSINT tool for gathering
	- Emails, sub-domains, hosts, employee names, open ports, and banners from different public sources like search engines, PGP key servers, and SHODAN computer database
- Written in python
- Many of its functions require an API key to effectively query the source
```
theHarvester -d www.hackthissite.org -n -n google
```


#### SUBLIST3R
- Uses OSINT and variety of search engines to enumerate websites subdomains
- Can conduct port scans against discovered websites
> - SubDomains are sometimes preferred targets for attackers 
> 	- Often separately managed by the smaller child organization
> 	- Frequently less secure than the parent domain
> 	- Child organizations are typically smaller with fewer resources than the parent
```
python sublist3r.py -d yahoo.com -b -t 50 -p 80,443,21,22
```


#### RECON-NG
- Full-featured web reconnaissance framework
- Has many modules with specific functions for conducting OSINT
- Written in python
- Requires API keys from targets to be effective
```
[recon-ng] > use recon/domains-vulnerabilities/xssed
[recon-ng] > set SOURCE cisco.com
[recon-ng] > run
```

#### INSPY
- Gather information from linkedin
```
apt install inspy
inspy --empspy /usr/share/inspy/wordlists/title-list-larget.txt Google
// search linkedin for google employees using wordlists

inspy --techspy /usr/share/inspy/wordlists/tech-list-small.txt cisco
// search for technologies in use for cisco as target company

```


#### ANDROID INSPY
- Follow a target's Instagram likes and comments

#### SPIDERFOOT
- OSINT automation tool
	- including target monitoring
- Written in python
- Alternatively has a cloud-hosted version
	- Differently subscription levels

#### OSR FRAMEWORK
- A Set of libraries for performing Open Source Intelligence tasks
- Has Various scripts and applications for
	- Username checking
	- DNS Lookups
	- Information Leaks research
	- Deep web search
	- Regular expression extraction etc.

#### METADATA EXTRACTION
- Useful information might reside in PDF or office files
- Use this hidden metadata to perform social engineering
- Tools
	- Metagoofil : #linux 
		- Extracts metadata from publicly available documents belongs to a target company (pdf, doc, xls, ppt, docx, pptx, xlsx) 
		- Usess Google hacks to find information in meta tags
		- Generates a report of (Username, emails addresses, software versions, server names, etc)
		- `metagoofil -d kali.org -t pdf -l 100 -n 25 -o kalipdf -f kalipdf.html`
		
	- ExtractMetaData
	- FOCA #windows
	- META Tag Analyzer
	- BUZZStream
	- Analyze metadata
	- Exiftool




### 2.3 Advanced Google Search
#### Google Hacking
- The use of specialized Google Searches
- Find unusual information such as:
	- Sites that may link back target's website
	- Information about partners, vendors, suppliers, and clients, etc.
	- Error messages that contain sensitive information
	- Files that contain passwords
	- Sensitive directories
	- Pages that contain hidden login portals
	- Advisories and servers vulnerabilities
	- Software version information
	- Web App source code
- Special Search Services
	- Google Advanced Search
	- Google Advance Image Search
	- Google Search Guide
	- 


#### Google Dorking
- Using search strings with advanced operators
- Find information not readily available on a website
- Can be used to find vulnerabilities, file containing passwords lists of emails, log files, live camera feeds, and much more
- Considered an easy way of hacking

##### Docking Operators

| Operator   | Example                                                                     | Description                                           |
| ---------- | --------------------------------------------------------------------------- | ----------------------------------------------------- |
| intitle:   | intitle:"String to be searched"                                             | find strings in the title of a page                   |
| allintext: | allintext:"contact"                                                         | find all terms in the title of a page                 |
| inurl:     | inurl:"news.php?id="                                                        | find strings in the url of a page                     |
| site:      | site:websitename.com "keyword"                                              | restrict a search to a particular site or domain      |
| filetype:  | filetype:pdf "Cryptography"                                                 | find specific type of files   based on file extension |
| link:      | link:"websitename.com"                                                      | search for all links to a site or URL                 |
| cache      | cache:website.com                                                           | display google's cached copy of a page                |
| info:      | info:www.example.com                                                        | display summary information about a page              |
| OR         | google or bing or duckduckgo                                                | Match at least one keyword                            |
| AND        | sumsung and apple                                                           | Match all keywords                                    |
| ""         | "Google Dorks" explained                                                    | Exact match                                           |
| -          | Linux-site: wikipedia.org                                                   | exclude a keywords                                    |
| \*         | "Username * password"                                                       | wildcards of one or more words                        |
| ()         | "Google (dorks or docking or hacking)" AND (explained or tutorial or guide) | Grouping keywords                                     |

##### GOOGLE DORK EXAMPLES
- Camera feeds - live feeds from AXIS cameras
	- intitle:"Live View / - AXIS | inurl:/mjpg/video.mjpg?timestamp
- Email lists contained in Excel files
	- filetype:xls inurl:"email.xls"
- Log files containing passwords and corresponding emails
	- filetypes:log intext:password intext:(@gmail.com | @yahoo.com | @hotmail.com)
- Open FTP servers that can contain sensitive information
	- intext:"index of" inrul:ftp



\
#### Google Hacking Database (GHDB)
https://www.exploit-db.com/google-hacking-database

### 2.4 Whois Footprinting
- Internet Authorities
- Whois
- Whois Tools

#### INTERNET AUTHORITIES

- Internet Corporation for assigned names and number (ICANN)
	- A not-for-profit public-benefit corporation
	- Dedicated to keeping the Internet secure, stable, and interoperable
	- Promotes competition and develops policy on the internet's unique identifiers
		- DNS names and Autonomous System (AS) numbers*
- The Internet Assigned Numbers Authority (IANA)
	- A department within ICANN
	- Maintains a central repository for internet standards
	- Verifies and updates changes to Top Level Domain (TLD) information
	- Distributes Internet numbers to regions for Internet use
- The Internet Engineering Task Force (IETF):
	- An Open standards organization
	- They develop and promote voluntary Internet standards (especially those related to IP)
	>Every  major network that is part of the internet has an identifying Autonomous systems number

#### REGIONAL INTERNET REGISTRIES (RIRS)
- Governing bodies that responsible for controlling all IP addresses and domain registration in their operations region
- American Registry for Internet Number (ARIN)
	- US, Cananda, Antartica and parts of the Carribbean region
- Asia-Pacific Network Information Centre (APNIC)
	- Asia, Australia, New Zealand
- African Network Information Center (AfriNIC) - Africa and the Indian Ocean
- Reseaux IP Europeens Network Co-ordination Centre (RIPE NCC)
	- Europe, Russia, Central Asia, Middle East
- Lating America and Caribbean Network Information Center (lACNIC)
	- Latin America and parts of the Carribean 


#### WHOIS
- A widely used query and response protocol
- Used to query database that store the registered users or assignees of an Internet resource such as:
	- Domain Names
	- IP address blocks
	- Autonomous system numbers
- The protocol stores and delivers database content in a human-readable format
- It is widely available for publicly available for use.

##### WHO MAINTAIN THE WHOIS DATABASE
- There is no single whois database
- Registrars and registries each mainain their own respective whois database
	- Registrars:- companies and organization that have ICANN accrediation and are registry certified to sell domain names.
		- Also responsible for any resellers under them
	- Registries- organizations responsible for maintaining the records of a specific top level domain (TLD) such as .com, .net, org, etc.
- ICANN requires that records remain accurate for the life of the domain registration.

#### WHOIS LOOKUP
- whois database are maintained by regional internet registries and hold personal information of domain owners
- whois query
	- Domain name and details
	- Owner information
	- NDS servers
	- Network Blocks
	- Autonomous System Numbers
	- When Created
	- Expiry
	- Last update
- Can aid attacker or ethical hacker with social engineering

##### POPULAR WHOIS LOOKUP TOOLS

|                                                                                                                                                                                                                                                                                                                                                                                                 | Mobile                        |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| - WHOIS.COM<br>- Domainnamestat.com<br>- LanWhoIs<br>- Batch IP Converter<br>- CallerIP<br>- WhoIs Lookup Multiple Addresses<br>- WhoIS Analyzer pro<br>- HotWhoIs<br>- ActiveWhoIs<br>- WhoIsThisDomain<br>- UltraTools<br>- SoftFuse Whois<br>- Domain Dossier<br>- BetterWhoIs<br>- WhoIs Online<br>- WebWiz<br>- Network-Tools.com<br>- DNSstuff<br>- NetworkSolutionsWhois<br>- WebToolHub | - Whosi & DNS Lookup<br>- WHO |
|                                                                                                                                                                                                                                                                                                                                                                                                 |                               |


- 






2.4.1 Activity - Conducting Whois Research


### 2.5 DNS Footprinting
- DNS Information
- DNS Query Tools
- Location Search Tools

#### 2.5.1. DNS Information
- Attackers uses DNS data of find key hosts on the target's network
- DNS record types

| a     |                                       |
| ----- | ------------------------------------- |
| A     | IPv4 host address                     |
| AAAA  | IPv6 host address                     |
| mx    | Mail server                           |
| NS    | Name Server                           |
| CNAME | alias                                 |
| SOA   | authority for domain                  |
| SRV   | service records                       |
| PTR   | maps IP Address to hostname           |
| RP    | responsible person                    |
| HINFO | Host Information record (CPU type/OS) |
| TXT   | Unstructured text record              |
|       |                                       |
#### 2.5.2 DNS Query Tools
- nslookup 
```
nslookup www.hackthissite.org
```
- dig
```
dig www.hackthisite.org
```
- host
- whatsmydns.net
- myDNSTools
- Professional Toolset
- DNS Records
- DNSData View
- DNSWatch
- DomainTools
- DNS Query Utility
- DNS Lookup
- SUBLIST3R `Sublist3r -d <domain>`

#### 2.5.3 LOCATION SEARCH TOOLS
helps to perform physical or aerial reconnaissance of a target
- Google Maps
- Google Earth
- Wikimapia
- National Geographic Maps
- Yahoo Maps
- Bing Maps
- 


2.5.1 Activity - Query DNS with NSLOOKUP


### 2.6 Website Footprinting

#### 2.6.1 Website Footprinting
- Monitoring and analyzing the target's website for information
	- Browse the target website
- Use Burp Suite, Zapproxy, Paros Proxy, Website informer, Firebug, etc. to determine
	- Connection status and content-type
	- Accept-Range and Last-Modified information
	- X-Powered-By information
	- Web server version
- Examine HTML sources
- Examining cookies
##### WEB SEARCH ENUMERATION
- Use OSINT to discover additional information about a website
- Identify personnel, hostnames, domain names, and useful data residing on exposed webservers
- Search Google, Netcraft, Shodan, Linkedin, PGP Key servers, and other sites
- Search known domain names and IP blocks

#### 2.6.2 Tools

###### SITEDIGGER
Search Google's cache
Looks for vulnerabilities, errors, configuration issues, proprietary information, and interesting security nuggets on web sites.
Use it to find information that can be exposed through Google Docking
###### DIRB
- Web Content scanner
- Looks for existing and hidden web objects
- Usefuls for finding hidden subdirectories in a web app
- Works by launching a dictionary based attack against a web server.
	- Analyzes the response

###### DIRBUSTER
similar to DIRB but GUI-based

#### 2.6.3 Spiders
- Web spiders automate searches on the target websites and collect information:
	- employee names, titles, addresses, email, phone and fax numbers, meta tags
- Helps with footprinting and social engieering attacks
- Tools
	 #SpiderFoot #VisualSEOStudio #WildSharkSEOSpider #Scrapy #ScreamingFrog #Xenu

#### 2.6.4 Mirroring
- Download an entire copy of the website to a local directory
- You can examine the entire website offline
- Helps gather information without making website request that could be detected.
- You can take your time searching
- Need to copy slowly.

###### WEBSITE MIRROING TOOLS
#HTTrackWebSiteCopier #SurfOffline #TeleportPro #PortableOfflineBrowser #GnuWget #BlackWidow #NCollectorStudio #WebSiteRipperCopier #PageNest #BackstreetBrowser #OfflineExplorerEnterprise #Archiveorg #WebWatcher

Archive.org
- Allows access to achieved versions of the website
	- Copies the site as it was at the time
	- You can find information that was subsequently deleted
	- Archived sites may or may not include original downloads	- 
- Also Contains extensive content uploaded by the community



#### 2.6.5 Update Monitoring
- Automatically checks web pages for updates and changes
- Sends alerts to interested users
- Example tools
	- #WebsiteWatch34 #visualPing #FollowThatPage #WatchThatPage #Check4Change #OnWebChange #Infominder


### 2.7 Email Footprinting

2.7.1Email Source Header
- Reading the email source header can reveal
	- Address from which the message was sent
	- Sender's mail server
	- Authentication system used by sender's mail server
	- Date and Time of Message
	- Sender's name
- Also Reveals:
	- Spoofed info
	- Bogus Links and phishing techniques
\
2.7.2 Email Tracking
Tracking emails can reveal
- Recipient IP Address
- Geolocation
- Email Received and read
- Read duration
- Proxy detection
- Links OS and Browser Info
- Forwarded email
- Recipient device type

2.7.3 Email Tracking Tools
#EmailTrackerPro #PoliteMail #Yesware #ContactMonkey #Zendio #ReadNotify #DidTheyReadit #traceEmail #EmailLookup #PointofMail #WhoReadMe #GetNotigy #G-LockAnalytics





### 2.8 NETWORK FOOTPRINTING
#### 2.8.1 LOCATE NETWORK RANGE
- map the target network
- find in RIR whois database search
- Search online
	- https://centralops.net/co/domaindossier.aspx
	- https://networksdb.io/ip-addresses-of/
- Use command prompt tools
	- whois
	- curl
	- host -t a github.io

#### 2.8.2 Traceroute
- Discover routers and firewall along the path to a target
- Uses ICMP or UDP with an increasing TTL to elicit router indentification
- Find the IP address of the target firewall 
- Help Map the the target network
##### ONLINE TRACEROUTE EXAMPLE
https://www.monitis.com/traceroute
https://centralops.net/co

##### TRACEROUTE TOOLS
#pathAnalyzerPro #VisualRoute #NetworkPinger #GEOSPider #vTrace #Trout #RoadkilTraceRoute #MagicNettrace #3DTraceRoute #AnalogXHyperTrace #NetworkSystemsTraceroute #PingPlotter
### 2.9 Social Network Footprinting

- Attackers use social networking sites to gain important and sensitive data about their target
	- They often create fake profiles through these social media
	- Aim is to lure their target and extract vulnerable information
- Employee May POST:
	- Personal information such as DOB, educational and employment background, spouse's name, etc.
	- Information about their company such as potential clients and business partners, trade secrets of business, websites, company's upcoming news, mergers and acquisitions, etc.
- Common social networking sites used
	- Facebook, mySpace, Linkedin, Twitter, Pinterest, Google+, YouTube, Instagram.

##### Information from social networking sites
- Present activity and physical location
- Job activities
- Company information
- Contact details, names, numbers, addresses, date of birth, photos
- Family and Friends
- Property information
- Bank details
- Background and criminal checks

##### People Search
- A Great source of personal and organizational information
- Residential addresses. email addresses, phone number
	- Satellite photos of residences
- Date of birth
- Photos and Social networking profiles
- Friend/Family/associates
- Hobbies/Current Activities/blogs
- Work information
	- Projects and operating environment
	- Travel details
- People Search Sites
	- #CheckPeople #Beenverified #Truthfinder #peopleWhiz #peoplelooker #intelius #checkmate #peoplefinder #IDtrue
 
#### SOCIAL MEDIA GROUPS, FORUMS, BLOGS
- Social Media Groups, forums and blogs provide more intimate information about a person
	- Current Interests
	- Current Activities
	- Hobbies
	- Political and social viewpoints
- Can be used to cultivate a relationship with the target
- Attackers create fictious profiles and attempt to join groups
- Disinformation campaigns use bots to
	- Automate posting
	- Increase visibility of an issue
	- Give malicious information traction
	- Make a opinion or idea seem to be popular.
- 


### 2.10 Footprinting and Reconnaissance Countermeasures
OSINT Countermeasures
- Recognize that once information is on the Internet, it might never fully disappear
- Perform OSINT on yourself regularly to see what's out there
- Identify information that might be harmful
- When possible, go to the sites that publish that information and remove it
- Delete/deactivate unnecessary social media profiles
- Use an identity protection service
- Use Shodan and Google Dorks to search for exposed files and devices
	- If any are discovered, implement protection measures
- Setup a monitoring services such as Google Alerts  to notify you if new information appears
- Train yourself (and you employees) to recognize the danger and be cautious about what they share on social media
- If Possible, use a data protection solution to minimize data leakage from the company.
- Turn off tracking feature on you phone and configure privacy settings
- Disable location on photos you plan to post publicity on social media.
- Remove metadata from images if you don't want others to know which device you are using to capture.
- Conduct only private dialogues, trying to avoid public communication on forums and other sites
- keep a close eye on which web pages and portals you visit
- some of them may require too much information for registration name, phone number and real address
- use different nicknames on the internet, it will be much more difficult to find you
- Switch your profile to private mode if the social network allows you to do this
- When adding friends on social media only add people you actually know in real life.


### 2.11 Footprinting and Reconnaissance Review
- Footprinting gathers as much information as possible about a target in advance of the attack
	- you are looking for any information that can help you break into the target network 
- Footprinting can be passive or active
- It's usually subtle / unnoticeable
- Small random seemingly unimportant details can be together paint a bigger picture or become important later in your hacking efforts
- OSINT is the use of publicly available source and tools to footprint target
- You can perform advanced Google searches using 'dorks' (search strings with advanced operators)
- The GoogleHacking Database (GHDB) list poplular dorks created by the community
- You can use, dig, nslookup, and many other tools to query a DNS server for host
- You can examine emails headers and use email tracking tools to identify the actual source of an email
- You can use WhoIs, Traceroute and other tools to identify IP Blocks , the firewalls IP address and other network-available points of entry to the target
- Social Networking sites and social media can provide a wealth of information
- 


