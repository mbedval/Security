###  17.1 MOBILE PLATFORM OVERVIEW
#### WHAT is a MOBILE device
- A mobile device is essentially a small hand-held computer with a touch screen.
- The user interface uses direct manipulation (multi-touch gestures)
- It has an embedded operating systems that can 
	- makes and receives voice calls
	- Send and receives voice calls
	- Connect to a network (including the internet)
	- Run applications
- Most mobile devices have a subscriber identify module (SIM ) card that contains a phone number and other information necessary to connect to a cellular carrier
- Most modern mobile devices can connect to multiple network types simultaneously including cellular, Wi-Fi Bluetooth, NFC
	- In can also connect to a PC via USB

#### MOBILE ECOSYSTEM
Mobile devices have an entire ecosystem of hardware, software services and vendors to support the mobile users.
mobileuser , MobieManufacturers, OperatingSystem, MobileApps, Website, testing developing tools, Mobile Apps, Mobile Websites developement companies , Mobile App stores, Mobile AD companies Carrier, Network, MobileCloud, Devices, Other
- 

#### OWASP Mobile to 10 risks
- Improper platform usage
	- The organization exposes a web service or API call consumed by the app
	- Attacker could feed malicious input to the vulnerable device
- Insecure Data Storage
	- App developer erroneously assumes users/malware will have no access to the device filesystem
- Insecure Communication
	- SSL / TLS may be used during authentication but not elsewhere in the communication
- Insecure Authentication
	- Weak or missing authentication schemes
	- Uptime limits may require apps have offline authentication, which attackers could learn to bypass
- insufficient Cryptography
	- 'Roll your own' encryption, or weak algorithm / key implementation
- Insecure authorization
	- Poor or missing authorization schemes can allow privilege escalation
- Client code quality
	- Attackers could fuzz the app to look for memory leak / overflow opportunities
- Code Tampering
	- Unauthorized versions and patches, can inject malicious instruction or remove security features
- Reverse Engineering
	- Hackers analyze the core binary a look for ways to compromise the app
- Extraneous functionality
	- Attackers download the app and look for hidden switches or test code artifacts that could be exploited
> Most people do not take mobile security as serious as they do laptops or computer security


#### SECURITY ISSUES FROM APPLICATION STORES
- Non-Existient or insufficient app vetting
- Malware / malicious apps distributed through store
- Social engineering of users to access apps outside store
- Malicious apps damage other apps so attackers can access sensitive data
- Unofficial app stores/ repositories
- Sideloading apps via email / Social media / alternate download sites / removeable media.

### 17.2 MOBILE DEVICE ATTACKS












### p2112