### 19.1 CLOUD COMPUTING CONCEPTS

Virtualization of some or all of your computing and network services
Offered by the Cloud Services Provider (CSP)

#### CHARACTERISTICS OF CLOUD COMPUTING
- ALL functionality is virtualized
- On-demand self-service
	- You buy a generated subscription
	- Then use whatever resources you like
	- Only pay for what you use
- Distributed storage
- Rapid Elasticity
- Automated management
- Broad network access
	- Wide variety of client types from nearly any location

#### SERVERLESS ARCHITECTURE
- "Serverless" is the most common cloud computing execution model
	- It separates computing functionality from the physical hardware
	- The cloud provider doesn't allocate a specific server to the customer
	- Instead the provider uses a virtual environment to allocate a protion of their server's CPU time, memory and disk space to the customer as needed
	- The services and functions are most likely spread across multiple servers in the provider's datacenter
- The serverless model can automatically 
	- Provision required computing resources on demand
	- Scale those resources up or down as needed
	- Scale resources to zero when the application stops running
- Every leading cloud services provider offers a serverless platform
- #Pay-As-You-Go Authentication, DAtabase, API , FileStorage, Reportng ,etc provided as Compute function and service

##### #Virtualization 
- A model in which computing functionality is separated from the physical hardware it runs on
- You run computing functionality as an application inside another computer
- A single powerful "host" computer can run entire operating systems and networks as individual applications
- You can also split the various compute functions across multiple hosts
- VMs run as apps on a host OS
- A hypervisor allows the VMs and host OS to share resources
- Common items that are virtualized : OS, APPS, Network devices, Network Connections, Storage

#### CHARACTERISTIC of Virtualization
- Partitioning : Many applications and multiple  OSes in a single physical systems
- Isolation : EACH VM is isolated from the host and other VMs
- Encapsulation : A virtual hard disk is a single file

#### VIRTUALIZATION TERMINOLOGY
- Virtual Desktop Infrastructure (VDI)
	- A virtualization implementation that separates the personal computing environment from a user's physical computer
	- The user's desktop runs as a VM in a datacenter
	- The user's PC connects to the VM across a network
- Virtual private Cloud (VPC)
	- A private network segment made available to a single cloud consumer on a public cloud 
- Virtual private network (VPN)
	- A secure tunnel created between two endpoints connected via an insecure network typically the internet
- User and entity behavior analytics (UEBA)
	- A system that can provide an automated identification of suspicious activity by user accounts and computer hosts

#### BENEFITS OF VIRTUALIZATION
- Improved business continuity during disaster recovery. Just 'Stand up' (enable a backup copy of the virtual machine)
- Reduced infrastructure cost. More efficiently use compute resources, floor space and electrical power.
- Improved operational efficiency
- Reduced system administration required
- Improved data protection and backup
- Improved service levels and service positioning 
- Improved control and compliance
- Anywhere access
- Minimum hardware investment and maintenance

#### CONTAINERS
- A lightweight VM for a single app
- More efficient that traditional virtual machine
	- Does not have its own OS
	- Borrows functionality from the host OS
- Has everything needed to run a single applications
	- Code , runtime, system tools, system libraries
- Examples include Docker, Kubernetes , Podman, OpenVZ and others
- Cloud-based container services have become very poplular

> VM runs on Guest OD communicating to HOST OS via #Hypervisor
> While Container communicates with Host OS via Container Engine

### 19.2 CLOUD TYPES
#### CLOUD SERVICE MODELS
- #saas : Software-as-a-service
- #Pass :
	- Platform-as-a-service
	- Provides the end-user with a development and/or generic computers without all the hassle of configuring and installing it themselves
	- If you want to develop a customized or specialized program, PaaS helps reduce the development time and overall costs by providing a ready to use platform
- IaaS :
	- Infrastructures-as-a service
	- Focused on the replacement of physical hardware at a customer location with cloud-based resources
	- Place your entire network in the cloud : subnets routers, switches , servers ,firewalls , WAN links, etc.

#### CLOUD DEPLOYMENT MODELS
1. Private cloud : Single organization use, typically on-premises
2. Public cloud : Open for public use, In SaaS, different companies might share the same application. Their data will be kept separate.. Typical in small business such as doctor's office
3. Community Cloud: Used by multiple organization with the same configuration or security requirements. Example: different bueraus within the same government agency 
4. Hybrid Cloud:
	1. Combined of two or more type of cloud
	2. Can also refer to an extension on the on-premises datacenter into the cloud
		1. Users can connect to either
		2. The on-prem facility treats the cloud as additional servers
		3. On-prem and cloud servers replicate to each other
		4. An "Always" VPN connects the two

#### Separation of  Responsibilities in the cloud
- On-Premises: Customer is responsible for everything
- IaaS : 
	- Customer is responsible for applications, data, runtime, middleware, O/S.
	- Service provider is responsible for virtualization, server, storage, networking
- PaaS :
	- Customer is responsible for application data
	- Service is provider responsible for runtime, middleware, O/S virtualization, servers, storage, networking
- SaaS : Service provider is responsible for (nearly) everything
- Check your contract and SLA for exact provider and customer division of responsibilities

#### FOG (EDGE) COMPUTING
- The #FOG is an extension of cloud based computing
	- Extends the cloud to an enterprise network edge
	- Coined by CISCO because FOG is a cloud to the ground
- A horizontal, system level architecture
- Computing, Storage, control and networking functions are brought closer to users along a cloud to thing continuum
- Decentralizes IoT devices
	- Runs cloud applications and services right at the "edge"
		- They have immediate or direct connection to the internet while being close to people
		- They can process data in real-time with no latency
		- They don't have to rely on information being sent to the cloud, then back down again
- Example : Cloud computing than is fragmented into specified need of industry forming "fog"
#### BENEFITS of FOG Computing
- Addresses the biggest challenges for IoT
	- Bandwidth
	- Latency
- Ensures QoS
- Reduces energy consumption / improve battery life
- Provides data privately (locally) / improves data security
- Fog enables us to build solutions around
	- Location awareness
	- Mobility
	- Wide geographical distribution
	- Low Latency between devices
	- Wireless access

#### FOG : Enabler for SMART IoT Devices
Provides new capabities such as sharing resources from one device to another
- Sharing resources from one devices to another
- Making real-time decisions
- Contextual data (available locally) for customized intelligence. Enhance user experience
- Autonomous network that operate locally
	- Can make decision such as saving energy and network bandwidth, improving data security reducing latency etc.
- Streamline online-to-offline processes
	- Leverage the physical proximity of the customer
	- Better authentication and cross-sell opportunities

#### FOG Computing Layers
- Cloud network : Remote server hosted on the internet to store, manage and process data
- Fog Network : Storage, Compute, Network , Control Accelerator (Closer to the end points)
- Things : Sensors attached to object of interest

#### The Fog Layers
- Fog Layer includes "Fog Nodes". 
	- Devices such as routers, gateways access points base stations, specific fog servers, etc
- Fog nodes are located at the edge of a network
	- Can be a hop distance from the end device
	- Fog nodes are situated between end devices and cloud data centers
- Fog nodes can be:
	- Static eg: located in a bus terminal or coffee shop
	- Moving : fitted inside in a moving vehicle
- Fog nodes ensure services to end devices
	- fog nodes can compute , transfer and store the data temporily
- Fog nodes use TCP/ IP to connect to the datacenter in the cloud

### 19.3 CLOUD BENEFITS AND CONSIDERATIONS
#### PROS OF CLOUD COMPUTING
- Only pay for what you use
	- Minimal investment in hardware
	- You need good connectivity and end user devices
- Rapid scalability / agility / flexibility
- If you implement SaaS, you don't need much technical expertise
- Most providers have considerably more fault tolerance / disaster recovery capability than the average customer has
- Nearly all on-promises functionally can be moved to the cloud.. Your users just need to be able to securely connect
- Cloud providers typically have more capabilities than on-premises datacenters including big data analytics, artificial intelligence integration, large scale parallel computing
#### CONS OF CLOUD COMPUTING
- The customer is dependent on the cloud provider to provide the necessary levels of service for their application
	- The customer does not manage the back-end infrastructure
	- The cloud provider is responsible for all back-end tasks such as provisioning, scheduling, scaling and patching
	- Make sure your Security policy covers any gaps in the provider's security policy
- Customer end-point devices that connect to the cloud must still have their own security (firewall, anti-virus etc..)
- You might have to utilize the provider's existing vendor testing and audits in place of normal penetration testing procedures
	- Most SaaS providers will not allow customers to conduct their own port scans or vulnerability scans against the SaaS service
- Customization may cost more
	- Be very careful of hidden costs
	- Ever if you have shut down VMs they are still running and incurring cost
	- You will also have costs for storage, advanced support, infrastructure services, etc
- You are at risk of not purchasing the solution you actually need. Work with the provider on your use case
- For PaaS and IaaS you still need to implement all the same security controls that you would in an on-premises environment
	- You will have to pay for fault-tolerance, load-balancing and the facilities and features necessary for disaster recovery.
- The Customer is dependent on the provider to:
	- Maintain adequate security
	- Be able to me SLAs
- Legal or regulatory requirements may prevent you from moving data to the cloud
	- Cloud datacenter locations are often trans-national
	- You may be required to keep data physically within your national borders
- Your contact might get you "locked in" to a single provider

#### CLOUD CONSIDERATIONS
- Application Security
- File storage Security
- Network Security
- Workload Security
- Container Image security
- Conformity


#### CLOUD SHARED SECURITY RESPONSIBITIY
- In a SaaS model, the customer has to ensure that the endpoints being used to access the cloud are secure
	- Since the consumer owns the endpoint (laptop, desktop, tablet, smartphone, etc. ) they are responsible for securing it
	- The provider will ensure that the back-end infrastructure performs properly and is hardened against security risks
- In a PaaS model, any application that the customer develops are the customer's responsibility to secure
- In an IaaS model, the customer must secure all aspect of the deployed virtual infrastructure as if it was physical infrastructure on their own premises

#### CLOUD FORENSIC
- Performing digital forensics on cloud assets is particularly challenging
	- The on-demand nature of cloud services means that instances are often created and destroyed again.
	- There is no real opportunity for forensic recovery of any data
- Cloud providers can mitigate this to some extent by using extensive logging and monitoring options
	- A CSP might also provide an option to generate a file system and momory snapshots from containers and VMs in response to an alert condition generated by a SIEM
- Employee workstations are often the easiest to conduct forensics on . They are single-user environment for the most part
- Mobile devices have some unique challenges due to their operating systems. Good forensics tool suites are available to ease the forensic acquisition and analysis of mobile
- On-premise servers are more challenging than a workstation to analyze. But they do not suffer from the same issue as cloud-based services and servers.

#### CLOUD SCENARIO 1
Which of the following are valid concerns when migrating to ta serverless architectures?
	- Dependency on the cloud service provider
	- Protection of endpoint security
	- Limited disaster recovery options will not be an issue

#### CLOUD SCENARIO 2
You company has recently been embarrassed by several high profile data breaches
The CIO proposes improving the company cybersecurity posture by migrating images of all the current servers and infrastructures into a cloud-based environment
What, if any, is the flaw in moving forward with this approach?
	This approach only changes the location of the network and not the attack surface of it.
A poorly implemented security model at a physical locations will still be a poorly implemented security model in the virtual location
Unless the fundamental causes of the security issues that caused the previous data breaches have been understood, mitigated and remediated, then migrating the current images into the cloud will change where the processing occurs without improving the networks security


#### 19.4 Cloud  RISKS AND VULNERABILITIES
- All Vulnerabilities of On-premises
- Additional risk of cloud are like
	- Datacenter is remote
	- Run by someone else
	- Shared with other customers
	- Easily accessed from anywhere
#### Provider Related Risk
- Failure of network management
- Failure or termination of cloud services
- Compromised management interface
- Risks posed by changes in jurisdiction
- Acquisition of cloud provider
- Computer equipment theft
- Malicious insiders
- modification of loss of backed up data
- Improper or illegal data handling
- Improper or incomplete data disposal
- Risks associated with compliance. You might be at risk if CSP cannot provide evidence of their compliance
- Inadequate infrastructure design and planning by the CSP . Might not be able to meet agreed service levels and performance  / latency requirements
#### TENANT CREATED RISKS
- Data breach/ loss
	- Data or keys are illegally accessed , lost , erased , misused
	- Loss of encryption keys
- Shadow IT : 
	- IT systems or solutions that are developed to handle an issue but aren't sent through the proper approval chain
- Risks with licensing
	- Client might incur huge fees if software is changed on a per-instance basis
- Abuse of cloud services
	- Attackers create anonymous access to cloud services
	- Perform all of the attacks previously studied
- Insufficient Due Diligence
	- Ignorance of the CSP's environment could cause contractual and responsibility gaps
- Insufficient infrastructure planning and design
	- You might not really understand what a cloud deployment entails.
	- Your subscription might include services you don't really need, or might be missing services you really do need
- Undetermined risk profiles
	- Clients are unable to get a clear pictures of the CSP's internal security procedures, compliance, system hardening and auditing, etc
- E-discovery and subpoena
- Loss of governance
- Client gives up control to the CSP
- Lock-in : Inability of client to migrate to another CSP or in-house systems due to lack of tools or standard data formats

#### CLOUD ADOPTION RISKS
- Economic Denial of Sustainability (CDOS)
- a HACKER might uses up your computer power, causing you to be charged for usage due to their activity
- Loss of security and operational logs
	- Under-provisioning of storage for logs
	- Unsynchronized system clocks that negatively affect automated tasks or cause time stamp mismatches
- Conflict between cloud environment and hardening procedures
	- Client procedures may conflict with the CSP's environment, negating implementations

#### CLOUD VULNERABILITIES
- Server Misconfigurations
	- The most common cloud vulnerability today
	- Improper permissions, not encrypting the data, and failing to differentiate between private and public data
	- Failing to properly configure cloud-based storage such as AWS S3 buckets leads to data breaches
- Insecure APIs
	- Improper use of HTTP methods like PUT , POST , DELETE in APIs can allow hackers to upload malware on your server or delete data.
	- Circumvent user defined policies
	- Breach in logging and monitoring
	- Unknown API dependencies
	- Reusable passwords / tokens
	- Insufficient input data validation
	- Improper access control and lack of input sanitization are also main causes of API compromise
- Lack-of-Multifactor Authentication
	- Weak authentication makes it easier for malicious actors to access your cloud services 
	- Insider threats 
		- Misconfiguration allows accidental security incidents
		- Formers employees / vendor / partners still have access
	- DDoS Attacks
		- Prefer a cloud vendor that offers DDoS protetion features
		- Engage the services of a third party ( #CrowdStrike, #CloudFlare) that specializes in DDoS protection
	- Lack of Visibility
		- Companies can end up using thousands of instances of cloud services
		- It's easy to lose track of what you have running
- Poor Coding Practices (on your part)
	- Security is typically a low priority of after thought in application development 
	- With a push to get customized cloud applications online as quickly as possible, software often contains bugs like SQLi, XSS , CSRF
	- These vulnerabilities are the root cause for the majority of cloud web services being compromised
- Issues with Shared technology
	- Most underlying cloud components (GPU, CPU caches) do not offer strong isolation
### 19.5 CLOUD THREATS AND COUNTERMEASURES
#### Using the cloud as a hacking tools
- Host malicious content in S3 bucket or other blob storage
- Quickly stand up a high-performing hacking workspace
- Use elastic / distributed cloud compute resources for intensive tasks such as brute forcing
- Leverage greater bandwidth provided by cloud services
- Launch attacks from systems that are physically / logically closer to the target
- Use distributed cloud infrastructure to manage botnets.

#### Cloud Threat and COUNTERMEASURES

| Threat                                                                                                                                                                                              | Countermeasures                                                                                                                                                                                                                                                                                                                                                                                              |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Sniffing                                                                                                                                                                                            | Require encrypted transmissions in the cloud and to the cloud                                                                                                                                                                                                                                                                                                                                                |
| Port scanning                                                                                                                                                                                       | Implement firewalls                                                                                                                                                                                                                                                                                                                                                                                          |
| Browser security misconfiguration                                                                                                                                                                   | Requires TLS, use XML encryption of SOAP messages                                                                                                                                                                                                                                                                                                                                                            |
| Virus / Malware injection                                                                                                                                                                           | - Create a whitelist of acceptable request<br>- Store clean hashes of requests so incoming request can be hashed and compared                                                                                                                                                                                                                                                                                |
| - Account or service Hijacking via Social Engineering Attacks<br>- Attacker can treat cloud login like any other website login page<br>- Create fake login page/phish to capture credentials        | - Implement input sanitization on all web apps<br>- Scan web apps for vulnerabilities and apply recommendations                                                                                                                                                                                                                                                                                              |
| Service Hijacking via Network sniffing                                                                                                                                                              | Be Sure to encrypt all data before transmission<br>Scan for promiscuous mode NICs                                                                                                                                                                                                                                                                                                                            |
| Session Hijacking via XSS Attacks<br>-could steal cookies and authentication tokens                                                                                                                 | Use SSL, Firewalls, Antivirus to help                                                                                                                                                                                                                                                                                                                                                                        |
| - Session Hijacking via session Reding (CSRF) <br>- Attacker uses your session to connect to your cloud                                                                                             | - Do not allow browser / websites to save login details <br>- Disallow HTTP referrals                                                                                                                                                                                                                                                                                                                        |
| - Domain Name SYSTEM (DNS) attacks <br>- DNS poisoning<br>-Cybersquatting , domain hijacking, domain snipping, (registering an elapsed domain name)                                                 | - Implement DNSSEC<br>- Configure DNS server to protect against cache pollution<br>Patch and update DNS servers<br>- Use an active check that validates the source of DNS responses<br>- Buy Domains that are variations of your company name<br>Trademark your company name to prove in court that you have a legitimate case over a cybersquatter                                                          |
| SQL Injection Attacks                                                                                                                                                                               | Sanitize and validate input, update and patch, use DB monitoring and IPS , web app firewal                                                                                                                                                                                                                                                                                                                   |
| Cryptanalysis attacks                                                                                                                                                                               | Use random number generation to add robustness to SSH keys and DNSSEC                                                                                                                                                                                                                                                                                                                                        |
| Wrapping attacks<br>-   Attackers duplicate the body of a SOAP message and send it to the server as if from a legitimate user                                                                       | Make sure the browser signs XML document                                                                                                                                                                                                                                                                                                                                                                     |
| Cloud Hopping<br>- Attack against managed service provider (MSP) infrastructure to gain access to tenant's sensitive data<br><br>- Attacker can leverage the cloud to hop between customer networks | Provider :<br>- - Implement a proactive incident response measures<br>IT /System administrators:<br>-- Employe data catergorization<br>Mitigates the damage of a breach / protects the company core data in case data are expose<br>-- Network segments can help <br>--- > Limit privileges and access to sensitive data and corporate networks<br>--- > Makes lateral movement more difficult for attackers |
| Escalation of privileges due to mistake in access allocation<br>-- illegal access to cloud  systems acquired <br>-- Weak authentication / authorization                                             | Patch systems apply least privilege to user and services                                                                                                                                                                                                                                                                                                                                                     |
| Failure of supply chain<br>Cloud security is directl propertional to security of each link                                                                                                          | Ensure you and your CSP have backup plans and alternate suppliers                                                                                                                                                                                                                                                                                                                                            |
| DoS and DDoS attacks                                                                                                                                                                                | - Implement fault tolerance and load balancing on services and network links<br>- Apply least privilege principle to all users that connect to your cloud                                                                                                                                                                                                                                                    |
| - Hardware / Infrastructure / environment failures<br>- Natural disasters<br>- War, Civil disturbances , terrorist activity<br>- 'Act of God'                                                       | - Ensures your SLA specifically covers these issues<br>- Ensures your SLA contains enforcement mechanism                                                                                                                                                                                                                                                                                                     |
| VM Escape <br>VM escape refers to malware running on a guest OS jumping to another guest or the host<br>- VM Escape is the biggest threat to virtualized system                                     | As with any other software type, it is vital to keep the hypervisor cod up to-date with patches for critical vulnerabilities                                                                                                                                                                                                                                                                                 |

SIDE CHANNEL /  CROSS -GUEST VM BREACH
- Malicious co-tenants might look for /attempt the following
	- timing variations, data remanence, acoustic cryptoanalysis , power monitoring differential fault analysis
- Countermeasures
	- Implement virtual firewall on the back end
	- Use random encryption algorithms to avoid predictability
	- Check for repeated access attempts to local memory, hypervisor, or shared hardware cache. you will have to tune process monitoring data and logs to collect this
	- Code your apps to access share resources such as memory cache in a consistent and predictable way. Thus offering less information to attacker on timing statistics or behavioral attributes

#### MAN- In - The - Cloud #MITC Attacks
- Advanced version of MITM
- Done by abusing cloud file synch service like Google Drive or Drop Box
- Hackers intercepts and reconfigure cloud services by exploiting vulnerabilities in the synchronization token system
- During the next synchronization with the cloud , the synchronization token is replaced with a new one that provides access to the attackers
- Users may never know that their account have been hacked
- An attacker can put back the original synchronizations tokens at any time
- There's also that compromised account will never be recovered
#### MITC COUNTERMEASURES
- IMPLEMEVT A CLOUD SECURITY BROKER ( #CASB)
	- The CASB will monitor cloud traffic for account anomalies generated by an MITC attack
- A CASB is a cloud- delivered cybersecurity servcie
	- It ensures the safe use of cloud computing applications and services to prevent accidental (or intentional) leakage of sensitive data, malware infection, regulatory noncompliance, and lack of visibility
	- It secures cloud application, whether they are hosted in public clouds (IaaS) , private clouds, or as Software-as-a-service (SaaS) applications
	- It also exposes the use of shadow IT - unsanctioned being used without the IT team's knowledge and approval

 #### APTs and New Threats
- Advanced Persistent Threats ( #APTs)
- New threats such as Spectre and Meltdown
	- Both attack break the isolation between applications and host OS
	- Attackers can read information from the OS Kernel
	- Not all cloud users install the latest security patches
- VM-Level attacks
	- Emerging threats to virtualization technologies
#### APT and new Threat COUNTERMEASURES
- Install a firewall. Choosing a firewall is an essential first layer of defense against APT attacks
- Enable a web application firewall
- Keep antivirus updated on all systems
- Implement instrusion prevention systems
- Create a Sandbox / #Sheepdip environment to check software before deployment
- Consider enagaing a provider that specialize in threat analytics and APT defense

#### SCENARIO 1
- A professional hacker team, targeted your organization's cloud services
- They infiltered the target' provider by sending spear-phishing emails
	- They distributed custom-mage malware to compromise user accounts and gain remote access to the cloud service
	- Further they accessed the target customer profiles with their MSP account, compressed the customer data, and stored them in the MSP
	- Then they used this information to launch further attacks on the target organization
	- What type of cloud attack it was??
	- ==Ans==: A Cloud Hopping Attack
	
#### 19.6 CLOUD SECURITY TOOLS AND BEST PRACTICES

#### CLOUD PENTESTING TOOLS
- #AWS inspector :
	- A customized security solution for AWS
	- IT can be used as a basic minimum or preliminary testing tool
- #S3Scanner:
	- An Open-source tool to scan S3 buckets for misconfiguration and dump their data.
- #MicroBurst:
	- A collection of PowerShell scripts to scan Azure services for security issues
	- Requires PowerShell
- #Azucar : 
	- Another popular PowerShell based Azure scanning tool
- #AzPowershell module
	- PowerShell cmdlets for azure cloud enumeration
- #Cloudsploit A popular open-source tool that can scan multiple types of cloud service providers like Azure AWS GCP OCI etc.
- #ScoutSuite Audits instances and policies created on multi-cloud platform
- #Prowlr An AWS auditor
- #Pacu : An exploitation framework for testing AWS account security
- #CoreCloudInspect : Pen-Testing application for AWS EC2 users

#### CLOUD SECURITY TOOLS
#CorecloudInspect #AlertLogic #DellCloudManager #QualysCloudPlatform #SymantecO3 #CloudApplicationVisibility #Proticor #PandaCloudOfficeProtection #CloudPassageHalo #SecludT #NessusEnterprise #TrendMicroInstant-on-Cloud-S

#### CLOUD SECURITY BEST PRACTICES

#### NIST RECOMMENDATIONS FOR SECURING THE CLOUD
- Assessment of risk to client data, infrastructure and software
- Determining appropriate deployement model
- Ensuring audit procedures are in place
- Renewing SLAs to guard against security gaps
- Establishments of adequate incident detection and reporting mechanism
- Analysis of Organization security objectives
- Determining who is responsible for data privacy and security issues


#### WORKING WITH THE CLOUD SERVCIES PROVIDER
- Be Very clear on responsibilties and duties between CSP and client
- Specify HR requirements as part of legal contracts, against possible malicious CSP insiders
- Require transparency from the CSP and good breach notification processes 
- Extensively research the CSP's dye diligence
- Have your own robust security policy and gap analysis with regard to the CSP
- You must make up for any security gaps that you need but the provider does not cover
- Have your own business Continuity Plan (BCP) and Disaster Recover (DR) That is not wholly dependent on the CSP
- Ensure your SLA permits vulnerability scanning and pen-testing

#### END USER CONNECTIONS
- Monitor client traffic for malicious activities
- Implement secure authentication and access controls
- Prevent users from sharing credentials
- Enforce acceptance use and employee behavior per policy and legal contracts
- Enforce least privilege on all end users
- Use a VPN to connect to the cloud

#### Encryption and key Management\
- Encryption data before sending to cloud
- Encrypt data in transit
- Implement strong key generation, storage and management
	- Do not store your private key in the cloud
	- You can store the data encryption key in the cloud
	- But then use a public key to encrypt the data encryption key
	- Keep the private key on premises / with you

#### MICROSERVICES AND CONTAINERIZATION
If you use microservices or containerization architecture
Check for data protection at both design and runtime
Implement robust registration and validation of cloud services
Understand the dependency chain associated with CSP APIs

#### CLOUD OUTAGE - 4 STEP DEFENSE MODEL
- Load Balancing :
	- Its is essential to have carefully planned , pre -engineered mechanism for load balancing to distribute client request across cluster nodes evenly
	- You must specify the failover procedure in the laod balancing mechanism
- Data scalability:
	- Cloud application must be designed to auto-scale, so more instances can be brought up to taken down as needed.
	- One solution is to use a central database and provide it with high availability through replication or partitioning
	- Another option is to make sure each application instance has its own data storage
- Geographically diversity
	- Cloud providers has data centers all over the world
	- Using a provider with multiple data centers can ensure that your applications and data are hosted in more than one location
	- In addition, this approach can help prevent outages caused by  natural disasters or other events that might affect a single data center
- Backup and recovery:
	- It is essential to have a backup and recovery plan in place for your cloud-based applications and data.
	- This should include regular backups stored in a different locations than the primary data and a tested disaster recovery plan
#### SCENARIO

- Your organization has recently migrated to a saas provider for its enterprise resource planning (ERP) software
- Before this migration,  a weekly port scan was conducted to help validate the on-premise systems security
- Which of the following actions should you take to validate the security of the cloud-based solution?
- You might have to utilized the provider's existing vendor testing and audits
- Most SaaS provider will not allow customers to conduct their own port scans or vulnerability scans against the SaaS service.
- This means you cannot scan using a VPN connection utilize different scanning tools, or hire a third party contractor to scan on your behalf

### 19.7 CLOUD COMPUTING REVIEW
- Cloud  computing is on-demand delivery of IT capabilities as a metered service
- Serverless architecture uses virtualization to separate compute functionality from the physical hardware it runs on.
- The customer can pay for specific functions they require and no more.
- Three categories of cloud services:
	- IaaS - Customer is responsible for the security of all features they use
	- PaaS - The customer is responsible for the security of the platform or app they create
	- SaaS - The provider is responsible for pretty much everything, though the customer must not abuse the service
- The cloud deployment models are : public, private, Community and Hybrid
- Attacker gain access to cloud services using various types of attacks
	- Cloud services are vulnerable to both traditional on-premises attacks web app attacks such as XSS and CSRF and cloud specific attacks such as cloud hopping and wrapping
- Cloud providers can offer dramatically more compute power, fault tolerance and disaster recovery than traditional on-premises can
- The cloud customer is dependent on the cloud service provider for some aspects of security
- Depending on the type of service you subscribe to , there is a shared responsibility for configuration and security
- You may have to depend on using the CSP's vendor tests and audits as part of your penetration test
- Make sure your own security plan covers any gaps in the providers plan
- You are also responsible for protecting your own end devices and making sure they can connect securely to the cloud
