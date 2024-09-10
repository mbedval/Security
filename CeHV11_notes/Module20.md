### 20.1 Cryptography concepts
#### Data states
- Data at Rest : Stored on a hard drive, USB stick, CD /DVD or any other type of electronic storage medium
- Data in Transist : Data is actively being transmitted on a network
- Data in use : Data is loaded into memory, is or will shortly be processed by the CPU
> you can encrypt data in any of these states to increase confidentiality and trust

#### CRYPTOGRAPHY
- The process of converting ordinary plain text into unintelligible text and vice-versa
- When encrypted the data can be safely stored, used or transmitted across a network
- Even if it is stolen or intercepted the attacker cannot read it
- Used to protect data confidentiality

#### COMPONENT OF CRYPTOGRAPHY
- unencrypted data (plain text)
- Algorithm (Cipher)
- key
- Ciphertext (encrypted text)

#### CIPHERS
- aka algorithm
- a mathematical formula for scrambling data
- Block cipher
	- Data is encrypted in fixed-size blocks (typically 64 bits)
	- Plain text is converted into cipher text one block at a time
	- Often some output from one encrypted block is added to the encryption of the next block
	- Good for large amounts of data.
- Stream cipher
	- Data encrypted in a continuous stream
	- Uses XOR to encrypt data one bit, byte or character at a time
	- Typically faster than block ciphers
	- Requires fewer resources and less complex circuitary
	- Good for real-time communications

#### TYPES OF CRYPTOGRAPHY
- Symmetric encryption
	- uses the same key for both encryption and decryption
- Asymmetric encryption
	- Uses one key for encryption and a different key for decryption
- Hashing:
	- One way encryption
	- Fixed length output for any lenght input
	- no key
	- Meant for data integrity
	- Data is not encrypted
	- Hashed output accompanies the data for anyone to verify

#### EXCLUSIVE OR (xOR)
- A Boolean logic operation that is widely used in cryptography
- Used in generating parity bits for error checking and fault tolerance
- Also used by stream ciphers such a RC4 to encrypt a bytestream
- The output is True (or 1) if and only if the two inputs are different
- The output is False (or 0) if two inputs have the same value
- Example:
- 11001100 + 01101010 = 10100110 

> Polymorphic shellcode encrypts its code using XORing The shellcode is then later decrypted and executed


#### ONE TIME PAD
- An encryption technique that cannot be cracked
- Every message is encrypted with a different pre-shared key. Only the involved parties know the keys
- Ensures that there is no pattern in the key for an attacker to guess or find. Even if one message is decrypted , all other messages remain secure
- Requires two identical copies of the pad be produced and distributed securely before use.
- Was popular during World War II

> The 'One Time pad' is for encryption, using a different key for each message. while OTP 'One time Password' is time-limited and used to authenticate the user or device for a single session. It is typically sent to a user's mobile phone via sms

#### GOVERMENT ACCESS TO KEYS (GAK)
- GAK requires software companies to provides the government with enough copies of their keys that the remaining keys could be deciphered
- The government guarantees they will keep the key secure
- The government guarantees the key will only be used if there is a court-issued warrant
- Similar to the government's right to wiretap phones

### 20.2 SYMMETRIC ENCRYPTION
- The same key is used to encrypt and decrypt
- Used extensively to protect data at rest
- Provides confidentiality
- Excellent for bulk data encryption
- Is fast with good performance
- Less resource intensive than asymmetric encryption - easier or smaller device
- Uses the same key to encrypt and decrypt
	- Key is at risk
	- You must share the key in advance
	- If the key is compromised, all files are at risk of loss of confidentiality

#### BLOCK CIPHER SYSMMETRIC ALGORITHM
- Take a block of plaintext bots
- Generates a block of ciphertext bits. Generally the same size
- The size of block is fixed in the given scheme
- The choice of block size does not directly affect to the strength of encryption scheme
- The strength of cipher depends up on the key length

#### BLOCK CIPHER SYMMETRIC ALGORITHMS
- DES :
	- Archetypal block cipher
	- Transforms fixed-length blocks of plaintext into ciphertext bit strings of equal length
	- Inherently weak with current technology
- 3DES : 
	- DES process repeated 3 times to increase encryption strength
- AES : The current US government standard)
	- Symmetric-key algorithm designed to secure unclassified, sensitive US government document
	- iterated block cipher designed to keep doing the same operation repeadtly
	- Block size of 128 bits
	- AES key sizes
		- 128 for AES -128
		- 192 for AES 192
		- 256 AES AES 256
- Blowfish
	- 64 bit block cipher
	- 32- 448 key length
	- Faster than DES
- TwoFish
	- 128 bit block cipher
	- 128 -256 key length
- RC2, RC5, RC6 
	- 64 -128 bit block cipher
	- Each iteration has increase the key size
	- RC6 supports 2040 bit keys

#### STREAM CIPHER SYSMMETRIC ALGORITHM
- Processes as individual bit, byte or character of plaintext at a time. Do not device the data into discrete blocks
- At the transmitting end, XOR each bit of : Your plaintext continuous stream + a pseudo-random sequence
- At the receiving end, use the same symmetric key and XOR to decrypt 
- Often faster than block ciphers
- Also useful when transmission errors are likely to occur
- They have little or no error propogation

#RC4 
	Popular stream cipher
	USed in Wi-Fi WEP
	Key length 40-2048 bits
#PKZip
	file archieve / compression program that uses a steam cipher to encrypt files

#### DATA AT REST SCENARIO
You are regularly perform backups of your critical servers
You can't afford to send the backup tapes to an off-site vendor for long-term storage and archiving
Instead you store the backup tapes in a safe in your office
Security auditors tells you it's safer to store the backup tapes off-site
Your manager wants to take the tapes home in her briefcase every night
What can she do to secure those tapes while in transit??
==encrypt the backup tapes ==
==for good measures have her carry them in a lockbox and not just her briefcase

> Even though someone is physically carrying the storage media to another location, the data itself is not being across a network where it can be intercepted by a sniffer.



### 20.3 ASYMMETRIC ENCRYPTION
- Also known as public key Cryptography
- You have a pair of keys 
- Public key to encrypt
- Private key to decrypt
- Keys are mathematically related
- Excellent for protecting the symmetric encryption key
	- Asymmetric encryption is slow
	- Use symmetric encryption to encrypt the data
	- Then protect the symmetric encryption key with an asymmetric key pair
- Provides confidentiality and integrity
- You request (or create your own) public / private key pair
- You can freely give away your public key to anyone
- You must carefully guard the private key. never let anyone else have access to it.
##### working of key pair : 
 - Two keys that are mathematically related. Encrypts with public key . Decrypt with related private key.
 - Digitally sign with  the private kye. Verify with the public key

##### Asymmetric Encryption Example
Original text is encrypted using public key. the data is then decrypted into original text with Private key when required

##### ASYMMETRIC ALGORITHM
- #RSA: De factor internet encryption standard
	- Based on the practical difficulty of factoring the product of two large prime numbers . The factoring problem
- Diffie-hellmann
	- Used for exchanging asymmetric keys
	- Diffie-Hellman (DH) groups determine the strength of the key used in the key exchange process
- #ECC 
	- Based on the algebraic structure of elliptic curves over finite fields
	- Can achieve the same level of security provided while using a shorted key length
		- An ECC 256 = RS 3072
		- Good for Devices that have lower computing power
		- Smart cards
		- Mobile Devices
#### PROTOCOLS THAT USE ASYMMETRIC CRYPTOGRAPHY
- PGP / GPG
- SSL / TLS
- S / MIMEa
- SSH
- Internet key exchange (IKE) for IPSEC

### 20.4 PUBLIC KEY EXCHANGE
- Alice has an asymmetric key pair
- She can give BOB a copy of her public key
- Bob can then use her public key to send her an encrypted message. Alice will then use her private key to decrypt 
- Alice can also use her private key to digitally sign messages
- Bob can use her public key to verify the signature

#### DIFFIE-HELLMAN KEY EXCHANGE
- Protocol for automatically exchanging public keys
- The first widely used method of safely developing and exchanging key over an insecure channel
- Largely replaced by RSA , which has its own exchange algorithm and can digitally sign certificates
- Diffie-Hellman groups are used to determine the strength of the key used in the Diffie-Hellman key exchange process
	- Higher Diffie-Hellman Group numbers are more secures
	- But higher groups also require additional CPU Power
- Commonly used DH Groups:
	- DH Group 1 : 768 -bit group
	- DH Group 2 : 1024 -bit group
	- DH Group 5 : 1536 -bit group
	- DH Group 14 : 2028- bit group
	- DH Group 15 : 3072-bit group

#### PRETTY GOOD PRIVACY #PGP 
- System for creating asymmetric key pairs and trading public keys
- Provides authentication and cryptographic privacy
- Used for digital signing, data compression, and to encrypt / decrypt emails messages , files and directories
- You can search MIT's PGP public key server
	- Use information about the person such as their email address
	- If someone public key is found , you can download it and put it on your key ring
- PGP  was sold to Symantec in 2010
- Open source replacement GPG
##### PGP/GPG process Example:
	Raw file encrypted with public key and encrypted file trasported to email /ftp
	Private key than is decrypted with Private key and raw file is retrieved
	

#### SSH key Generation
- Tools such as  #PuTTY can create a key pair
- You can then use the generated public key to establish an SSH session
- Linux command`ssh-keygen -t rsa`
- files `id_rsa and id_rsa.pub` are generated in `.ssh `folder


### 20.5 PKI 
#### PUBLIC KEY INFRASTRUCTURE (PKI)
- PKI is an arrangement that binds public keys with respective identities of entities . Such as people organization devices services
- PKI is a set of roles, policies , hardware , software and procedures
	- used to create, manage, distribute, use store and revoke digital certification and manage public-key encryption
- Used to facilitates the secure electronic transfer of information for a range of network activities including : e-Commerce, internet banking, confidential emails
- PKI is required for activities where:
	- Simple passwords are an inadequate authentication method
	- More rigorous proof is required to confirm the identity of the parties involved in the communication
- The information being transferred need to be validated

#### PKI COMPONENTS
- Certificate Authority (CA)
	- AKA Certification Authority
	- A service that registers and issues certificates
	- May be automated or manual
- Registration authority
	- A role that may be delegated by a CA to assure valid and Correct registration
	- Responsible for accepting requests for digital certificates and authenticating the entity making the request
- Validation Authority
	- Validates the identity of an entity bearing a certificate
- Certificates
	- A document issue by the CA
	- Contains the issued public key
	- is Accompanied by a private key
#### DIGITAL CERTIFICATES
- A public key on a document
	- Includes some metadata about the key
- Issued to the user, device or service by a certification authority
- When initially issue to the user/ device the certificate is accompanied by an encrypted private key
- The user / device downloads the certificate
- When they install the certificate on their device, it installs both keys in the device's keystore
- App that need to use Asymmetric encryption can then obtain access to the keys

#### SELF -SIGNED CERTIFICATE
- User creates private and public keys using any available tool
- User self-sign document with public key
- Document delivered to receiver
- Public keys are traded
- A temporary symmetric session key is created
- The session key is protected by out public keys, which can only be decrypted by out private keys

#### CERTIFICATE AUTHORITY HIERARCHY
- A root CA is the highest authority
- IT issue certificates to digitally sign sub-ordinates CAs
- The sub-ordinates CAs issue certificates to user and clients
- Client : use CA-Certificate, key-generation, period of time, Revocation list (CRL) 
- There will be server certificate and key exchange, which will provide encrypted communication

#### POPULAR CERTIFICATION AUTHORITIES
#verisign #DigiCert #GoDaddy #Microsoft #COMODO #NortonSymantec #Thawte #Entrust 

#### KEY ESCROW
- A Specially component of PKI
- A copy of a private key is stored to provide third-party access and to facilitates recovery operations
- The private key is held in escrow, or stored by a third party
- A key that is lost or compromised by its original user(S) may be used to decrypt encrypted materials
- Allows restoration of the original material to its unencrypted state
- Keys held in escrow can also be divided into parts
	- Each part is stored by a different entity
	- All parts must be retrieved and put together to recreate the private key
	- This reduces the risk of fraud and collusion

 ### 20.6 DIGITAL SIGNATURES
 - Uses Asymmetric cryptography
 - Simulates security properties of a written signature in digital form
 - Created with the user's private key
 - Accompanies the file/ network packet / code
 - Proves the integrity and identity of the files/ network packets / code it signs


#### DIGITAL SIGNATURE CONSIDERATIONS
- You cannot move or copy a digital signature from one document to another
	- Each document / packet / file must have its own signature
	- The signature is a hash of the original document encrypted with the private key of the signing party
- The digital signature must be unforgeable and authentic
- You can be legally liable for documents that contain your digital signature
- Both the sender and receiver must have the ability to use the digital signatures
	- For example : DNSSEC is specification that allows DNS server to attach digital signatures to DNS records
	- In reality , since DNSSEC is an add-on capability , most Internet clients are not configured to use it.


### 20.7 HASHING
- Any function that can be used to map data of arbitrary size to data of fixed size
- Used to assure integrity of a file, packet or any other stored or transmitted data
- Creates a one-way encryption
- Does not require a key
- Does not modify the original file/data
- Produces a fixed -length output , regardless of the size of the input
- The values returned by a hash function are called hash values , hash codes, digests or simply hashes
- Any slight change to the input dramatically changes the output
- used to securely store passwords
> Computationally infeasible to decrypt , Resistant to Collisions, Two different inputs must not create the same output. 
> Collision attack is an attempt to find two input strings of a hash function that produce the same hash result.

#### POPULAR HASHING ALGORITHMS
- MD2 / MD4 / MD5 - 128 bit
	- ie. MD5 32 hex numbers = '5d41402abc4b2a76b9719d911017c592'
- Secure Hash Algorithm
	- SHA1
	- SHA2: it can be 
		- SHA 256 - 64 hex number
		- SHA-384 - 96 Hex number
		- SHA-512 - 128 Hex number 
	- SHA3 : The latest version of SHA, have same hash length as SHA2, Internal structure is significantly different, currently the strongest hashing algorithm
- RIPEMD : 160 bit - 40 hex numbers '108f07b8382412612c048d07d13f814118445acd'

#### MICROSOFT HASHING ALGORITHMS
- LAN MANAGER (LM)
- A weak implementation of DES
	- Password is restricted to a maximum of 14 characters
	- Converts passwords to uppercase
	- Any password less than 14 characters is "NullPadded" to bring it to 14 characters 
	- The 14 characters are then split into two 7 bytes halves
	- Each half is used to create a 56 - bit DES key
		- The DES keys are used to encrypt their respective half of the password
		- The two password halves are concatenate to a create a 14-byte LM hash
	- The Null padding is easy to identify, even when encrypted
	- Hashes are sent in clear text over the network
	- Still used for backward compatibility
- NT HASH
	- Unicode characters
	- 128 bit
	- Unsalted MD4

#### ROLE of HASHING IN CYBER FORENSICS
- The first thing that must eb done after acquiring a forensic disk image is to:
	- Create a hash digest of the source drive and destination image file
	- Ensure they are identical
- A critical step in the presentation of evidence will be to prove:
	- Analysis has been performed on an identical image to the data present on the physical media
	- Neither data set has been tampered with
- The standard means of proving this is to create a cryptographic hash (fingerprint) of the disk contents and any derivative images made from it
- When comparing hash values, you need to use the same algorithm used to create the reference value

#### PASS-THE HASH ATTACK
A hacking technique that allows an attacker to authenticate without the password
	The username and password are not entered normally at a login screen
	Instead, the password hash is provided over the network using a special app
Used when a password is too difficult to crack
Requires the attacker to obtain the password hash ahead of time
Hashes can be dumpted from memory using tools such as: #Minikatz, #psexec , #metasploitMeterpreter, #fdump, #pwdump, #cachedump, etc

### 20.8 COMMON CRYPTOGRAPHY USE CASES

#### PRIMARY USE CASES #CIA`
- Encryption : Protect confidentiality
- Hashing : Protect Integrity
- Digital Signatures : Authenticate , Protect Authenticity, Non-Repudiation


#### DISK ENCRYPTION TYPES
DISK encryption protects data at rest
- File system encryption : 	Encrypt file system points that tell the OS where it find a file
- File encryption: Specific files or folders are themselves encrypted
- Full disk encryption:
	- Secures all data stored on your hard drives
	- Includes swap files and hidden files
	- Does not require any user intervention
	- Does not protect data in transit: So data is unencrypted before it is copied to a USB stick , document attached to an email, or while transmitted over the network
- Popular Disk Encryption Products
	- #MicrosoftBitLocker #BroadComSymantectEndpointEncryption #AppleFileVault #CheckPointHarmonyEndpoint #ESETProtect #McAfeeCompleteDataProtection #TrendMicroEndPointEncryption #MicroFocusZenWorksFullDiskEncryption #RohdeAndSchwarzTrustedDisk #SophosCentralDeviceEncryption
- Scenario :
	- user travels lot, he worries that his laptop containing confidential documents might be stolen. what do you suggest to address his concern?
	- Answer: Use full disk encryption on his laptop to protect his data

#### EMAIL ENCRYPTION
- You can use an online secure email provider or your local email client
- Obtain or create a certificate (public key)
- Select the certificate in the email client. Alternatively , upload the certificate to the email provider
- In an enterprise environment, users certificates are distributed and managed by the email server and/ or directory service.
- SMTP does not encrypt by default
- STARTTLS is the SMTP command to transmit emails over TLS

### NETWORK COMMUNICATION ENCRYPTION
with SSH, SSL/TLS , OPENSSL

#### SECURE SHELL #SSH 
Layer 7 protocol for secure remote logins and data transfer
TCP 22
Replacement for telnet and Berkeley remote-utilities
Includes Secure -Copy (SCP) and Secure FTP (SFTP) for data transfer
Provides encrypted channel to be used for remote login , file transfer and command execution
Provides very strong user and host-to-host authentication
Provides secure communication over the internet


#### SECURE SOCKET LAYER #SSL 
- Layer 6 Protocol that establish a secure connection between a client and server
- Used to secure confidentiality and integrity of data transmissions over the internet
	- Particularly used by HTTPS to encrypt web traffic
	- Server proves its identity to the client
	- Server provides its public key to client
- Allows a client and server to:
	- Authenticate each other
	- Choose an encryption algorithm
	- Exchange public keys
	- Create a temporary session key
- Uses RSA asymmetric encryption
- Last version was SSL 3.0
- Has been replaced by TLS
- No longer considered secure
- Most Modern browsers no longer support SSL
- SSL Communication Process:
	- Client Hello to server
	- Server response to Client
	- Public key generation #sessionkey to server
	- Server acknowledgement to client
	- Connection Established
#### TRANSPORT LAER SECURITY #TLS
- The successor to SSL
- Fixes SSL security vulnerability 
- Uses stronger encryption algorithms
- Can work over different ports
- More standardized Can support emerging encryption algorithms
- Currently at version 1.3

#### OPENSSL 
- A general purpose cryptography library
- Open-source implementation of the SSL and TLS protocols
	- Performs encryption / decryptions
- Includes tools for generating
	- Generating RSA private keys
	- Certificate Signing Requests CSRs
	- Checksums
- Can manage certificates
- Widely used by internet servers and the majority of HTTPS websites

### VPN ENCRYPTION
WITH ipsec, l2TP ,PPTP SSL
#### #ipsec
- aKA ip Security
- The strongest of the VPN protocols
- Most widely used
- Works at layers 3 (IP only)
- Encrypts and authenticates data sent over a network
- Provides : Origin authenticity through source authentication
- Data integrity through hash functions
- Confidentiality through encryption
- Has two layer 3 protocols 
	- Authentication Header (AH)
		- Digitally signs IP Header to guarantee packet integrity
		- No Payload encryption
		- MD5 / HMAC , SHA + HMAC
		- Protocol ID 51
	- Encapsulating security Paylaod (ESP)
		- Encrypts the payload using DES, 3DES or AES
		- Also adds digitally signed UDP header to the payload to guarantee payload integrity
		- Protocol ID 50
	- You can use either or both protocols
- Includes a key exchange protocol
	- ISAKMP: Used to secure the IPSEC key exchange process
	- UDP 500
> HMAC includes the private key in the message digest to prove identity

##### IPSEC MODES
- Transport mode
	- End-to-End encryption
	- VPN created between hosts
	- Good for:
		- Protecting clear text protocols
		- Client-server connections across the Internet
		- Server-Server connections in the LAN , DMZ or between the DMZ and LAN
- Tunnel Mode
	- Gateway-gateway encryption
		- Routers / Firewalls
	- The entire original IP Packet is protected by IPSec
	- IPSec Wraps the original packet , encrypts it , adds a new IP header and sends it to the other side of the VPN tunnel (IPSec peer)
	- Hosts have no knowledge that their traffic is being sent through the tunnel
	- Good for connecting sites across the Internet


##### IPSEC AH Transport and Tunnel Modes
AH digital signature Only  -- no encryption
- Original IP Packet  has ; IP Header + TCP Header + Data
- AH Transport Mode : IP Header + AH Header + TCP Header + Data
- AH Tunnel Mode : New IP Header + AH Header + IP Header + TCP Header + Data

#### IPSEC ESP TRANSPORT AND TUNNEL MODES
Encryption and digital signatures
- Transport Mode 
	IP header + UDP Header + Authenticated  + ESP Auth data
		Authenticated : ESP Header + Encrypted
		Encrypted  =  IP Payload + ESP Trailer

- Tunnel mode
	- New IP  header + UDP header + Authenticated + ESP Auth data
		- Authenticated : ESP header +Encrypted 
		- Encrypted = Original IP Header + IP Payload + ESP Trailer

#### l2TP
- Layer 2 Tunneling protocol
- Encapsulates but does not encrypt
- Can carry any payload : IP , IPX , NetBEUI
- Depends on IPSec ESP for IP encryption 
	- IPSEC over L2TP
	- UDP 500 (IKE)
- Can encapsulate but not encrypt other protocols

Exampled:
Original Frame: Ethernet Header + IP Header + TCP Segment + Data

Original Frame now tunnel payload + `New headers for L2TP tunnel` + `New headers for IPSec tunnel`
	- ==`New Header for L2TP tunnel`== = Ethernet header + IP header + UDP Header + LT2TP Header
	- New header for IPSec tunnel = Ethernet Header + IP header +` IPSec Tunnel Header` 

#### PPTP
- Point-to-point Tunneling protocol
- TCP port 1723
- Protocol ID 47 (GRE)
- Combination of Generic Routing Encapsulation (GRE) and PPP
- Can carry various payloads (IP, IPX, NetBEUI)
- Weak encryption
- No digital signatures
- Very easy to implement
Example:
	Data Link Header + IP Header + GRE Header + [PPP FRAME] + Data link Trailer
	[PPP Frame] : PPP Header + PPP Payload (IP Datagram, IPX Datagram, NetBEUI frame)

#### SSL VPN
Not a traditional VPN. No tunneling / encapsulation
Uses SSL / TLS to encrypt the payload only
Firewall friendly
Requires an SSL VPN Gateway to terminate the tunnel (Decrypt)
Example:
	Remote user with any browser Via SSL/TLS Tunneled connect to Server via [Firewall]  [SSL VPN Gateway ]

### 20.9 CRYPTOGRAPHY TOOLS
#### CRYPTOGRAPHY TOOLS
#AutoKrypt #CryptainerLE-FreeEncryption-Software #SteganosLockNote #AxCrypt #CryptoForge #NcryptXL #ccrypt #WinAES #EncryptOnClick #GNUPrivacyGuard ( #GPG)

#### CRYPTOGRAPHY TOOLKIT
A command line tool to use various OpenSSL cryptography functions 
Uses SSL v2 / v3 and TLS v1
Key features:
	Key rotation and versioning
	Safe default algorithms, key lengths, and modes
	Automated generation of ciphertext signatures and initialization vectors
	Python, Java, and C++ implementations
	Java international support
#### CRYPTOGRAPHY TOOLS FOR MOBILE
#SecretSpaceEncryptor #CryptoSymm #CipherSender 


#### HASHING TOOL EXAMPLES
#MicrosoftHASHtool #md5256Sum #CRCCalculator #SHACalculator #MD2Calculator #MD4Calculator #md5Calculator #MD6HashGenerator #Adler-32Calculator #RIPEMDCalculator #WhirlpoolCalculator #NTLMCalculator #CrackStation #HashCalc #MD5Calculator #HashMyFiles #MD5HashCalculator #HashDroid #HashCalculator 

### 20.10 CRYPTOGRAPHY ATTACKS
#### CODE BREAKING METHODOLOGIES
- Trickery and Deceit : social engineering
- Brute Force : Tre combinations until you crack it
- Frequency Analysis : Look for repeat Patterns
- Frequency Analysis : Look for repeat patterns
- Meet-in-the-Middle : Examine encrypted and unencrypted text to figure out the key
- Side Channel : Examine emissions from electronic circuitry to determine corresponding algorithm activity


#### COMPUTATIONAL RESOURCES
- Attacks can be characterized by the resources they require
- Time: The number of computation steps : (eg: test encryptions) that must be performed
- Memory : The amount of storage required to perform the attack
- Data : The quantity and type of plaintexts and ciphertext required for an approach

#### HIGH-PERFORMANCE COMPUTING (HPC)
One of the most essential tools in cryptanalysis
Leverages GPU-powered parallel processing across multiple compute nodes
	A graphical processing Unit (GPU) is a built-in CPU on a video card
	The GPU offloads computationally-intensive tasks such as video rendering from the CPU 
	It can also be used in cryptanalysis
You  can also use the cloud to provide extensive compute resources 
You can even distribute your cracking across a bot army

#### HASH COLLIIONS ATTACK
- An attempt to find two input strings of a hash function that produce the same hash result
- Because has functions have infinite input length and pre-defined output length
- There is inevitable going to be the possibility of two different inputs that produce the same output hash
- A strong hashing algorithm is resistant to collisions


#### HEARTBLEED

#### CRYPTOANALYSIS COUNTERMEASURES
- A severe memory handling bug
- Affects OpenSSL version 1.0.1 through 1.0.1f
- Exists in the implementation of the TLS Heartbeat extension
	- Heartbeats are used to keep the TLS session alive
- Could be used to reveal up to 64 KB of the Application's memory with every heatbeat
- By reading the memory of the web server , attackers could access sensitive data including the server's private key
- CVE-2014-0160

#### #POODLE 
- A webserver security vulnerability 
- Takes advantages of SSL fallback
	- CVE-2014-3566
	- The attacker tricks the server and client into downgrading the connection
	- From TLS 1.2 to the less secure SSL 3.0
- ##### POODLE ATTACK STAGES
- The attacker inserts themselves as man-in-the-middle between client and server
- The attacker falsely drops connections, tricking the server into assuming that the client does not support TLS 1.2
- As the client and the server communicate using SSL 3.0 the attacker can use the confidential information, to make sure that the POODLE attack succeeds, the attacker uses social engineering to trick the user into running a Java Script in their browser


#### CRYPTANALYSIS TECHNIQUES
- Ciphertext only : 
	- The CRYPTANALYSIS has access only to a collection of ciphertext or code texts:
- known plaintext attack:
	- The analysst may have access to some of all the plaintext of the ciphertext
	- The Goal is to discover the key used to encrypt the message and decrypt the message 
	- Once the key is identified, an attacker can decode all messages that had been encrypted by utilizing that key
- Chosen plaintext attack
	- The analyst either knows the encryption algorithm or has access to the device used to do the encryption
	- The Analyst can encrypt the 'chosen plaintext' with the targeted algorithm to obtain data about the key
- Adaptive chosen Plaintext
	- Like a chosen-plaintext attack, except the attacker can choose subsequent plaintexts based on information learned from previous encryptions
- Related-key attack
	- Like a chosen-plaintext attack
	- Except the attacker can obtain ciphertext encrypted under too different keys
	- The keys are unknown but the relationship between them is known.
	- Example : Two key differ by one bit
- Man-In-The-Middle attack
	- The attacker finds a way to insert themselves into the communication channel between two parties who wish to exchange public keys
	- The attacker then performs a key exchange with each party
		- The original parties believes they are exchanging keys with each other
		- The two parties end up utilizing keys that are familiar to the attacker
- Integral Cryptanalysis Attack
	- Uses sets of plaintexts
	- Part of the painetext is kept constant
	- The rest of the plaintext is modified
	- This attack can be especially useful when applied to block ciphers that are based on substitution-permutation networks

#### MEET-IN-THE-MIDDLE ATTACK
- A type of known plaintext attack
- Uses two known assets:
	- a plaintext block
	- an associated ciphertext block
- The attacker uses both assets to decipher the key
- The attack involves working from either end of the encryption chain toward the middle
	- As opposed to tying brute-force permutations from one end of the encryption process to the other.
- Common Attack against Data Encryption Standard (DES)
	- Can break ciphers that use two or more keys for multiple encryption using the same algorithm (2DES, 3DES)
- Example: 
	- Compute and store mappings (Expected calculation)
	- Compute decryption (Actual Encryption)
	- Compare from both directions: 

#### SIDE-CHANNEL ATTACK
Electronic circuitry always 'leaks' various forms of radiant energy as it processes signals and executes commands
A Side-channel attack takes advantages of observable external changes (side-channel properties in the circuitry during ) processing
	Heat generated , power consume execution time
	These changes happen at different times during algorithm execution
If an attacker can run their own code on the encryption / decryption hardware
	They can more quickly figure out what the different physical changes indicate

#### CRYPTANALYSIS TOOL EXAMPLES
- #CrypTool : 
	- An open-source protects that produces e-learning programs and a web portal for learning about cryptanalysis and cryptographic algorithms
- #Cryptol 
	- Analyzes algorithms and implementations
	- initially designed for the NSA
	- is also widely used by private firms
- #EverCrack 
	- A GPL open-source software that mainly deals with monoalphabetic substitution and transposition ciphers
	- Its cryptanalysis engine supports multiple language
- #Ganzua
	- An open-source cryptanalysis tool used for classical poly-alphabetic and mono-alphabetic ciphers.
	- Lets users outline nearly complete arbitrary cipher and plain alphabets

> Cryptanalysis is the process of deciphering encrypted message without being told the key
	
#### PASSWORD CRACKING TOOL
- John-the-Ripper
	- Supports hundreds of hash and cipher types
	- Can use large words lists
- Hashcat Performs dictionary and brute force password attacks
- Utilizes both a computer's GPU as well as CPU for high performance 
- Rainbow Tables
	- Specialized dictionary list
	- Pre-computed hashes
- There are various online password cracking services your can use
- You can also try social engineering to trick the user into divulging their password

#### RUBBER HOSE ATTACK
Extraction of cryptographic secrets from a person by coercion or torture


#### CRYPTANLAYSIS COUNTERMEASURES
- There are a number of strategies that you can employ to protect your cryptosystem
	- Choose stronger cryptographic algorithms where practical
	- Use longer keys or key stretching to counter a brute force attack
	- Carefully protect private keys
		- Encrypt the keys and store locally
		- Do not store in the cloud
		- Neven hard-code a cryptographic key in an application
	- If the computer system has limited resources, consider using algorithms that provide comparable protection while using less computer power
		- e.g. Elliptic curve cryptography #ECC over RSA
	- Ensure application developers use well-vetted crypto frameworks
	- Do not attempt to "roll your own" encryption in application development
	- Use bug bounties and public challenges to help vet your algorithm
		- Having thousands of security researches enthusiastically trying to break your cryptosystem will reveal its weaknesses more quickly than any other methods
		- A publicly known algorithm that no one have been able to crack is likely to be stronger than a secret algorithm that has been minimally tested
	- Use compensating controls to reduce the risk of side-channel attacks
		- Example : use Tempest Shielding prevent electrical emanations from being intercepted
	- ##
#### 20.11 CRYPTOGRAPHY REVIEW
- Encryption happens at OSI layer 6 (Presentation layer)
- Data has three possible states: at rest (stored don storage media) in transit (being transmitted across a network), in use (in RAM)
- Cryptography is the conversion of the data into jumbled code to keep it safe
- Cryptography components are :
	- Plain text + key + Cipher (algorithm) = ciphertext
- Plain text is a generic term often used to describe any unencrypted data
- A key is anything that can be reduced to a number 
	- Also called a secret
	- The longer the key, the stronger the encryption
	- A key can be made longer by adding a salt or initialization Vector to it
- A Cipher is a mathematical formula that uses the key to encrypt the data
- Ciphertext is data that has been encrypted
- Symmetric encryption uses same key for encryption and decryption
	- It must be known to both parties and agreed upon in advance
	- If it becomes compromised , everything encrypted with it is also considered to be compromised 
- Symmetric algorithms includes DES ,3DES , AES
	- DES and 3DES are no longer considered secure
	- AES is the current standard
- Symmetric encryption has relatively good performance and is used to encrypt larger amount of data
- A block cipher divides the data into chunks
	- Encrypts each chunk one at a time
	- It is well suited for encryption larger amount of data
- A stream cipher uses a key that is being continuously, randomly generated
	- it xOR's the key bits against the data bits, producing a stream of encrypted bits
	- It is well suited to encrypt Realtime data such as Realtime voice/ video or network (Wi-Fi) transmissions
- Asymmetric encryption uses a public /private key pair to encrypt  /decrypt
	- The two keys are mathematically related
	- You freely give away the public key
	- You carefully guard the private key from unauthorized disclosure
- In asymmetric encryption, you encrypt with one key (Typically the public key)
	- Then decrypt with the other (typically the private key)
- In order to send someone data that only they can read, you must use THEIR public key to encrypt it. They will then use their private key to decrypt the data
- Diffie-Hellmann or RSA are two popular key exchange algorithms used to securely trade public keys across the network
- The most popular asymmetric algorithms in use today is RSA
	- it is based on large factor (prime numbers)
- ECC is another popular asymmetric algorithm
	- It is based on the algebraic structure of elliptic curves over finite fields
	- It provides the same level of protection as RSA while consuming considerably fewer resources 
	- It is preferred choice for small devices such as smart cards and mobile / wireless device
- Because RSA encryption is computationally expensive , a client and server will trade public keys
	- They will then use those keys to jointly create a temporary symmetric session key
	- Even if the transmission is intercepted , without one of the private keys an attacker cannot decrypt the message
- A certificate is a public key on a document. It is accompanied by a protected private key
- You can use your private key to digitally sign data
	- This proves authenticity
	- Others can verify the signature by using the public key from your certificate
	- You can be legally held liable if others use your private key to impersonate you
- You can generate your own public / private key pairs or certificates 
- Public key Infrastructure uses well -known certificate authorities (CA) to issue certificates to the general public
- These certificates are trusted by everyone because operating systems ship with certificates from the well-known Root CAs
- Thus the chain of authenticity can be proven all the way up to the issuing CA
- Hashing creates a fixed -length output from a variable input
	- It proves data integrity
	- In general, hashing does not use a key in the hashing process
	- A hash is computations infeasible to decrypt
	- User passwords are typically stored as hashes in a operating system file
- Hashing algorithms should be resistant to collisions. A collision is where two different inputs produce the same output
- Popular hashing algorithms includes MDS, SHA1, SHA256, LM, NTLM
- HMAC is another hashing algorithm that add the user's private key to the data before it is hashed. this proves both authenticity and integrity
- There are many practical uses for cryptography in data storage network transmission, e-Commerce, VPNs , email , etc.
- There are many ways to try to break encryption
- If you cannot break the encryption, try social engineering or co-ercion

- 
- 
- 
	- 










