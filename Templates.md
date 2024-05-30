**Syntax**
	command : nmap -sX -v Target-IP
**Request**: Probe Packet with (FIN + URG + PSH)
**Response**: If no response than Port is Open, Else RST package is responded by target for closed port
**Advantage**:
- Avoids many IDS and the TCP Three-way handshakes
**Dis-Advantage**: