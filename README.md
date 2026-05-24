# Python Network Scanner

A basic Python-based network scanner that performs:

- SYN Port Scanning
- Banner Grabbing
- Manual Banner Grabbing for HTTP and SMB
- Basic Vulnerability Detection using known CVEs

This project was built for learning purposes using Python, Scapy, and sockets.

---

# Features

## Port Scanning
The scanner uses a TCP SYN Scan technique to detect open ports.

It sends TCP SYN packets and analyzes the server response:

- SYN/ACK → Port is OPEN
- RST → Port is CLOSED
- No response → Filtered / Firewalled / No response

Implemented using:

- Scapy
- Raw TCP packets

---

# Banner Grabbing

The tool attempts to identify services running on open ports.

## Automatic Banner Grabbing
For services that automatically expose banners such as:

- FTP
- SSH
- SMTP
- Telnet

The scanner connects using sockets and waits for the service banner.

---

## Manual Banner Grabbing

Some protocols do not automatically return banners.

The scanner manually sends protocol-specific payloads for:

### HTTP
Sends:

GET / HTTP/1.1
Host: example.com

### SMB
Sends a basic SMB negotiate request packet.

---

# Vulnerability Detection

The scanner performs basic vulnerability matching based on service banners.

It compares detected service versions against a small local vulnerability database containing:

- Product version
- CVE ID
- Vulnerability description

Currently supported:

| Protocol | Vulnerability |
|---|---|
| HTTP | CVE-2021-41773 |
| SMB | CVE-2017-0144 (EternalBlue) |
| FTP | CVE-2015-3306 |
| SSH | CVE-2018-15473 |

---

# Technologies Used

- Python 3
- Scapy
- Socket Programming

---

# Installation

Install Scapy:

pip install scapy

Run the script with administrator/root privileges.

Windows:
python port_scanner_and_grabber.py

Linux:
sudo python3 port_scanner_and_grabber.py

---

# Example Usage

Give an IP of a server you want to check ports on..
90.130.70.73

Port: 21
Port: !

Example output:

Port 21 is open on the server 90.130.70.73
Banner: 220 ProFTPD 1.3.5 Server ready.
Alert: exposed to CVE-2015-3306

---

# Project Structure

port_scanner_and_grabber.py
README.md

---

# Educational Purpose

This project was created for educational and research purposes only.

Do not scan systems without authorization.

---

# Future Improvements

Possible future upgrades:

- Multi-threaded scanning
- OS fingerprinting
- Service fingerprint database
- JSON export
- GUI dashboard
- Nmap-style reporting
- TLS/HTTPS support
- UDP scanning

---

# Author

Created by Shachar Levi
