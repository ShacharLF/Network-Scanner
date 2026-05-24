from scapy.all import *
import random
import socket
from scapy.layers.inet import TCP, IP

ip_to_check = input("Give an IP of a server you want to check ports on..").strip()


port_list = []
print("Give all the port numbers you wanna check, to stop insert press !..")

while True:
    user_input = input("Port: ")
    if user_input == "!":
        break

    if user_input.isdigit():
        port_list.append(int(user_input))
    else:
        print("Invalid input, Enter a number or '!' to stop.")


def banner_grabber(ip, port):
    grabber_socket = socket.socket()
    grabber_socket.settimeout(2)
    grabber_socket.connect((ip, port))

    banner = grabber_socket.recv(1024).decode(errors="ignore")
    grabber_socket.close()

    if banner:
        print("The banner that points on which server is open on this port is:", banner)
        vuln_scan(banner)
        return banner.strip()
    else:
        return "No banner received so cannot identify which service is running on this open port"


def manual_banner_grabber(ip, port):
    HTTP_PAYLOAD = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

    SMB_PAYLOAD = (b"\x00\x00\x00\x85"
                   b"\xff\x53\x4d\x42"
                   b"\x72\x00\x00\x00"
                   b"\x18\x53\xc8\x00"
                   b"\x00\x00\x00\x00\x00\x00"
                   b"\x00\x00"
                   b"\x00\x00"
                   b"\x00\x00"
                   b"\x00\x00"
                   b"\x00\x00"
                   b"\x00"
                   b"\x02"
                   b"\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00")

    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))

        if port in (80, 8080, 8000):
            s.send(HTTP_PAYLOAD)
            banner = s.recv(4096)
            s.close()

            if banner:
                return banner.decode(errors="ignore")
            else:
                return "No response"

        elif port == 445:
            s.send(SMB_PAYLOAD)
            banner = s.recv(4096)
            s.close()

            # לא מפעילים vuln_scan כאן — רק מחזירים בנר
            return banner

        return "Unsupported port"

    except Exception as e:
        return f"Error: {e}"


def vuln_scan(banner):
    vuln_db = {
        "HTTP": [
            {
                "product": "Apache/2.4.49",
                "cve": "CVE-2021-41773",
                "description": "Path traversal vulnerability."
            }
        ],

        "SMB": [
            {
                "product": "Windows 7 SMBv1",
                "cve": "CVE-2017-0144",
                "description": "EternalBlue (remote code execution)."
            }
        ],

        "FTP": [
            {
                "product": "ProFTPD 1.3.5",
                "cve": "CVE-2015-3306",
                "description": "RCE, allows manipulating multiple files on server."
            }
        ],

        "SSH": [
            {
                "product": "OpenSSH_7.7",
                "cve": "CVE-2018-15473",
                "description": "User enumeration vulnerability."
            }
        ]
    }

    # HTTP
    if "Apache/2.4.49" in banner:
        print("Alert: exposed to:", vuln_db["HTTP"][0]["cve"],
              vuln_db["HTTP"][0]["description"],
              "Because:", vuln_db["HTTP"][0]["product"])

    # SMB (זיהוי לפי זה שהפונקציה הראשית תעביר לנו banner מסוג bytes)
    elif isinstance(banner, bytes):
        print("Alert: exposed to:", vuln_db["SMB"][0]["cve"],
              vuln_db["SMB"][0]["description"],
              "Because service is:", vuln_db["SMB"][0]["product"])

    # FTP
    elif "ProFTPD 1.3.5" in banner:
        print("Alert: exposed to:", vuln_db["FTP"][0]["cve"],
              vuln_db["FTP"][0]["description"],
              "Because:", vuln_db["FTP"][0]["product"])

    # SSH
    elif "OpenSSH_7.7" in banner:
        print("Alert: exposed to:", vuln_db["SSH"][0]["cve"],
              vuln_db["SSH"][0]["description"],
              "Because:", vuln_db["SSH"][0]["product"])

    else:
        print("Scanner found no known CVEs for this banner.")


def port_scan(ip, ports):
    for port in ports:

        syn_pkt = IP(dst=ip) / TCP(dport=port, flags="S", seq=random.randint(0, 2**32 - 1))
        resp = sr1(syn_pkt, timeout=2, verbose=0)

        if resp is None:
            print(f"Port {port}: no response")
            continue

        if resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags

            if flags == 18:
                print("port", port, "is open on the server", ip)

                if port in (80, 8080, 8000, 445):
                    banner = manual_banner_grabber(ip, port)
                else:
                    banner = banner_grabber(ip, port)

                print("This banner:", banner)
                vuln_scan(banner)

            elif flags == 4:
                print("port", port, "is closed on the server", ip)

            else:
                print("unexpected TCP flags was received", flags)

        else:
            print(f"Port {port}: received non-TCP response")


port_scan(ip_to_check, port_list)
