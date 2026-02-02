import socket
from urllib.parse import urlparse

def scan_url_ports(url, start_port=1, end_port=1024):
    print("\n[ FalconX ] URL-Based Port Scan Started")

    # Step 1: Parse URL
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or url
    print(f"[+] Hostname extracted: {hostname}")

    # Step 2: Resolve IP
    try:
        resolved_ip = socket.gethostbyname(hostname)
        print(f"[+] Resolved IP Address: {resolved_ip}")
    except socket.gaierror:
        print("[-] Failed to resolve hostname")
        return

    # Step 3: Scan Ports
    print(f"[+] Scanning ports {start_port}-{end_port} ...")
    open_ports = []

    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((resolved_ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except:
            continue

    # Step 4: Risk Evaluation
    if not open_ports:
        risk = "LOW"
        indication = "No exposed ports detected"
    elif len(open_ports) <= 3:
        risk = "MEDIUM"
        indication = "Limited service exposure detected"
    else:
        risk = "HIGH"
        indication = "Multiple exposed services increase attack surface"

    # Step 5: Output Results
    print("\n========== FalconX Scan Result ==========")
    print(f"Target URL       : {url}")
    print(f"Hostname         : {hostname}")
    print(f"Resolved IP      : {resolved_ip}")
    print(f"Scan Range       : {start_port}-{end_port}")
    print(f"Open Ports       : {open_ports if open_ports else 'None'}")
    print(f"Risk Level       : {risk}")
    print(f"Security Insight : {indication}")
    print("----------------------------------------")
    print("Framework Mapping:")
    print("- OWASP A05 : Security Misconfiguration")
    print("- CIS Control 4 : Secure Configuration")
    print("- MITRE ATT&CK TA0007 : Discovery")
    print("----------------------------------------")
    print("Recommendation:")
    print("Close unused ports, restrict access via firewall,")
    print("and expose only required services.")
    print("========================================")


# Program Entry Point

if __name__ == "__main__":
    print("===== FalconX Security Scanner =====")
    target_url = input("Enter target URL: ").strip()

    start_port = int(input("Enter start port (default - 1): ") or 1)
    end_port = int(input("Enter end port (default - 1024): ") or 1024)

    scan_url_ports(target_url, start_port, end_port)

