import nmap

# Create an Nmap object
nm = nmap.PortScanner()

# Define the target IP address and port range
target_ip = input("Enter the target ip address: ")
port_range = input("Enter the port(s) to scan: ")

# Perform a vulnerability scan using Nmap's vuln scripts
nm.scan(target_ip, port_range, arguments="-sT -sV ")

# Print the vulnerability scan results
for host in nm.all_hosts():
    for port in nm[host].all_tcp():
        if nm[host]["tcp"][port]["state"] == "open":
            service_name = nm[host]["tcp"][port]["name"]
            print(f"Service: {service_name} on port {port} is running")

            # Check for vulnerabilities
            if "script" in nm[host]["tcp"][port]:
                for script in nm[host]["tcp"][port]["script"]:
                    if script["id"] == "vuln":
                        print(f"Vulnerability: {script['output']}")
