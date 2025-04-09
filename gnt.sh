#!/bin/bash

# Function to check and install GNS3 if not installed
function install_gns3() {
    if ! command -v gns3server &> /dev/null; then
        echo "GNS3 is not installed. Installing GNS3..."
        sudo apt-get update
        sudo apt-get install -y gns3-server gns3-gui
        echo "GNS3 installed successfully."
    else
        echo "GNS3 is already installed."
    fi
}

# Function to check if GNS3 server is running, and start it if not
function start_gns3() {
    if ! pgrep -x "gns3server" > /dev/null; then
        echo "GNS3 server is not running. Starting GNS3..."
        nohup gns3server > /dev/null 2>&1 &
        echo "GNS3 server started successfully."
    else
        echo "GNS3 server is already running."
    fi
}

# Function to check and configure UFW
function ufwd() {
    if ! command -v ufw &> /dev/null; then
        echo "UFW is not installed. Installing..."
        sudo apt-get update
        sudo apt-get install -y ufw
        echo "UFW installed successfully."
    fi

    # Enable UFW
    sudo ufw enable

    # Check rules on major ports
    major_ports=("22" "80" "443" "8080")  # Add or remove ports as needed

    echo "Checking UFW rules on major ports:"
    for port in "${major_ports[@]}"; do
        sudo ufw status | grep -q "$port"
        if [ $? -eq 0 ]; then
            echo "Port $port: Allowed"
        else
            echo "Port $port: Denied"
        fi
    done
}

# Function to simulate a DNS attack using GNS3 API
function gns3_dns_attack_simulation() {
    # Make sure GNS3 is running
    if ! pgrep -x "gns3server" > /dev/null; then
        echo "GNS3 server is not running. Please start GNS3."
        exit 1
    fi

    # Assuming GNS3 API is running on localhost:3080 (default port)
    GNS3_API="http://localhost:3080/v2"
    PROJECT_ID="your_project_id_here"

    echo "Simulating DNS attack on GNS3..."

    # Fetch the GNS3 project details
    curl -s "$GNS3_API/projects/$PROJECT_ID" | jq .

    # Add DNS attack simulation (example: running a DNS server attack tool like dnsmasq on a simulated node)
    # Modify with real DNS attack simulation logic depending on your network topology
    echo "Simulating DNS attack within GNS3 network topology..."
    curl -s -X POST "$GNS3_API/projects/$PROJECT_ID/commands" -d '{
        "command": "run_dns_attack",
        "args": {"attack_type": "amplification", "target_ip": "192.168.0.100"}
    }' | jq .

    # Log the results of the attack simulation
    echo "DNS attack simulation completed. Please check your GNS3 topology for further analysis."
}

# Function to print mitigation strategies for DNS attacks
function mitigate_dns_attack() {
    echo "====================================="
    echo "    Mitigating DNS Attack"
    echo "====================================="
    
    echo "[1] Use DNS Filtering"
    echo "    - Implement DNS filtering solutions like Pi-hole to block malicious DNS traffic."
    echo ""

    echo "[2] Rate Limiting DNS Queries"
    echo "    - Configure your DNS server to limit the number of queries from a single IP."
    echo "    - Example: Set 'rate-limit' on DNS server configuration."
    echo ""

    echo "[3] Enable DNSSEC"
    echo "    - Enable DNSSEC (DNS Security Extensions) to prevent DNS spoofing and man-in-the-middle attacks."
    echo "    - Example: Add DNSSEC keys to your DNS provider configuration."
    echo ""

    echo "[4] Use Anycast DNS"
    echo "    - Distribute DNS traffic across multiple data centers to mitigate DDoS attacks."
    echo "    - Example: Use services like Cloudflare or AWS Route 53."
    echo ""

    echo "[5] Monitor DNS Logs for Suspicious Activity"
    echo "    - Use tools like 'dnstop' or 'tcpdump' to analyze DNS traffic for anomalies."
    echo ""

    echo "[6] Block DNS Amplification Attacks"
    echo "    - Example: Configure rate-limiting on DNS servers and block DNS responses to spoofed requests."
    echo ""

    echo "[7] Use Firewalls to Block Malicious Traffic"
    echo "    - Example: Use UFW or iptables to restrict inbound and outbound DNS traffic."
    echo ""

    echo "====================================="
    echo "    END OF DNS MITIGATION STRATEGIES"
    echo "====================================="
}

# Function to execute the full report
function network_report() {
    echo "====================================="
    echo "     NETWORK STATUS REPORT"
    echo "====================================="
    echo ""

    # Your existing network status and analysis functions
    # Skipping for brevity; assume the previous network_report is included here.
}

# Function to run DNS attack mitigation and GNS3 analysis
function DNS_attack_analysis() {
    echo -e "\e[31mSimulating and mitigating DNS attacks...\e[0m"
    gns3_dns_attack_simulation

    echo -e "\e[31mMitigation strategies for DNS attacks:\e[0m"
    mitigate_dns_attack
}

# Execute the full setup and checks
install_gns3    # Install GNS3 if necessary
start_gns3      # Start GNS3 server if it's not running
network_report  # Run network status report
DNS_attack_analysis  # Run DNS attack analysis and mitigation
