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

# Function to check system health and logs
function checks() {
    echo "====================================="
    echo "     SERVER HEALTH CHECK"
    echo "====================================="
    echo "Uptime:"  
    uptime  
    echo "Currently connected users:"  
    w  
    echo "--------------------"  
    echo "Last logins:"  
    last -a | head -3  
    echo "--------------------"  
    echo "Disk and memory usage:"  
    df -h | xargs | awk '{print "Free/total disk: " $11 " / " $9}'  
    free -m | xargs | awk '{print "Free/total memory: " $17 " / " $8 " MB"}'  
    echo "--------------------"  
    start_log=$(head -1 /var/log/messages | cut -c 1-12)  
    oom=$(grep -ci kill /var/log/messages)  
    echo "OOM errors since $start_log : $oom"
    echo "--------------------"  
    echo "Utilization and most expensive processes:"  
    top -b | head -3  
    echo  
    top -b | head -10 | tail -4  
}

# Function to use tcpdump for network packet capture
function TcDump() {
    interface="eth0" 
    duration=60 
    threshold=100 

    analyze_packets() { 
        packet_count=$(tcpdump -c $threshold -i $interface 2>/dev/null | wc -l) 
        echo "Captured $packet_count packets in $duration seconds." 

        if [ $packet_count -ge $threshold ]; then 
            echo "Potential DoS attack detected!" 
        else 
            echo "No signs of a DoS attack." 
        fi 
    } 

    if ! command -v tcpdump &> /dev/null; then 
        echo "tcpdump is not installed. Please install it before running this script." 
        exit 1 
    fi 

    echo "Capturing network packets on $interface for $duration seconds..." 
    tcpdump -i $interface -c $threshold -w captured_packets.pcap & 

    sleep $duration 

    pkill tcpdump 

    analyze_packets
}

# Function to use Wireshark (tshark) for network analysis
function Wire() { 
    if ! command -v tshark &> /dev/null; then 
        echo "Wireshark is not installed. Please install Wireshark and run the script again." 
        exit 1 
    fi 
    echo "Capturing network traffic for analysis..." 
    tshark -i any -f "port 80" -w capture.pcap -a duration:60  

    echo "Analyzing captured traffic for potential DoS attack..." 
    tshark -r capture.pcap 

    rm -f capture.pcap 
}

# Function to execute DoS security checks
function CDos() { 
    echo -e "\e[31mUsing UFW to assess major ports for Rules Set\e[0m" 
    ufwd 

    echo -e "\e[31mRunning Server Health Checks\e[0m" 
    checks 

    echo -e "\e[31mUsing TcpDump Now...\e[0m" 
    TcDump 

    echo -e "\e[31mUsing Wireshark now...\e[0m" 
    Wire 
}

# Function to display network report
function network_report() {
    echo "====================================="
    echo "     NETWORK STATUS REPORT"
    echo "====================================="
    echo ""

    # Get public IP
    echo "[+] Public IP Address:"
    curl -s https://ifconfig.me
    echo -e "\n"

    # Get local IP address
    echo "[+] Local Network Information:"
    ip -br addr show | grep "UP" | awk '{print $1, $3}'
    echo ""

    # Show active network interfaces
    echo "[+] Active Network Interfaces:"
    ip link show | grep -E "^[0-9]+: " | awk '{print $2}' | tr -d ':'
    echo ""

    # Display listening ports
    echo "[+] Open Ports and Listening Services:"
    sudo netstat -tulnp | grep LISTEN
    echo ""

    # Display active network connections
    echo "[+] Active Network Connections:"
    sudo netstat -antp | grep ESTABLISHED
    echo ""

    # Show network traffic statistics
    echo "[+] Network Traffic Statistics:"
    ip -s link | awk '/^[0-9]+:/{print $2} /RX:|TX:/{print}'
    echo ""

    # Check system load and CPU usage
    echo "[+] System Load and CPU Usage:"
    uptime
    top -b -n 1 | grep "Cpu(s)" | awk '{print "CPU Load: " $2 "% user, " $4 "% system, " $8 "% idle"}'
    echo ""

    echo "====================================="
    echo "     DoS Attack Prevention Tips"
    echo "====================================="

    echo "[1] Install and Configure a Firewall (UFW/IPTables)"
    echo "    - Example: sudo ufw allow 22/tcp  (to allow SSH)"
    echo "    - Example: sudo ufw enable  (to activate firewall)"
    echo ""

    echo "[2] Limit Incoming Connections"
    echo "    - Example: sudo iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 10 -j DROP"
    echo ""

    echo "[3] Use Rate Limiting"
    echo "    - Example: sudo iptables -A INPUT -p tcp --dport 22 -m recent --set --name SSH"
    echo "               sudo iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP"
    echo ""

    echo "[4] Enable SYN Flood Protection"
    echo "    - Example: sudo sysctl -w net.ipv4.tcp_syncookies=1"
    echo ""

    echo "[5] Monitor Network for Unusual Traffic"
    echo "    - Use 'iftop' or 'nload' to analyze traffic in real-time."
    echo ""

    echo "[6] Consider DDoS Protection Services"
    echo "    - Cloudflare, AWS Shield, or Akamai for advanced mitigation."
    echo ""

    echo "[7] Disable Unused Services"
    echo "    - Run 'sudo systemctl list-units --type=service' and disable unwanted services."
    echo ""

    echo "====================================="
    echo "     END OF REPORT"
    echo "====================================="
}

# Execute the full setup and checks
install_gns3    # Install GNS3 if necessary
start_gns3      # Start GNS3 server if it's not running
network_report  # Run network status report
CDos            # Run DNS attack analysis and mitigation
