

#!/bin/bash 
  
  
 function ufwd () 
 { 
  
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
  
  
  
 function checks() 
 { 
  
 echo "uptime:"  
  uptime  
  echo "Currently connected:"  
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
  echo -n "OOM errors since $start_log :" $oom  
  echo ""  
  echo "--------------------"  
  echo "Utilization and most expensive processes:"  
  top -b | head -3  
  echo  
  top -b | head -10 | tail -4  
  
  
  
  
 } 
  
  

 function TcDump() 
 { 
  
 interface="eth0" 
 duration=60 
 threshold=100 
  
 # Function to analyze captured packets 
 analyze_packets() { 
     # Analyze packets to detect potential DoS attack patterns 
     packet_count=$(tcpdump -c $threshold -i $interface 2>/dev/null | wc -l) 
  
     echo "Captured $packet_count packets in $duration seconds." 
  
     if [ $packet_count -ge $threshold ]; then 
         echo "Potential DoS attack detected!" 
     else 
         echo "No signs of a DoS attack." 
     fi 
 } 
  
 # Check if tcpdump is installed 
 if ! command -v tcpdump &> /dev/null; then 
     echo "tcpdump is not installed. Please install it before running this script." 
     exit 1 
 fi 
  
 # Run tcpdump to capture network packets 
 echo "Capturing network packets on $interface for $duration seconds..." 
 tcpdump -i $interface -c $threshold -w captured_packets.pcap & 
  
 # Sleep for the specified duration 
 sleep $duration 
  
 # Stop tcpdump after capturing 
 pkill tcpdump 
  
 # Analyze captured packets 
 analyze_packets 
  
 # Clean up captured packets file 
 rm -f captured_packets.pcap 
  
  
 } 
  
 function Wire() 
 { 
  
     if ! command -v tshark &> /dev/null; then 
     echo "Wireshark is not installed. Please install Wireshark and run the script again." 
     exit 1 
     fi 
     echo "Capturing network traffic for analysis..." 
  
     # Adjust the capture filter based on your needs 
     # In this example, it captures traffic on port 80 (HTTP) 
     tshark -i any -f "port 80" -w capture.pcap -a duration:60  # Capture for 60 seconds 
  
     echo "Analyzing captured traffic for potential DoS attack..." 
  
     # Analyze the capture file using Wireshark's command-line interface 
     tshark -r capture.pcap 
  
     # Clean up: remove the capture file 
     rm -f capture.pcap 
  
  
 } 
  
  
  
  
 function CDos() 
 { 
  
 echo -e "\e[31mUsing UFW to asses major ports for Rules Set\e[0m" 
  
 ufwd 
 echo -e "\e[31mRunnig Server health Checks\e[0m" 
  
 checks 
  
  
 echo -e "\e[31mUsing Hping Now....\e[0m" 
 hpi 
  
 echo -e "\e[31mUsing TcDump Now\e[0m" 
 TcDump 
  
 echo -e "\e[31mUsing Wireshark now...\e[0m" 
 Wire 
  
 
  
  
 } 
  
  
  
