

#!/bin/bash

required_tools=( "tcpdump" "wireshark" "nload" "snort")

 # Function to check and install tools
function check_install_tools() {
     for tool in "${required_tools[@]}"; do
         if ! command -v "$tool" &> /dev/null; then
             echo "$tool is not installed. Installing..."
             sudo apt-get update
             sudo apt-get install -y "$tool"
             echo "$tool installed successfully."
         fi
     done
 }


function nz
{

echo -e "\e[31mLive monitoring started\e[0m"
 nload

}

check_install_tools


session_name="newt"

# Create a new tmux session named "newt" and split it horizontally
tmux new-session -d -s $session_name
tmux split-window -h -t $session_name:0

# Send commands to each pane
tmux send-keys -t $session_name:0.0 "bash tool.sh" C-m
tmux send-keys -t $session_name:0.1 "nz" C-m

# Attach to the newly created session
tmux attach -t $session_name
