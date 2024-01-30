

#!/bin/bash

session_name="newt"

# Create a new tmux session named "newt" and split it horizontally
tmux new-session -d -s $session_name
tmux split-window -h -t $session_name:0

# Send commands to each pane
tmux send-keys -t $session_name:0.0 "pwd" C-m
tmux send-keys -t $session_name:0.1 "whoami" C-m

# Attach to the newly created session
tmux attach -t $session_name
