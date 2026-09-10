#!/bin/zsh
# Remove the AES67 PTP agent LaunchAgent and its binary.
set -e
LABEL="com.aes67driver.ptpagent"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

launchctl bootout "gui/$UID/$LABEL" 2>/dev/null || true
rm -f "$PLIST"
sudo rm -f /usr/local/bin/AES67PTPAgent
rm -f /tmp/aes67_ptp_clock
echo "Agent removed."
