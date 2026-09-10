#!/bin/zsh
#
# Install the AES67 PTP agent as a LaunchAgent.
#
# The driver cannot run a PTP slave from inside coreaudiod, so this agent runs
# one and publishes grandmaster time for the driver to use as its media clock.
# Without it the driver's transmitted RTP timestamps are not aligned to the
# grandmaster and receivers reject the stream as carrying no data.
#
# Runs as you, not root: it needs no elevated privileges.
#
#   ./install-ptp-agent.sh [interface]      (default: en0)
#
set -e

INTERFACE="${1:-en0}"
LABEL="com.aes67driver.ptpagent"
BINARY="/usr/local/bin/AES67PTPAgent"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILT="$SRC_DIR/../build/Tools/AES67PTPAgent"

if [[ ! -x "$BUILT" ]]; then
    echo "error: $BUILT not found. Build it first:  make AES67PTPAgent" >&2
    exit 1
fi

echo "Installing agent binary to $BINARY (needs sudo)"
sudo mkdir -p "$(dirname "$BINARY")"
sudo cp "$BUILT" "$BINARY"
sudo chmod 755 "$BINARY"

echo "Installing LaunchAgent to $PLIST"
mkdir -p "$(dirname "$PLIST")"
sed "s|<string>en0</string>|<string>$INTERFACE</string>|" \
    "$SRC_DIR/LaunchAgents/$LABEL.plist" > "$PLIST"

# Reload rather than load, so re-running this picks up changes.
launchctl bootout "gui/$UID/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$UID" "$PLIST"
launchctl kickstart -k "gui/$UID/$LABEL"

sleep 3
if launchctl print "gui/$UID/$LABEL" >/dev/null 2>&1; then
    echo "Agent running on interface $INTERFACE. Log: /tmp/aes67_ptpagent.log"
    echo "Shared clock: /tmp/aes67_ptp_clock"
else
    echo "error: agent did not start; see /tmp/aes67_ptpagent.log" >&2
    exit 1
fi
