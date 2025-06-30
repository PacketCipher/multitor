#!/bin/bash

# Default to 5 TOR instances if TOR_INSTANCES is not set or not a number
DEFAULT_TOR_INSTANCES=5
TOR_INSTANCE_COUNT="${TOR_INSTANCES:-$DEFAULT_TOR_INSTANCES}"

# Validate that TOR_INSTANCE_COUNT is a number
if ! [[ "$TOR_INSTANCE_COUNT" =~ ^[0-9]+$ ]]; then
  echo "Warning: TOR_INSTANCES value ('$TOR_INSTANCES') is not a valid number. Defaulting to $DEFAULT_TOR_INSTANCES instances." >&2
  TOR_INSTANCE_COUNT=$DEFAULT_TOR_INSTANCES
fi

echo "Starting multitor with $TOR_INSTANCE_COUNT Tor instances..."

# Execute multitor
# The user is root because we are in a container.
# Ports for SOCKS and Control are internal to the container.
# HAProxy is enabled by default to provide a single entry point.
# Logs are redirected to /tmp/multitor.log and then tailed to ensure they go to Docker's log output.
# The --debug and --verbose flags are included for better insight during runtime.
multitor \
  --init "$TOR_INSTANCE_COUNT" \
  --user root \
  --socks-port 9000 \
  --control-port 9900 \
  --proxy privoxy \
  --haproxy \
  --verbose \
  --debug > /tmp/multitor.log 2>&1

# Tail the log file to keep the container running and output logs
# Using `tail -f` on a file that might not exist immediately can be problematic.
# Ensure the log file exists before tailing or handle the error.
if [ ! -f /tmp/multitor.log ]; then
    touch /tmp/multitor.log
fi
tail -f /tmp/multitor.log
