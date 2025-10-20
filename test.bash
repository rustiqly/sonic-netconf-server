#!/bin/bash

# Simple NETCONF client using SSH
# Usage: ./send-netconf.sh [username]

USER=${1:-netconf}
HOST=localhost
PORT=831

# Define a simple NETCONF <get> RPC message
read -r -d '' NETCONF_MESSAGE <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<rpc message-id="101"
     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <get>
    <filter type="subtree">
      <interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"/>
    </filter>
  </get>
</rpc>]]>]]>
EOF

echo "Sending NETCONF command to $HOST:$PORT as user $USER..."
echo

# Send the message over SSH using the NETCONF subsystem
ssh -p "$PORT" -s "$USER@$HOST" netconf <<EOF
$NETCONF_MESSAGE
EOF
