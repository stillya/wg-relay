#!/bin/bash
set -e

systemctl daemon-reload
systemctl enable wg-relay

echo ""
echo "wg-relay installed successfully."
echo "Edit /etc/wg-relay/config.yaml to configure your proxy, then start the service:"
echo "  systemctl start wg-relay"
echo ""
echo "To view logs: journalctl -u wg-relay -f"
echo "To override service settings: systemctl edit wg-relay"
