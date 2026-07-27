#!/bin/bash
# Example: Set up passkey entries for MCP servers
# Run this script to interactively create entries for your MCP servers

set -e

echo "=== Passkey MCP Setup ==="
echo ""
echo "This script will help you create passkey entries for your MCP servers."
echo "Secrets are stored securely in the system keychain."
echo ""

echo "=== Setting up Slack entry ==="
echo "You will need:"
echo "  - SLACK_XOXC_TOKEN"
echo "  - SLACK_XOXD_COOKIE"
echo ""
read -p "Create slack entry? [y/N]: " create_slack
if [[ "$create_slack" =~ ^[Yy]$ ]]; then
    passkey new
    # Enter: slack, then the field names and values
fi

echo ""
echo "=== Setting up GitHub entry ==="
echo "You will need:"
echo "  - GITHUB_TOKEN"
echo ""
read -p "Create github entry? [y/N]: " create_github
if [[ "$create_github" =~ ^[Yy]$ ]]; then
    passkey new
    # Enter: github, then GITHUB_TOKEN and value
fi

echo ""
echo "=== Verify entries ==="
echo "Current entries:"
passkey list

echo ""
echo "=== Done! ==="
echo "Update your MCP config to use passkey. See mcp-config-example.json"
