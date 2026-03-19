#!/bin/bash
# install-freeipa.sh
# Run as root on ipa01.lab.internal after OS provisioning.
set -euo pipefail

HOSTNAME="ipa01.lab.internal"
DOMAIN="lab.internal"
REALM="LAB.INTERNAL"
IPA_IP="192.168.10.5"
FORWARDER="192.168.1.1"  # Your upstream DNS

echo "=== Installing FreeIPA Server ==="

# Set hostname
hostnamectl set-hostname "$HOSTNAME"

# Install IPA server with DNS
dnf install -y freeipa-server freeipa-server-dns

# Run installer
# NOTE: Passwords prompted interactively — or pass --admin-password and --ds-password
ipa-server-install \
  --hostname="$HOSTNAME" \
  --domain="$DOMAIN" \
  --realm="$REALM" \
  --ip-address="$IPA_IP" \
  --setup-dns \
  --forwarder="$FORWARDER" \
  --auto-reverse \
  --no-ntp \
  --unattended

echo ""
echo "=== FreeIPA Installation Complete ==="
echo "Admin UI: https://$HOSTNAME/ipa/ui"
echo "CA cert:  /etc/ipa/ca.crt"
echo ""
echo "Next steps:"
echo "  1. kinit admin"
echo "  2. Run ldap-schema/*.ldif files to create groups and service accounts"
echo "  3. Run: bash /home/ansible/freeipa/ldap-schema/service-accounts.ldif"
