#!/bin/sh
set -e

mkdir -p /secrets /data

# Export database encryption key to profile so it's always accessible in shell
cat <<EOF > /etc/profile.d/db_key.sh
export DATABASE_ENCRYPTION_KEY="${DATABASE_ENCRYPTION_KEY:-LAB_ENCRYPTION_KEY_FIXED_2026_DO_NOT_ROTATE}"
EOF

# Ensure secret profile script exists
if [ ! -f /secrets/api_secret.env ]; then
  cat <<EOF > /secrets/api_secret.env
export API_SECRET="${API_SECRET:-LAB_INITIAL_SECRET_ABC123}"
EOF
fi

if [ ! -f /secrets/ldap_secret.env ]; then
  cat <<EOF > /secrets/ldap_secret.env
export LDAP_ADMIN_PASSWORD="${LDAP_ADMIN_PASSWORD:-adminpassword}"
EOF
fi

# Ensure profile sources secrets file on every shell login / sh execution
echo '[ -f /secrets/api_secret.env ] && . /secrets/api_secret.env' >> /etc/profile
echo '[ -f /secrets/ldap_secret.env ] && . /secrets/ldap_secret.env' >> /etc/profile
echo '[ -f /etc/profile.d/db_key.sh ] && . /etc/profile.d/db_key.sh' >> /etc/profile
[ -f /root/.bashrc ] && echo '[ -f /secrets/api_secret.env ] && . /secrets/api_secret.env' >> /root/.bashrc
[ -f /root/.profile ] && echo '[ -f /secrets/api_secret.env ] && . /secrets/api_secret.env' >> /root/.profile

echo "[Backend] Starting Flask server on port 5000..."
exec python app.py
