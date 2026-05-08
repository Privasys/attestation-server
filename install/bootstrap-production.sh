#!/bin/bash
# Bootstrap script for Privasys Attestation Server on GCP production.
# Run as root (or with sudo) on a fresh Ubuntu 24.04 Minimal VM.
#
# Provisions: SGX DCAP libraries, Go, attestation-server binary, Caddy reverse proxy.
# QPL is configured to use Intel PCS directly (no local PCCS required).
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "=== 1. System prerequisites ==="
apt-get update
apt-get install -y git openssl curl wget gnupg \
  debian-keyring debian-archive-keyring apt-transport-https

echo "=== 2. Intel SGX DCAP libraries ==="
curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
  | gpg --dearmor -o /usr/share/keyrings/intel-sgx-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-keyring.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" \
  > /etc/apt/sources.list.d/intel-sgx.list
apt-get update
apt-get install -y libsgx-dcap-quote-verify libsgx-dcap-default-qpl libsgx-dcap-ql-dev

echo "=== 3. Configure QPL ==="
cat > /etc/sgx_default_qcnl.conf <<'QPL'
{
  "pccs_url": "https://api.trustedservices.intel.com/sgx/certification/v4/",
  "use_secure_cert": true,
  "collateral_service": "https://api.trustedservices.intel.com/sgx/certification/v4/",
  "retry_times": 6,
  "retry_delay": 10,
  "local_pck_url": "",
  "pck_cache_expire_hours": 168,
  "verify_collateral_cache_expire_hours": 168
}
QPL

echo "=== 4. Install Go ==="
GO_VERSION=1.22.4
if [ ! -d /usr/local/go ]; then
  wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
  tar -C /usr/local -xzf /tmp/go.tar.gz
  rm /tmp/go.tar.gz
fi
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
/usr/local/go/bin/go version

echo "=== 5. Build attestation-server ==="
if [ ! -d /opt/attestation-server ]; then
  git clone https://github.com/Privasys/attestation-server.git /opt/attestation-server
fi
cd /opt/attestation-server
mkdir -p dist
/usr/local/go/bin/go build -o dist/attestation-server ./src/
echo "Built: $(ls -la dist/attestation-server)"

echo "=== 6. Create attestation-server systemd service ==="
cat > /etc/systemd/system/attestation-server.service <<'SVC'
[Unit]
Description=Privasys Attestation Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/attestation-server
Environment=OIDC_ISSUER=https://privasys.id
Environment=OIDC_AUDIENCE=attestation-server
ExecStart=/opt/attestation-server/dist/attestation-server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SVC
systemctl daemon-reload
systemctl enable attestation-server

echo "=== 7. Install Caddy ==="
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update
apt-get install -y caddy
caddy version

echo "=== 8. Configure Caddy ==="
cat > /etc/caddy/Caddyfile <<'CADDY'
as.privasys.org {
    reverse_proxy /* localhost:8080

    log {
        output file /var/log/caddy/access.log
    }
}
CADDY
mkdir -p /var/log/caddy

echo "=== 9. Start services ==="
systemctl start attestation-server
systemctl restart caddy
sleep 2
curl -s http://localhost:8080/healthz
echo ""

echo "=== Bootstrap complete ==="
