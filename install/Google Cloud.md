# Installing the Attestation Server on Google Cloud

This guide walks through deploying the Privasys Attestation Server on a
Google Cloud VM with Intel DCAP support, fronted by Caddy for automatic HTTPS.

---

## 1. Create the VM

Create a Compute Engine instance (e.g. `attestation-server-eu-lon-1`).
The server only verifies quotes — it does **not** need to run inside a TEE itself.
A small general-purpose VM is sufficient (e.g. `e2-medium`, 2 vCPUs / 4 GB RAM,
Ubuntu 24.04).

## 2. System prerequisites

```bash
sudo apt update
sudo apt install -y git nodejs npm cracklib-runtime openssl \
  libsgx-dcap-quote-verify libsgx-dcap-default-qpl libsgx-dcap-ql-dev
```

## 3. Install Intel PCCS (from source)

The official Debian package has a known issue
([intel/confidential-computing.tee.dcap.pccs#37](https://github.com/intel/confidential-computing.tee.dcap.pccs/issues/37)),
so build from the standalone repository instead.

```bash
# Create the system user
sudo useradd --system --shell /bin/false pccs || true

# Prepare the directory structure
sudo mkdir -p /opt/intel/sgx-dcap-pccs/{db,logs,private}

# Clone and build
git clone https://github.com/intel/confidential-computing.tee.dcap.pccs.git ~/pccs-source
cd ~/pccs-source/service
sudo ./install.sh          # choose option 1 to ignore npm audit warnings

# Deploy to the system directory
sudo cp -r ~/pccs-source/service/* /opt/intel/sgx-dcap-pccs/
sudo chown -R pccs:pccs /opt/intel/sgx-dcap-pccs
```

### Generate the PCCS self-signed certificate

```bash
sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout /opt/intel/sgx-dcap-pccs/private/private.pem \
  -out    /opt/intel/sgx-dcap-pccs/private/file.crt \
  -subj   "/C=US/ST=CA/L=SantaClara/O=Intel/CN=localhost"

sudo chmod 700 /opt/intel/sgx-dcap-pccs/private
sudo chmod 600 /opt/intel/sgx-dcap-pccs/private/*
```

### Configure and start PCCS

```bash
# Set your Intel PCS API key in the config
sudo nano /opt/intel/sgx-dcap-pccs/config/default.json

# Initialise the database
sudo -u pccs node /opt/intel/sgx-dcap-pccs/pccs_server.js --setup

# Install and start the systemd service
sudo cp /opt/intel/sgx-dcap-pccs/pccs.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pccs
```

### Verify PCCS is running

```bash
curl -kv https://localhost:8081/sgx/certification/v4/rootcacrl
```

You should see hex-encoded CRL data in the response.

## 4. Install Go

```bash
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
source ~/.profile
```

## 5. Build the Attestation Server

```bash
git clone https://github.com/Privasys/attestation-server.git ~/attestation-server
cd ~/attestation-server
go build -o dist/attestation-server ./src/
```

## 6. Generate the JWT signing key

```bash
openssl genpkey -algorithm Ed25519 -out ~/attestation-server/server-jwt.key
openssl pkey -in ~/attestation-server/server-jwt.key -pubout \
  -out ~/attestation-server/server-jwt.pub
chmod 600 ~/attestation-server/server-jwt.key
```

## 7. Create the systemd service

Create `/etc/systemd/system/attestation-server.service`:

```ini
[Unit]
Description=Privasys Attestation Server
After=network.target pccs.service

[Service]
Type=simple
WorkingDirectory=/home/bertrand/attestation-server
Environment=JWT_SIGNING_KEY_FILE=/home/bertrand/attestation-server/server-jwt.key
ExecStart=/home/bertrand/attestation-server/dist/attestation-server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now attestation-server
sudo systemctl status attestation-server
```

## 8. Issue an API key

```bash
JWT_SIGNING_KEY_FILE=~/attestation-server/server-jwt.key \
  ~/attestation-server/dist/attestation-server issue \
  --subject "acme-corp" --scope "verify" --days 90
```

See [docs/api-keys.md](../docs/api-keys.md) for the full token management guide.

## 9. Set up Caddy as a reverse proxy

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy
```

Edit `/etc/caddy/Caddyfile`:

```caddyfile
gcp-lon-1.dcap.privasys.org {
    reverse_proxy /api/* localhost:8080

    log {
        output file /var/log/caddy/access.log
    }
}
```

```bash
sudo systemctl restart caddy
```

Caddy will automatically obtain a Let's Encrypt certificate for the domain.

## 10. Test

```bash
curl -X POST https://gcp-lon-1.dcap.privasys.org/api/verify \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"quote": "<base64-encoded-quote>"}'
```