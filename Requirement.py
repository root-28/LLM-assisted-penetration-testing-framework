# ============================================
# CELL 1: Environment Setup
# ============================================

from google.colab import drive
drive.mount('/content/drive')

import os, subprocess, json, re
WORKDIR = "/content/drive/MyDrive/recon_project"
os.makedirs(WORKDIR, exist_ok=True)
os.chdir(WORKDIR)
print(f"✅ Working dir: {os.getcwd()}")

# ---- Install tools ----
!apt-get update -qq
!apt-get install -y -qq nmap whois dnsutils curl wget jq python3-pip git

# ---- Subfinder ----
if not os.path.exists("/usr/local/bin/subfinder"):
    !wget -q https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_2.6.6_linux_amd64.zip -O /tmp/sf.zip
    !unzip -q -o /tmp/sf.zip -d /usr/local/bin/
    !chmod +x /usr/local/bin/subfinder

# ---- httpx (live host detect) ----
if not os.path.exists("/usr/local/bin/httpx"):
    !wget -q https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_1.6.9_linux_amd64.zip -O /tmp/httpx.zip
    !unzip -q -o /tmp/httpx.zip -d /usr/local/bin/
    !chmod +x /usr/local/bin/httpx

# ---- Python libs ----
!pip install -q openai google-generativeai requests beautifulsoup4 \
    python-whois rich dnspython

print("✅ Setup complete")