<<<<<<< HEAD
Enumerate subdomains and scan for ISP bypass with VirusTotal, crt.sh, DNSdumpster, Shodan, Nmap, and sslscan. Live color-coded results, supports proxies, custom DNS. For authorized use only.

=======
# ISPBypass

Enumerate subdomains and scan for ISP bypass with VirusTotal, crt.sh, DNSdumpster, Shodan, Nmap, and sslscan. Live color-coded results, supports proxies, custom DNS. For authorized use only.

## Features
- Subdomain enumeration using an internal wordlist, VirusTotal, crt.sh, DNSdumpster, CDN Finder, and Shodan.
- Scans for DNS records (A, AAAA, MX, NS), HTTP/HTTPS status, open ports, and ping latency.
- Optional Nmap and SSL scans (requires root privileges).
- Live color-coded output: green for `[WORKING]` (HTTP 200/301/302), pink/magenta for `[ACTIVE]` (resolves/ports open), grey for `[DEAD]`.
- Saves results to `output/domains.{txt,csv,json}`.
- Supports 1,264 TLDs for comprehensive subdomain generation.

## Prerequisites
- Python 3.6+
- Required Python packages: `requests`, `pythonping`, `beautifulsoup4`, `tqdm`, `termcolor`, `retrying`, `shodan`
- For root users: `nmap` and `sslscan`
- Termux (Android), Linux, or Windows
- Shodan API key (included or replace with your own)
- VirusTotal API key (included or replace with your own)

>>>>>>> f0d4b70 (Add README with instructions and command usage)
## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/AriesGad/ispbypass.git
   cd ispbypass
   pip install -r requirements.txt
   pip install requests pythonping beautifulsoup4 tqdm termcolor retrying shodan
   termux-setup-storage

<<<<<<< HEAD
=======
USAGE:

>>>>>>> f0d4b70 (Add README with instructions and command usage)
# Display help
python3 ispbypass.py -h

# Scan a single domain
python3 ispbypass.py -d example.com

# scan a single ip
python3 ispbypass.py -d 172.0.0.1

# scan CTRL ip range
python3 ispbypass.py -d 172.0.0.0/24

# Scan with custom ports
python3 ispbypass.py -d example.com -p 80,443,8080

# Use a custom wordlist
python3 ispbypass.py -d example.com --wordlist custom_wordlist.txt

# Use a proxy
python3 ispbypass.py -d example.com --proxy proxies.txt

# Filter results
python3 ispbypass.py -d example.com --filter-ports 80,443 --filter-status 200,301

# Run with root for Nmap/SSL scans
sudo python3 ispbypass.py -d example.com
