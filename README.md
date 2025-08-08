Enumerate subdomains and scan for ISP bypass with VirusTotal, crt.sh, DNSdumpster, Shodan, Nmap, and sslscan. Live color-coded results, supports proxies, custom DNS. For authorized use only.

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/AriesGad/ispbypass.git
   cd ispbypass
   pip install -r requirements.txt

# Display help
python3 ispbypass.py -h

# Scan a single domain
python3 ispbypass.py -d example.com

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
