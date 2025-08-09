#!/usr/bin/env python3
import argparse
import dns.resolver
import requests
import pythonping
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import threading
import json
import csv
import os
import socket
import time
import subprocess
from tqdm import tqdm
import logging
import random
import shodan
from termcolor import colored
from retrying import retry
import getpass
import ipaddress
import sys

# Banner
BANNER = r"""
                        ______
                     .-        -.
                    /            \
                   |,  .-.  .-.  ,|
                   | )(_o/  \o_)( |
                   |/     /\     \|
                   (_     ^^     _)
                    \__|IIIIII|__/
                     | \IIIIII/ |
                     \          /
                      `--------`

                     +-----------+
                     | ISPBYPASS |
                     +-----------+

ISP-BYPASS - Find Working Hosts and Subdomains
Version: 1.4 | Author: ♈️ariesgad♈️ | Enhanced by Grok
"""

# API keys
VIRUSTOTAL_API_KEY = "11ae53bcdcfa8d42d47347073f0ddbe342180f9f5d219d8d1e2df30db14103e2"
SHODAN_API_KEY = "s35jHyUC1RO0riYFS4B9yQQ66KppWtiD"

# Internal wordlist
WORDLIST = [
    "cdn", "video", "api", "app", "dashboard", "www", "mail", "ftp", "blog", "test",
    "dev", "staging", "prod", "login", "auth", "secure", "cloud", "media", "stream",
    "admin", "portal", "web", "vpn", "proxy", "remote", "backup", "db", "sql", "ns",
    "mx", "smtp", "pop3", "imap", "git", "ci", "cdn1", "cdn2", "assets", "static"
]

# Expanded TLDs (sample, replace with full list from IANA)
TLDS = [
    ".com", ".org", ".net", ".edu", ".gov", ".mil", ".biz", ".info", ".name", 
    ".int", ".coop", ".aero", ".museum", ".jobs", ".travel", ".mobi", ".pro", 
    ".cat", ".asia", ".tel", ".xxx",
    ".app", ".tech", ".online", ".site", ".store", ".shop", ".blog", ".club", 
    ".xyz", ".live", ".digital", ".world", ".work", ".guru", ".expert", 
    ".solutions", ".services", ".media", ".news", ".studio", ".design", 
    ".agency", ".consulting", ".academy", ".training", ".events", ".community", 
    ".team", ".center", ".photography", ".photo", ".video", ".audio", ".music", 
    ".game", ".games", ".bet", ".casino", ".hosting", ".cloud", ".software", 
    ".technology", ".dev", ".fun", ".space", ".top", ".vip", ".win", ".art", 
    ".love", ".life", ".health", ".news", ".fitness", ".fashion", ".yoga",
    ".ac", ".ad", ".ae", ".af", ".ag", ".ai", ".al", ".am", ".ao", ".aq", 
    ".ar", ".as", ".at", ".au", ".aw", ".ax", ".az", ".ba", ".bb", ".bd", 
    ".be", ".bf", ".bg", ".bh", ".bi", ".bj", ".bm", ".bn", ".bo", ".br", 
    ".bs", ".bt", ".bw", ".by", ".bz", ".ca", ".cc", ".cd", ".cf", ".cg", 
    ".ch", ".ci", ".ck", ".cl", ".cm", ".cn", ".co", ".cr", ".cu", ".cv", 
    ".cw", ".cx", ".cy", ".cz", ".de", ".dj", ".dk", ".dm", ".do", ".dz",
    ".ec", ".ee", ".eg", ".er", ".es", ".et", ".eu", ".fi", ".fj", ".fk", 
    ".fm", ".fo", ".fr", ".ga", ".gd", ".ge", ".gf", ".gg", ".gh", ".gi", 
    ".gl", ".gm", ".gn", ".gp", ".gq", ".gr", ".gs", ".gt", ".gu", ".gw", 
    ".gy", ".hk", ".hm", ".hn", ".hr", ".ht", ".hu",
    ".xn--p1ai", ".xn--j1aef", ".xn--80asehdb", ".xn--80aswg", ".xn--mgbab2bd"
]

# Lock for thread-safe operations
lock = threading.Lock()
active_domains = []

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("ispbypass.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Proxy pool
PROXY_POOL = []

def load_proxies(proxy_file):
    """Load proxies from a file."""
    global PROXY_POOL
    if proxy_file and os.path.isfile(proxy_file):
        with open(proxy_file, "r") as f:
            PROXY_POOL = [line.strip() for line in f if line.strip()]
        logger.info(f"Loaded {len(PROXY_POOL)} proxies from {proxy_file}")
    elif proxy_file:
        PROXY_POOL = [proxy_file]
        logger.info(f"Using single proxy: {proxy_file}")

def get_random_proxy():
    """Return a random proxy from the pool."""
    return {"http": random.choice(PROXY_POOL), "https": random.choice(PROXY_POOL)} if PROXY_POOL else None

def resolve_dns(domain, dns_server=None):
    """Resolve DNS for a domain and return A, AAAA, MX, and NS records."""
    logger.info(f"Resolving DNS for {domain}")
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns_server] if dns_server else ["8.8.8.8", "1.1.1.1"]
    records = {"A": [], "AAAA": [], "MX": [], "NS": []}
    try:
        for record_type in records.keys():
            try:
                answers = resolver.resolve(domain, record_type, raise_on_no_answer=False)
                records[record_type] = [str(rdata) for rdata in answers]
            except Exception as e:
                logger.warning(f"Failed to resolve {record_type} for {domain}: {e}")
    except Exception as e:
        logger.error(f"DNS resolution error for {domain}: {e}")
    return records

def check_http(domain, proxies=None, timeout=5):
    """Check if domain is live via HTTP/HTTPS."""
    proxies = proxies or get_random_proxy()
    for protocol in ["http", "https"]:
        url = f"{protocol}://{domain}"
        try:
            response = requests.get(url, timeout=timeout, proxies=proxies, allow_redirects=False)
            logger.info(f"HTTP check for {url}: Status {response.status_code}")
            return response.status_code, protocol
        except requests.RequestException as e:
            logger.warning(f"HTTP check failed for {url}: {e}")
            continue
    return None, None

def port_scan(domain, ports=[80, 443, 8080, 8443], timeout=2):
    """Scan specified ports on the domain (non-root, socket-based)."""
    logger.info(f"Scanning ports {ports} for {domain}")
    open_ports = []
    try:
        ip = socket.gethostbyname(domain)
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
            except:
                pass
            finally:
                sock.close()
    except socket.gaierror:
        logger.warning(f"Could not resolve IP for {domain}")
    return open_ports

def ping_test(domain, timeout=2):
    """Perform a ping test to estimate speed."""
    logger.info(f"Pinging {domain}")
    try:
        response = pythonping.ping(domain, count=4, timeout=timeout)
        if response.success():
            logger.info(f"Ping successful for {domain}: {response.rtt_avg_ms}ms")
            return response.rtt_avg_ms
        return None
    except Exception as e:
        logger.warning(f"Ping failed for {domain}: {e}")
        return None

@retry(stop_max_attempt_number=3, wait_fixed=15000)
def get_virustotal_subdomains(domain):
    """Fetch subdomains from VirusTotal with retry logic."""
    logger.info(f"Querying VirusTotal for subdomains of {domain}")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        subdomains = [item["id"] for item in data.get("data", [])]
        logger.info(f"Found {len(subdomains)} VirusTotal subdomains for {domain}")
        return subdomains
    except requests.RequestException as e:
        logger.error(f"Error querying VirusTotal for {domain}: {e}")
        raise

def get_crtsh_subdomains(domain):
    """Fetch subdomains from crt.sh (free certificate transparency logs)."""
    logger.info(f"Querying crt.sh for subdomains of {domain}")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        subdomains = list(set([entry["name_value"].strip() for entry in data if entry["name_value"].endswith(f".{domain}")]))
        logger.info(f"Found {len(subdomains)} crt.sh subdomains for {domain}")
        return subdomains
    except requests.RequestException as e:
        logger.error(f"Error querying crt.sh for {domain}: {e}")
        return []

def get_dnsdumpster_subdomains(domain):
    """Fetch subdomains from DNSdumpster via web scraping."""
    logger.info(f"Querying DNSdumpster for subdomains of {domain}")
    url = "https://dnsdumpster.com/"
    try:
        session = requests.Session()
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        csrf_token = soup.find("input", {"name": "csrfmiddlewaretoken"})["value"]
        
        headers = {"Referer": url}
        data = {"csrfmiddlewaretoken": csrf_token, "targetip": domain}
        response = session.post(url, data=data, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        
        subdomains = []
        for table in soup.find_all("table"):
            for row in table.find_all("tr"):
                cells = row.find_all("td")
                if cells and len(cells) > 0:
                    subdomain = cells[0].text.strip().split("\n")[0]
                    if subdomain.endswith(f".{domain}") and subdomain != domain:
                        subdomains.append(subdomain)
        logger.info(f"Found {len(subdomains)} DNSdumpster subdomains for {domain}")
        return subdomains
    except Exception as e:
        logger.error(f"Error querying DNSdumpster for {domain}: {e}")
        return []

def get_cdnfinder_domains(url_or_domain):
    """Fetch domains and CDNs from CDN Finder."""
    logger.info(f"Querying CDN Finder for {url_or_domain}")
    url = "https://www.cdnplanet.com/tools/cdnfinder/"
    try:
        session = requests.Session()
        data = {"url": url_or_domain}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Referer": url
        }
        response = session.post(url, data=data, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        
        domains = []
        results_table = soup.find("table", {"class": "table"})
        if results_table:
            for row in results_table.find_all("tr")[1:]:
                cells = row.find_all("td")
                if len(cells) >= 2:
                    hostname = cells[0].text.strip()
                    if hostname:
                        domains.append(hostname)
        logger.info(f"Found {len(domains)} CDN Finder domains for {url_or_domain}")
        return domains
    except Exception as e:
        logger.error(f"Error querying CDN Finder for {url_or_domain}: {e}")
        return []

@retry(stop_max_attempt_number=3, wait_fixed=15000)
def get_shodan_subdomains(domain):
    """Fetch subdomains from Shodan."""
    logger.info(f"Querying Shodan for subdomains of {domain}")
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.dns.domain_info(domain)
        subdomains = [sub["subdomain"] + f".{domain}" for sub in results.get("subdomains", [])]
        logger.info(f"Found {len(subdomains)} Shodan subdomains for {domain}")
        return subdomains
    except shodan.APIError as e:
        logger.error(f"Shodan API error for {domain}: {e}")
        return []

def nmap_scan(domain, nmap_args="-sV -sC -p 80,443,8080,8443,53"):
    """Perform an Nmap scan on the domain."""
    logger.info(f"Running Nmap scan on {domain} with args: {nmap_args}")
    try:
        ip = socket.gethostbyname(domain)
        cmd = f"nmap {nmap_args} {ip}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        nmap_output = result.stdout
        open_ports = []
        services = []
        for line in nmap_output.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                port = int(parts[0].split("/")[0])
                service = parts[2] if len(parts) > 2 else "unknown"
                open_ports.append(port)
                services.append({"port": port, "service": service})
        logger.info(f"Nmap results for {domain}: Ports={open_ports}, Services={services}")
        return {"ports": open_ports, "services": services, "output": nmap_output}
    except subprocess.CalledProcessError as e:
        if "Permission denied" in e.stderr or "Operation not permitted" in e.stderr:
            logger.warning(f"Nmap scan for {domain} requires root privileges. Skipping.")
            return {"ports": [], "services": [], "output": "Skipped: Root privileges required"}
    except Exception as e:
        logger.error(f"Nmap scan error for {domain}: {e}")
        return {"ports": [], "services": [], "output": ""}

def ssl_scan(domain):
    """Perform an SSL/TLS scan using sslscan."""
    logger.info(f"Running SSL scan on {domain}")
    try:
        cmd = f"sslscan {domain}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        ssl_output = result.stdout
        logger.info(f"SSL scan completed for {domain}")
        return {"output": ssl_output}
    except subprocess.CalledProcessError as e:
        if "Permission denied" in e.stderr or "Operation not permitted" in e.stderr:
            logger.warning(f"SSL scan for {domain} requires root privileges. Skipping.")
            return {"output": "Skipped: Root privileges required"}
    except Exception as e:
        logger.error(f"SSL scan error for {domain}: {e}")
        return {"output": ""}

def check_root_privileges():
    """Check if the user has root privileges."""
    return os.geteuid() == 0 if hasattr(os, "geteuid") else getpass.getuser() == "root"

def scan_domain(domain, ports=[80, 443, 8080, 8443, 53], proxies=None, dns_server=None, timeout=5, output_dir="output", free_host=None, filter_ports=None, filter_status=None):
    """Scan a single domain for DNS, HTTP/HTTPS, ports, ping, Nmap, and SSL."""
    result = {
        "domain": domain,
        "dns_records": {},
        "status_code": None,
        "protocol": None,
        "ports": [],
        "ping_ms": None,
        "nmap": {"ports": [], "services": [], "output": ""},
        "ssl": {"output": ""},
        "sources": [],
        "status": "dead"
    }
    
    # Check root privileges
    has_root = check_root_privileges()
    
    # DNS resolution
    result["dns_records"] = resolve_dns(domain, dns_server)
    if result["dns_records"]["A"]:
        result["sources"].append("DNS")
        result["status"] = "active"
    
    # HTTP/HTTPS check
    status_code, protocol = check_http(domain, proxies, timeout)
    result["status_code"] = status_code
    result["protocol"] = protocol
    if status_code:
        result["sources"].append("HTTP/HTTPS")
        if status_code in [200, 301, 302, 403]:
            result["status"] = "working"
    
    # Port scanning
    result["ports"] = port_scan(domain, ports, timeout)
    if result["ports"]:
        result["sources"].append("PortScan")
        result["status"] = "active" if result["status"] != "working" else "working"
    
    # Ping test
    result["ping_ms"] = ping_test(domain, timeout)
    if result["ping_ms"]:
        result["sources"].append("Ping")
        result["status"] = "active" if result["status"] != "working" else "working"
    
    # Nmap scan (only if domain resolves and root privileges are available)
    if result["dns_records"]["A"] and has_root:
        result["nmap"] = nmap_scan(domain)
        if result["nmap"]["ports"]:
            result["sources"].append("Nmap")
            result["status"] = "active" if result["status"] != "working" else "working"
    elif not has_root:
        result["nmap"]["output"] = "Skipped: Root privileges required"
        logger.warning(f"Nmap scan for {domain} skipped due to lack of root privileges")
    
    # SSL scan (only if domain resolves and root privileges are available)
    if result["dns_records"]["A"] and has_root:
        result["ssl"] = ssl_scan(domain)
        if result["ssl"]["output"] and "Skipped" not in result["ssl"]["output"]:
            result["sources"].append("SSL")
            result["status"] = "active" if result["status"] != "working" else "working"
    elif not has_root:
        result["ssl"]["output"] = "Skipped: Root privileges required"
        logger.warning(f"SSL scan for {domain} skipped due to lack of root privileges")
    
    # Filter results
    if filter_ports and not any(port in result["ports"] for port in filter_ports):
        return None
    if filter_status and result["status_code"] not in filter_status:
        return None
    
    # Save results
    save_result(result, output_dir)
    
    # Add to active domains list if active
    with lock:
        if result["status"] in ["active", "working"]:
            active_domains.append(result)
    
    # Live color-coded output
    if result["status"] == "working":
        print(colored(f"[WORKING] {domain}", "green"))
    elif result["status"] == "active":
        print(colored(f"[ACTIVE] {domain}", "magenta"))
    else:
        print(colored(f"[DEAD] {domain}", "grey"))
    
    return result

def save_result(result, output_dir):
    """Save scan results to TXT, CSV, and JSON with status."""
    os.makedirs(output_dir, exist_ok=True)
    
    with lock:
        # TXT output
        with open(f"{output_dir}/domains.txt", "a") as f:
            f.write(f"[{result['status'].upper()}] {result['domain']} - A: {', '.join(result['dns_records']['A'])} - "
                    f"MX: {', '.join(result['dns_records']['MX'])} - "
                    f"NS: {', '.join(result['dns_records']['NS'])} - "
                    f"Status: {result['status_code']} ({result['protocol']}) - "
                    f"Ports: {result['ports']} - Ping: {result['ping_ms']}ms - "
                    f"Nmap: {result['nmap']['ports']} ({[s['service'] for s in result['nmap']['services']]}) - "
                    f"SSL: {'Available' if result['ssl']['output'] and 'Skipped' not in result['ssl']['output'] else 'None'} - "
                    f"Sources: {result['sources']}\n")
        
        # CSV output
        with open(f"{output_dir}/domains.csv", "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                result["status"],
                result["domain"],
                ",".join(result["dns_records"]["A"]),
                ",".join(result["dns_records"]["MX"]),
                ",".join(result["dns_records"]["NS"]),
                result["status_code"],
                result["protocol"],
                ",".join(map(str, result["ports"])),
                result["ping_ms"],
                ",".join(map(str, result["nmap"]["ports"])),
                ",".join([s["service"] for s in result["nmap"]["services"]]),
                "Available" if result["ssl"]["output"] and "Skipped" not in result["ssl"]["output"] else "None",
                ",".join(result["sources"])
            ])
        
        # JSON output
        json_file = f"{output_dir}/domains.json"
        json_data = []
        if os.path.exists(json_file):
            with open(json_file, "r") as f:
                try:
                    json_data = json.load(f)
                except:
                    json_data = []
        json_data.append(result)
        with open(json_file, "w") as f:
            json.dump(json_data, f, indent=4)

def scan_all_domains(domains, ports=[80, 443, 8080, 8443, 53], proxies=None, dns_server=None, timeout=5, output_dir="output", free_host=None, filter_ports=None, filter_status=None, max_workers=20):
    """Scan a list of domains and their subdomains with optimized threading."""
    global active_domains
    active_domains = []
    
    logger.info(f"Scanning {len(domains)} domains with {max_workers} workers")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_domain, domain, ports, proxies, dns_server, timeout, output_dir, free_host, filter_ports, filter_status) for domain in domains]
        for future in tqdm(futures, total=len(domains), desc="Scanning domains"):
            future.result()
    
    # Display sorted list of active domains
    if active_domains:
        print("\nActive Working Hosts (Potential ISP Bypass):")
        for result in sorted(active_domains, key=lambda x: x["status"], reverse=True):
            if result["status"] == "working":
                print(colored(result["domain"], "green"))
            elif result["status"] == "active":
                print(colored(result["domain"], "magenta"))
            else:
                print(colored(result["domain"], "grey"))
    else:
        print("\nNo active working hosts found.")

def load_wordlist(wordlist_file):
    """Load custom wordlist from a file."""
    if os.path.isfile(wordlist_file):
        with open(wordlist_file, "r") as f:
            words = [line.strip() for line in f if line.strip()]
        logger.info(f"Loaded {len(words)} words from {wordlist_file}")
        return words
    logger.warning(f"Wordlist file {wordlist_file} not found. Using default wordlist.")
    return WORDLIST

def scan_with_nmap(target):
    try:
        # Run nmap with ping scan (-sn) and grepable output (-oG -)
        result = subprocess.run(['nmap', '-sn', '-oG', '-', target], capture_output=True, text=True, check=True)
        output = result.stdout
        
        up_hosts = []
        for line in output.splitlines():
            if line.startswith('Host:') and 'Status: Up' in line:
                # Extract IP from "Host: IP ()"
                ip = line.split()[1]
                up_hosts.append(ip)
        
        return up_hosts
    
    except subprocess.CalledProcessError as e:
        print(f"Error running nmap: {e.stderr}", file=sys.stderr)
        return []
    except FileNotFoundError:
        print("Nmap not found. Please install nmap on your system.", file=sys.stderr)
        return []

def main():
    """Main function to parse arguments and run the script."""
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="ISP-BYPASS - Enhanced with VirusTotal, crt.sh, DNSdumpster, CDN Finder, Shodan, Nmap, and sslscan")
    parser.add_argument("-d", "--domain", help="Target domain (e.g., google.com)")
    parser.add_argument("-f", "--file", help="File containing list of domains (one per line)")
    parser.add_argument("--free-host", help="Free browsing host for subdomain scanning")
    parser.add_argument("--dns", help="Custom DNS server (e.g., 8.8.8.8)")
    parser.add_argument("--proxy", help="Proxy server or file with proxies (e.g., http://proxy:port or proxies.txt)")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan (e.g., 80,443,8080)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for HTTP, ping, and port scans (seconds)")
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    parser.add_argument("--wordlist", help="Custom wordlist file for subdomain enumeration")
    parser.add_argument("--filter-ports", help="Comma-separated list of ports to filter results (e.g., 80,443)")
    parser.add_argument("--filter-status", help="Comma-separated list of HTTP status codes to filter results (e.g., 200,301)")
    parser.add_argument("--max-workers", type=int, default=20, help="Number of concurrent threads (default: 20)")
    
    args = parser.parse_args()
    
    # Load proxies
    load_proxies(args.proxy)
    
    # Parse ports and status codes for filtering
    ports = [int(p.strip()) for p in args.ports.split(",")] if args.ports else [80, 443, 8080, 8443, 53]
    filter_ports = [int(p.strip()) for p in args.filter_ports.split(",")] if args.filter_ports else None
    filter_status = [int(s.strip()) for s in args.filter_status.split(",")] if args.filter_status else None
    
    # Load custom wordlist
    wordlist = load_wordlist(args.wordlist) if args.wordlist else WORDLIST
    
    domains = []
    
    # Handle input domains or IPs
    if args.domain:
        try:
            network = ipaddress.ip_network(args.domain, strict=False)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            print(f"Scanning IP or range for live hosts: {args.domain}")
            live_hosts = scan_with_nmap(args.domain)
            
            if '/' in args.domain:  # Assume it's a range if CIDR notation is used
                if live_hosts:
                    print(f"Live proxies in range {args.domain}:")
                    for host in live_hosts:
                        print(host)
                else:
                    print(f"No live proxies found in range {args.domain}.")
            else:
                if live_hosts:
                    print(f"Proxy {args.domain} is live.")
                else:
                    print(f"Proxy {args.domain} is down.")
            return  # Exit after IP scan

        else:
            has_tld = any(args.domain.endswith(tld) for tld in TLDS)
            domains = [args.domain] if has_tld else [f"{args.domain}{tld}" for tld in TLDS]
            if has_tld:
                domains.extend([f"{sub}.{args.domain}" for sub in wordlist])
                domains.extend(get_virustotal_subdomains(args.domain))
                domains.extend(get_crtsh_subdomains(args.domain))
                domains.extend(get_dnsdumpster_subdomains(args.domain))
                domains.extend(get_cdnfinder_domains(args.domain))
                domains.extend(get_shodan_subdomains(args.domain))
    
    elif args.file:
        if os.path.exists(args.file):
            with open(args.file, "r") as f:
                domains = [line.strip() for line in f if line.strip()]
            for domain in domains[:]:
                has_tld = any(domain.endswith(tld) for tld in TLDS)
                if has_tld:
                    domains.extend([f"{sub}.{domain}" for sub in wordlist])
                    domains.extend(get_virustotal_subdomains(domain))
                    domains.extend(get_crtsh_subdomains(domain))
                    domains.extend(get_dnsdumpster_subdomains(domain))
                    domains.extend(get_cdnfinder_domains(domain))
                    domains.extend(get_shodan_subdomains(domain))
        else:
            logger.error(f"File '{args.file}' not found.")
            return
    
    # Handle free browsing host
    if args.free_host:
        logger.info(f"Scanning free browsing host: {args.free_host}")
        has_tld = any(args.free_host.endswith(tld) for tld in TLDS)
        if has_tld:
            domains.extend([f"{sub}.{args.free_host}" for sub in wordlist])
            domains.extend(get_virustotal_subdomains(args.free_host))
            domains.extend(get_crtsh_subdomains(args.free_host))
            domains.extend(get_dnsdumpster_subdomains(args.free_host))
            domains.extend(get_cdnfinder_domains(args.free_host))
            domains.extend(get_shodan_subdomains(args.free_host))
    
    # Deduplicate domains
    domains = list(set(domains))
    
    # Check root privileges
    if not check_root_privileges():
        logger.warning("Running without root privileges. Nmap and sslscan will be skipped unless sudo is used.")
    
    # Scan all domains
    scan_all_domains(domains, ports, get_random_proxy(), args.dns, args.timeout, args.output, args.free_host, filter_ports, filter_status, args.max_workers)

if __name__ == "__main__":
    main()