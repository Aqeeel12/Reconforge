import shodan
import requests
import nmap
import os
from dotenv import load_dotenv

load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

def scan_shodan(target):
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.host(target)
        
        open_ports = []
        for item in results['data']:
            open_ports.append({
                'port': item['port'],
                'service': item.get('product', 'unknown'),
                'version': item.get('version', 'unknown'),
                'banner': item.get('banner', '')[:200]
            })
        
        return {
            'ip': results['ip_str'],
            'organization': results.get('org', 'unknown'),
            'os': results.get('os', 'unknown'),
            'ports': open_ports,
            'hostnames': results.get('hostnames', [])
        }
    
    except shodan.APIError as e:
        return {'error': str(e)}


def scan_subdomains(domain):
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=10)
        data = response.json()
        
        subdomains = set()
        for entry in data:
            name = entry['name_value']
            for sub in name.split('\n'):
                if domain in sub:
                    subdomains.add(sub.strip())
        
        return {
            'domain': domain,
            'subdomains': list(subdomains)
        }
    
    except Exception as e:
        return {'error': str(e)}


def scan_nmap(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sV -T4 --top-ports 100')
        
        results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    results.append({
                        'port': port,
                        'state': service['state'],
                        'service': service['name'],
                        'product': service['product'],
                        'version': service['version']
                    })
        
        return {
            'target': target,
            'scan_results': results
        }
    
    except Exception as e:
        return {'error': str(e)}


def run_full_scan(target):
    print(f"[*] Starting full scan on {target}")
    
    results = {}
    
    print("[*] Running Shodan scan...")
    results['shodan'] = scan_shodan(target)
    
    print("[*] Running Nmap scan...")
    results['nmap'] = scan_nmap(target)
    
    print("[*] Running subdomain scan...")
    results['subdomains'] = scan_subdomains(target)
    
    print("[✅] Scan complete!")
    return results