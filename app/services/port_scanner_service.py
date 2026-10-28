import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List

COMMON_PORTS = [
    {
        'port': 21,
        'service': 'FTP',
        'proto': 'TCP',
        'risk': 'Medium',
        'risk_class': 'warning',
        'desc': 'File Transfer Protocol. Often transmits credentials in cleartext.',
        'remediation': 'Switch to SFTP (Port 22) or FTPS with TLS encryption.'
    },
    {
        'port': 22,
        'service': 'SSH',
        'proto': 'TCP',
        'risk': 'Low',
        'risk_class': 'success',
        'desc': 'Secure Shell. Encrypted remote administration.',
        'remediation': 'Disable root login, enforce public-key authentication, and use Fail2ban.'
    },
    {
        'port': 23,
        'service': 'Telnet',
        'proto': 'TCP',
        'risk': 'Critical',
        'risk_class': 'danger',
        'desc': 'Legacy cleartext terminal. Passwords and commands are sent in plain text over the wire!',
        'remediation': 'IMMEDIATELY disable Telnet daemon and replace with SSH (Port 22).'
    },
    {
        'port': 25,
        'service': 'SMTP',
        'proto': 'TCP',
        'risk': 'Medium',
        'risk_class': 'warning',
        'desc': 'Simple Mail Transfer Protocol.',
        'remediation': 'Ensure STARTTLS is enforced and open relaying is disabled.'
    },
    {
        'port': 53,
        'service': 'DNS',
        'proto': 'TCP',
        'risk': 'Low',
        'risk_class': 'info',
        'desc': 'Domain Name System name resolution.',
        'remediation': 'Prevent open DNS recursion to avoid DNS amplification DDoS attacks.'
    },
    {
        'port': 80,
        'service': 'HTTP',
        'proto': 'TCP',
        'risk': 'Medium',
        'risk_class': 'warning',
        'desc': 'Unencrypted World Wide Web traffic.',
        'remediation': 'Enforce automatic 301 redirection to HTTPS (Port 443).'
    },
    {
        'port': 110,
        'service': 'POP3',
        'proto': 'TCP',
        'risk': 'Medium',
        'risk_class': 'warning',
        'desc': 'Cleartext email retrieval protocol.',
        'remediation': 'Upgrade to POP3S (Port 995) or IMAPS (Port 993) with TLS.'
    },
    {
        'port': 143,
        'service': 'IMAP',
        'proto': 'TCP',
        'risk': 'Medium',
        'risk_class': 'warning',
        'desc': 'Internet Message Access Protocol.',
        'remediation': 'Enforce IMAPS (Port 993) with mandatory TLS encryption.'
    },
    {
        'port': 443,
        'service': 'HTTPS',
        'proto': 'TCP',
        'risk': 'Low',
        'risk_class': 'success',
        'desc': 'Encrypted web transport via TLS.',
        'remediation': 'Enforce TLS 1.2+ only; disable deprecated TLS 1.0 and 1.1.'
    },
    {
        'port': 445,
        'service': 'SMB',
        'proto': 'TCP',
        'risk': 'Critical',
        'risk_class': 'danger',
        'desc': 'Server Message Block. Prime target for EternalBlue exploits and lateral ransomware propagation.',
        'remediation': 'BLOCK Port 445 at firewall boundary! Never expose SMB directly to the public internet.'
    },
    {
        'port': 3306,
        'service': 'MySQL',
        'proto': 'TCP',
        'risk': 'High',
        'risk_class': 'danger',
        'desc': 'MySQL / MariaDB database server.',
        'remediation': 'Bind to 127.0.0.1 or private VPC only. Never expose database ports to the internet.'
    },
    {
        'port': 3389,
        'service': 'RDP',
        'proto': 'TCP',
        'risk': 'High',
        'risk_class': 'danger',
        'desc': 'Windows Remote Desktop Protocol. Frequent target for credential brute-force and BlueKeep.',
        'remediation': 'Put RDP behind a VPN, enforce Network Level Authentication (NLA) and MFA.'
    },
    {
        'port': 5432,
        'service': 'PostgreSQL',
        'proto': 'TCP',
        'risk': 'High',
        'risk_class': 'danger',
        'desc': 'PostgreSQL relational database server.',
        'remediation': 'Restrict pg_hba.conf to trusted subnet and enforce TLS client certs.'
    },
    {
        'port': 8080,
        'service': 'HTTP-Alt',
        'proto': 'TCP',
        'risk': 'Medium',
        'risk_class': 'warning',
        'desc': 'Alternate HTTP / Proxy / Dev server.',
        'remediation': 'Ensure administrative dashboards (e.g. Tomcat/Jenkins) have strong authentication.'
    }
]

def check_single_port(ip: str, port_info: Dict[str, Any], timeout: float = 0.8) -> Dict[str, Any]:
    port = port_info['port']
    start_time = time.time()
    is_open = False
    latency_ms = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        latency_ms = round((time.time() - start_time) * 1000, 1)
        if result == 0:
            is_open = True
        sock.close()
    except Exception:
        is_open = False

    return {
        'port': port,
        'service': port_info['service'],
        'proto': port_info['proto'],
        'is_open': is_open,
        'status': 'OPEN' if is_open else 'CLOSED',
        'latency_ms': latency_ms if is_open else None,
        'risk': port_info['risk'],
        'risk_class': port_info['risk_class'],
        'desc': port_info['desc'],
        'remediation': port_info['remediation']
    }

def audit_host_ports(host: str) -> Dict[str, Any]:
    """
    Performs non-intrusive port hygiene audit against the specified host.
    """
    cleaned_host = host.strip().lower()
    # Remove protocol prefix if entered
    if '://' in cleaned_host:
        cleaned_host = cleaned_host.split('://')[1].split('/')[0].split(':')[0]
    else:
        cleaned_host = cleaned_host.split('/')[0].split(':')[0]

    try:
        target_ip = socket.gethostbyname(cleaned_host)
    except Exception as e:
        return {
            'target': host,
            'hostname': cleaned_host,
            'ip': None,
            'error': f'DNS resolution failed for {cleaned_host}: {str(e)}',
            'open_ports_count': 0,
            'ports': [],
            'critical_findings': []
        }

    port_results = []
    critical_findings = []

    # Safe concurrent check
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_map = {
            executor.submit(check_single_port, target_ip, p): p
            for p in COMMON_PORTS
        }
        for future in as_completed(future_map):
            try:
                res = future.result()
                port_results.append(res)
                if res['is_open'] and res['risk'] in ['High', 'Critical']:
                    critical_findings.append({
                        'port': res['port'],
                        'service': res['service'],
                        'risk': res['risk'],
                        'remediation': res['remediation']
                    })
            except Exception:
                pass

    # Sort results by port number
    port_results.sort(key=lambda x: x['port'])
    open_count = sum(1 for p in port_results if p['is_open'])

    # Calculate overall hygiene score (100 is cleanest)
    hygiene_score = 100
    for cf in critical_findings:
        if cf['risk'] == 'Critical':
            hygiene_score -= 30
        elif cf['risk'] == 'High':
            hygiene_score -= 15
    hygiene_score = max(10, hygiene_score)

    return {
        'target': host,
        'hostname': cleaned_host,
        'ip': target_ip,
        'error': None,
        'open_ports_count': open_count,
        'total_scanned': len(COMMON_PORTS),
        'hygiene_score': hygiene_score,
        'ports': port_results,
        'critical_findings': critical_findings
    }
