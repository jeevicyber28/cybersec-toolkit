import socket
import ipaddress
import urllib.request
import json
from typing import Dict, Any, List

def analyze_ip_and_domain(query: str, timeout: int = 3) -> Dict[str, Any]:
    """
    Performs IP threat intelligence, network range classification,
    reverse DNS lookups, and Geo-IP/ASN enrichment.
    """
    cleaned = query.strip()
    if '://' in cleaned:
        cleaned = cleaned.split('://')[1].split('/')[0].split(':')[0]
    else:
        cleaned = cleaned.split('/')[0].split(':')[0]

    result: Dict[str, Any] = {
        'query': query,
        'cleaned_target': cleaned,
        'ip': None,
        'is_ip_address': False,
        'ip_version': 4,
        'classification': 'Unknown',
        'is_private': False,
        'is_loopback': False,
        'is_global': False,
        'reverse_dns': None,
        'geo_info': {},
        'dns_records': {},
        'risk_indicators': [],
        'error': None
    }

    # Determine if input is raw IP or domain
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        result['ip'] = str(ip_obj)
        result['is_ip_address'] = True
        result['ip_version'] = ip_obj.version
        result['is_private'] = ip_obj.is_private
        result['is_loopback'] = ip_obj.is_loopback
        result['is_global'] = ip_obj.is_global

        if ip_obj.is_loopback:
            result['classification'] = 'Loopback (Localhost Host-Only)'
        elif ip_obj.is_private:
            result['classification'] = 'Private Network (RFC 1918 / Non-Routable)'
        elif ip_obj.is_reserved:
            result['classification'] = 'Reserved / IETF Special Purpose'
        elif ip_obj.is_multicast:
            result['classification'] = 'Multicast Range'
        elif ip_obj.is_global:
            result['classification'] = 'Publicly Routable Internet IP'
        else:
            result['classification'] = 'Special Purpose Address'

    except ValueError:
        # It's a hostname / domain
        result['is_ip_address'] = False
        try:
            resolved_ip = socket.gethostbyname(cleaned)
            result['ip'] = resolved_ip
            ip_obj = ipaddress.ip_address(resolved_ip)
            result['ip_version'] = ip_obj.version
            result['is_private'] = ip_obj.is_private
            result['is_loopback'] = ip_obj.is_loopback
            result['is_global'] = ip_obj.is_global
            result['classification'] = 'Publicly Routable' if ip_obj.is_global else 'Private / Internal'
        except Exception as e:
            result['error'] = f"Unable to resolve domain '{cleaned}': {str(e)}"
            return result

    # Reverse DNS PTR
    if result['ip']:
        try:
            ptr_name, _, _ = socket.gethostbyaddr(result['ip'])
            result['reverse_dns'] = ptr_name
        except Exception:
            result['reverse_dns'] = 'No PTR record registered'

    # DNS Record Enumeration for Domains
    if not result['is_ip_address']:
        records: Dict[str, List[str]] = {'A': [], 'AAAA': []}
        try:
            # IPv4
            a_info = socket.getaddrinfo(cleaned, None, socket.AF_INET)
            records['A'] = sorted(list(set([item[4][0] for item in a_info])))
        except Exception:
            pass

        try:
            # IPv6
            aaaa_info = socket.getaddrinfo(cleaned, None, socket.AF_INET6)
            records['AAAA'] = sorted(list(set([item[4][0] for item in aaaa_info])))
        except Exception:
            pass

        result['dns_records'] = records

    # Geo-IP & ASN Enrichment (Only for Global Public IPs)
    if result['is_global'] and result['ip']:
        try:
            geo_url = f"http://ip-api.com/json/{result['ip']}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            req = urllib.request.Request(geo_url, headers={'User-Agent': 'CyberSecToolkit/2.0'})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                geo_data = json.loads(response.read().decode('utf-8'))
                if geo_data.get('status') == 'success':
                    result['geo_info'] = {
                        'country': geo_data.get('country'),
                        'country_code': geo_data.get('countryCode'),
                        'city': geo_data.get('city'),
                        'region': geo_data.get('regionName'),
                        'zip': geo_data.get('zip'),
                        'isp': geo_data.get('isp'),
                        'org': geo_data.get('org'),
                        'asn': geo_data.get('as'),
                        'lat': geo_data.get('lat'),
                        'lon': geo_data.get('lon'),
                        'timezone': geo_data.get('timezone')
                    }
        except Exception as e:
            result['geo_info'] = {'notice': f'Live GeoIP lookup skipped ({str(e)})'}

    # Threat & Suspicious Signals
    lower_target = cleaned.lower()
    if any(lower_target.endswith(t) for t in ['.duckdns.org', '.ngrok.io', '.localtunnel.me', '.no-ip.org']):
        result['risk_indicators'].append('Uses dynamic DNS or tunnel service frequently abused by threat actors for C2/phishing.')

    if result['is_ip_address'] and result['is_global']:
        result['risk_indicators'].append('Raw IP address entered instead of domain name (often used to bypass domain reputation blocklists).')

    return result
