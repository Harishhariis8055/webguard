#!/usr/bin/env python3
"""
WebGuard - Website Firewall Detection Tool
A tool to detect web application firewalls and security measures on websites.
"""

import requests
import socket
import re
import sys
from urllib.parse import urlparse
import time
from typing import Dict, List, Tuple

class WebGuardScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebGuard-Scanner/1.0 (Security Research Tool)'
        })
        
    def normalize_url(self, url: str) -> str:
        """Normalize URL to ensure proper format"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    def get_server_info(self, url: str) -> Dict:
        """Get basic server information"""
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            return {
                'status_code': response.status_code,
                'server': headers.get('Server', 'Unknown'),
                'powered_by': headers.get('X-Powered-By', 'Unknown'),
                'headers': dict(headers),
                'response_time': response.elapsed.total_seconds(),
                'final_url': response.url
            }
        except Exception as e:
            return {'error': str(e)}
    
    def detect_cloudflare(self, headers: Dict, server_info: Dict) -> Dict:
        """Detect Cloudflare WAF"""
        cf_indicators = []
        confidence = 0
        
        # Check CF-specific headers
        cf_headers = ['cf-ray', 'cf-cache-status', 'cf-request-id', 'cf-visitor']
        for header in cf_headers:
            if any(header.lower() in h.lower() for h in headers.keys()):
                cf_indicators.append(f"CloudFlare header detected: {header}")
                confidence += 25
        
        # Check server header
        server = headers.get('Server', '').lower()
        if 'cloudflare' in server:
            cf_indicators.append("CloudFlare in Server header")
            confidence += 30
        
        # Check for CF IP ranges (simplified check)
        try:
            parsed_url = urlparse(server_info.get('final_url', ''))
            ip = socket.gethostbyname(parsed_url.netloc)
            # This is a simplified check - CloudFlare has many IP ranges
            if ip.startswith(('104.16.', '104.17.', '172.64.', '104.18.')):
                cf_indicators.append(f"IP {ip} appears to be CloudFlare")
                confidence += 20
        except:
            pass
        
        return {
            'detected': confidence > 30,
            'confidence': min(confidence, 100),
            'indicators': cf_indicators,
            'description': "CloudFlare is a popular CDN and Web Application Firewall that provides DDoS protection, caching, and security features."
        }
    
    def detect_aws_waf(self, headers: Dict) -> Dict:
        """Detect AWS WAF"""
        aws_indicators = []
        confidence = 0
        
        # Check for AWS-specific headers
        if 'x-amzn-requestid' in [h.lower() for h in headers.keys()]:
            aws_indicators.append("AWS Request ID header detected")
            confidence += 40
        
        if 'x-amz-cf-id' in [h.lower() for h in headers.keys()]:
            aws_indicators.append("AWS CloudFront ID detected")
            confidence += 35
        
        server = headers.get('Server', '').lower()
        if 'amazon' in server or 'aws' in server:
            aws_indicators.append("AWS/Amazon in Server header")
            confidence += 25
        
        return {
            'detected': confidence > 30,
            'confidence': min(confidence, 100),
            'indicators': aws_indicators,
            'description': "AWS WAF is Amazon's Web Application Firewall that helps protect web applications from common exploits."
        }
    
    def detect_incapsula(self, headers: Dict) -> Dict:
        """Detect Incapsula/Imperva WAF"""
        incap_indicators = []
        confidence = 0
        
        # Check for Incapsula-specific headers
        incap_headers = ['x-iinfo', 'x-cdn', 'incap-ses']
        for header in incap_headers:
            if any(header.lower() in h.lower() for h in headers.keys()):
                incap_indicators.append(f"Incapsula header detected: {header}")
                confidence += 35
        
        # Check for Incapsula in various headers
        for header_name, header_value in headers.items():
            if 'incap' in header_value.lower() or 'imperva' in header_value.lower():
                incap_indicators.append(f"Incapsula/Imperva reference in {header_name}")
                confidence += 30
        
        return {
            'detected': confidence > 30,
            'confidence': min(confidence, 100),
            'indicators': incap_indicators,
            'description': "Incapsula (now Imperva) is a cloud-based WAF that provides DDoS protection and application security."
        }
    
    def detect_sucuri(self, headers: Dict) -> Dict:
        """Detect Sucuri WAF"""
        sucuri_indicators = []
        confidence = 0
        
        # Check for Sucuri-specific headers
        if 'x-sucuri-id' in [h.lower() for h in headers.keys()]:
            sucuri_indicators.append("Sucuri ID header detected")
            confidence += 50
        
        server = headers.get('Server', '').lower()
        if 'sucuri' in server:
            sucuri_indicators.append("Sucuri in Server header")
            confidence += 40
        
        return {
            'detected': confidence > 30,
            'confidence': min(confidence, 100),
            'indicators': sucuri_indicators,
            'description': "Sucuri is a website security platform that provides WAF, malware scanning, and DDoS protection."
        }
    
    def detect_akamai(self, headers: Dict) -> Dict:
        """Detect Akamai WAF"""
        akamai_indicators = []
        confidence = 0
        
        # Check for Akamai-specific headers
        akamai_headers = ['akamai-origin-hop', 'x-akamai-transformed']
        for header in akamai_headers:
            if any(header.lower() in h.lower() for h in headers.keys()):
                akamai_indicators.append(f"Akamai header detected: {header}")
                confidence += 35
        
        server = headers.get('Server', '').lower()
        if 'akamai' in server:
            akamai_indicators.append("Akamai in Server header")
            confidence += 40
        
        return {
            'detected': confidence > 30,
            'confidence': min(confidence, 100),
            'indicators': akamai_indicators,
            'description': "Akamai is a CDN and cloud security platform that provides WAF and DDoS protection services."
        }
    
    def detect_generic_waf(self, headers: Dict) -> Dict:
        """Detect generic WAF indicators"""
        waf_indicators = []
        confidence = 0
        
        # Common WAF headers
        waf_headers = [
            'x-waf', 'x-firewall', 'x-security', 'x-protected-by',
            'x-sucuri-cache', 'x-mod-pagespeed', 'x-shield'
        ]
        
        for header in waf_headers:
            if any(header.lower() in h.lower() for h in headers.keys()):
                waf_indicators.append(f"WAF-related header: {header}")
                confidence += 20
        
        # Check for security-related server headers
        server = headers.get('Server', '').lower()
        security_keywords = ['security', 'firewall', 'guard', 'shield', 'protect']
        for keyword in security_keywords:
            if keyword in server:
                waf_indicators.append(f"Security keyword '{keyword}' in Server header")
                confidence += 15
        
        return {
            'detected': confidence > 20,
            'confidence': min(confidence, 100),
            'indicators': waf_indicators,
            'description': "Generic WAF or security solution detected based on common indicators."
        }
    
    def check_security_headers(self, headers: Dict) -> Dict:
        """Check for common security headers"""
        security_headers = {
            'Strict-Transport-Security': 'HSTS - Forces HTTPS connections',
            'Content-Security-Policy': 'CSP - Prevents XSS attacks',
            'X-Frame-Options': 'Prevents clickjacking attacks',
            'X-Content-Type-Options': 'Prevents MIME type sniffing',
            'X-XSS-Protection': 'Browser XSS protection',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Controls browser features'
        }
        
        found_headers = {}
        for header, description in security_headers.items():
            for h_name in headers.keys():
                if header.lower() == h_name.lower():
                    found_headers[header] = {
                        'value': headers[h_name],
                        'description': description
                    }
        
        return found_headers
    
    def scan_website(self, url: str) -> Dict:
        """Main scanning function"""
        print(f"🔍 Scanning {url}...")
        
        # Normalize URL
        url = self.normalize_url(url)
        
        # Get server information
        print("   → Getting server information...")
        server_info = self.get_server_info(url)
        
        if 'error' in server_info:
            return {'error': f"Failed to connect to {url}: {server_info['error']}"}
        
        headers = server_info['headers']
        
        # Detect various WAFs
        print("   → Detecting firewalls and security solutions...")
        detections = {
            'CloudFlare': self.detect_cloudflare(headers, server_info),
            'AWS WAF': self.detect_aws_waf(headers),
            'Incapsula/Imperva': self.detect_incapsula(headers),
            'Sucuri': self.detect_sucuri(headers),
            'Akamai': self.detect_akamai(headers),
            'Generic WAF': self.detect_generic_waf(headers)
        }
        
        # Check security headers
        print("   → Analyzing security headers...")
        security_headers = self.check_security_headers(headers)
        
        return {
            'url': url,
            'server_info': server_info,
            'waf_detections': detections,
            'security_headers': security_headers,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S')
        }

def print_results(results: Dict):
    """Print scan results in a formatted way"""
    if 'error' in results:
        print(f"\n❌ Error: {results['error']}")
        return
    
    print(f"\n{'='*60}")
    print(f"  WebGuard Scan Results")
    print(f"{'='*60}")
    print(f"URL: {results['url']}")
    print(f"Scan Time: {results['scan_time']}")
    
    # Server Information
    print(f"\n📋 Server Information:")
    server_info = results['server_info']
    print(f"   Status Code: {server_info.get('status_code', 'Unknown')}")
    print(f"   Server: {server_info.get('server', 'Unknown')}")
    print(f"   Powered By: {server_info.get('powered_by', 'Unknown')}")
    print(f"   Response Time: {server_info.get('response_time', 0):.2f}s")
    
    # WAF Detections
    print(f"\n🔥 Firewall/WAF Detection Results:")
    waf_detected = False
    
    for waf_name, detection in results['waf_detections'].items():
        if detection['detected']:
            waf_detected = True
            print(f"\n   ✅ {waf_name} DETECTED")
            print(f"      Confidence: {detection['confidence']}%")
            print(f"      Description: {detection['description']}")
            if detection['indicators']:
                print(f"      Indicators:")
                for indicator in detection['indicators']:
                    print(f"        • {indicator}")
    
    if not waf_detected:
        print("   ❌ No major WAF/Firewall detected")
        print("   ℹ️  This doesn't mean the site is unprotected - there might be:")
        print("      • Custom security solutions")
        print("      • Server-level firewalls")
        print("      • Network-level protection")
    
    # Security Headers
    print(f"\n🔒 Security Headers Analysis:")
    security_headers = results['security_headers']
    
    if security_headers:
        print("   ✅ Found security headers:")
        for header_name, header_info in security_headers.items():
            print(f"      • {header_name}: {header_info['description']}")
    else:
        print("   ⚠️  No common security headers detected")
        print("      Consider implementing: HSTS, CSP, X-Frame-Options, etc.")
    
    print(f"\n{'='*60}")

def main():
    print("🛡️  WebGuard - Website Firewall Detection Tool")
    print("="*50)
    print("This tool helps identify Web Application Firewalls and security measures.")
    print("Use responsibly and only scan websites you own or have permission to test.\n")
    
    scanner = WebGuardScanner()
    
    while True:
        try:
            # Get URL from user
            url = input("Enter website URL to scan (or 'quit' to exit): ").strip()
            
            if url.lower() in ['quit', 'q', 'exit']:
                print("👋 Goodbye!")
                break
            
            if not url:
                print("❌ Please enter a valid URL")
                continue
            
            # Perform scan
            results = scanner.scan_website(url)
            
            # Print results
            print_results(results)
            
            print("\n" + "="*60)
            
        except KeyboardInterrupt:
            print("\n\n👋 Scan interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()
