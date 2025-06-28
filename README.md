# WebGuard - Website Firewall Detection Tool

A Python tool for detecting Web Application Firewalls (WAF) and security measures on websites. This tool helps security researchers, developers, and website owners understand the security posture of web applications.

## Legal Disclaimer

**IMPORTANT**: This tool is intended for legitimate security research and testing. Only use it on:
- Websites you own
- Websites you have explicit permission to test
- Public websites for educational purposes (passive scanning only)

Unauthorized scanning of websites may violate terms of service or local laws. Use responsibly.

## Features

- **Multi-WAF Detection**: Identifies popular WAF solutions including:
  - CloudFlare
  - AWS WAF
  - Incapsula/Imperva
  - Sucuri
  - Akamai
  - Generic WAF indicators

- **Security Headers Analysis**: Checks for important security headers:
  - HSTS (HTTP Strict Transport Security)
  - CSP (Content Security Policy)
  - X-Frame-Options
  - X-Content-Type-Options
  - X-XSS-Protection
  - And more...

- **Server Information**: Gathers basic server details
- **Confidence Scoring**: Provides confidence levels for detections
- **Interactive Interface**: User-friendly command-line interface

## 📋 Requirements

- Python 3.6 or higher
- `requests` library

## 🛠Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/webguard.git
cd webguard
```

### 2. Install dependencies
```bash
pip install requests
```

### 3. Make executable (optional)
```bash
chmod +x webguard.py
```

## Usage

### Basic Usage
```bash
python3 webguard.py
```

### Example Session
```
🛡WebGuard - Website Firewall Detection Tool
==================================================
Enter website URL to scan (or 'quit' to exit): example.com

Scanning https://example.com...
   → Getting server information...
   → Detecting firewalls and security solutions...
   → Analyzing security headers...

============================================================
🛡WebGuard Scan Results
============================================================
URL: https://example.com
Scan Time: 2025-01-15 10:30:45

📋 Server Information:
   Status Code: 200
   Server: cloudflare
   Powered By: Unknown
   Response Time: 0.45s

Firewall/WAF Detection Results:

   ✅ CloudFlare DETECTED
      Confidence: 85%
      Description: CloudFlare is a popular CDN and Web Application Firewall that provides DDoS protection, caching, and security features.
      Indicators:
        • CloudFlare header detected: cf-ray
        • CloudFlare in Server header
        • IP 104.16.132.229 appears to be CloudFlare

🔒 Security Headers Analysis:
   ✅ Found security headers:
      • Strict-Transport-Security: HSTS - Forces HTTPS connections
      • X-Frame-Options: Prevents clickjacking attacks
```

## 🔍 What WebGuard Detects

### WAF/Firewall Solutions
| WAF Provider | Detection Method |
|--------------|------------------|
| **CloudFlare** | CF headers, IP ranges, server signatures |
| **AWS WAF** | AWS-specific headers, CloudFront indicators |
| **Incapsula/Imperva** | Incapsula headers, response signatures |
| **Sucuri** | Sucuri-specific headers and server info |
| **Akamai** | Akamai headers and signatures |
| **Generic WAF** | Common WAF headers and keywords |

### Security Headers
- **HSTS**: HTTP Strict Transport Security
- **CSP**: Content Security Policy
- **X-Frame-Options**: Clickjacking protection
- **X-Content-Type-Options**: MIME sniffing protection
- **X-XSS-Protection**: Cross-site scripting protection
- **Referrer-Policy**: Referrer information control
- **Permissions-Policy**: Browser feature control

## 📊 Understanding Results

### Confidence Levels
- **90-100%**: Very high confidence - multiple strong indicators
- **70-89%**: High confidence - strong indicators present
- **50-69%**: Medium confidence - some indicators found
- **30-49%**: Low confidence - weak indicators
- **Below 30%**: Not detected

### Indicators
Each detection includes specific indicators that triggered the identification:
- Header analysis
- Server signature analysis
- IP range analysis (for some providers)
- Response pattern analysis

## 🔧 Advanced Usage

### Scanning Multiple Sites
You can scan multiple websites in sequence by running the tool and entering different URLs when prompted.

### Automated Scanning
For batch scanning, you could modify the script or create a wrapper script that reads URLs from a file.

## 🚨 Limitations

- **Passive Detection Only**: Uses only HTTP headers and responses
- **No Payload Testing**: Doesn't send malicious payloads
- **False Positives**: Some detections might be incorrect
- **False Negatives**: Some WAFs might not be detected
- **Rate Limiting**: Some sites may rate-limit requests

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-waf-detection`)
3. Commit your changes (`git commit -m 'Add detection for XYZ WAF'`)
4. Push to the branch (`git push origin feature/new-waf-detection`)
5. Open a Pull Request

### Adding New WAF Detection
To add detection for a new WAF:
1. Create a new detection method following the existing pattern
2. Add it to the `scan_website` method
3. Test with known instances of the WAF
4. Update the README

## 📝 License

This project is licensed under the MIT License - see the [LICENSE] file for details.

## ⚖️ Ethical Use

This tool is designed for:
- Security research and education
- Penetration testing (with proper authorization)
- Understanding your own website's security
- Academic research

**Please use responsibly and ethically.**

## 🔗 Related Tools

- **Wappalyzer**: Technology detection
- **Whatweb**: Web application fingerprinting
- **Nmap**: Network discovery and security auditing
- **Nikto**: Web vulnerability scanner

## 📞 Support

If you encounter issues or have questions:
1. Check the existing issues on GitHub
2. Create a new issue with detailed information
3. Include the full error message and steps to reproduce

## 🏆 Acknowledgments

- Thanks to the security research community
- Inspired by various WAF detection tools
- Built with Python and the `requests` library

---

**Remember**: Always obtain proper authorization before scanning websites you don't own!
