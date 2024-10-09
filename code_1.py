import re
import requests
import socket
import ssl
import whois
from datetime import datetime

# Basic phishing patterns
PHISHING_KEYWORDS = ['login', 'update', 'secure', 'account', 'bank', 'signin', 'verify']
BLACKLISTED_DOMAINS = ['malicious.com', 'phishing-site.com', 'bad-domain.org']

# Function to check for phishing patterns in URL
def check_url_patterns(url):
    # Check for phishing keywords in the URL
    for keyword in PHISHING_KEYWORDS:
        if keyword in url.lower():
            return True, f"Suspicious keyword '{keyword}' found in URL"
    
    # Check if the URL is too long or has unusual characters
    if len(url) > 75:
        return True, "URL length exceeds safe threshold (75 characters)"
    
    # Check for uncommon special characters in URL
    if re.search(r"[@#\$%^&*()<>?/\|}{~:]", url):
        return True, "URL contains unusual characters"
    
    return False, "URL pattern seems safe"

# Function to check if the domain is blacklisted
def check_blacklist(url):
    domain = url.split("/")[2]  # Extract domain from URL
    if domain in BLACKLISTED_DOMAINS:
        return True, f"Domain '{domain}' is blacklisted"
    return False, "Domain is not blacklisted"

# Function to check SSL certificate validity
def check_ssl_certificate(url):
    try:
        domain = url.split("/")[2]  # Extract domain from URL
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.connect((domain, 443))
        ssl_info = conn.getpeercert()
        if ssl_info:
            expiry_date = datetime.strptime(ssl_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
            if expiry_date < datetime.now():
                return True, "SSL certificate is expired"
            else:
                return False, "SSL certificate is valid"
    except Exception:
        return True, "SSL certificate check failed"

# Function to check domain age using WHOIS
def check_domain_age(url):
    try:
        domain = url.split("/")[2]  # Extract domain from URL
        whois_info = whois.whois(domain)
        creation_date = whois_info.creation_date
        
        if isinstance(creation_date, list):  # Handle case where multiple dates are returned
            creation_date = creation_date[0]
        
        age_days = (datetime.now() - creation_date).days
        
        if age_days < 30:  # If domain is younger than 30 days, it's suspicious
            return True, f"Domain age is suspicious: {age_days} days old"
        else:
            return False, f"Domain is {age_days} days old"
    except Exception:
        return True, "Failed to retrieve domain age"

# Main function to scan the URL
def scan_url(url):
    # Step 1: Check for phishing patterns
    phishing_flag, phishing_msg = check_url_patterns(url)
    if phishing_flag:
        return f"Phishing detected: {phishing_msg}"
    
    # Step 2: Check against blacklist
    blacklist_flag, blacklist_msg = check_blacklist(url)
    if blacklist_flag:
        return f"Warning: {blacklist_msg}"
    
    # Step 3: SSL certificate validation
    ssl_flag, ssl_msg = check_ssl_certificate(url)
    if ssl_flag:
        return f"SSL issue: {ssl_msg}"
    
    # Step 4: Domain age check
    age_flag, age_msg = check_domain_age(url)
    if age_flag:
        return f"Warning: {age_msg}"

    return "The URL appears safe."

# Example usage
if __name__ == "__main__":
    url_to_scan = input("Enter URL to scan: ")
    result = scan_url(url_to_scan)
    print(result)
