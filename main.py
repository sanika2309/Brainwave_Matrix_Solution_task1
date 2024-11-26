import requests
import re
import socket
import ssl
from urllib.parse import urlparse


# Function to check for suspicious patterns
def is_suspicious_pattern(url) :
    suspicious_patterns = [
        r'\b(?:http|https):\/\/(?:www\.)?example\.com\b',  # Replace with actual patterns
        r'\b(?:http|https):\/\/(?:www\.)?phishing-site\.com\b',  # Replace with actual patterns
        r'\b(?:http|https):\/\/[A-Za-z0-9-]+\.[A-Za-z]{2,}\.[A-Za-z]{2,}\b',  # Example pattern
    ]

    for pattern in suspicious_patterns :
        if re.search(pattern, url) :
            return True
    return False


# Function to check DNS resolution
def check_dns(url) :
    domain = urlparse(url).netloc
    try :
        socket.gethostbyname(domain)
        return True
    except socket.gaierror :
        return False


# Function to check SSL certificate
def check_ssl(url) :
    domain = urlparse(url).netloc
    try :
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as s :
            s.connect((domain, 443))
        return True
    except Exception as e :
        return False


# Main function to run the scanner
def main() :
    url_to_scan = input("Enter the URL to scan: ")

    print("Scanning URL...")

    # Check for suspicious patterns
    if is_suspicious_pattern(url_to_scan) :
        print("Suspicious pattern detected!")
    else :
        print("No suspicious patterns found.")

    # Check DNS resolution
    if check_dns(url_to_scan) :
        print("DNS resolution successful.")
    else :
        print("DNS resolution failed.")

    # Check SSL certificate
    if check_ssl(url_to_scan) :
        print("SSL certificate is valid.")
    else :
        print("SSL certificate is invalid or not present.")

    # Final verdict
    if is_suspicious_pattern(url_to_scan) or not check_dns(url_to_scan) or not check_ssl(url_to_scan) :
        print("Verdict: Potentially unsafe link.")
    else :
        print("Verdict: Safe link.")


if __name__ == "__main__" :
    main()