# app.py

import os
import subprocess
import json
from email import policy
from email.parser import BytesParser
from email.header import decode_header
from email.utils import parseaddr
import hashlib
import requests
import tempfile
import time
import yaml
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Read API keys from environment variables
API_KEY_VIRUSTOTAL = os.getenv('API_KEY_VIRUSTOTAL')
API_KEY_ABUSEIPDB = os.getenv('API_KEY_ABUSEIPDB')
API_KEY_URLHAUS = os.getenv('API_KEY_URLHAUS')

def parse_email(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    raw_subject, encoding = decode_header(msg['Subject'] or '')[0]
    if isinstance(raw_subject, bytes):
        subject = raw_subject.decode(encoding or 'utf-8', errors='replace')
    else:
        subject = str(raw_subject)
    sender_email = str(msg['From'] or '')
    sender_ip = None
    sender_return_path = None
    urls = []
    attachments = []
    hashes = []

    def decode_email_value(value, encoding='utf-8'):
        if isinstance(value, bytes):
            value = value.decode(encoding)
        return value

    if 'Return-Path' in msg:
        sender_return_path = decode_email_value(msg['Return-Path'])
    
    if 'Received' in msg:
        for header in msg['Received']:
            if header[0].lower() == 'from' and len(header) >= 3:
                sender_email, encoding = header[2]
                sender_email = decode_email_value(sender_email, encoding)
                sender_ip = parseaddr(sender_email)[1]

    for part in msg.walk():
        if part.get_content_maintype() == 'text':
            text = part.get_payload(decode=True).decode()
            for url in part.get_all('Link', []):
                urls.append(url['href'].decode())
        
        if part.get_filename():
            attachment_data = part.get_payload(decode=True)
            if attachment_data is None:
                raise ValueError(f"Unable to decode attachment: {part.get_filename()}")

            hashes.append(get_attachment_hash(attachment_data))
            if part.get_filename().endswith('.eml'):
                with tempfile.NamedTemporaryFile(delete=False, dir=os.path.dirname(file_path)) as temp:
                    temp.write(attachment_data)
                    temp_path = temp.name
                    attachments.append(temp_path)

    return {
        'subject': subject,
        'sender_email': sender_email,
        'sender_ip': sender_ip,
        'sender_return_path': sender_return_path,
        'urls': urls,
        'attachments': attachments,
        'hashes': hashes
    }

def get_attachment_hash(attachment_data):
    return hashlib.sha256(attachment_data).hexdigest()

def call_api(api_key, url, data=None, method='GET'):
    headers = {'x-apikey': api_key}
    response = requests.request(method, url, headers=headers, data=data)
    response.raise_for_status()
    return response.json()

def check_abuseipdb(sender_ip):
    if sender_ip:
        return call_api(API_KEY_ABUSEIPDB, f'https://api.abuseipdb.com/v2/check?ip={sender_ip}')
    return []

def check_virustotal(file_hashes):
    if file_hashes:
        if not API_KEY_VIRUSTOTAL:
            raise RuntimeError('Set a valid API_KEY_VIRUSTOTAL in your environment or .env file.')

        results = {}
        for file_hash in file_hashes:
            try:
                results[file_hash] = call_api(
                    API_KEY_VIRUSTOTAL,
                    f'https://www.virustotal.com/api/v3/files/{file_hash}'
                )
            except requests.HTTPError as error:
                if error.response is not None and error.response.status_code == 404:
                    continue
                if error.response is not None and error.response.status_code == 401:
                    raise RuntimeError(
                        'VirusTotal rejected API_KEY_VIRUSTOTAL. Check that it is a valid API key '
                        'with access to the VirusTotal API.'
                    ) from error
                raise
        return results
    return {}

def check_urlhaus(urls):
    if urls:
        results = {}
        for url in urls:
            response = call_api(API_KEY_URLHAUS, f'https://urlhaus.abuse.ch/v2/search/?q=url:{url}')
            results[url] = response.json()
        return results
    return {}

def calculate_risk_score(subject, sender_email, sender_ip, sender_return_path, urls, hashes, abuseipdb_results, virustotal_results, urlhaus_results):
    risk_score = 0
    
    if sender_email != sender_return_path:
        risk_score += 25
    
    if sender_ip and 'malicious' in check_abuseipdb(sender_ip):
        risk_score += 40
    
    for result in virustotal_results.values():
        analysis_results = result['data']['attributes'].get('last_analysis_results', {})
        for threat in analysis_results.values():
            if threat.get('category') == 'malicious':
                risk_score += 10
            threat_info = (threat.get('result') or '').lower()
            if 'malware' in threat_info:
                risk_score += 20
            if 'phishing' in threat_info:
                risk_score += 15
    
    for url, result in urlhaus_results.items():
        if result['response_code'] == 404:
            continue
        if 'malicious' in result['metadata']:
            risk_score += 20
    
    for url in urls:
        if 'malicious' in check_urlhaus(url).get('category', ''):
            risk_score += 10
    
    return risk_score

def generate_report(subject, sender_email, sender_ip, sender_return_path, urls, hashes, risk_score):
    markdown = f"### Email Incident Report\n\n**Subject:** {subject}\n\n**Sender:** {sender_email} ({sender_ip} / {sender_return_path})\n\n**Attachments:** {', '.join(hashes)}\n\n**Malicious URLs:** {', '.join(url for url in urls if 'malicious' in check_urlhaus(url).get('category', ''))}\n\n**Risk Score:** {risk_score} / 100\n\n**Verdict:** {'SAFE' if risk_score < 20 else 'SUSPICIOUS' if risk_score < 40 else 'MALICIOUS'}\n\nFor more details, please review the full report."

    print(markdown)
    return markdown

def main(file_path):
    # Validate file path
    if not os.path.isfile(file_path):
        raise ValueError(f"File not found: {file_path}")
    
    # Parse email
    email_data = parse_email(file_path)
    sender_email = email_data['sender_email']
    sender_ip = email_data['sender_ip']
    sender_return_path = email_data['sender_return_path']
    urls = email_data['urls']
    hashes = email_data['hashes']
    
    # Perform threat intelligence checks
    abuseipdb_results = check_abuseipdb(sender_ip)
    virustotal_results = check_virustotal(hashes)
    urlhaus_results = check_urlhaus(urls)
    
    # Calculate risk score
    risk_score = calculate_risk_score(
        email_data['subject'],
        sender_email,
        sender_ip,
        sender_return_path,
        urls,
        hashes,
        abuseipdb_results,
        virustotal_results,
        urlhaus_results
    )
    
    # Generate report
    markdown = generate_report(email_data['subject'], sender_email, sender_ip, sender_return_path, urls, hashes, risk_score)
    
    # Save report to file
    with open('incident_report.md', 'w') as report_file:
        report_file.write(markdown)
    
    print("Incident report saved to incident_report.md")

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print("Usage: python app.py <path_to_email_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    main(file_path)
    