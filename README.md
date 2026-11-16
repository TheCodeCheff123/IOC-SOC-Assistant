
# IOC-SOC-Assistant

## Project Overview
The **IOC-SOC-Assistant** is a Python-based tool designed to automate the process of parsing suspicious email files, extracting indicators of compromise (IoCs), and integrating threat intelligence data. This reduces the alert fatigue in the phishing triage process by automatically querying threat intelligence APIs like VirusTotal, AbuseIPDB, and URLhaus.

## Key Features
- **Email Parsing**: Extracts headers, sender IP, return-path, URLs, and attachment hashes from .eml files.
- **Threat Intelligence Integration**: Automatically queries free or accessible APIs to check the reputation of extracted IPs, domains, and file hashes.
- **Risk Scoring Engine**: Evaluates findings (e.g., SPF failure + mismatched return-path + known malicious IP) and outputs a clear Risk Score (0-100) and verdict.
- **Structured Reporting**: Generates a clean Markdown or JSON incident report that a SOC analyst can copy straight into a ticketing system like Jira or ServiceNow.

## Installation & Setup Steps
1. **Clone the Repository**: 
   ```
   git clone https://github.com/yourusername/IOC-SOC-Assistant.git
   ```
2. **Install Dependencies**: 
   ```
   pip install -r requirements.txt
   ```
3. **Set Environment Variables**: 
   - Replace `YOUR_API_KEY_VIRUSTOTAL`, `YOUR_API_KEY_ABUSEIPDB`, and `YOUR_API_KEY_URLHAUS` with your actual API keys.
   ```bash
   export API_KEY_VIRUSTOTAL=YOUR_API_KEY_VIRUSTOTAL
   export API_KEY_ABUSEIPDB=YOUR_API_KEY_ABUSEIPDB
   export API_KEY_URLHAUS=YOUR_API_KEY_URLHAUS
   ```

## Usage Example
To run the script and process a suspicious email file named `suspicious.eml`:
```bash
python app.py --file suspicious.eml
```

## Author/Portfolio Note
This tool was written to demonstrate the capabilities of SOC automation and to provide a foundation for more complex and robust solutions. For more information or contributions, please contact [Your Contact Information].
