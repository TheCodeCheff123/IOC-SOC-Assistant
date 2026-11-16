
# IOC-SOC-Assistant

## Project Overview
The **IOC-SOC-Assistant** is a Python-based tool designed to automate the process of parsing suspicious email files, extracting indicators of compromise (IoCs), and integrating threat intelligence data. This reduces the alert fatigue in the phishing triage process by automatically querying threat intelligence APIs like VirusTotal, AbuseIPDB, and URLhaus.

## Key Features
- **Email Parsing**: Extracts headers, sender IP, return-path, URLs, and attachment hashes from .eml files.
- **Threat Intelligence Integration**: Automatically queries free or accessible APIs to check the reputation of extracted IPs, domains, and file hashes.
- **Risk Scoring Engine**: Evaluates findings (e.g., SPF failure + mismatched return-path + known malicious IP) and outputs a clear Risk Score (0-100) and verdict.
- **Structured Reporting**: Prints and saves a Markdown incident report as `incident_report.md`.

## Threat Intelligence APIs

The project extracts indicators from an email and uses these services to add reputation context:

| API | Indicator checked | Purpose in this project |
| --- | --- | --- |
| VirusTotal | SHA-256 hashes of attachments | Looks up existing file analysis and detection results. |
| AbuseIPDB | Sender IP address | Checks whether the sender IP has been reported for abusive activity. |
| URLhaus | URLs found in the email | Checks whether a URL is associated with malware distribution. |

These results are intended to contribute to the email's risk score. VirusTotal is queried using its file-hash lookup endpoint. Review [ISSUES_FACED.md](./ISSUES_FACED.md) for known response-parsing limitations in the AbuseIPDB and URLhaus integrations.

## Installation & Setup Steps
1. **Clone the Repository**: 
   ```
   git clone https://github.com/yourusername/IOC-SOC-Assistant.git
   ```
2. **Install Dependencies**: 
   ```
   pip install -r requirements.txt
   ```
3. **Configure API Keys**: Add your own keys to a local `.env` file using the exact variable names read by `app.py`:
   ```bash
   API_KEY_VIRUSTOTAL=your_virustotal_key
   API_KEY_ABUSEIPDB=your_abuseipdb_key
   API_KEY_URLHAUS=your_urlhaus_key
   ```
   Keep real keys private. `.env` is listed in `.gitignore`; do not commit it.

## Usage Example
Pass the path to a suspicious email file as the script's single argument:
```bash
python app.py suspicious.eml
```
The generated report is written to `incident_report.md` in the current working directory.

## Author/Portfolio Note
This tool was written to demonstrate the capabilities of SOC automation and to provide a foundation for more complex and robust solutions. For more information or contributions, please contact [Your Contact Information].
