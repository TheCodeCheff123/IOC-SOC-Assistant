# Issues Faced and Fixes

This document records the errors encountered while getting email parsing, threat-intelligence lookups, and report generation working. No API keys or other secrets are included.

## Resolved Issues

### Email subject decoding

The original code assumed the `Subject` header always existed and that its decoded value was bytes. Email headers can be absent or already represented as strings, so that assumption could fail. Subject decoding now handles an empty header, decodes byte values using the declared encoding (or UTF-8), and replaces invalid byte sequences instead of crashing.

### Sender header decoding

With `BytesParser(policy=policy.default)`, the `From` header is an address-header object, not necessarily bytes. Calling `.decode()` on it raised an `AttributeError`. The parser now converts the header to a string.

### Attachment hashing

The parser passed an attachment's filename (for example, `Invoice_99281.pdf.exe`) to a function that opens filesystem paths. The attachment was embedded in the email, not present as a file at that path, causing `FileNotFoundError`. Hashes are now calculated from the decoded attachment contents.

### Saving the incident report

`markdown` was local to `generate_report()`, but `main()` tried to write it without receiving that value, causing a `NameError`. `generate_report()` now returns the Markdown and `main()` writes the returned value to `incident_report.md`.

### VirusTotal endpoint and response format

The initial request sent a hash to the VirusTotal `/files` collection endpoint instead of looking up that hash at `/files/{hash}`. This produced a 400 response. The lookup now uses the file-specific endpoint, and risk scoring reads VirusTotal's v3 analysis results rather than the older response shape. A 404 for a hash with no existing report is skipped.

### API-key environment variable names

`app.py` reads `API_KEY_VIRUSTOTAL`, `API_KEY_ABUSEIPDB`, and `API_KEY_URLHAUS` from the environment. The `.env` file initially used names in the opposite order, such as `VIRUSTOTAL_API_KEY`, so those values were not found by `os.getenv()`. The names were aligned with what the application reads. A VirusTotal 401 still means the configured key was rejected; the key must be valid and have API access. The key itself is intentionally not documented here.

## Known Issues Not Yet Fixed

### AbuseIPDB response handling

The AbuseIPDB response is passed into risk scoring, but the scoring code makes another API call and checks whether the string `malicious` is a key in the response object. It does not evaluate AbuseIPDB's response fields, so its result may not affect the score correctly.

### URLhaus response handling

`call_api()` already returns decoded JSON, but `check_urlhaus()` calls `.json()` on that returned value again. The later scoring and report code also expects fields that may not match the URLhaus endpoint's response format. As a result, URL checks can fail or be scored incorrectly.

### Git push refspec

The message `src refspec main does not match any` means Git could not find a local ref named `main` to push, commonly because the local branch has another name or no commit exists yet. This is separate from application behavior and was not changed as part of the code fixes; check the current branch and commit history before pushing.
