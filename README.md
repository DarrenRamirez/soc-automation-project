# 🛡️ SOC Automation Project – Wazuh, Shuffle, TheHive, and VirusTotal

## Project Overview
This project demonstrates an automated Security Operations Center (**SOC**) workflow integrating **Wazuh**, **Shuffle**, **TheHive**, and **VirusTotal** for **threat detection, alert enrichment, and incident management**.

### **Tools Used:**
- **Wazuh:** Security monitoring and alerting
- **Shuffle:** Automation and orchestration
- **TheHive:** Incident response and case management
- **VirusTotal:** Threat intelligence enrichment

## High-Level Workflow Steps
### 1️⃣ **Event Detection – Wazuh Agent & Manager**
- **Wazuh Agent** on endpoints collects security events (e.g., Mimikatz detection).
  
<img src="https://imgur.com/OEtBgAw.png" alt="Imgur Image" />

*Ref 1: Begin the instance of mimikatz on a virtual machine*

- Events are forwarded to **Wazuh Manager**, which analyzes them using detection rules.

<img src="https://imgur.com/PZarXhJ.png" alt="Imgur Image" />

*Ref 2: Rule set in Wazuh for mimikats detection*

- **Alerts are generated** and sent to **Shuffle** via API.

### 2️⃣ **Alert Processing – Shuffle SOAR**
- **Shuffle** receives alerts from **Wazuh Manager**.

<img src="https://imgur.com/iMeLDso.png" alt="Imgur Image" />

*Ref 3: Shuffle output from wazuh via a webhook*

- **Extracts key observables** (e.g., **SHA256 hashes, IP addresses**) from alerts.

<img src="https://imgur.com/dTlRhJp.png" alt="Imgur Image" />

*Ref 4: Parsing out the hash to be enriched by virustotal using regex and the input gathered from webhook*

- **Enriches observables** using:
  - **VirusTotal API** (for file hashes and IP reputation)
  - **OSINT tools** for threat intelligence
- **Sends enriched alerts** to **TheHive**.

### 3️⃣ **Threat Intelligence – VirusTotal Enrichment**
- **VirusTotal API** is queried with the **SHA256 hash**.
- Results such as:
  - **Malicious detection ratio**
  - Associated threat labels
  - Scan reports
- Results are passed back to **Shuffle**.

<img src="https://imgur.com/FN6Lx0H.png" alt="Imgur Image" />

*Ref 5: Result of virustotal report on hash is successful, creating a status of 200*

<img src="https://imgur.com/R0uurjW.png" alt="Imgur Image" />

*Ref 6: By drilling into the results and identifying them as harmful, the system will pass that information on to the detection process.*

### 4️⃣ **Incident Creation – TheHive**
- **TheHive** receives enriched alerts from **Shuffle** via API (`/api/v1/alert`).
- **Creates a new case** with:
  - **Description:** Alert summary from Wazuh
  - **Tags:** (e.g., `T1003` for credential dumping)
  - **Severity level:** Based on enrichment results
- Displays the alert in **TheHive UI** for investigation.

<img src="https://imgur.com/i7sW0XF.png" alt="Imgur Image" />

*Ref 7: Results in TheHive.*

- **Shuffle** also create a simpliar alert in an email

<img src="https://imgur.com/8OZzl5U.png" alt="Imgur Image" />

*Ref 8: Email example of an alert*

### 5️⃣ **SOC Analyst Review – TheHive UI**
- **SOC Analysts** review alerts and cases in **TheHive UI**.
- Analysts can:
  - Investigate observables
  - Add comments and tasks
  - Escalate the incident if necessary

## Workflow Summary:
```
[Wazuh Agent] → [Wazuh Manager] → [Shuffle] → [VirusTotal] → [TheHive]/[Email] → [SOC Analyst]
```

<img src="https://imgur.com/Vv2bsxa.png" alt="Imgur Image" />

*Ref 9: Shuffle Workflow*

## API Examples
### **TheHive API – Create Alert**
```json
POST /api/v1/alert
{
  "title": "Mimikatz Detected",
  "description": "Mimikatz activity detected by Wazuh",
  "type": "external",
  "severity": 3,
  "tags": ["mimikatz", "T1003"],
  "tlp": 2,
  "pap": 2,
  "source": "Wazuh",
  "observables": [
    { "dataType": "hash", "data": "SHA256_HASH" }
  ]
}
```

### **VirusTotal API – File Report Lookup**
```bash
curl -X GET "https://www.virustotal.com/api/v3/files/{hash}" \
-H "x-apikey: $VT_API_KEY"
```

## Common Issues & Fixes
### 1. **Invalid JSON Error from TheHive**
- Ensure proper JSON formatting with commas and escaped characters.
- Validate JSON payloads using [jsonlint.com](https://jsonlint.com).

### 2. **SSL Error from VirusTotal API**
- Use `SSL Verify: False` if using self-signed certificates.
- Verify TLS version compatibility.

### 3. **Error `error.expected.jsarray` from TheHive API**
- Wrap the payload in an array as TheHive API expects lists for bulk queries.

---
## Conclusion
This project showcases the power of **SOC automation** to streamline alert processing, perform rapid threat enrichment, and manage incidents effectively. The integration of **Wazuh, Shuffle, TheHive, and VirusTotal** reduces manual workloads and provides faster insights for SOC analysts.

