# Censys-io-For-Splunk-app

# Introduction

Censys.io is a leading internet intelligence platform providing real-time visibility into internet-connected devices, infrastructure, and threats, helping security teams discover, monitor, and analyze their external attack surfaces to proactively find vulnerabilities, track changes, and manage risks across global networks, using a comprehensive "Internet Map" built from extensive, continuous scanning. It serves as a tool for organizations, security professionals, and researchers to understand their digital footprint and defend against cyber threats. 

# Overview
Censys.io for Splunk provides full visibility into your organization’s externally exposed digital footprint using Python code to query the Censys public scan database.   This Splunk App enables security teams to **discover, monitor, analyze, and operationalize external attack surface data** directly in Splunk


# Key Functions & Features:

- Internet Mapping: Continuously scans public IP addresses and domains to build a detailed, searchable map of the internet's assets (hosts, services, certificates).
- Attack Surface Management (ASM): Helps organizations find unknown, vulnerable, or misconfigured internet-facing assets, reducing blind spots.
- Threat Hunting: Provides data and tools for security teams to hunt for threats, assess their impact, and investigate incidents.
- Deep Context: Offers rich context on discovered assets, including software components, TLS details, WHOIS data, and vulnerability (CVE) information.
- Platform & API: Delivers insights via an interactive search engine, API, and integrations with other security tools, supporting large-scale analysis

---

## Supported Asset and Intelligence Types

Censys provides visibility into the following externally observable assets and metadata:

- IP Addresses
- Hosts and Services
- Open Ports and Protocols
- Software and Product Fingerprints
- SSL/TLS Certificates
- Certificate Authorities
- Domains and Hostnames
- Autonomous System Numbers (ASNs)
- Organizations
- Geolocation Metadata
- Internet-Wide Search Results
- ASM Inventory and Discoveries (if licensed)

---

## Features

### 🛡️ Core Capabilities

| Feature | Description |
|------|-------------|
| 🌐 External Asset Discovery | Identify exposed hosts and services |
| 🔍 Internet-Wide Search | Query Censys global scan index |
| 🧭 Host Intelligence | Deep inspection of services and banners |
| 🧬 Certificate Intelligence | SSL/TLS certificate visibility |
| 🕵️ Exposure Context | Protocols, software, and metadata |
| 🧾 Evidence Preservation | Raw API responses retained |

---

### 📈 Analytics and Visibility

| Feature | Description |
|------|-------------|
| 📊 Exposure Trends | Track asset and service changes |
| 🔄 First-Seen Detection | Identify newly observed assets |
| 🧱 Infrastructure Mapping | IP → ASN → Organization |
| 🔐 Certificate Monitoring | Certificate inventory and metadata |
| 🧠 Investigative Pivoting | Pivot across IPs, domains, and certs |

---

### ⚙️ Operational Excellence

| Feature | Description |
|------|-------------|
| 📡 Modular Input Framework | Secure API-based ingestion |
| 🔑 Credential Management | Encrypted credential storage |
| 🌐 Proxy Support | Enterprise proxy compatibility |
| 🩺 Health Monitoring | API reachability and status |
| 📋 Operational Logging | Full ingestion traceability |
| ⏱️ Rate-Limit Awareness | Throttling-safe polling |

---

## 📊 Dashboards

| Dashboard | Description |
|---------|-------------|
| Overview | High-level external exposure summary |
| Hosts | Internet-exposed hosts and services |
| Services | Port, protocol, and software analysis |
| Certificates | SSL/TLS certificate inventory |
| Domains | Domain and hostname visibility |
| ASN Exposure | ASN-level exposure analysis |
| New Assets | Newly observed assets |
| Search Analytics | Search query trends |
| Operations | Ingestion status and metrics |
| Health | API and data freshness monitoring |

Dashboards are designed for **investigation-first workflows**, not executive summaries.

---

# Censys for Splunk App  
## Sourcetype → Dashboard Mapping (Authoritative)

---

## 🟦 Core Internet Scan (Data Plane)

| Sourcetype | Dashboards |
|-----------|------------|
| `censys:host` | Overview, Hosts, Inventory, Locations, Autonomous Systems |
| `censys:host:service` | Services & Ports, Ports & Protocols |
| `censys:host:software` | Software, Operating Systems |
| `censys:host:os` | Operating Systems |
| `censys:host:dns` | DNS |
| `censys:host:whois` | WHOIS |
| `censys:host:tls` | TLS |
| `censys:host:jarm` | JARM |
| `censys:host:label` | Labels |
| `censys:location` | Locations |
| `censys:asn` | Autonomous Systems |

---

## 🟨 Certificates & Cryptography

| Sourcetype | Dashboards |
|-----------|------------|
| `censys:certificate` | Certificates |
| `censys:certificate:transparency` | Certificate Transparency |
| `censys:certificate:precertificate` | Precertificates |
| `censys:certificate:lite` | Lite Certificates |
| `censys:certificate:history` | Certificate History |
| `censys:certificate:cve` | CVE Context |

---

## 🟥 Threat Intelligence & Hunting

| Sourcetype | Dashboards |
|-----------|------------|
| `censys:threat` | Threat Overview |
| `censys:cve:context` | CVE Context |
| `censys:c2:label` | C2 Infrastructure |
| `censys:malicious:infrastructure` | Malicious Infrastructure |
| `censys:detection:pivot` | Detection Pivots |
| `censys:host:history` | Historical Changes |

---

## 🟩 Attack Surface Management (ASM)

| Sourcetype | Dashboards |
|-----------|------------|
| `censys:asm:asset` | ASM Overview, Inventory |
| `censys:asm:risk` | Risks |
| `censys:asm:risk:category` | Risk Categories |
| `censys:asm:cve:risk` | CVE Risks |
| `censys:asm:trend` | Trends & Benchmarks |
| `censys:asm:port` | Ports & Protocols |
| `censys:asm:metric` | Metrics |
| `censys:asm:seed` | Seeds |
| `censys:asm:excluded_asset` | Excluded Assets |

---

## 🟪 Logbook, Audit & Change Tracking

| Sourcetype | Dashboards |
|-----------|------------|
| `censys:logbook:event` | Logbook Events |
| `censys:audit:user_activity` | User Activity |
| `censys:audit:role_change` | Configuration Changes |
| `censys:audit:asset_change` | Asset Changes |
| `censys:audit:risk_change` | Risk Changes |

---

## 🟫 Organization, Access & Usage

| Sourcetype | Dashboards |
|-----------|------------|
| `censys:user` | Users |
| `censys:role` | Roles & Permissions |
| `censys:api_key` | API Keys |
| `censys:credit:usage` | Credit Usage |
| `censys:usage:trend` | Usage Trends |

---

## ⚙️ Operations & Health

| Sourcetype | Dashboards |
|-----------|------------|
| `censys:health` | Data Health |
| `censys:api:status` | API Status |
| `censys:ingestion:metric` | Ingestion Metrics |
| `censys:error` | Error Tracking |

---

## 📘 Reference & Enablement

| Sourcetype | Dashboards |
|-----------|------------|
| `censys:data:definition` | Data Definitions |
| `censys:query:example` | Query Examples |
| `censys:cenql:reference` | CenQL Reference |
| `censys:field:definition` | Field Explorer |

---

## 🧭 Navigation Structure

(Splunk default/data/ui/nav/default.xml equivalent)

⸻

## Overview
	- Overview
	
	- Global asset counts
	
	- Hosts, domains, certs, risks
	
	- Data freshness & credit usage

⸻

# 🌐 Internet Scan (Core Censys)

Derived from:

	- Host dataset
	
	- Certificates
	
	- DNS
	
	- WHOIS
	
	- Services
	
	- Software

# Dashboards
	- Hosts
	
	- Services & Ports
	
	- Software Inventory
	
	- Operating Systems
	
	- Autonomous Systems (ASN)
	
	- Locations (Geo)
	
	- DNS
	
	- WHOIS
	
	- TLS & Certificates
	
	- JARM Fingerprints
	
	- Labels / Tags

This directly maps to:
	-	platform-host-dataset
	
	-   host definitions (location, ASN, OS, DNS, WHOIS, services)

⸻

# 🔐 Certificates
	- Certificates
	
	- Certificate Transparency
	
	- Precertificates
	
	- Lite Certificates
	
	- Certificate History (for hunting)

Backed by CT + cert datasets
Used heavily in threat hunting & detection logic

⸻

# 🎯 Threat Intelligence & Hunting

Derived from:

	- Threat hunting docs
	
	- CVE context
	
	- C2 labels
	
	- JARM
	
	- Cert history

# Dashboards
	- Threat Overview
	
	- CVE Context
	
	- C2 Infrastructure
	
	- Malicious Infrastructure
	
	- Historical Changes
	
	- Detection Pivots

This is where Censys shines — and where Splunk beats their UI.

⸻

# 🧠 Attack Surface Management (ASM)

Clean separation from Internet Scan.

# Dashboards
	•	ASM Overview
	•	Inventory
	•	Risks
	•	Risk Categories
	•	CVE Risks
	•	Trends & Benchmarks
	•	Ports & Protocols
	•	Metrics
	•	Seeds
	•	Excluded Assets

Mapped exactly to:
	•	ASM dashboards
	•	ASM metrics
	•	ASM seeds
	•	ASM risks
	•	ASM trends

⸻

# 📓 Logbook & Audit

Derived from:
	•	Logbook API
	•	Org audit logging

# Dashboards
	•	Logbook Events
	•	User Activity
	•	Configuration Changes
	•	Risk Changes
	•	Asset Changes

This answers your earlier question about:

“How do we find users, permissions, and activity?”

# → Logbook + Org Management APIs

⸻

# 👥 Organization & Access

Derived from:
	•	Org management
	•	RBAC docs
	•	Credits

# Dashboards
	•	Users
	•	Roles & Permissions
	•	API Keys
	•	Credit Usage
	•	Usage Trends

⸻
# ⚙️ Operations

	•	Data Health
	•	API Status
	•	Ingestion Metrics
	•	Error Tracking
	•	Rate-Limit Visibility

⸻
# 📚 Reference
	•	Data Definitions
	•	Query Examples
	•	CenQL Reference
	•	Field Explorer





---

## Deployment

### Step 1: Install the App

1. Download Censys_For_Splunk_App-1.0.0.tar.gz
2. In Splunk Web, go to Apps → Manage Apps
3. Select Install app from file
4. Upload the package
5. Restart Splunk if prompted

---

### Step 2: Configure the App

This app uses a guided setup workflow to ensure secure and compliant configuration.

Navigate to Apps → Censys.io for Splunk → Setup to configure:

- Censys API credentials (stored securely)
- Optional enterprise proxy settings
- Modular input enablement and polling intervals

All inputs are disabled by default and must be explicitly enabled.

#### API Configuration
- Censys API ID
- Censys API Secret
- API Base URL  
  https://search.censys.io/api
- Request Timeout
- Verify SSL Certificates

#### Proxy Configuration (Optional)
- Enable Proxy
- Proxy URL
- Proxy Username
- Proxy Password

#### Data Inputs
- Host Lookups
- Search Queries
- Certificate Inventory
- Domain Monitoring
- ASN Monitoring
- ASM Inventory (if licensed)

---

### Step 3: Validate Configuration

- Test API connectivity
- Validate authentication
- Verify API plan and ASM entitlements
- Automatic validation on first launch

---

### Step 4: Verify Data Collection

Run the following search in Splunk:

    index=security_censys sourcetype=censys:*
    | stats count by sourcetype

---

## 📦 Requirements

- Splunk Enterprise or Splunk Cloud
- Python 3.x (Splunk bundled)
- Censys API Access (Search and/or ASM)
- Network access to Censys APIs

---

## ✅ AppInspect Compliance

- Proper Splunk directory structure
- No hardcoded credentials
- Inputs disabled by default
- Encrypted credential storage
- app.manifest included
- Apache License
- Setup-based configuration

---

## 🛠️ Troubleshooting

### No Data Appearing
- Verify API credentials and permissions
- Confirm inputs are enabled
- Check API rate limits
- Review Splunk internal logs

### API Errors
- Validate API plan capabilities
- Confirm ASM entitlements (if used)
- Check Censys service availability

### Proxy Issues
- Validate proxy connectivity
- Confirm SSL inspection compatibility
- Test proxy reachability from Splunk

---

## 📚 References

- Censys Search API  
  https://search.censys.io/api

- Censys ASM Documentation  
  https://docs.censys.com

- Censys Python SDK  
  https://github.com/censys/censys-python

- Splunk Documentation  
  https://docs.splunk.com

---

## 📜 License

Apache License
